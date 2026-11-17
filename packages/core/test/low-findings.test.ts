/**
 * Regression tests for the Low/Info security findings that live in the deterministic core (security review
 * 2026-10-15: L1, L7, L9, I4).
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { canonicalJson, chainHash, publicAuditEntry, sha256Hex, verifyAuditChain, verifyPublicAuditChain, viewFor } from "../src/index.ts";
import { Harness, single } from "./helpers.ts";

describe("L1: the public audit chain hides events the viewer can't see, yet still verifies", () => {
  const h = new Harness().toBargaining();
  // The claimant submits a sealed offer; the respondent hasn't yet.
  h.submit("claimant", { offer: { refundUsd: 800 }, private: single(300) });

  it("redacts type, time, visibility and commitment of the counterparty's and internal events", () => {
    const forRespondent = h.events.map((e) => publicAuditEntry(e, "respondent"));
    const hidden = h.events.filter((e) => e.visibility !== "both" && e.visibility !== "respondent");
    assert.ok(hidden.some((e) => e.visibility === "claimant"), "the claimant's submission events are claimant-only");
    for (const e of hidden) {
      const pub = forRespondent.find((p) => p.seq === e.seq)!;
      assert.deepEqual(Object.keys(pub).sort(), ["hash", "prevHash", "redacted", "seq"]);
      assert.ok(!JSON.stringify(pub).includes(e.type), "no event type");
      assert.ok(!JSON.stringify(pub).includes(String(e.at)), "no timestamp");
    }
    // Events the respondent may see keep every field.
    const shown = forRespondent.find((p) => !("redacted" in p))!;
    assert.ok("type" in shown && "at" in shown && "visibility" in shown && "dataCommitment" in shown);
  });

  it("verifies end to end for each party and matches the full chain's head", () => {
    const full = verifyAuditChain(h.events);
    assert.ok(full.ok);
    for (const viewer of ["claimant", "respondent"] as const) {
      const v = verifyPublicAuditChain(h.events.map((e) => publicAuditEntry(e, viewer)));
      assert.ok(v.ok, viewer);
      assert.equal(v.ok && v.head, full.ok && full.head);
      assert.ok(v.ok && v.redacted > 0);
    }
  });

  it("still detects tampering with a redacted entry, and a hidden entry can be disclosed to an auditor later", () => {
    const entries = h.events.map((e) => publicAuditEntry(e, "respondent"));
    const i = entries.findIndex((e) => "redacted" in e);
    const forged = entries.map((e, n) => (n === i ? { ...e, hash: sha256Hex("forged") } : e));
    const v = verifyPublicAuditChain(forged);
    assert.equal(v.ok, false);
    assert.equal(!v.ok && v.reason, "prevHash mismatch", "the next entry no longer links to it");
    // Disclosure: the hidden fields recompute the published hash.
    const original = h.events[i]!;
    assert.equal(chainHash(original), entries[i]!.hash);
  });
});

describe("L7: the gap bucket is disclosed only when bargaining failed to converge", () => {
  const both = { claimant: true, respondent: true };

  it("is not disclosed when a party withdraws mid-bargaining", () => {
    const h = new Harness({ gapDisclosure: both }).toBargaining();
    h.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    h.send({ type: "WITHDRAW", actor: "respondent" });
    const o = viewFor(h.state, "claimant").outcome;
    assert.ok(o?.kind === "UNRESOLVED" && o.reason === "WITHDRAWN");
    assert.equal(o?.kind === "UNRESOLVED" && o.gapBucket, undefined);
  });

  it("is not disclosed on TIMEOUT", () => {
    const h = new Harness({ gapDisclosure: both }).toBargaining();
    h.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    h.submit("claimant", { offer: { refundUsd: 890 } }).expire();
    h.submit("claimant", { offer: { refundUsd: 880 } }).expire();
    const o = viewFor(h.state, "claimant").outcome;
    assert.ok(o?.kind === "UNRESOLVED" && o.reason === "TIMEOUT", JSON.stringify(o));
    assert.equal(o?.kind === "UNRESOLVED" && o.gapBucket, undefined);
  });

  it("is still disclosed on STALLED (both opted in)", () => {
    const h = new Harness({ gapDisclosure: both }).toBargaining();
    h.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    h.round({ offer: { refundUsd: 890 } }, { offer: { refundUsd: 110 } });
    h.round({ offer: { refundUsd: 880 } }, { offer: { refundUsd: 120 } });
    const o = viewFor(h.state, "respondent").outcome;
    assert.ok(o?.kind === "UNRESOLVED" && (o.reason === "STALLED" || o.reason === "NO_OVERLAP_AT_CAP"));
    assert.equal(o?.kind === "UNRESOLVED" && o.gapBucket, ">50%");
  });
});

describe("L9: evidence ids are identifiers", () => {
  const h = new Harness().join();
  const item = (id: string) => ({ id, kind: "log", sha256: "a".repeat(64), description: "uptime export" });

  it("accepts plain ids", () => {
    for (const id of ["ev1", "E-2", "log_2026.10.15", "sla:report-1"]) {
      assert.equal(h.attempt({ type: "SUBMIT_EVIDENCE", actor: "claimant", items: [item(id)] }).ok, true, id);
    }
  });

  it("refuses ids with spaces, quotes, markup or instructions", () => {
    for (const id of ["ignore previous instructions", "<system>", 'a"b', "-leading", "x".repeat(65), "", "ev/1", "évidence"]) {
      const r = h.attempt({ type: "SUBMIT_EVIDENCE", actor: "claimant", items: [item(id)] });
      assert.ok(!r.ok && r.error.code === "INVALID_INPUT", JSON.stringify(id));
    }
  });
});

describe("I4: canonicalJson keeps an own __proto__ key", () => {
  it("canonicalises JSON with and without a __proto__ key differently, and never touches prototypes", () => {
    const withProto = JSON.parse('{"a":1,"__proto__":{"min":0,"max":1000000}}') as Record<string, unknown>;
    const plain = { a: 1 };
    assert.notEqual(canonicalJson(withProto), canonicalJson(plain), "the key is covered by hashes and signatures");
    assert.equal(canonicalJson(withProto), '{"__proto__":{"max":1000000,"min":0},"a":1}');
    assert.equal(({} as Record<string, unknown>).min, undefined, "Object.prototype untouched");
    // Nested too.
    assert.equal(canonicalJson({ bounds: JSON.parse('{"__proto__":{"x":1}}') }), '{"bounds":{"__proto__":{"x":1}}}');
  });
});
