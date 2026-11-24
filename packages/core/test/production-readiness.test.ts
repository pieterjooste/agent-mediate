/**
 * Regression tests for the 2026-11-11 production-readiness review findings in @agent-mediate/core:
 * - PR-PROTO-H1: mandate shape/bounds validation in createDispute and apply
 * - PR-CORE-M1: canonicalJson rejects non-plain objects (Date, Map, Set, RegExp, Uint8Array, class instances)
 * - PR-CORE-M2: zero-grid-point mandate rejection, validateNoticeDelivery shape checks, MAX_OUTAGE_EXTENSION_MS cap
 * - PR-L5: findLeaks visible floating-point tolerance
 * - PR-L6: verifyAuditChain / verifyPublicAuditChain malformed-input safety
 * - Hard invariant: RULES_HASH === "8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4" (v1.3.0)
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  apply,
  canonicalJson,
  createDispute,
  DomainError,
  extendDeadlines,
  findLeaks,
  GENESIS_HASH,
  mandateCovers,
  MAX_OUTAGE_EXTENSION_MS,
  requireMandateCovers,
  RULES_HASH,
  RULES_VERSION,
  validateMandateShape,
  validateNoticeDelivery,
  verifyAuditChain,
  verifyPublicAuditChain,
  viewFor,
  type DomainEvent,
  type Issue,
  type Mandate,
  type NoticeDelivery,
  type PublicAuditEntry,
} from "../src/index.ts";
import { CLAIMANT, CONTRACT, mandate, REFUND, RESPONDENT, SALT, T0 } from "./helpers.ts";

describe("2026-11-11 production-readiness: @agent-mediate/core", () => {
  it("preserves RULES_VERSION 1.4.0 and RULES_HASH invariant", () => {
    assert.equal(RULES_VERSION, "1.4.0");
    assert.equal(RULES_HASH, "10b48aa0d8a4a71808f5550f951ad128aa0af44b775b2c88c73ddb1dd1cee173");
  });

  it("PR-CORE-M1: canonicalJson rejects non-plain objects instead of serializing them as {}", () => {
    class CustomBox {
      x = 1;
    }
    const badValues: unknown[] = [
      new Date(0),
      new Map([["a", 1]]),
      new Set([1]),
      /abc/,
      new Uint8Array([1, 2, 3]),
      new CustomBox(),
      { nested: new Date(123456) },
      [new Map()],
    ];
    for (const v of badValues) {
      assert.throws(() => canonicalJson(v), /Non-plain object/, `expected canonicalJson to reject ${Object.prototype.toString.call(v)}`);
    }
    const nullProto = Object.assign(Object.create(null) as Record<string, unknown>, { b: 2, a: 1 });
    assert.equal(canonicalJson(nullProto), '{"a":1,"b":2}');
  });

  it("PR-PROTO-H1 & PR-CORE-M2: validates mandate shape and rejects zero-grid-point mandate intervals", () => {
    const stepTen: Issue = { ...REFUND, min: 0, max: 1000, step: 10 };
    const zeroGridMandate = mandate(CLAIMANT, { refundUsd: { min: 1, max: 9 } });
    assert.equal(mandateCovers(zeroGridMandate, stepTen), false);
    assert.throws(
      () => requireMandateCovers(zeroGridMandate, [stepTen]),
      (e: unknown) => e instanceof DomainError && e.code === "MANDATE_VIOLATION",
    );

    const zeroGridDetMandate: Mandate = {
      ...mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }),
      determinationConsent: true,
      determinationBounds: { refundUsd: { min: 11, max: 19 } },
    };
    assert.throws(
      () => requireMandateCovers(zeroGridDetMandate, [stepTen]),
      (e: unknown) => e instanceof DomainError && e.code === "MANDATE_VIOLATION",
    );

    // Malformed mandate shapes fail cleanly with DomainError rather than TypeError
    assert.throws(
      () => validateMandateShape({ ...mandate(CLAIMANT, { refundUsd: { min: 0, max: 100 } }), bounds: null as unknown as Mandate["bounds"] }, CLAIMANT, T0),
      (e: unknown) => e instanceof DomainError && e.code === "INVALID_INPUT",
    );

    const badCreate = createDispute(
      {
        id: "dsp_bad_mandate",
        auditSalt: SALT,
        claimantId: CLAIMANT,
        claimantMandate: { ...mandate(CLAIMANT, { refundUsd: { min: 0, max: 100 } }), bounds: [] as unknown as Mandate["bounds"] },
        respondentId: RESPONDENT,
        contractHash: CONTRACT,
        claim: { summary: "SLA outage", requestedRemedy: "Refund" },
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0,
    );
    assert.equal(badCreate.ok, false);
    assert.equal(badCreate.error.code, "INVALID_INPUT");

    const ok = createDispute(
      {
        id: "dsp_valid_grid",
        auditSalt: SALT,
        claimantId: CLAIMANT,
        claimantMandate: zeroGridMandate,
        respondentId: RESPONDENT,
        contractHash: CONTRACT,
        claim: { summary: "SLA outage", requestedRemedy: "Refund" },
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0,
    );
    assert.equal(ok.ok, true);
    const badJoin = apply(
      ok.state,
      {
        type: "JOIN",
        actor: "respondent",
        respondentId: RESPONDENT,
        mandate: { ...mandate(RESPONDENT, { refundUsd: { min: 0, max: 1000 } }), bounds: [] as unknown as Mandate["bounds"] },
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0 + 1000,
    );
    assert.equal(badJoin.ok, false);
    assert.equal(badJoin.error.code, "INVALID_INPUT");

    // Zero-grid-point mandate is rejected when confirming issues
    const joined = apply(
      ok.state,
      {
        type: "JOIN",
        actor: "respondent",
        respondentId: RESPONDENT,
        mandate: mandate(RESPONDENT, { refundUsd: { min: 0, max: 1000 } }),
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0 + 1000,
    );
    assert.equal(joined.ok, true);
    const closed1 = apply(joined.state, { type: "CLOSE_EVIDENCE", actor: "claimant" }, T0 + 2000);
    assert.equal(closed1.ok, true);
    const closed2 = apply(closed1.state, { type: "CLOSE_EVIDENCE", actor: "respondent" }, T0 + 3000);
    assert.equal(closed2.ok, true);
    const proposed = apply(closed2.state, { type: "PROPOSE_ISSUES", actor: "system", issues: [stepTen] }, T0 + 4000);
    assert.equal(proposed.ok, true);
    const confirmZeroGrid = apply(
      proposed.state,
      { type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: proposed.state.issueNegotiation.proposedHash! },
      T0 + 5000,
    );
    assert.equal(confirmZeroGrid.ok, false);
    assert.equal(confirmZeroGrid.error.code, "MANDATE_VIOLATION");
  });

  it("PR-CORE-M2: validates NoticeDelivery shapes and enforces MAX_OUTAGE_EXTENSION_MS in extendDeadlines", () => {
    assert.doesNotThrow(() =>
      validateNoticeDelivery({
        method: "standing_webhook",
        delivered: true,
        verifiedEndpoint: true,
        attempted: ["standing_webhook"],
        at: T0,
      }),
    );
    for (const bad of [
      null,
      { method: "sms", delivered: true, verifiedEndpoint: false, attempted: [], at: T0 },
      { method: "standing_webhook", delivered: false, verifiedEndpoint: true, attempted: ["standing_webhook"], at: T0 },
      { method: "none", delivered: true, verifiedEndpoint: false, attempted: [], at: T0 },
      { method: "email", delivered: true, verifiedEndpoint: false, attempted: ["sms"], at: T0 },
    ]) {
      assert.throws(() => validateNoticeDelivery(bad as unknown as NoticeDelivery), DomainError);
    }

    const created = createDispute(
      {
        id: "dsp_outage_cap",
        auditSalt: SALT,
        claimantId: CLAIMANT,
        claimantMandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }),
        respondentId: RESPONDENT,
        contractHash: CONTRACT,
        claim: { summary: "Outage cap check", requestedRemedy: "Refund" },
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0,
    );
    assert.equal(created.ok, true);
    const initialDeadline = created.state.stageDeadline!;

    // First extension exceeds MAX_OUTAGE_EXTENSION_MS -> clamped to MAX_OUTAGE_EXTENSION_MS
    const ext1 = extendDeadlines(
      created.state,
      { fromMs: T0 + 1_000, byMs: MAX_OUTAGE_EXTENSION_MS + 600_000, reason: "platform_outage" },
      T0 + 10_000,
    );
    assert.equal(ext1.ok, true);
    assert.equal(ext1.state.outageExtensionMs, MAX_OUTAGE_EXTENSION_MS);
    assert.equal(ext1.state.stageDeadline, initialDeadline + MAX_OUTAGE_EXTENSION_MS);
    assert.equal(ext1.events.length, 1);

    // Once at the cap, further outage extensions are no-ops
    const ext2 = extendDeadlines(
      ext1.state,
      { fromMs: T0 + 15_000, byMs: 60_000, reason: "platform_outage" },
      T0 + 20_000,
    );
    assert.equal(ext2.ok, true);
    assert.equal(ext2.events.length, 0);
    assert.equal(ext2.state.stageDeadline, ext1.state.stageDeadline);
  });

  it("PR-L5 & PR-L6: findLeaks respects floating-point visible values and audit verifiers never throw on malformed entries", () => {
    const created = createDispute(
      {
        id: "dsp_float_leak",
        auditSalt: SALT,
        claimantId: CLAIMANT,
        claimantMandate: mandate(CLAIMANT, { rate: { min: 0.1, max: 0.9 } }),
        respondentId: RESPONDENT,
        contractHash: CONTRACT,
        claim: { summary: "Rate check", requestedRemedy: "Adjust rate" },
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0,
    );
    assert.equal(created.ok, true);
    const s = apply(
      created.state,
      {
        type: "JOIN",
        actor: "respondent",
        respondentId: RESPONDENT,
        mandate: mandate(RESPONDENT, { rate: { min: 0.1, max: 0.3 } }),
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0 + 1000,
    );
    assert.equal(s.ok, true);
    const view = viewFor(s.state, "claimant");
    // 0.1 + 0.2 === 0.30000000000000004: respondent's max bound is 0.3, so leaking 0.30000000000000004 outside view is detected,
    // while when claimant's own mandate bound is 0.3, 0.30000000000000004 matches the visible value within 1e-9 without a false positive.
    assert.equal(findLeaks(JSON.stringify({ view }), s.state, "claimant").length, 0);
    assert.ok(findLeaks(JSON.stringify({ view, extraLeak: 0.1 + 0.2 }), s.state, "claimant").length >= 1);
    const sameVisibleState = createDispute(
      {
        id: "dsp_float_visible",
        auditSalt: SALT,
        claimantId: CLAIMANT,
        claimantMandate: mandate(CLAIMANT, { rate: { min: 0.1, max: 0.3 } }),
        respondentId: RESPONDENT,
        contractHash: CONTRACT,
        claim: { summary: "Rate check", requestedRemedy: "Adjust rate" },
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0,
    );
    assert.equal(sameVisibleState.ok, true);
    const sameJoined = apply(
      sameVisibleState.state,
      {
        type: "JOIN",
        actor: "respondent",
        respondentId: RESPONDENT,
        mandate: mandate(RESPONDENT, { rate: { min: 0.1, max: 0.3 } }),
        feePaid: true,
        discloseGapOnFailure: false,
      },
      T0 + 1000,
    );
    assert.equal(sameJoined.ok, true);
    assert.equal(findLeaks(String(0.1 + 0.2), sameJoined.state, "claimant").length, 0);

    // PR-L6: verifyAuditChain & verifyPublicAuditChain return { ok: false } instead of throwing on malformed entries
    assert.equal(verifyAuditChain(null as unknown as DomainEvent[]).ok, false);
    assert.equal(verifyAuditChain([{ seq: 1, prevHash: GENESIS_HASH } as unknown as DomainEvent]).ok, false);
    assert.equal(verifyPublicAuditChain(null as unknown as PublicAuditEntry[]).ok, false);
    assert.equal(verifyPublicAuditChain([{ seq: 1, redacted: "yes", prevHash: GENESIS_HASH, hash: "a".repeat(64) } as unknown as PublicAuditEntry]).ok, false);
  });
});
