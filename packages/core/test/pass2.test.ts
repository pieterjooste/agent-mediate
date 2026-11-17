/**
 * Regression tests for the core side of security review pass 2 (CR2-2, CR2-6, CR2-7, CR2-9, CR2-14).
 * CR2-2's non-interference and bisection tests are in disclosure.test.ts; CR2-11 in machine.test.ts.
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  deriveProposalKey,
  extendDeadlines,
  MAX_OUTAGE_EXTENSION_MS,
  nashProposal,
  presentProposal,
  proposalSplitFromKey,
  utility,
  viewFor,
  type Issue,
} from "../src/index.ts";
import { DAY, expectError, fullBounds, Harness, mandate, MIN, REFUND, RESPONDENT, single, T0 } from "./helpers.ts";

describe("CR2-2(b) / CR2-14: the proposal split is keyed per party pair and contract with a platform secret", () => {
  const SECRET = "platform-secret-".padEnd(48, "s");
  const C = "c".repeat(64);

  it("derives the same key for the same pair (either order) and contract, a different one otherwise", () => {
    const k = deriveProposalKey(SECRET, "did:a", "did:b", C);
    assert.equal(deriveProposalKey(SECRET, "did:b", "did:a", C), k, "refiling with the roles swapped doesn't redraw α");
    assert.notEqual(deriveProposalKey(SECRET, "did:a", "did:b", "d".repeat(64)), k);
    assert.notEqual(deriveProposalKey(SECRET, "did:a", "did:c", C), k);
    assert.notEqual(deriveProposalKey("another-secret".padEnd(48, "x"), "did:a", "did:b", C), k, "parties can't compute it without the platform secret");
    assert.match(k, /^[0-9a-f]{64}$/);
  });

  it("α is fixed for identical inputs (no averaging by refiling) and independent across different inputs", () => {
    const k = deriveProposalKey(SECRET, "did:a", "did:b", C);
    const basis = { claimant: single(300), respondent: single(700) };
    const a1 = proposalSplitFromKey(k, basis);
    assert.equal(proposalSplitFromKey(k, structuredClone(basis)), a1);
    assert.ok(a1 >= 0.3 && a1 <= 0.7);
    const others = [310, 320, 330, 340].map((w) => proposalSplitFromKey(k, { claimant: single(w), respondent: single(700) }));
    assert.equal(new Set([a1, ...others]).size, 5, "varying one's own walkaway yields fresh α, so no linear system to solve");
  });

  it("disputes created with a proposal key use it for every proposal", () => {
    const key = deriveProposalKey(SECRET, "agent:buyer.example", "agent:vendor.example", "c".repeat(64));
    const h = new Harness({ proposalKey: key }).toBargaining();
    h.round({ offer: { refundUsd: 800 }, private: single(300) }, { offer: { refundUsd: 200 }, private: single(700) });
    const basis = { claimant: single(300), respondent: single(700) };
    assert.deepEqual(h.state.bargaining!.proposal!.views!.claimant, nashProposal([REFUND], basis, proposalSplitFromKey(key, basis)));
    assert.equal(h.state.proposalKey, key);
    assert.ok(!JSON.stringify(viewFor(h.state, "claimant")).includes(key), "never disclosed");
  });
});

describe("CR2-2(a): without a zone, each party gets a stand-in of the same shape that never settles", () => {
  const issues: Issue[] = [REFUND];
  const noZone = { claimant: single(700), respondent: single(300) }; // claimant needs ≥ 700, respondent pays ≤ 300

  it("stand-ins sit at or above each party's own walkaway and can't settle, even if both accept", () => {
    const p = presentProposal(issues, noZone, 0.5);
    assert.equal(p.settles, false);
    assert.ok(p.views.claimant.refundUsd! >= 700, "the claimant's stand-in is no worse for it than its walkaway");
    assert.ok(p.views.respondent.refundUsd! <= 300, "the respondent's too");
    // Reflection: the stand-in lies α times the deficit (400) above the viewer's walkaway, but never beyond the issue
    // range, so here α · 300 (the room left up to 1000, or down to 0).
    assert.equal(p.views.claimant.refundUsd, 850);
    assert.equal(p.views.respondent.refundUsd, 150);
    const h = new Harness().toBargaining();
    h.round({ offer: { refundUsd: 1000 }, private: single(700) }, { offer: { refundUsd: 0 }, private: single(300) });
    assert.equal(h.state.bargaining!.proposal!.settles, false);
    h.round({ offer: { refundUsd: 1000 }, response: "accept" }, { offer: { refundUsd: 0 }, response: "accept" });
    assert.equal(h.state.status, "BARGAINING", "accepting a stand-in looks exactly like a counterparty rejection");
    assert.equal(viewFor(h.state, "claimant").bargaining!.yourHistory.at(-1)!.response, "accept");
  });

  it("the stand-in's distance from a party's own walkaway has the same form as a real proposal's", () => {
    const own = utility(issues, { refundUsd: 1 }, { refundUsd: 400 }, "claimant");
    // Real: counterparty walkaway 600 (zone of 200). Stand-in: counterparty walkaway 200 (deficit of 200).
    const real = presentProposal(issues, { claimant: single(400), respondent: single(600) }, 0.5);
    const fake = presentProposal(issues, { claimant: single(400), respondent: single(200) }, 0.5);
    assert.equal(real.settles, true);
    assert.equal(fake.settles, false);
    const gain = (p: typeof real) => utility(issues, { refundUsd: 1 }, p.views.claimant, "claimant") - own;
    assert.equal(gain(real), gain(fake), "a zone of width d and a deficit of d look identical to the claimant");
  });

  it("works for several issues: every stand-in is feasible for its viewer", () => {
    const CREDIT: Issue = { id: "serviceCreditUsd", label: "Credit", unit: "USD", min: 0, max: 500, step: 10, claimantPrefers: "higher", obligor: "respondent" };
    const two = [REFUND, CREDIT];
    const basis = {
      claimant: { weights: { refundUsd: 0.7, serviceCreditUsd: 0.3 }, walkaway: { refundUsd: 900, serviceCreditUsd: 450 } },
      respondent: { weights: { refundUsd: 0.4, serviceCreditUsd: 0.6 }, walkaway: { refundUsd: 100, serviceCreditUsd: 50 } },
    };
    assert.equal(nashProposal(two, basis), null, "no zone");
    const p = presentProposal(two, basis, 0.45);
    assert.equal(p.settles, false);
    assert.ok(utility(two, basis.claimant.weights, p.views.claimant, "claimant") >= utility(two, basis.claimant.weights, basis.claimant.walkaway, "claimant") - 1e-9);
    assert.ok(utility(two, basis.respondent.weights, p.views.respondent, "respondent") >= utility(two, basis.respondent.weights, basis.respondent.walkaway, "respondent") - 1e-9);
  });
});

describe("CR2-6: cumulative outage extension is capped per dispute", () => {
  it("stops extending after 48 hours in total", () => {
    const h = new Harness();
    const deadline = h.state.stageDeadline!;
    const first = extendDeadlines(h.state, { fromMs: T0, byMs: 30 * 3_600_000, reason: "platform_outage" }, T0 + 31 * 3_600_000);
    assert.ok(first.ok);
    const second = extendDeadlines(first.state, { fromMs: T0 + 31 * 3_600_000, byMs: 30 * 3_600_000, reason: "platform_outage" }, T0 + 62 * 3_600_000);
    assert.ok(second.ok);
    assert.equal(second.state.stageDeadline, deadline + MAX_OUTAGE_EXTENSION_MS);
    assert.equal(second.state.outageExtensionMs, MAX_OUTAGE_EXTENSION_MS);
    assert.deepEqual(second.events.at(-1)!.data.capped, true);
    const third = extendDeadlines(second.state, { fromMs: T0 + 62 * 3_600_000, byMs: 3_600_000, reason: "platform_outage" }, T0 + 63 * 3_600_000);
    assert.ok(third.ok && third.events.length === 0 && third.state.stageDeadline === second.state.stageDeadline);
  });
});

describe("CR2-7: issue ids are short lowerCamelCase identifiers", () => {
  it("accepts lowerCamelCase and refuses underscores, capitals first, spaces, markup and length > 24", () => {
    const h = new Harness().toIssueConfirmation();
    const issue = (id: string): Issue => ({ ...REFUND, id });
    assert.ok(h.attempt({ type: "PROPOSE_ISSUES", actor: "system", issues: [issue("refundUsd2")] }).ok);
    for (const id of ["refund_usd", "RefundUsd", "refund usd", "<b>x</b>", "a".repeat(25), "1refund", ""]) {
      expectError(h.attempt({ type: "PROPOSE_ISSUES", actor: "system", issues: [issue(id)] }), "INVALID_INPUT");
    }
  });
});

describe("CR2-9: the respondent may lengthen windows when joining", () => {
  it("effective windows are the longer of both, within platform limits; shortening is ignored", () => {
    const h = new Harness({ config: { roundTimeoutMs: 2 * MIN, stageTimeoutMs: 10 * MIN, determinationTimeoutMs: 5 * MIN } });
    const join = (windows: Record<string, number>) =>
      h.attempt({ type: "JOIN", actor: "respondent", respondentId: RESPONDENT, mandate: mandate(RESPONDENT, fullBounds([REFUND])), feePaid: true, discloseGapOnFailure: false, windows });
    expectError(join({ roundTimeoutMs: 2 * 3_600_000 }), "INVALID_INPUT");
    const r = join({ roundTimeoutMs: 10 * MIN, stageTimeoutMs: MIN * 10, determinationTimeoutMs: 30 * MIN });
    assert.ok(r.ok);
    assert.equal(r.state.config.roundTimeoutMs, 10 * MIN);
    assert.equal(r.state.config.determinationTimeoutMs, 30 * MIN);
    assert.equal(r.state.config.stageTimeoutMs, 10 * MIN);
    assert.equal(r.state.stageDeadline, h.now + 10 * MIN);
    assert.deepEqual(r.events.find((e) => e.type === "RESPONDENT_JOINED")!.data.windowsRaised, { roundTimeoutMs: 10 * MIN, determinationTimeoutMs: 30 * MIN });
    assert.equal(viewFor(r.state, "claimant").rules.roundTimeoutMs, 10 * MIN, "both see the effective windows");
    // MECH-4: raising roundTimeoutMs past bargainingWallClockMs lifts bargainingWallClockMs so round 1 is never truncated.
    const lifted = join({ roundTimeoutMs: 25 * MIN });
    assert.ok(lifted.ok);
    assert.equal(lifted.state.config.bargainingWallClockMs, 25 * MIN);
    void DAY;
  });
});
