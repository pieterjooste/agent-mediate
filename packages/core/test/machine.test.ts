import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildSettlementInstruction,
  buildUnresolvedCertificate,
  createDispute,
  extendDeadlines,
  issuesHash,
  nashProposal,
  NO_SHOW_NOTICE,
  proposalSplit,
  SPLIT_MAX,
  SPLIT_MIN,
  verifyAuditChain,
  viewFor,
} from "../src/index.ts";
import {
  CLAIMANT,
  CONTRACT,
  CREDIT,
  expectError,
  Harness,
  mandate,
  MIN,
  REFUND,
  RESPONDENT,
  SALT,
  single,
  T0,
} from "./helpers.ts";

/** Standard opening: claimant asks 800 (walkaway 300), respondent offers 200 (walkaway 700). */
function opened(h: Harness): Harness {
  return h.toBargaining().round(
    { offer: { refundUsd: 800 }, private: single(300) },
    { offer: { refundUsd: 200 }, private: single(700) },
  );
}

/** The proposal the platform computes for `opened`: asymmetric Nash with the dispute's secret split. */
function expectedProposal(h: Harness, claimantWalkaway = 300, respondentWalkaway = 700) {
  return nashProposal([REFUND], { claimant: single(claimantWalkaway), respondent: single(respondentWalkaway) }, proposalSplit(SALT, h.state.id));
}

describe("settlement paths", () => {
  it("settles at the midpoint when offers cross", () => {
    const h = opened(new Harness());
    assert.equal(h.state.bargaining!.round, 2);
    assert.deepEqual(h.state.bargaining!.proposal!.views?.claimant, expectedProposal(h), "Nash proposal (secret split) in round 2");
    assert.deepEqual(h.state.bargaining!.proposal!.views?.respondent, expectedProposal(h), "with a zone both see the same proposal");
    h.round({ offer: { refundUsd: 600 }, response: "reject" }, { offer: { refundUsd: 600 }, response: "reject" });
    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.deepEqual(h.state.outcome, {
      kind: "SETTLED",
      method: "OVERLAP_MIDPOINT",
      terms: { refundUsd: 600 },
      at: h.now,
      roundsCompleted: 2,
    });
    const instruction = buildSettlementInstruction(h.state);
    assert.deepEqual(instruction.obligors, ["respondent"]);
    assert.equal(instruction.auditRoot, h.state.audit.head);
  });

  it("settles on the platform proposal when both accept", () => {
    const h = opened(new Harness());
    const proposal = h.state.bargaining!.proposal!.views!.claimant;
    h.round({ offer: { refundUsd: 700 }, response: "accept" }, { offer: { refundUsd: 300 }, response: "accept" });
    assert.equal(h.state.outcome!.kind, "SETTLED");
    assert.equal(h.state.outcome!.kind === "SETTLED" && h.state.outcome!.method, "PROPOSAL_ACCEPTED");
    assert.deepEqual(h.state.outcome!.kind === "SETTLED" && h.state.outcome!.terms, proposal);
  });

  it("does not settle when only one side accepts the proposal", () => {
    const h = opened(new Harness());
    h.round({ offer: { refundUsd: 700 }, response: "accept" }, { offer: { refundUsd: 300 }, response: "reject" });
    assert.equal(h.state.status, "BARGAINING");
    assert.equal(h.state.bargaining!.round, 3);
  });

  it("with proposalBasis=offers, splits the gap between current offers and ignores declared walkaways", () => {
    const proposalFor = (claimantWalkaway: number) => {
      const h = new Harness({ config: { proposalBasis: "offers" } }).toBargaining();
      h.round({ offer: { refundUsd: 800 }, private: single(claimantWalkaway) }, { offer: { refundUsd: 200 }, private: single(700) });
      const prop = h.state.bargaining!.proposal!;
      return { views: prop.views, settles: prop.settles };
    };
    const p300 = proposalFor(300);
    const p600 = proposalFor(600);
    assert.equal(p300.settles, true);
    assert.ok(p300.views?.claimant.refundUsd !== undefined);
    assert.deepEqual(p300, p600, "exaggerating the walkaway no longer moves the proposal");
  });
});

describe("proposal confidentiality (security review H1, M13)", () => {
  it("the split is secret, fixed per dispute, within [0.3, 0.7], and varies across disputes", () => {
    const splits = Array.from({ length: 200 }, (_, i) => proposalSplit(`salt-${i}`, `dsp_${i}`));
    assert.ok(splits.every((a) => a >= SPLIT_MIN && a <= SPLIT_MAX));
    assert.equal(proposalSplit("s", "d"), proposalSplit("s", "d"), "deterministic for the platform");
    assert.ok(Math.min(...splits) < 0.35 && Math.max(...splits) > 0.65, "spread across the range");
  });

  it("a party can no longer recover the counterparty's walkaway as 2P - own walkaway", () => {
    // Single issue 0..1000 step 10; claimant walkaway 300, respondent walkaway 700. With the old symmetric
    // proposal, 2P - 300 = 700 exactly in every dispute. Now the estimate misses in most disputes, and the
    // honest bound a party can derive (Wc + (P - Wc) / 0.7 .. Wc + (P - Wc) / 0.3) is wide.
    let exact = 0;
    let widths = 0;
    const N = 200;
    for (let i = 0; i < N; i++) {
      const p = nashProposal([REFUND], { claimant: single(300), respondent: single(700) }, proposalSplit(`salt-${i}`, `dsp_${i}`))!.refundUsd!;
      if (Math.abs(2 * p - 300 - 700) <= REFUND.step) exact++;
      widths += (p - 300) / SPLIT_MIN - (p - 300) / SPLIT_MAX;
    }
    assert.ok(exact / N < 0.2, `estimate within one step in ${exact}/${N} disputes`);
    assert.ok(widths / N > 300, `mean width of the walkaway bound ${Math.round(widths / N)} (zone of agreement is 400)`);
  });

  it("private inputs are fixed by the first offer; repeating them unchanged is allowed", () => {
    const h = opened(new Harness());
    expectError(
      h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 2, offer: { refundUsd: 800 }, private: single(400), proposalResponse: "reject" }),
      "INVALID_INPUT",
    );
    h.round({ offer: { refundUsd: 800 }, private: single(300), response: "reject" }, { offer: { refundUsd: 200 }, response: "reject" });
    assert.equal(h.state.bargaining!.round, 3);
  });
});

describe("mandate authority (security review H2)", () => {
  it("rejects a replacement mandate from a different principal (e.g. one the agent signed itself)", () => {
    const h = new Harness().toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    const wider = { ...mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }), principalId: CLAIMANT };
    expectError(h.attempt({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: issuesHash([REFUND]), mandate: wider }), "MANDATE_VIOLATION");
    // The same principal may still issue a replacement.
    h.send({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: issuesHash([REFUND]), mandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 900 } }, undefined, T0) });
  });

  it("rejects a replacement that is not newer than the current mandate (CR2-11)", () => {
    const h = new Harness().toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    const hash = issuesHash([REFUND]);
    // An older (or same-age, or undated) mandate from the same principal can't be swapped back in.
    for (const issuedAt of [T0 - 120_000, T0 - 60_000, undefined]) {
      const old = { ...mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }), issuedAt };
      if (issuedAt === undefined) delete (old as { issuedAt?: number }).issuedAt;
      expectError(h.attempt({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash, mandate: old }), "MANDATE_VIOLATION");
    }
    expectError(h.attempt({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash, mandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }, undefined, T0 + 10 * MIN) }), "INVALID_INPUT");
    assert.equal(h.attempt({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash, mandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }, undefined, T0) }).ok, true);
  });

  it("enforces a signed scope: wrong contract or counterparty is rejected", () => {
    const base = mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } });
    const file = (m: typeof base) =>
      createDispute(
        { id: "d", auditSalt: SALT, claimantId: CLAIMANT, claimantMandate: m, respondentId: RESPONDENT, contractHash: CONTRACT, claim: { summary: "x", requestedRemedy: "y" }, feePaid: true, discloseGapOnFailure: false },
        T0,
      );
    assert.equal(file({ ...base, scope: { contractHash: CONTRACT, counterpartyId: RESPONDENT } }).ok, true);
    const wrongContract = file({ ...base, scope: { contractHash: "e".repeat(64) } });
    assert.equal(!wrongContract.ok && wrongContract.error.code, "MANDATE_VIOLATION");
    const wrongCounterparty = file({ ...base, scope: { counterpartyId: "agent:someone-else" } });
    assert.equal(!wrongCounterparty.ok && wrongCounterparty.error.code, "MANDATE_VIOLATION");
  });
});

describe("offer rules", () => {
  it("rejects retractions per issue", () => {
    const h = opened(new Harness());
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 2, offer: { refundUsd: 810 }, proposalResponse: "reject" }), "RETRACTION");
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "respondent", round: 2, offer: { refundUsd: 190 }, proposalResponse: "reject" }), "RETRACTION");
  });

  it("rejects offers outside the principal's mandate", () => {
    const h = new Harness({ respondentBounds: { refundUsd: { min: 0, max: 600 } } }).toBargaining();
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "respondent", round: 1, offer: { refundUsd: 610 }, private: single(600) }), "MANDATE_VIOLATION");
  });

  it("still presents a proposal outside a mandate (Info-4, CR2-2), but that party can't accept it and it never settles", () => {
    // Two issues: both walkaways lie inside their own mandates, yet the linear Nash proposal pushes refundUsd to 1000 (> respondent max 600).
    const h = new Harness({
      issues: [REFUND, CREDIT],
      respondentBounds: { refundUsd: { min: 0, max: 600 }, serviceCreditUsd: { min: 0, max: 500 } },
    }).toBargaining();
    h.round(
      { offer: { refundUsd: 900, serviceCreditUsd: 400 }, private: { weights: { refundUsd: 0.9, serviceCreditUsd: 0.1 }, walkaway: { refundUsd: 200, serviceCreditUsd: 0 } } },
      { offer: { refundUsd: 100, serviceCreditUsd: 50 }, private: { weights: { refundUsd: 0.1, serviceCreditUsd: 0.9 }, walkaway: { refundUsd: 600, serviceCreditUsd: 300 } } },
    );
    const p = h.state.bargaining!.proposal!;
    assert.ok(p.views!.respondent.refundUsd! > 600, "the Nash point exceeds the respondent's mandate max 600");
    expectError(
      h.attempt({ type: "SUBMIT_ROUND", actor: "respondent", round: 2, offer: { refundUsd: 100, serviceCreditUsd: 50 }, proposalResponse: "accept" }),
      "MANDATE_VIOLATION",
    );
    h.round({ offer: { refundUsd: 900, serviceCreditUsd: 400 }, response: "accept" }, { offer: { refundUsd: 100, serviceCreditUsd: 50 }, response: "reject" });
    assert.equal(h.state.status, "BARGAINING", "the claimant's acceptance alone settles nothing");
  });

  it("rejects declared walkaways outside the principal's mandate (MECH-5)", () => {
    const h = new Harness({
      claimantBounds: { refundUsd: { min: 500, max: 1000 } },
      respondentBounds: { refundUsd: { min: 0, max: 400 } },
    }).toBargaining();
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 1, offer: { refundUsd: 800 }, private: single(400) }), "MANDATE_VIOLATION");
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "respondent", round: 1, offer: { refundUsd: 200 }, private: single(450) }), "MANDATE_VIOLATION");
  });

  it("requires mandates to outlive bargaining + determination at issue confirmation, and rejects expired mandates (MECH-5)", () => {
    // At CONFIRM_ISSUES, stageDeadline is T0 + 30m, bargainingWallClockMs is 60m, determinationTimeoutMs is 10m -> first confirmer needs >= T0 + 100m.
    const short = new Harness({
      claimantMandateExpiry: T0 + 95 * MIN,
      determination: { claimant: true, respondent: true },
      config: { roundTimeoutMs: 30 * MIN, bargainingWallClockMs: 60 * MIN, determinationTimeoutMs: 10 * MIN },
    }).toIssueConfirmation();
    short.send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    expectError(short.attempt({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: issuesHash([REFUND]) }), "MANDATE_EXPIRED");

    // If a platform outage extends bargaining past a mandate's signed expiry, SUBMIT_ROUND still rejects with MANDATE_EXPIRED.
    const h = new Harness({
      claimantMandateExpiry: T0 + 120 * MIN,
      config: { roundTimeoutMs: 30 * MIN, bargainingWallClockMs: 60 * MIN },
    }).toBargaining();
    const ext = extendDeadlines(h.state, { fromMs: T0, byMs: 130 * MIN, reason: "platform_outage" }, T0 + 130 * MIN);
    assert.ok(ext.ok);
    h.state = ext.state;
    h.advance(125 * MIN);
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 1, offer: { refundUsd: 800 }, private: single(300) }), "MANDATE_EXPIRED");
  });

  it("requires private inputs with the first offer and a response while a proposal is open", () => {
    const h = new Harness().toBargaining();
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 1, offer: { refundUsd: 800 } }), "INVALID_INPUT");
    expectError(
      h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 1, offer: { refundUsd: 800 }, private: single(300), proposalResponse: "accept" }),
      "INVALID_INPUT",
    );
    const h2 = opened(new Harness());
    expectError(h2.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 2, offer: { refundUsd: 700 }, proposalResponse: "maybe" as never }), "INVALID_INPUT");
    // Not answering is a rejection (proposals are open in every round since CR2-2).
    assert.equal(h2.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 2, offer: { refundUsd: 700 } }).ok, true);
  });

  it("rejects wrong rounds, duplicates and off-grid values", () => {
    const h = new Harness().toBargaining();
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 2, offer: { refundUsd: 800 }, private: single(300) }), "WRONG_ROUND");
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 1, offer: { refundUsd: 805 }, private: single(300) }), "INVALID_INPUT");
    h.submit("claimant", { offer: { refundUsd: 800 }, private: single(300) });
    expectError(h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 1, offer: { refundUsd: 790 } }), "ALREADY_SUBMITTED");
  });
});

describe("termination without a deal", () => {
  it("ends STALLED when the gap stops closing", () => {
    // Non-overlapping walkaways: no proposals, so no responses needed.
    const h = new Harness().toBargaining();
    h.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    h.round({ offer: { refundUsd: 890 } }, { offer: { refundUsd: 110 } });
    assert.equal(h.state.status, "BARGAINING");
    h.round({ offer: { refundUsd: 880 } }, { offer: { refundUsd: 120 } });
    assert.equal(h.state.status, "UNRESOLVED");
    assert.deepEqual(h.state.outcome, { kind: "UNRESOLVED", reason: "STALLED", at: h.now, roundsCompleted: 3 });
  });

  it("does not stall when parties actively concede inside a <5% gap (MECH-3)", () => {
    const h = new Harness().toBargaining();
    // Gap 0.04 -> 0.03 -> 0.02 -> 0 (settlement), never killed as STALLED.
    h.round({ offer: { refundUsd: 520 }, private: single(400) }, { offer: { refundUsd: 480 }, private: single(600) });
    h.round({ offer: { refundUsd: 510 }, response: "reject" }, { offer: { refundUsd: 480 }, response: "reject" });
    h.round({ offer: { refundUsd: 500 }, response: "reject" }, { offer: { refundUsd: 480 }, response: "reject" });
    assert.equal(h.state.status, "BARGAINING");
    h.round({ offer: { refundUsd: 500 }, response: "reject" }, { offer: { refundUsd: 500 }, response: "reject" });
    assert.equal(h.state.outcome?.kind, "SETTLED");
  });

  it("ends NO_OVERLAP_AT_CAP at maxRounds", () => {
    const h = new Harness({ config: { maxRounds: 3, stallThreshold: 0 } }).toBargaining();
    h.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    h.round({ offer: { refundUsd: 800 } }, { offer: { refundUsd: 200 } });
    h.round({ offer: { refundUsd: 700 } }, { offer: { refundUsd: 300 } });
    assert.equal(h.state.outcome!.kind === "UNRESOLVED" && h.state.outcome!.reason, "NO_OVERLAP_AT_CAP");
  });

  it("never opens a round with less than one full round window left on the bargaining wall clock (MECH-4)", () => {
    const h = new Harness({ config: { roundTimeoutMs: 10 * MIN, bargainingWallClockMs: 15 * MIN, stallThreshold: 0 } }).toBargaining();
    h.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    // Respondent misses round 2 at T0 + 10m; only 5m (< 10m roundTimeoutMs) remain on wallClockDeadline,
    // so bargaining ends NO_OVERLAP_AT_CAP immediately instead of opening a truncated round 3 that could cause TIMEOUT.
    h.submit("claimant", { offer: { refundUsd: 800 } }).expire();
    assert.equal(h.state.outcome!.kind === "UNRESOLVED" && h.state.outcome!.reason, "NO_OVERLAP_AT_CAP");
    assert.equal(h.state.outcome!.roundsCompleted, 2);
  });

  it("ends TIMEOUT when a party never makes an offer", () => {
    const h = new Harness().toBargaining();
    h.submit("claimant", { offer: { refundUsd: 900 }, private: single(700) }).expire();
    assert.equal(h.state.outcome!.kind === "UNRESOLVED" && h.state.outcome!.reason, "TIMEOUT");
    assert.deepEqual(buildUnresolvedCertificate(h.state).participation, { claimant: "ON_TIME", respondent: "MISSED_ROUNDS" });
  });

  it("lets a missed round stand on the last offer, and ends TIMEOUT on the second miss", () => {
    const h = new Harness({ config: { stallThreshold: 0 } }).toBargaining();
    h.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    h.submit("claimant", { offer: { refundUsd: 800 } }).expire();
    assert.equal(h.state.status, "BARGAINING", "first miss: offer stands");
    assert.equal(h.state.bargaining!.misses.respondent, 1);
    h.submit("claimant", { offer: { refundUsd: 700 } }).expire();
    assert.equal(h.state.outcome!.kind === "UNRESOLVED" && h.state.outcome!.reason, "TIMEOUT");
  });

  it("processes a passed deadline before a late command", () => {
    const h = opened(new Harness({ config: { stallThreshold: 0 } }));
    h.advance(h.state.bargaining!.roundDeadline - h.now);
    const late = h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 2, offer: { refundUsd: 700 }, proposalResponse: "reject" });
    expectError(late, "WRONG_ROUND");
    assert.equal(h.state.bargaining!.round, 2, "rejected command leaves state untouched");
  });

  it("ends UNNOTIFIED_EXPIRY when unnotified, and RESPONDENT_NO_SHOW only after verified respondent notice (SEC3-6, DISC-2(d))", () => {
    const unnotified = new Harness().expire();
    assert.equal(unnotified.state.outcome!.kind === "UNRESOLVED" && unnotified.state.outcome!.reason, "UNNOTIFIED_EXPIRY");
    const unnotifiedCert = buildUnresolvedCertificate(unnotified.state);
    assert.equal(unnotifiedCert.participation.respondent, "UNNOTIFIED");
    assert.equal(unnotifiedCert.notice, NO_SHOW_NOTICE);

    const unverifiedContact = new Harness()
      .send({
        type: "RECORD_NOTICE",
        actor: "system",
        noticeDelivery: { method: "unverified_contact", delivered: true, verifiedEndpoint: false, attempted: ["unverified_contact"], at: 1 },
      })
      .expire();
    assert.equal(unverifiedContact.state.outcome!.kind === "UNRESOLVED" && unverifiedContact.state.outcome!.reason, "UNNOTIFIED_EXPIRY");
    assert.equal(buildUnresolvedCertificate(unverifiedContact.state).participation.respondent, "UNNOTIFIED");

    const verified = new Harness()
      .send({
        type: "RECORD_NOTICE",
        actor: "system",
        noticeDelivery: { method: "standing_webhook", delivered: true, verifiedEndpoint: true, attempted: ["standing_webhook"], at: 1 },
      })
      .expire();
    assert.equal(verified.state.outcome!.kind === "UNRESOLVED" && verified.state.outcome!.reason, "RESPONDENT_NO_SHOW");
    const verifiedCert = buildUnresolvedCertificate(verified.state);
    assert.equal(verifiedCert.participation.respondent, "NO_SHOW");
  });

  it("ends WITHDRAWN on withdrawal", () => {
    const h = opened(new Harness()).send({ type: "WITHDRAW", actor: "respondent" });
    assert.equal(h.state.outcome!.kind === "UNRESOLVED" && h.state.outcome!.reason, "WITHDRAWN");
  });
});

describe("issue confirmation gate", () => {
  it("requires the exact proposed hash", () => {
    const h = new Harness().toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    expectError(h.attempt({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: issuesHash([CREDIT]) }), "HASH_MISMATCH");
  });

  it("ends ISSUES_NOT_AGREED after the proposal limit", () => {
    const h = new Harness({ config: { maxIssueProposals: 2 } }).toIssueConfirmation();
    const h1 = issuesHash([REFUND]);
    h.send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] }).send({
      type: "REJECT_ISSUES",
      actor: "respondent",
      issuesHash: h1,
    });
    assert.equal(h.state.status, "ISSUE_CONFIRMATION");
    h.send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] }).send({
      type: "REJECT_ISSUES",
      actor: "claimant",
      issuesHash: h1,
    });
    assert.equal(h.state.outcome!.kind === "UNRESOLVED" && h.state.outcome!.reason, "ISSUES_NOT_AGREED");
  });

  it("requires the mandate to cover every issue, and accepts a replacement mandate", () => {
    const h = new Harness({ claimantBounds: { refundUsd: { min: 0, max: 1000 } }, issues: [REFUND, CREDIT] }).toIssueConfirmation();
    h.send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND, CREDIT] });
    const hash = issuesHash([REFUND, CREDIT]);
    expectError(h.attempt({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash }), "MANDATE_VIOLATION");
    const replacement = mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 }, serviceCreditUsd: { min: 0, max: 500 } }, undefined, T0);
    h.send({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash, mandate: replacement });
    assert.equal(h.state.issueNegotiation.confirmed.claimant, true);
  });

  it("moves on from evidence at the deadline", () => {
    const h = new Harness().join().expire();
    assert.equal(h.state.status, "ISSUE_CONFIRMATION");
  });

  it("rejects duplicate evidence ids", () => {
    const h = new Harness().join();
    const item = { id: "uptime-log", kind: "log", sha256: "d".repeat(64), description: "Signed uptime log" };
    h.send({ type: "SUBMIT_EVIDENCE", actor: "claimant", items: [item] });
    expectError(h.attempt({ type: "SUBMIT_EVIDENCE", actor: "respondent", items: [item] }), "INVALID_INPUT");
  });
});

describe("binding final-offer determination (opt-in)", () => {
  const consent = { claimant: true, respondent: true };
  function stalled(h: Harness): Harness {
    h.toBargaining();
    h.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    h.round({ offer: { refundUsd: 890 } }, { offer: { refundUsd: 110 } });
    return h.round({ offer: { refundUsd: 880 } }, { offer: { refundUsd: 120 } });
  }

  it("opens instead of UNRESOLVED only when both consented", () => {
    assert.equal(stalled(new Harness({ determination: { claimant: true, respondent: false } })).state.status, "UNRESOLVED");
    assert.equal(stalled(new Harness({ determination: consent })).state.status, "DETERMINATION");
  });

  it("awards the final offer closer to the reference", () => {
    const h = stalled(new Harness({ determination: consent }));
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 600 } });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: { refundUsd: 400 } });
    h.send({ type: "SET_DETERMINATION_REFERENCE", actor: "system", terms: { refundUsd: 450 } });
    assert.deepEqual(h.state.outcome && h.state.outcome.kind === "SETTLED" && [h.state.outcome.method, h.state.outcome.terms], [
      "FINAL_OFFER_DETERMINATION",
      { refundUsd: 400 },
    ]);
  });

  it("uses the last bargaining offer if a final offer is missing", () => {
    const h = stalled(new Harness({ determination: consent }));
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 600 } });
    h.send({ type: "SET_DETERMINATION_REFERENCE", actor: "system", terms: { refundUsd: 300 } });
    h.expire();
    // Respondent's standing offer 120 is 0.18 from the reference; claimant's 600 is 0.30.
    assert.deepEqual(h.state.outcome!.kind === "SETTLED" && h.state.outcome!.terms, { refundUsd: 120 });
  });

  it("fails cleanly without a reference, and cannot be withdrawn from", () => {
    const h = stalled(new Harness({ determination: consent }));
    expectError(h.attempt({ type: "WITHDRAW", actor: "claimant" }), "INVALID_STATE");
    expectError(h.attempt({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 890 } }), "RETRACTION");
    h.expire();
    assert.equal(h.state.outcome!.kind === "UNRESOLVED" && h.state.outcome!.reason, "DETERMINATION_FAILED");
  });

  it("ends DETERMINATION_FAILED if the winning final offer exceeds the loser's mandate or determinationBounds (MECH-1)", () => {
    // Respondent's principal only authorised up to 400; claimant's 600 is closer to reference 550, so binding respondent to 600 must be refused.
    const h = stalled(
      new Harness({
        determination: consent,
        claimantBounds: { refundUsd: { min: 500, max: 1000 } },
        respondentBounds: { refundUsd: { min: 0, max: 400 } },
      }),
    );
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 600 } });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: { refundUsd: 350 } });
    h.send({ type: "SET_DETERMINATION_REFERENCE", actor: "system", terms: { refundUsd: 550 } });
    assert.equal(h.state.status, "UNRESOLVED");
    assert.equal(h.state.outcome?.kind === "UNRESOLVED" && h.state.outcome.reason, "DETERMINATION_FAILED");

    // Optional determinationBounds can widen or tighten determination authority relative to bargaining bounds.
    const h2 = stalled(
      new Harness({
        determination: consent,
        claimantBounds: { refundUsd: { min: 500, max: 1000 } },
        respondentBounds: { refundUsd: { min: 0, max: 400 } },
        respondentDeterminationBounds: { refundUsd: { min: 0, max: 650 } },
      }),
    );
    h2.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 600 } });
    h2.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: { refundUsd: 350 } });
    h2.send({ type: "SET_DETERMINATION_REFERENCE", actor: "system", terms: { refundUsd: 550 } });
    assert.equal(h2.state.outcome?.kind === "SETTLED" && h2.state.outcome.terms.refundUsd, 600);
  });

  it("updates determinationConsent when a replacement mandate is registered at issue confirmation (MECH-1)", () => {
    const h = new Harness({ determination: { claimant: false, respondent: true } }).toIssueConfirmation();
    h.send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    const hash = issuesHash([REFUND]);
    const replacement = mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }, undefined, T0, { determinationConsent: true });
    h.send({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash, mandate: replacement });
    h.send({ type: "CONFIRM_ISSUES", actor: "respondent", issuesHash: hash });
    assert.equal(viewFor(h.state, "claimant").determinationEnabled, true);
  });
});

describe("settlement execution", () => {
  function settled(): Harness {
    return opened(new Harness()).round({ offer: { refundUsd: 600 }, response: "reject" }, { offer: { refundUsd: 600 }, response: "reject" });
  }

  it("is HONORED once the obligee confirms", () => {
    const h = settled();
    expectError(h.attempt({ type: "SUBMIT_EXECUTION_PROOF", actor: "claimant", reference: "x" }), "NOT_AUTHORIZED");
    h.send({ type: "SUBMIT_EXECUTION_PROOF", actor: "respondent", reference: "base:0xabc" });
    h.send({ type: "CONFIRM_EXECUTION", actor: "claimant" });
    assert.equal(h.state.status, "HONORED");
  });

  it("is BREACH_REPORTED at the deadline when no proof was submitted", () => {
    const h = settled().expire();
    assert.equal(h.state.status, "BREACH_REPORTED");
    const breach = h.events.find((e) => e.type === "BREACH_REPORTED")!;
    assert.deepEqual(breach.data, {
      breachedBy: ["respondent"],
      proofsSubmittedBy: [],
      outcomeHash: buildSettlementInstruction(h.state).outcomeHash,
    });
  });

  it("treats uncontested proof at the deadline as HONORED so a silent obligee cannot manufacture a breach (MECH-2)", () => {
    const h = settled().send({ type: "SUBMIT_EXECUTION_PROOF", actor: "respondent", reference: "base:0xabc" }).expire();
    assert.equal(h.state.status, "HONORED");
    const honored = h.events.find((e) => e.type === "HONORED")!;
    assert.deepEqual(honored.data, {
      unconfirmedProofs: ["respondent"],
      outcomeHash: buildSettlementInstruction(h.state).outcomeHash,
    });
  });

  it("supports CONTEST_EXECUTION: contested proof ends BREACH_REPORTED unless cured and confirmed (MECH-2)", () => {
    const h = settled();
    expectError(h.attempt({ type: "CONTEST_EXECUTION", actor: "claimant", reason: "premature" }), "INVALID_STATE");
    h.send({ type: "SUBMIT_EXECUTION_PROOF", actor: "respondent", reference: "base:0xbogus" });
    h.send({ type: "CONTEST_EXECUTION", actor: "claimant", reason: "transaction reverted on Base" });
    expectError(h.attempt({ type: "CONTEST_EXECUTION", actor: "claimant", reason: "duplicate" }), "ALREADY_SUBMITTED");
    // Re-submitting proof alone cannot silently erase the obligee's contest right before the deadline.
    h.send({ type: "SUBMIT_EXECUTION_PROOF", actor: "respondent", reference: "base:0xbogus2" });
    h.expire();
    assert.equal(h.state.status, "BREACH_REPORTED");
    const breach = h.events.find((e) => e.type === "BREACH_REPORTED")!;
    assert.deepEqual(breach.data, {
      breachedBy: ["respondent"],
      proofsSubmittedBy: ["respondent"],
      contested: ["respondent"],
      outcomeHash: buildSettlementInstruction(h.state).outcomeHash,
    });

    // Honest cure before deadline: obligor re-submits valid proof and obligee confirms -> HONORED.
    const cured = settled();
    cured.send({ type: "SUBMIT_EXECUTION_PROOF", actor: "respondent", reference: "base:0xwrong" });
    cured.send({ type: "CONTEST_EXECUTION", actor: "claimant", reason: "wrong memo" });
    cured.send({ type: "SUBMIT_EXECUTION_PROOF", actor: "respondent", reference: "base:0xfixed" });
    cured.send({ type: "CONFIRM_EXECUTION", actor: "claimant" });
    assert.equal(cured.state.status, "HONORED");
  });

  it("creates no obligation and settles immediately as HONORED when terms equal the obligee's worst extreme (MECH-2)", () => {
    const h = new Harness().toBargaining();
    h.round({ offer: { refundUsd: 0 }, private: single(0) }, { offer: { refundUsd: 0 }, private: single(100) });
    assert.equal(h.state.status, "HONORED");
    assert.deepEqual(h.state.execution?.obligors, []);
    assert.deepEqual(buildSettlementInstruction(h.state).obligors, []);
  });
});

describe("admission and fees", () => {
  it("enforces FILER_PAYS only — respondents join free and SPLIT is rejected", () => {
    const h = new Harness();
    h.join(false);
    assert.equal(h.state.status, "EVIDENCE");
    expectError(
      createDispute(
        {
          id: "d_split",
          auditSalt: SALT,
          claimantId: CLAIMANT,
          claimantMandate: mandate(CLAIMANT, {}),
          respondentId: RESPONDENT,
          contractHash: CONTRACT,
          claim: { summary: "s", requestedRemedy: "r" },
          feePaid: true,
          discloseGapOnFailure: false,
          config: { feeMode: "SPLIT" as unknown as "FILER_PAYS" },
        },
        T0,
      ),
      "INVALID_INPUT",
    );
  });

  it("rejects an impostor respondent", () => {
    const h = new Harness();
    expectError(
      h.attempt({
        type: "JOIN",
        actor: "respondent",
        respondentId: "agent:impostor",
        mandate: mandate("agent:impostor", { refundUsd: { min: 0, max: 1000 } }),
        feePaid: true,
        discloseGapOnFailure: false,
      }),
      "NOT_AUTHORIZED",
    );
  });

  it("enforces round-cap bounds (3–8), bargainingWallClockMs >= roundTimeoutMs (MECH-4), and requires the filing fee", () => {
    const base = {
      id: "d",
      auditSalt: SALT,
      claimantId: CLAIMANT,
      claimantMandate: mandate(CLAIMANT, {}),
      respondentId: RESPONDENT,
      contractHash: CONTRACT,
      claim: { summary: "s", requestedRemedy: "r" },
      feePaid: true,
      discloseGapOnFailure: false,
    };
    expectError(createDispute({ ...base, config: { maxRounds: 9 } }, T0), "INVALID_INPUT");
    expectError(createDispute({ ...base, config: { maxRounds: 2 } }, T0), "INVALID_INPUT");
    expectError(createDispute({ ...base, config: { roundTimeoutMs: 20 * MIN, bargainingWallClockMs: 15 * MIN } }, T0), "INVALID_INPUT");
    assert.equal(createDispute({ ...base, config: { maxRounds: 8 } }, T0).ok, true);
    expectError(createDispute({ ...base, feePaid: false }, T0), "FEE_REQUIRED");
  });

  it("refuses windows below the platform minimums, so no signed adverse outcome can come within minutes (M2)", () => {
    const base = {
      id: "d",
      auditSalt: SALT,
      claimantId: CLAIMANT,
      claimantMandate: mandate(CLAIMANT, {}),
      respondentId: RESPONDENT,
      contractHash: CONTRACT,
      claim: { summary: "s", requestedRemedy: "r" },
      feePaid: true,
      discloseGapOnFailure: false,
    };
    const MIN = 60_000;
    const HOUR = 60 * MIN;
    for (const config of [
      { joinTimeoutMs: MIN }, // the reviewer's case: RESPONDENT_NO_SHOW after 60 s
      { joinTimeoutMs: 24 * HOUR - 1 },
      { roundTimeoutMs: 5_000 },
      { roundTimeoutMs: 2 * MIN - 1 }, // CR2-9: round floor 2 minutes
      { bargainingWallClockMs: MIN },
      { stageTimeoutMs: MIN },
      { determinationTimeoutMs: MIN },
      { executionTimeoutMs: HOUR }, // BREACH_REPORTED an hour after settling
    ]) {
      expectError(createDispute({ ...base, config }, T0), "INVALID_INPUT");
    }
    const atMinimum = createDispute(
      { ...base, config: { joinTimeoutMs: 24 * HOUR, roundTimeoutMs: 2 * MIN, bargainingWallClockMs: 10 * MIN, stageTimeoutMs: 10 * MIN, determinationTimeoutMs: 5 * MIN, executionTimeoutMs: 24 * HOUR } },
      T0,
    );
    assert.ok(atMinimum.ok);
    // The respondent sees every window before deciding to join.
    const rules = viewFor(atMinimum.state, "respondent").rules;
    assert.deepEqual([rules.joinTimeoutMs, rules.stageTimeoutMs, rules.determinationTimeoutMs, rules.executionTimeoutMs], [24 * HOUR, 10 * MIN, 5 * MIN, 24 * HOUR]);
  });
});

describe("determinism and audit", () => {
  function scenario(): Harness {
    return opened(new Harness()).round({ offer: { refundUsd: 600 }, response: "reject" }, { offer: { refundUsd: 600 }, response: "reject" });
  }

  it("replays to identical state and audit head", () => {
    const a = scenario();
    const b = scenario();
    assert.equal(a.state.audit.head, b.state.audit.head);
    assert.deepEqual(a.state, b.state);
  });

  it("produces a verifiable chain that detects tampering", () => {
    const h = scenario();
    const ok = verifyAuditChain(h.events, SALT);
    assert.ok(ok.ok);
    assert.equal(ok.ok && ok.head, h.state.audit.head);

    const tamperedData = structuredClone(h.events);
    const submission = tamperedData.find((e) => e.type === "ROUND_SUBMISSION")!;
    (submission.data as { offer: unknown }).offer = { refundUsd: 1000 };
    assert.equal(verifyAuditChain(tamperedData, SALT).ok, false, "operator check catches data edits");

    const tamperedChain = structuredClone(h.events);
    tamperedChain[3]!.at += 1;
    assert.equal(verifyAuditChain(tamperedChain).ok, false, "public check catches chain edits");
  });

  it("does not mutate the input state", () => {
    const h = new Harness().toBargaining();
    const before = structuredClone(h.state);
    h.attempt({ type: "SUBMIT_ROUND", actor: "claimant", round: 1, offer: { refundUsd: 800 }, private: single(300) });
    assert.deepEqual(h.state, before);
  });

  it("reports every party view with the next deadline", () => {
    const h = new Harness().toBargaining();
    assert.equal(viewFor(h.state, "claimant").nextDeadline, h.state.bargaining!.roundDeadline);
    assert.equal(h.state.config.maxRounds, 6, "default round cap");
  });

  it("refuses to bind an expired principal mandate in RESPOND_IMPROVEMENT or after outage deadline extensions (FS-H2)", () => {
    // 1. RESPOND_IMPROVEMENT: claimant accepts while mandate is active; respondent accepts after claimant's mandate expired.
    const hImp = new Harness({
      issues: [REFUND, CREDIT],
      claimantBounds: { refundUsd: { min: 0, max: 1000 }, serviceCreditUsd: { min: 0, max: 500 } },
      respondentBounds: { refundUsd: { min: 0, max: 1000 }, serviceCreditUsd: { min: 0, max: 500 } },
    }).toBargaining();
    hImp.state.parties.claimant.mandate.expiresAt = hImp.now + 60 * 60_000;
    hImp.round(
      { offer: { refundUsd: 500, serviceCreditUsd: 250 }, private: { weights: { refundUsd: 0.9, serviceCreditUsd: 0.1 }, walkaway: { refundUsd: 200, serviceCreditUsd: 0 } } },
      { offer: { refundUsd: 500, serviceCreditUsd: 250 }, private: { weights: { refundUsd: 0.1, serviceCreditUsd: 0.9 }, walkaway: { refundUsd: 800, serviceCreditUsd: 500 } } },
    );
    assert.equal(hImp.state.execution?.improvement?.status, "OPEN");
    assert.equal(hImp.state.outcome?.kind, "SETTLED");
    const baselineTerms = structuredClone(hImp.state.outcome.terms);
    hImp.send({ type: "RESPOND_IMPROVEMENT", actor: "claimant", response: "accept" });
    hImp.now = hImp.state.parties.claimant.mandate.expiresAt + 1_000;
    hImp.send({ type: "RESPOND_IMPROVEMENT", actor: "respondent", response: "accept" });
    assert.equal(hImp.state.execution?.improvement?.status, "DECLINED");
    assert.equal(hImp.state.outcome?.kind, "SETTLED");
    assert.deepEqual(hImp.state.outcome.terms, baselineTerms, "baseline settlement preserved");

    // 2. Outage extension during BARGAINING pushing past claimant's mandate prevents asymmetric DETERMINATION lockout.
    const hDet = new Harness({ determination: { claimant: true, respondent: true } }).toBargaining();
    hDet.state.parties.claimant.mandate.expiresAt = hDet.now + 30 * 60_000;
    hDet.round({ offer: { refundUsd: 900 }, private: single(700) }, { offer: { refundUsd: 100 }, private: single(300) });
    hDet.round({ offer: { refundUsd: 890 } }, { offer: { refundUsd: 110 } });
    // Outage pushes clocks past claimant's mandate before Round 3 resolves.
    const ext = extendDeadlines(hDet.state, { fromMs: hDet.now, byMs: 40 * 60_000, reason: "outage" }, hDet.now + 40 * 60_000);
    assert.ok(ext.ok);
    hDet.state = ext.state;
    hDet.now += 40 * 60_000;
    hDet.send({ type: "SUBMIT_ROUND", actor: "respondent", round: 3, offer: { refundUsd: 120 }, proposalResponse: "reject" });
    hDet.expire();
    assert.equal(hDet.state.status, "UNRESOLVED", "must not open asymmetric DETERMINATION when claimant mandate has expired");
  });
});
