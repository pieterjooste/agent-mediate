/**
 * Phase 3A core mechanism tests:
 * - MECH-7: Constrained Nash bargaining over optional per-issue private.limits + D75 stand-in non-interference
 * - MECH-6: Clamped crossing midpoint inside both mandates
 * - MECH-8: Offer-independent declaredReferenceTerms + mean-weight L1 weightedDistance in determination
 * - MECH-10: Post-settlement Pareto frontier improvement (execution.improvement + RESPOND_IMPROVEMENT)
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildSettlementInstruction,
  canonicalJson,
  clampedCrossingTerms,
  compactViewFor,
  crossingTerms,
  declaredReferenceTerms,
  distance,
  findLeaks,
  issuesHash,
  MAX_MANDATE_UPDATES,
  nashProposal,
  paretoImproveTerms,
  presentProposal,
  publicAuditEntry,
  utility,
  verifyPublicAuditChain,
  viewFor,
  weightedDistance,
  withinMandate,
  type Issue,
  type PrivateInputs,
} from "../src/index.ts";
import { CLAIMANT, CONTRACT, CREDIT, DAY, expectError, Harness, mandate, REFUND, RESPONDENT, single, T0 } from "./helpers.ts";

const TWO_ISSUES: Issue[] = [REFUND, CREDIT];

describe("MECH-7: constrained Nash bargaining over private.limits", () => {
  it("keeps multi-issue Nash proposals inside both parties' narrow mandates when private.limits are declared", () => {
    // Claimant strongly prefers refund (0.85) over credit (0.15); respondent strongly prefers keeping cash (0.85 on refund, 0.15 on credit).
    // Unrestricted Nash pushes serviceCreditUsd to 500 and refundUsd upward, or vice versa.
    // Suppose respondent's principal capped serviceCreditUsd at 300 and refundUsd at 600, while claimant needs >= 350 refund.
    const cBounds = { refundUsd: { min: 350, max: 1000 }, serviceCreditUsd: { min: 100, max: 500 } };
    const rBounds = { refundUsd: { min: 0, max: 600 }, serviceCreditUsd: { min: 0, max: 300 } };

    const privWithoutLimits: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 0.85, serviceCreditUsd: 0.15 }, walkaway: { refundUsd: 350, serviceCreditUsd: 100 } },
      respondent: { weights: { refundUsd: 0.15, serviceCreditUsd: 0.85 }, walkaway: { refundUsd: 600, serviceCreditUsd: 300 } },
    };
    const unrestricted = nashProposal(TWO_ISSUES, privWithoutLimits, 0.5)!;
    assert.ok(unrestricted !== null);
    // Unrestricted Nash gives claimant refundUsd = 1000 (since wc/wr = 0.85/0.15 > 0.15/0.85), which exceeds respondent's mandate max 600!
    assert.equal(unrestricted.refundUsd > 600, true, "unrestricted Nash escapes respondent's narrow refund mandate");

    const privWithLimits: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { ...privWithoutLimits.claimant, limits: cBounds },
      respondent: { ...privWithoutLimits.respondent, limits: rBounds },
    };
    const constrained = nashProposal(TWO_ISSUES, privWithLimits, 0.5)!;
    assert.ok(constrained !== null, "box-constrained Nash finds a feasible trade inside both narrow mandates");
    assert.ok(constrained.refundUsd >= 350 && constrained.refundUsd <= 600);
    assert.ok(constrained.serviceCreditUsd >= 100 && constrained.serviceCreditUsd <= 300);

    // End-to-end through the dispute state machine: round 2 proposal is within both mandates and settles when both accept.
    const h = new Harness({ issues: TWO_ISSUES, claimantBounds: cBounds, respondentBounds: rBounds }).toBargaining();
    h.round(
      { offer: { refundUsd: 900, serviceCreditUsd: 450 }, private: privWithLimits.claimant },
      { offer: { refundUsd: 100, serviceCreditUsd: 50 }, private: privWithLimits.respondent },
    );
    assert.equal(h.state.status, "BARGAINING");
    assert.equal(h.state.bargaining!.round, 2);
    const propC = viewFor(h.state, "claimant").bargaining!.openProposal!;
    const propR = viewFor(h.state, "respondent").bargaining!.openProposal!;
    assert.deepEqual(propC.terms, propR.terms);
    assert.equal(compactViewFor(h.state, "claimant").proposalWithinYourMandate, true);
    assert.equal(compactViewFor(h.state, "respondent").proposalWithinYourMandate, true);

    h.round(
      { offer: { refundUsd: 850, serviceCreditUsd: 400 }, response: "accept" },
      { offer: { refundUsd: 150, serviceCreditUsd: 80 }, response: "accept" },
    );
    assert.equal(h.state.outcome?.kind, "SETTLED");
    if (h.state.outcome?.kind === "SETTLED") {
      assert.equal(h.state.outcome.method, "PROPOSAL_ACCEPTED");
      assert.deepEqual(h.state.outcome.terms, propC.terms);
    }
  });

  it("validates private.limits against grid, walkaway, mandate, and round-1 immutability", () => {
    const cBounds = { refundUsd: { min: 200, max: 900 } };
    const h = new Harness({ claimantBounds: cBounds }).toBargaining();

    // Walkaway outside limits
    expectError(
      h.attempt({
        type: "SUBMIT_ROUND",
        actor: "claimant",
        round: 1,
        offer: { refundUsd: 800 },
        private: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 300 }, limits: { refundUsd: { min: 400, max: 800 } } },
      }),
      "INVALID_INPUT",
    );
    // Limits exceeding mandate
    expectError(
      h.attempt({
        type: "SUBMIT_ROUND",
        actor: "claimant",
        round: 1,
        offer: { refundUsd: 800 },
        private: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 300 }, limits: { refundUsd: { min: 100, max: 800 } } },
      }),
      "MANDATE_VIOLATION",
    );
    // Unknown issue id in limits
    expectError(
      h.attempt({
        type: "SUBMIT_ROUND",
        actor: "claimant",
        round: 1,
        offer: { refundUsd: 800 },
        private: {
          weights: { refundUsd: 1 },
          walkaway: { refundUsd: 300 },
          limits: { refundUsd: { min: 300, max: 800 }, extraIssue: { min: 0, max: 10 } },
        },
      }),
      "INVALID_INPUT",
    );
    // Empty grid interval (step is 10, [301, 309] has no grid point)
    expectError(
      h.attempt({
        type: "SUBMIT_ROUND",
        actor: "claimant",
        round: 1,
        offer: { refundUsd: 800 },
        private: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 300 }, limits: { refundUsd: { min: 301, max: 309 } } },
      }),
      "INVALID_INPUT",
    );

    // Valid round 1 with limits; attempting to alter limits in round 2 is rejected.
    h.round(
      {
        offer: { refundUsd: 800 },
        private: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 300 }, limits: { refundUsd: { min: 250, max: 850 } } },
      },
      { offer: { refundUsd: 100 }, private: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 400 } } },
    );
    expectError(
      h.attempt({
        type: "SUBMIT_ROUND",
        actor: "claimant",
        round: 2,
        offer: { refundUsd: 750 },
        private: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 300 }, limits: { refundUsd: { min: 260, max: 850 } } },
        proposalResponse: "reject",
      }),
      "INVALID_INPUT",
    );
    // Leak scanner flags counterparty limits in free text.
    const leaks = findLeaks("Claimant capped limits between 250 and 850.", h.state, "respondent");
    assert.ok(leaks.some((l) => l.source === "counterparty.limits.refundUsd.min" && l.token === "250"));
    assert.ok(leaks.some((l) => l.source === "counterparty.limits.refundUsd.max" && l.token === "850"));
  });

  it("preserves D75 / CR2-2 stand-in non-interference when private.limits are disjoint", () => {
    const cLimits = { refundUsd: { min: 600, max: 1000 }, serviceCreditUsd: { min: 200, max: 500 } };
    const rLimits = { refundUsd: { min: 0, max: 400 }, serviceCreditUsd: { min: 0, max: 150 } };
    const basis: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 0.7, serviceCreditUsd: 0.3 }, walkaway: { refundUsd: 650, serviceCreditUsd: 250 }, limits: cLimits },
      respondent: { weights: { refundUsd: 0.6, serviceCreditUsd: 0.4 }, walkaway: { refundUsd: 350, serviceCreditUsd: 120 }, limits: rLimits },
    };

    const p = presentProposal(TWO_ISSUES, basis, 0.5);
    assert.equal(p.settles, false);
    assert.ok(withinMandate(TWO_ISSUES, mandate(CLAIMANT, cLimits), p.views.claimant), "claimant stand-in lies inside claimant limits");
    assert.ok(withinMandate(TWO_ISSUES, mandate(RESPONDENT, rLimits), p.views.respondent), "respondent stand-in lies inside respondent limits");
    assert.ok(
      utility(TWO_ISSUES, basis.claimant.weights, p.views.claimant, "claimant") >=
        utility(TWO_ISSUES, basis.claimant.weights, basis.claimant.walkaway, "claimant") - 1e-9,
    );
    assert.ok(
      utility(TWO_ISSUES, basis.respondent.weights, p.views.respondent, "respondent") >=
        utility(TWO_ISSUES, basis.respondent.weights, basis.respondent.walkaway, "respondent") - 1e-9,
    );

    // Even if both parties accept their stand-in, the dispute does not settle and advances cleanly to round 3.
    const h = new Harness({ issues: TWO_ISSUES, claimantBounds: cLimits, respondentBounds: rLimits }).toBargaining();
    h.round(
      { offer: { refundUsd: 900, serviceCreditUsd: 450 }, private: basis.claimant },
      { offer: { refundUsd: 100, serviceCreditUsd: 50 }, private: basis.respondent },
    );
    h.round(
      { offer: { refundUsd: 800, serviceCreditUsd: 400 }, response: "accept" },
      { offer: { refundUsd: 200, serviceCreditUsd: 100 }, response: "accept" },
    );
    assert.equal(h.state.status, "BARGAINING");
    assert.equal(h.state.bargaining!.round, 3);
  });
});

describe("MECH-6: clamped crossing midpoint inside both mandates", () => {
  it("clamps and compensates crossing multi-issue offers when the raw midpoint escapes one party's mandate", () => {
    const cBounds = { refundUsd: { min: 500, max: 1000 }, serviceCreditUsd: { min: 200, max: 500 } };
    const rBounds = { refundUsd: { min: 0, max: 1000 }, serviceCreditUsd: { min: 0, max: 300 } };
    const mandates = { claimant: mandate(CLAIMANT, cBounds), respondent: mandate(RESPONDENT, rBounds) };
    const privates: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 0.8, serviceCreditUsd: 0.2 }, walkaway: { refundUsd: 500, serviceCreditUsd: 200 } },
      respondent: { weights: { refundUsd: 0.2, serviceCreditUsd: 0.8 }, walkaway: { refundUsd: 900, serviceCreditUsd: 150 } },
    };
    // Claimant offers (500, 200) -> Uc = 0.8*0.5 + 0.2*0.4 = 0.48, Ur = 0.2*0.5 + 0.8*0.6 = 0.58.
    // Respondent offers (900, 150) -> Ur = 0.2*0.1 + 0.8*0.7 = 0.58 <= Ur(c), Uc = 0.8*0.9 + 0.2*0.3 = 0.78 >= Uc(c).
    const offers = {
      claimant: { refundUsd: 500, serviceCreditUsd: 200 },
      respondent: { refundUsd: 900, serviceCreditUsd: 150 },
    };
    const rawMid = crossingTerms(TWO_ISSUES, offers, privates)!;
    assert.deepEqual(rawMid, { refundUsd: 700, serviceCreditUsd: 180 });
    assert.equal(withinMandate(TWO_ISSUES, mandates.claimant, rawMid), false, "raw midpoint serviceCreditUsd=180 < claimant min 200");

    const clamped = clampedCrossingTerms(TWO_ISSUES, offers, privates, mandates)!;
    assert.ok(clamped !== null, "clampedCrossingTerms rescues the crossing deal inside both mandates");
    assert.equal(withinMandate(TWO_ISSUES, mandates.claimant, clamped), true);
    assert.equal(withinMandate(TWO_ISSUES, mandates.respondent, clamped), true);
    assert.ok(
      utility(TWO_ISSUES, privates.claimant.weights, clamped, "claimant") >=
        utility(TWO_ISSUES, privates.claimant.weights, offers.claimant, "claimant") - 1e-9,
    );
    assert.ok(
      utility(TWO_ISSUES, privates.respondent.weights, clamped, "respondent") >=
        utility(TWO_ISSUES, privates.respondent.weights, offers.respondent, "respondent") - 1e-9,
    );

    // End-to-end in resolveRound: settles immediately as OVERLAP_MIDPOINT!
    const h = new Harness({ issues: TWO_ISSUES, claimantBounds: cBounds, respondentBounds: rBounds }).toBargaining();
    h.round({ offer: offers.claimant, private: privates.claimant }, { offer: offers.respondent, private: privates.respondent });
    assert.equal(h.state.outcome?.kind, "SETTLED");
    if (h.state.outcome?.kind === "SETTLED") {
      assert.equal(h.state.outcome.method, "OVERLAP_MIDPOINT");
      assert.deepEqual(h.state.outcome.terms, clamped);
    }
  });
});

describe("MECH-8: offer-independent determination reference and weighted distance", () => {
  it("computes declaredReferenceTerms independently of bargaining offers", () => {
    const overlapPrivs: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 300 } },
      respondent: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 700 } },
    };
    assert.deepEqual(declaredReferenceTerms([REFUND], overlapPrivs), { refundUsd: 500 });

    const noOverlapPrivs: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 700 } },
      respondent: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 300 } },
    };
    assert.deepEqual(declaredReferenceTerms([REFUND], noOverlapPrivs), { refundUsd: 500 });
  });

  it("defeats low-weight-issue sacrifice gaming in final-offer determination via mean-weight L1 distance", () => {
    // Both parties agree refundUsd has weight 0.9 and serviceCreditUsd has weight 0.1.
    const privs: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 0.9, serviceCreditUsd: 0.1 }, walkaway: { refundUsd: 600, serviceCreditUsd: 250 } },
      respondent: { weights: { refundUsd: 0.9, serviceCreditUsd: 0.1 }, walkaway: { refundUsd: 400, serviceCreditUsd: 250 } },
    };
    const ref = declaredReferenceTerms(TWO_ISSUES, privs); // { refundUsd: 500, serviceCreditUsd: 250 }
    assert.deepEqual(ref, { refundUsd: 500, serviceCreditUsd: 250 });

    // Claimant games uniform L1 by matching serviceCreditUsd=250 (0% error on minor issue) while demanding refundUsd=900 (40% error on 0.9-weight issue):
    // Uniform distance = (0.40 + 0.00) / 2 = 0.20.
    // Respondent submits honest compromise refundUsd=400 (10% error on 0.9-weight issue) and serviceCreditUsd=50 (40% error on 0.1-weight issue):
    // Uniform distance = (0.10 + 0.40) / 2 = 0.25 (respondent WOULD LOSE under uniform distance!).
    // Mean-weight distance: claimant = 0.9*0.40 + 0.1*0.00 = 0.36; respondent = 0.9*0.10 + 0.1*0.40 = 0.13 (respondent WINS!).
    const cFinal = { refundUsd: 900, serviceCreditUsd: 250 };
    const rFinal = { refundUsd: 400, serviceCreditUsd: 50 };
    assert.ok(distance(TWO_ISSUES, cFinal, ref) < distance(TWO_ISSUES, rFinal, ref), "gamer beats respondent on unweighted distance");
    assert.ok(
      weightedDistance(TWO_ISSUES, rFinal, ref, { refundUsd: 0.9, serviceCreditUsd: 0.1 }) <
        weightedDistance(TWO_ISSUES, cFinal, ref, { refundUsd: 0.9, serviceCreditUsd: 0.1 }),
      "weightedDistance penalises extreme demand on the 0.9-weight issue",
    );

    const h = new Harness({
      issues: TWO_ISSUES,
      config: { maxRounds: 3, stallThreshold: 0 },
      determination: { claimant: true, respondent: true },
    }).toBargaining();
    h.round({ offer: { refundUsd: 950, serviceCreditUsd: 400 }, private: privs.claimant }, { offer: { refundUsd: 50, serviceCreditUsd: 0 }, private: privs.respondent });
    h.round({ offer: { refundUsd: 920, serviceCreditUsd: 350 }, response: "reject" }, { offer: { refundUsd: 100, serviceCreditUsd: 20 }, response: "reject" });
    h.round({ offer: { refundUsd: 900, serviceCreditUsd: 250 }, response: "reject" }, { offer: { refundUsd: 150, serviceCreditUsd: 50 }, response: "reject" });
    assert.equal(h.state.status, "DETERMINATION");

    h.send({ type: "SET_DETERMINATION_REFERENCE", actor: "system", terms: ref });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: cFinal });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: rFinal });

    assert.equal(h.state.outcome?.kind, "SETTLED");
    if (h.state.outcome?.kind === "SETTLED") {
      assert.equal(h.state.outcome.method, "FINAL_OFFER_DETERMINATION");
      assert.deepEqual(h.state.outcome.terms, rFinal);
    }
  });
});

describe("MECH-10: post-settlement Pareto frontier improvement", () => {
  const privates: Record<"claimant" | "respondent", PrivateInputs> = {
    claimant: { weights: { refundUsd: 0.8, serviceCreditUsd: 0.2 }, walkaway: { refundUsd: 300, serviceCreditUsd: 100 } },
    respondent: { weights: { refundUsd: 0.2, serviceCreditUsd: 0.8 }, walkaway: { refundUsd: 700, serviceCreditUsd: 400 } },
  };

  it("offers a Pareto-superior package after an interior crossing settlement, masks pending responses, and upgrades terms when both accept", () => {
    const h = new Harness({ issues: TWO_ISSUES }).toBargaining();
    // Both offer (500, 250) -> immediate OVERLAP_MIDPOINT at (500, 250) with Uc = 0.5, Ur = 0.5 (sum = 1.0).
    // Pareto frontier trades serviceCreditUsd -> 0 for refundUsd -> 1000: at (750, 0), Uc = 0.8*0.75 = 0.60, Ur = 0.2*0.25 + 0.8*1.0 = 0.85 (sum = 1.45)!
    h.round(
      { offer: { refundUsd: 500, serviceCreditUsd: 250 }, private: privates.claimant },
      { offer: { refundUsd: 500, serviceCreditUsd: 250 }, private: privates.respondent },
    );

    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.equal(h.state.outcome?.kind, "SETTLED");
    const baseline = h.state.outcome?.kind === "SETTLED" ? h.state.outcome.terms : null;
    assert.deepEqual(baseline, { refundUsd: 500, serviceCreditUsd: 250 });

    const imp = h.state.execution?.improvement;
    assert.ok(imp && imp.status === "OPEN", "Pareto improvement offered");
    assert.ok(utility(TWO_ISSUES, privates.claimant.weights, imp.terms, "claimant") > utility(TWO_ISSUES, privates.claimant.weights, baseline!, "claimant"));
    assert.ok(utility(TWO_ISSUES, privates.respondent.weights, imp.terms, "respondent") > utility(TWO_ISSUES, privates.respondent.weights, baseline!, "respondent"));

    assert.equal(compactViewFor(h.state, "claimant").nextActions[0], "respond_improvement");
    assert.equal(compactViewFor(h.state, "respondent").nextActions[0], "respond_improvement");

    // Claimant accepts first; respondent's view must NOT reveal claimant's pending acceptance while status is OPEN.
    h.send({ type: "RESPOND_IMPROVEMENT", actor: "claimant", response: "accept" });
    assert.equal(viewFor(h.state, "claimant").execution!.improvement!.responses.claimant, "accept");
    assert.equal(viewFor(h.state, "respondent").execution!.improvement!.responses.claimant, null, "counterparty pending response is masked");

    // Respondent accepts -> outcome.terms upgrades to imp.terms, settlement instruction & audit chain remain valid.
    h.send({ type: "RESPOND_IMPROVEMENT", actor: "respondent", response: "accept" });
    assert.equal(h.state.execution!.improvement!.status, "ACCEPTED");
    assert.equal(h.state.outcome?.kind, "SETTLED");
    if (h.state.outcome?.kind === "SETTLED") {
      assert.deepEqual(h.state.outcome.terms, imp.terms);
    }
    const instruction = buildSettlementInstruction(h.state);
    assert.deepEqual(instruction.terms, imp.terms);
    const chain = verifyPublicAuditChain(h.events.map((e) => publicAuditEntry(e, "claimant")));
    assert.equal(chain.ok, true);
  });

  it("keeps baseline terms if one side declines or starts executing directly (backwards-compatible race guard)", () => {
    // Case A: explicit decline
    const h1 = new Harness({ issues: TWO_ISSUES }).toBargaining();
    h1.round(
      { offer: { refundUsd: 500, serviceCreditUsd: 250 }, private: privates.claimant },
      { offer: { refundUsd: 500, serviceCreditUsd: 250 }, private: privates.respondent },
    );
    h1.send({ type: "RESPOND_IMPROVEMENT", actor: "respondent", response: "decline" });
    assert.equal(h1.state.execution!.improvement!.status, "DECLINED");
    if (h1.state.outcome?.kind === "SETTLED") {
      assert.deepEqual(h1.state.outcome.terms, { refundUsd: 500, serviceCreditUsd: 250 });
    }
    expectError(h1.attempt({ type: "RESPOND_IMPROVEMENT", actor: "claimant", response: "accept" }), "INVALID_STATE");

    // Case B: obligor submits execution proof directly without calling RESPOND_IMPROVEMENT
    const h2 = new Harness({ issues: TWO_ISSUES }).toBargaining();
    h2.round(
      { offer: { refundUsd: 500, serviceCreditUsd: 250 }, private: privates.claimant },
      { offer: { refundUsd: 500, serviceCreditUsd: 250 }, private: privates.respondent },
    );
    assert.equal(h2.state.execution!.improvement!.status, "OPEN");
    h2.send({ type: "SUBMIT_EXECUTION_PROOF", actor: "respondent", reference: "0xabc123" });
    assert.equal(h2.state.execution!.improvement!.status, "DECLINED", "starting execution closes open improvement");
    expectError(h2.attempt({ type: "RESPOND_IMPROVEMENT", actor: "claimant", response: "accept" }), "INVALID_STATE");
    h2.send({ type: "CONFIRM_EXECUTION", actor: "claimant" });
    assert.equal(h2.state.status, "HONORED");

    // Single-issue settlements never attach an improvement
    assert.equal(
      paretoImproveTerms(
        [REFUND],
        { refundUsd: 500 },
        { claimant: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 300 } }, respondent: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 700 } } },
        { claimant: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }), respondent: mandate(RESPONDENT, { refundUsd: { min: 0, max: 1000 } }) },
      ),
      null,
    );
  });
});

describe("D126: Resolving non-overlapping mandates (1 + A + C, v1.2.0)", () => {
  it("Item 1: resolves non-overlapping voluntary bargaining bounds via wider two-tier determinationBounds", () => {
    const h = new Harness({
      issues: [REFUND],
      config: { maxRounds: 3 },
      claimantBounds: { refundUsd: { min: 600, max: 1000 } },
      respondentBounds: { refundUsd: { min: 0, max: 450 } },
      determination: { claimant: true, respondent: true },
      claimantDeterminationBounds: { refundUsd: { min: 450, max: 1000 } },
      respondentDeterminationBounds: { refundUsd: { min: 0, max: 600 } },
    }).toBargaining();

    h.round({ offer: { refundUsd: 800 }, private: single(600) }, { offer: { refundUsd: 200 }, private: single(450) });
    h.round({ offer: { refundUsd: 700 }, response: "reject" }, { offer: { refundUsd: 350 }, response: "reject" });
    h.round({ offer: { refundUsd: 600 }, response: "reject" }, { offer: { refundUsd: 450 }, response: "reject" });

    assert.equal(h.state.status, "DETERMINATION", "disjoint voluntary bounds enter binding final-offer determination");
    // Declared reference is midpoint(600, 450) = 520 (even grid index 52). Both parties submit final offers inside wider determinationBounds.
    h.send({
      type: "SET_DETERMINATION_REFERENCE",
      actor: "system",
      terms: declaredReferenceTerms([REFUND], { claimant: single(600), respondent: single(450) }),
    });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 530 } });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: { refundUsd: 500 } });
    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.equal(h.state.outcome?.kind, "SETTLED");
    if (h.state.outcome?.kind === "SETTLED") {
      assert.equal(h.state.outcome.method, "FINAL_OFFER_DETERMINATION");
      assert.deepEqual(h.state.outcome.terms, { refundUsd: 530 });
    }
  });

  it("Upgrade A: monotonically widens mandates in BARGAINING with frozen Round-1 private inputs and zero counterparty leakage", () => {
    // 1. Disjoint 1D mandates [600, 1000] vs [0, 450]
    const h = new Harness({
      issues: [REFUND],
      claimantBounds: { refundUsd: { min: 600, max: 1000 } },
      respondentBounds: { refundUsd: { min: 0, max: 450 } },
    }).toBargaining();

    h.round({ offer: { refundUsd: 800 }, private: single(600) }, { offer: { refundUsd: 250 }, private: single(450) });

    // Capture claimant's views BEFORE respondent escalates its mandate
    const beforeFull = canonicalJson(viewFor(h.state, "claimant"));
    const beforeCompact = canonicalJson(compactViewFor(h.state, "claimant"));

    h.send({
      type: "UPDATE_MANDATE",
      actor: "respondent",
      mandate: mandate(RESPONDENT, { refundUsd: { min: 0, max: 560 } }, T0 + 30 * DAY, T0 + 1_000),
    });

    // Strict zero-bit non-interference: counterparty full & compact views are byte-for-byte identical!
    assert.equal(canonicalJson(viewFor(h.state, "claimant")), beforeFull);
    assert.equal(canonicalJson(compactViewFor(h.state, "claimant")), beforeCompact);
    assert.deepEqual(findLeaks(JSON.stringify(viewFor(h.state, "claimant")), h.state, "claimant"), []);
    assert.equal(h.state.parties.respondent!.mandateUpdates, 1);
    assert.deepEqual(h.state.bargaining!.private.respondent, single(450), "Round-1 walkaway stays frozen");

    // Claimant also widens [600, 1000] -> [500, 1000], then crossing offers settle cleanly at 530
    h.send({
      type: "UPDATE_MANDATE",
      actor: "claimant",
      mandate: mandate(CLAIMANT, { refundUsd: { min: 500, max: 1000 } }, T0 + 30 * DAY, T0 + 2_000),
    });
    h.round({ offer: { refundUsd: 520 }, response: "reject" }, { offer: { refundUsd: 540 }, response: "reject" });
    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.equal(h.state.outcome?.kind, "SETTLED");
    if (h.state.outcome?.kind === "SETTLED") {
      assert.equal(h.state.outcome.method, "OVERLAP_MIDPOINT");
      assert.deepEqual(h.state.outcome.terms, { refundUsd: 530 });
    }
    assert.equal(verifyPublicAuditChain(h.events.map((e) => publicAuditEntry(e, "claimant"))).ok, true);
    assert.equal(verifyPublicAuditChain(h.events.map((e) => publicAuditEntry(e, "respondent"))).ok, true);

    // 2. Multi-issue dispute where unconstrained Nash proposal exceeds narrow mandate -> nextActions surfaces "update_mandate"
    const h2 = new Harness({
      issues: TWO_ISSUES,
      claimantBounds: { refundUsd: { min: 350, max: 1000 }, serviceCreditUsd: { min: 100, max: 500 } },
      respondentBounds: { refundUsd: { min: 0, max: 600 }, serviceCreditUsd: { min: 0, max: 300 } },
    }).toBargaining();
    h2.round(
      {
        offer: { refundUsd: 900, serviceCreditUsd: 450 },
        private: { weights: { refundUsd: 0.85, serviceCreditUsd: 0.15 }, walkaway: { refundUsd: 350, serviceCreditUsd: 100 } },
      },
      {
        offer: { refundUsd: 100, serviceCreditUsd: 50 },
        private: { weights: { refundUsd: 0.15, serviceCreditUsd: 0.85 }, walkaway: { refundUsd: 600, serviceCreditUsd: 300 } },
      },
    );
    const rCompactBefore = compactViewFor(h2.state, "respondent");
    assert.equal(rCompactBefore.proposalWithinYourMandate, false);
    assert.deepEqual(rCompactBefore.nextActions, ["submit_offer", "update_mandate"]);

    // Respondent widens refundUsd max from 600 to 1000 (and claimant widens serviceCreditUsd min from 100 to 0) -> openProposal is within both mandates and both accept!
    h2.send({
      type: "UPDATE_MANDATE",
      actor: "respondent",
      mandate: mandate(RESPONDENT, { refundUsd: { min: 0, max: 1000 }, serviceCreditUsd: { min: 0, max: 500 } }, T0 + 30 * DAY, T0 + 1_000),
    });
    h2.send({
      type: "UPDATE_MANDATE",
      actor: "claimant",
      mandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 }, serviceCreditUsd: { min: 0, max: 500 } }, T0 + 30 * DAY, T0 + 2_000),
    });
    const rCompactAfter = compactViewFor(h2.state, "respondent");
    assert.equal(rCompactAfter.proposalWithinYourMandate, true);
    assert.deepEqual(rCompactAfter.nextActions, ["submit_offer"]);
    h2.round(
      { offer: { refundUsd: 850, serviceCreditUsd: 400 }, response: "accept" },
      { offer: { refundUsd: 150, serviceCreditUsd: 100 }, response: "accept" },
    );
    assert.equal(h2.state.outcome?.kind, "SETTLED");
    if (h2.state.outcome?.kind === "SETTLED") {
      assert.equal(h2.state.outcome.method, "PROPOSAL_ACCEPTED");
    }
  });

  it("Upgrade A: enforces monotonic expansion, principal/scope/issuedAt guards, cap MAX_MANDATE_UPDATES = 3, and DETERMINATION widening", () => {
    const h = new Harness({
      issues: [REFUND],
      config: { maxRounds: 3 },
      claimantBounds: { refundUsd: { min: 600, max: 1000 } },
      respondentBounds: { refundUsd: { min: 0, max: 450 } },
      determination: { claimant: true, respondent: true },
      claimantDeterminationBounds: { refundUsd: { min: 600, max: 1000 } },
      respondentDeterminationBounds: { refundUsd: { min: 0, max: 450 } },
    });
    // Disallowed before BARGAINING
    expectError(
      h.attempt({ type: "UPDATE_MANDATE", actor: "claimant", mandate: mandate(CLAIMANT, { refundUsd: { min: 500, max: 1000 } }, T0 + 30 * DAY, T0 + 1_000) }),
      "INVALID_STATE",
    );
    h.toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    expectError(
      h.attempt({ type: "UPDATE_MANDATE", actor: "claimant", mandate: mandate(CLAIMANT, { refundUsd: { min: 500, max: 1000 } }, T0 + 30 * DAY, T0 + 1_000) }),
      "INVALID_STATE",
    );
    const iHash = issuesHash([REFUND]);
    h.send({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: iHash }).send({ type: "CONFIRM_ISSUES", actor: "respondent", issuesHash: iHash });

    // Wrong principalId
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: { ...mandate(CLAIMANT, { refundUsd: { min: 500, max: 1000 } }, T0 + 30 * DAY, T0 + 1_000), principalId: "principal:impostor" },
      }),
      "MANDATE_VIOLATION",
    );
    // Stale issuedAt
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 500, max: 1000 } }, T0 + 30 * DAY, T0 - 60_000),
      }),
      "MANDATE_VIOLATION",
    );
    // Shortened expiresAt
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 500, max: 1000 } }, T0 + 29 * DAY, T0 + 1_000),
      }),
      "MANDATE_VIOLATION",
    );
    // Revoking determinationConsent
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 500, max: 1000 } }, T0 + 30 * DAY, T0 + 1_000, { determinationConsent: false }),
      }),
      "MANDATE_VIOLATION",
    );
    // Narrowing bounds ([600, 1000] -> [650, 1000])
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 650, max: 1000 } }, T0 + 30 * DAY, T0 + 1_000, {
          determinationConsent: true,
          determinationBounds: { refundUsd: { min: 600, max: 1000 } },
        }),
      }),
      "MANDATE_VIOLATION",
    );
    // Narrowing determinationBounds ([600, 1000] -> [650, 1000])
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 600, max: 1000 } }, T0 + 30 * DAY, T0 + 1_000, {
          determinationConsent: true,
          determinationBounds: { refundUsd: { min: 650, max: 1000 } },
        }),
      }),
      "MANDATE_VIOLATION",
    );
    // Wrong scope
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 500, max: 1000 } }, T0 + 30 * DAY, T0 + 1_000, {
          determinationConsent: true,
          scope: { contractHash: "0".repeat(64), counterpartyId: RESPONDENT },
        }),
      }),
      "MANDATE_VIOLATION",
    );

    // Exhaust MAX_MANDATE_UPDATES = 3 on claimant, then verify 4th is rejected
    for (let step = 1; step <= MAX_MANDATE_UPDATES; step++) {
      const minVal = 600 - step * 30;
      h.send({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: minVal, max: 1000 } }, T0 + 30 * DAY, T0 + step * 1_000, {
          determinationConsent: true,
          determinationBounds: { refundUsd: { min: minVal, max: 1000 } },
        }),
      });
    }
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 450, max: 1000 } }, T0 + 30 * DAY, T0 + 9_000, {
          determinationConsent: true,
          determinationBounds: { refundUsd: { min: 450, max: 1000 } },
        }),
      }),
      "MANDATE_VIOLATION",
    );

    // Advance into DETERMINATION, then respondent widens determinationBounds in DETERMINATION so final offer settles!
    h.round({ offer: { refundUsd: 800 }, private: single(600) }, { offer: { refundUsd: 200 }, private: single(450) });
    h.round({ offer: { refundUsd: 700 }, response: "reject" }, { offer: { refundUsd: 350 }, response: "reject" });
    h.round({ offer: { refundUsd: 600 }, response: "reject" }, { offer: { refundUsd: 450 }, response: "reject" });
    assert.equal(h.state.status, "DETERMINATION");
    h.send({
      type: "SET_DETERMINATION_REFERENCE",
      actor: "system",
      terms: declaredReferenceTerms([REFUND], { claimant: single(600), respondent: single(450) }),
    });
    h.send({
      type: "UPDATE_MANDATE",
      actor: "respondent",
      mandate: mandate(RESPONDENT, { refundUsd: { min: 0, max: 450 } }, T0 + 30 * DAY, T0 + 5_000, {
        determinationConsent: true,
        determinationBounds: { refundUsd: { min: 0, max: 560 } },
      }),
    });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 530 } });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: { refundUsd: 510 } });
    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.equal(h.state.outcome?.kind, "SETTLED");
  });

  it("Upgrade C: validates adoptSuggestedIds on REJECT_ISSUES and clears requestedSuggestedIds when PROPOSE_ISSUES runs", () => {
    const h = new Harness({ issues: [REFUND], config: { maxIssueProposals: 2 } }).toIssueConfirmation();
    h.send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    const p1Hash = h.state.issueNegotiation.proposedHash!;

    for (const bad of [[], ["a", "b", "c"], ["dup", "dup"], ["bad space"], ["constructor"]]) {
      expectError(h.attempt({ type: "REJECT_ISSUES", actor: "claimant", issuesHash: p1Hash, adoptSuggestedIds: bad }), "INVALID_INPUT");
    }

    h.send({ type: "REJECT_ISSUES", actor: "claimant", issuesHash: p1Hash, adoptSuggestedIds: ["serviceCreditUsd"] });
    assert.deepEqual(h.state.issueNegotiation?.requestedSuggestedIds, ["serviceCreditUsd"]);
    const rejEv = h.events.findLast((e) => e.type === "ISSUES_REJECTED");
    assert.deepEqual(rejEv?.data.adoptSuggestedIds, ["serviceCreditUsd"]);

    h.send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND, CREDIT] });
    const p2Hash = h.state.issueNegotiation.proposedHash!;
    assert.equal(h.state.issueNegotiation?.requestedSuggestedIds, undefined, "cleared on next PROPOSE_ISSUES");
    // Final proposal (proposalCount === maxIssueProposals === 2) cannot request another round of adoptSuggestedIds
    expectError(
      h.attempt({ type: "REJECT_ISSUES", actor: "respondent", issuesHash: p2Hash, adoptSuggestedIds: ["serviceCreditUsd"] }),
      "INVALID_STATE",
    );
  });
});
