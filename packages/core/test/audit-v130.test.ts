/**
 * Regression tests for the v1.3.0 audit remediation in @agent-mediate/core:
 * - BUG-1: large-step snap() tolerance, 0-grid-point mandate rejection, and strict UPDATE_MANDATE monotonicity
 * - BUG-2: nashOnBox + clean() on-grid terms when |v| > 1e6 (e.g. step: 49, max: 4_900_000)
 * - SEC-1: determinationConsent frozen at BARGAINING start (no final-round unilateral ambush or live side-channel)
 * - BUG-3: REJECT_ISSUES requires matching issuesHash (HASH_MISMATCH on stale/concurrent proposal)
 * - BUG-7: tighter determinationBounds guarded in SUBMIT_ROUND, DETERMINATION nextActionsFor surfaces update_mandate,
 *          and extendDeadlines outage extensions do not break bounds-only UPDATE_MANDATE
 * - SEC-6: findLeaks catches trailing punctuation units, slash/hyphen assignments, and secrets matching rules metadata
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildCheckpointMerkleTree,
  compactViewFor,
  declaredReferenceTerms,
  extendDeadlines,
  findLeaks,
  isOnGrid,
  issuesHash,
  mandateCovers,
  nextActionsFor,
  verifyCheckpointInclusion,
  viewFor,
  type CheckpointLeafInput,
  type Issue,
} from "../src/index.ts";
import { CLAIMANT, expectError, expectOk, Harness, mandate, REFUND, RESPONDENT, single, T0 } from "./helpers.ts";

const HUGE_STEP: Issue = {
  id: "weiAmount",
  label: "Settlement Wei",
  unit: "wei",
  min: 0,
  max: 1e12,
  step: 1e12,
  claimantPrefers: "higher",
  obligor: "respondent",
};

const LARGE_INT_GRID: Issue = {
  id: "usdcUnits",
  label: "USDC Atomic Units",
  unit: "uUSDC",
  min: 0,
  max: 4_900_000,
  step: 49,
  claimantPrefers: "higher",
  obligor: "respondent",
};

describe("v1.3.0 core audit regressions", () => {
  it("BUG-1: rejects 0-grid-point mandates on large steps and prevents UPDATE_MANDATE from shrinking raw bounds", () => {
    const trapMandate = mandate(CLAIMANT, { weiAmount: { min: 0.5e12, max: 1e12 - 500 } });
    assert.equal(mandateCovers(trapMandate, HUGE_STEP), false);

    const h = new Harness({
      issues: [HUGE_STEP],
      claimantBounds: { weiAmount: { min: 0, max: 1e12 } },
      respondentBounds: { weiAmount: { min: 0, max: 1e12 } },
    }).toBargaining();

    // Round 1 opens proposals for Round 2
    h.round(
      { offer: { weiAmount: 1e12 }, private: { weights: { weiAmount: 1 }, walkaway: { weiAmount: 1e12 } } },
      { offer: { weiAmount: 0 }, private: { weights: { weiAmount: 1 }, walkaway: { weiAmount: 1e12 } } },
    );
    assert.equal(viewFor(h.state, "claimant").bargaining!.openProposal!.terms.weiAmount, 1e12);
    h.submit("claimant", { offer: { weiAmount: 1e12 }, response: "accept" });

    // Attempting to narrow max from 1e12 to 1e12 - 500 (which used to pass snap(1e-9)) must fail MANDATE_VIOLATION
    const narrowed = mandate(CLAIMANT, { weiAmount: { min: 0, max: 1e12 - 500 } }, undefined, h.now + 100);
    expectError(h.attempt({ type: "UPDATE_MANDATE", actor: "claimant", mandate: narrowed }), "MANDATE_VIOLATION");

    // Respondent accepts and proposal settles cleanly
    h.submit("respondent", { offer: { weiAmount: 0 }, response: "accept" });
    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.equal(h.state.outcome?.kind === "SETTLED" && h.state.outcome.method, "PROPOSAL_ACCEPTED");
  });

  it("BUG-2: declaredReferenceTerms and DETERMINATION settle cleanly on >1e6 non-power-of-10 integer grids", () => {
    const ref = declaredReferenceTerms([LARGE_INT_GRID], {
      claimant: { weights: { usdcUnits: 1 }, walkaway: { usdcUnits: 1_004_892 } },
      respondent: { weights: { usdcUnits: 1 }, walkaway: { usdcUnits: 2_000_033 } },
    });
    assert.ok(isOnGrid(LARGE_INT_GRID, ref.usdcUnits!), `expected on-grid value, got ${ref.usdcUnits}`);

    const h = new Harness({
      issues: [LARGE_INT_GRID],
      config: { maxRounds: 3, stallThreshold: 0 },
      claimantBounds: { usdcUnits: { min: 1_004_892, max: 4_900_000 } },
      respondentBounds: { usdcUnits: { min: 0, max: 2_000_033 } },
      determination: { claimant: true, respondent: true },
    }).toBargaining();

    for (let r = 0; r < 3; r++) {
      h.round(
        {
          offer: { usdcUnits: 4_900_000 - r * 49 },
          ...(r === 0 ? { private: { weights: { usdcUnits: 1 }, walkaway: { usdcUnits: 1_004_892 } } } : {}),
          ...(r > 0 ? { response: "reject" as const } : {}),
        },
        {
          offer: { usdcUnits: r * 49 },
          ...(r === 0 ? { private: { weights: { usdcUnits: 1 }, walkaway: { usdcUnits: 2_000_033 } } } : {}),
          ...(r > 0 ? { response: "reject" as const } : {}),
        },
      );
    }
    assert.equal(h.state.status, "DETERMINATION");
    h.send({ type: "SET_DETERMINATION_REFERENCE", actor: "system", terms: ref });
    assert.ok(isOnGrid(LARGE_INT_GRID, h.state.determination!.reference!.usdcUnits!));
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { usdcUnits: 1_960_000 } });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: { usdcUnits: 1_470_000 } });
    assert.equal(h.state.status, "EXECUTION_PENDING");
    assert.equal(h.state.outcome?.kind === "SETTLED" && h.state.outcome.method, "FINAL_OFFER_DETERMINATION");
  });

  it("SEC-1: freezes determinationConsent once BARGAINING begins (prevents final-round unilateral ambush)", () => {
    const h = new Harness({
      determination: { claimant: true, respondent: false },
      config: { maxRounds: 3 },
    }).toBargaining();
    assert.equal(viewFor(h.state, "claimant").determinationEnabled, false);

    const flipToTrue = mandate(RESPONDENT, { refundUsd: { min: 0, max: 1000 } }, undefined, h.now + 100, {
      determinationConsent: true,
    });
    expectError(h.attempt({ type: "UPDATE_MANDATE", actor: "respondent", mandate: flipToTrue }), "MANDATE_VIOLATION");
  });

  it("BUG-3: REJECT_ISSUES requires matching issuesHash", () => {
    const h = new Harness().toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    expectError(
      h.attempt({ type: "REJECT_ISSUES", actor: "claimant", issuesHash: issuesHash([HUGE_STEP]) }),
      "HASH_MISMATCH",
    );
    h.send({ type: "REJECT_ISSUES", actor: "claimant", issuesHash: issuesHash([REFUND]) });
    assert.equal(h.events.at(-1)?.type, "ISSUES_REJECTED");
  });

  it("BUG-7: guards tighter determinationBounds in SUBMIT_ROUND, exposes update_mandate in DETERMINATION, and handles outage shifts", () => {
    const h = new Harness({
      config: { maxRounds: 3, stallThreshold: 0 },
      claimantBounds: { refundUsd: { min: 400, max: 1000 } },
      claimantDeterminationBounds: { refundUsd: { min: 600, max: 1000 } },
      respondentBounds: { refundUsd: { min: 0, max: 500 } },
      determination: { claimant: true, respondent: true },
    }).toBargaining();

    // Offer 500 is inside voluntary bounds [400, 1000] but outside tighter determinationBounds [600, 1000]
    expectError(
      h.attempt({
        type: "SUBMIT_ROUND",
        actor: "claimant",
        round: 1,
        offer: { refundUsd: 500 },
        private: single(600),
      }),
      "MANDATE_VIOLATION",
    );

    // Outage extension must not break bounds-only UPDATE_MANDATE with original expiresAt
    const tightExpiry = h.state.bargaining!.wallClockDeadline + h.state.config.determinationTimeoutMs + 1_000;
    h.state.parties.claimant.mandate.expiresAt = tightExpiry;
    const ext = expectOk(extendDeadlines(h.state, { fromMs: h.now - 1_000, byMs: 60_000, reason: "outage" }, h.now), "extend");
    h.state = ext.state;
    const widened = mandate(CLAIMANT, { refundUsd: { min: 350, max: 1000 } }, tightExpiry, h.now + 50, {
      determinationConsent: true,
      determinationBounds: { refundUsd: { min: 550, max: 1000 } },
    });
    h.send({ type: "UPDATE_MANDATE", actor: "claimant", mandate: widened });

    // Reach DETERMINATION and verify nextActionsFor surfaces update_mandate before final offer
    for (let r = 0; r < 3; r++) {
      h.round(
        { offer: { refundUsd: 800 - r * 50 }, ...(r === 0 ? { private: single(600) } : { response: "reject" as const }) },
        { offer: { refundUsd: 200 + r * 50 }, ...(r === 0 ? { private: single(400) } : { response: "reject" as const }) },
      );
    }
    assert.equal(h.state.status, "DETERMINATION");
    assert.deepEqual(nextActionsFor(h.state, "claimant"), ["submit_final_offer", "update_mandate"]);
    assert.deepEqual(compactViewFor(h.state, "claimant").nextActions, ["submit_final_offer", "update_mandate"]);
  });

  it("SEC-6 & PERF-5: findLeaks catches trailing punctuation/slash/hyphen leaks and secrets equal to rules.maxRounds; Merkle proofs verify in O(log N)", () => {
    const step1Refund: Issue = { ...REFUND, step: 1 };
    const h = new Harness({
      issues: [step1Refund],
      respondentBounds: { refundUsd: { min: 0, max: 6 } },
    })
      .toBargaining()
      .round({ offer: { refundUsd: 800 }, private: single(300) }, { offer: { refundUsd: 0 }, private: single(6) });

    const h730 = new Harness()
      .toBargaining()
      .round({ offer: { refundUsd: 800 }, private: single(300) }, { offer: { refundUsd: 200 }, private: single(730) });

    for (const sample of ["730.00USD.", "refundUsd/730", "walkaway-730"]) {
      assert.ok(
        findLeaks(sample, h730.state, "claimant").some((l) => l.source === "counterparty.walkaway.refundUsd"),
        `expected leak for ${sample}`,
      );
    }
    // Respondent's secret mandate max / walkaway is 6 (matching rules.maxRounds = 6, which is metadata, not a domain value!)
    assert.ok(
      findLeaks("Counterparty max is 6.", h.state, "claimant").some((l) => l.source === "counterparty.mandate.refundUsd.max"),
    );

    const leaves: CheckpointLeafInput[] = Array.from({ length: 19 }, (_, i) => ({
      disputeId: `dsp_${String(i).padStart(2, "0")}`,
      status: "HONORED" as const,
      auditSeq: i + 1,
      auditHead: `${(i + 1).toString(16).padStart(64, "0")}`,
      outcomeHash: null,
    }));
    const tree = buildCheckpointMerkleTree(leaves);
    assert.equal(tree.leafCount, 19);
    for (const leaf of leaves) {
      const proof = tree.proofFor(leaf.disputeId);
      assert.ok(proof);
      assert.equal(verifyCheckpointInclusion(leaf, proof, tree.merkleRoot, { expectedTotalLeaves: leaves.length }), true);
    }
  });
});
