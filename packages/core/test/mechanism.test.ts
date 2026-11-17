import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  claimantShare,
  computeGap,
  crossingTerms,
  declaredReferenceTerms,
  gapBucket,
  isStalled,
  midpointPackage,
  nashProposal,
  presentProposal,
  validateIssues,
} from "../src/index.ts";
import { isOnGrid, snap } from "../src/mechanism.ts";
import { CREDIT, REFUND, single } from "./helpers.ts";

describe("utility primitives", () => {
  it("computes the claimant share in the preferred direction", () => {
    assert.equal(claimantShare(REFUND, 250), 0.25);
    const days = { ...REFUND, id: "days", min: 0, max: 30, step: 1, claimantPrefers: "lower" as const };
    assert.equal(claimantShare(days, 0), 1);
    assert.equal(claimantShare(days, 30), 0);
  });

  it("snaps exact halves to the even grid index (unbiased)", () => {
    assert.equal(snap(REFUND, 15, "nearest"), 20);
    assert.equal(snap(REFUND, 25, "nearest"), 20);
    assert.equal(snap(REFUND, 26, "nearest"), 30);
    assert.equal(snap(REFUND, 26, "floor"), 20);
    assert.equal(snap(REFUND, 21, "ceil"), 30);
  });

  it("computes per-issue midpoints on the grid", () => {
    assert.deepEqual(midpointPackage([REFUND, CREDIT], { refundUsd: 300, serviceCreditUsd: 100 }, { refundUsd: 600, serviceCreditUsd: 150 }), {
      refundUsd: 450,
      serviceCreditUsd: 120,
    });
  });
});

describe("gap and stall detection", () => {
  it("measures only the shortfall between ask and offer", () => {
    assert.equal(computeGap([REFUND], { refundUsd: 800 }, { refundUsd: 200 }), 0.6);
    assert.equal(computeGap([REFUND], { refundUsd: 500 }, { refundUsd: 600 }), 0);
  });

  it("stalls only after `window` consecutive low-progress rounds", () => {
    assert.equal(isStalled([0.8, 0.78], 2, 0.05), false, "needs window + 1 data points");
    assert.equal(isStalled([0.8, 0.78, 0.76], 2, 0.05), true);
    assert.equal(isStalled([0.8, 0.7, 0.68], 2, 0.05), false, "one good round resets");
    assert.equal(isStalled([0.8, 0.8, 0.8], 2, 0), false, "threshold 0 disables");
    // MECH-3: active concessions inside a <5% gap reduce the remaining gap by >=5% per round and must not stall.
    assert.equal(isStalled([0.04, 0.03, 0.02], 2, 0.05), false, "25% and 33% relative reductions are active progress");
    assert.equal(isStalled([0.04, 0.04, 0.04], 2, 0.05), true, "zero movement at a 4% gap still stalls");
  });

  it("buckets the opt-in gap disclosure coarsely", () => {
    assert.equal(gapBucket(0.05), "<10%");
    assert.equal(gapBucket(0.2), "10-25%");
    assert.equal(gapBucket(0.3), "25-50%");
    assert.equal(gapBucket(0.6), ">50%");
  });
});

describe("crossing offers", () => {
  it("settles at the midpoint only when each side is offered at least its own ask", () => {
    const privates = { claimant: single(300), respondent: single(700) };
    assert.deepEqual(crossingTerms([REFUND], { claimant: { refundUsd: 500 }, respondent: { refundUsd: 600 } }, privates), {
      refundUsd: 550,
    });
    assert.equal(crossingTerms([REFUND], { claimant: { refundUsd: 610 }, respondent: { refundUsd: 600 } }, privates), null);
  });
});

describe("Nash proposal (single negotiating text)", () => {
  it("splits a single-issue zone of agreement down the middle", () => {
    assert.deepEqual(nashProposal([REFUND], { claimant: single(300), respondent: single(700) }), { refundUsd: 500 });
    assert.deepEqual(nashProposal([REFUND], { claimant: single(300), respondent: single(500) }), { refundUsd: 400 });
  });

  it("returns null when declared walkaways leave no zone of agreement", () => {
    assert.equal(nashProposal([REFUND], { claimant: single(700), respondent: single(300) }), null);
  });

  it("trades across issues: each side gets what it values most", () => {
    const issues = [REFUND, CREDIT];
    const terms = nashProposal(issues, {
      claimant: { weights: { refundUsd: 0.9, serviceCreditUsd: 0.1 }, walkaway: { refundUsd: 0, serviceCreditUsd: 0 } },
      respondent: { weights: { refundUsd: 0.1, serviceCreditUsd: 0.9 }, walkaway: { refundUsd: 1000, serviceCreditUsd: 500 } },
    });
    // Claimant cares about cash, respondent about not issuing credit: both reach 0.9 utility,
    // versus 0.5 each from a naive per-issue split.
    assert.deepEqual(terms, { refundUsd: 1000, serviceCreditUsd: 0 });
  });

  it("never proposes below either declared walkaway", () => {
    const issues = [REFUND, CREDIT];
    const terms = nashProposal(issues, {
      claimant: { weights: { refundUsd: 0.5, serviceCreditUsd: 0.5 }, walkaway: { refundUsd: 400, serviceCreditUsd: 200 } },
      respondent: { weights: { refundUsd: 0.7, serviceCreditUsd: 0.3 }, walkaway: { refundUsd: 700, serviceCreditUsd: 300 } },
    })!;
    assert.ok(terms);
    const uc = 0.5 * (terms.refundUsd! / 1000) + 0.5 * (terms.serviceCreditUsd! / 500);
    const ur = 0.7 * (1 - terms.refundUsd! / 1000) + 0.3 * (1 - terms.serviceCreditUsd! / 500);
    assert.ok(uc >= 0.5 - 1e-9, `claimant utility ${uc}`);
    assert.ok(ur >= 0.7 * 0.3 + 0.3 * 0.4 - 1e-9, `respondent utility ${ur}`);
  });

  it("recursively snaps coarse-step multi-issue pivots to find valid discrete zones of agreement (FS-H1)", () => {
    const issues = [
      { id: "i1", label: "Coarse", unit: "USD", min: 0, max: 100, step: 50, claimantPrefers: "higher" as const, obligor: "respondent" as const },
      { id: "i2", label: "Fine", unit: "USD", min: 0, max: 100, step: 10, claimantPrefers: "higher" as const, obligor: "respondent" as const },
    ];
    const privates = {
      claimant: { weights: { i1: 0.6, i2: 0.4 }, walkaway: { i1: 50, i2: 20 } },
      respondent: { weights: { i1: 0.55, i2: 0.45 }, walkaway: { i1: 50, i2: 40 } },
    };
    const terms = nashProposal(issues, privates, 0.5);
    assert.deepEqual(terms, { i1: 50, i2: 30 });
    const presented = presentProposal(issues, privates, 0.5);
    assert.equal(presented.settles, true);
    assert.deepEqual(presented.views.claimant, { i1: 50, i2: 30 });
    assert.deepEqual(declaredReferenceTerms(issues, privates), { i1: 50, i2: 30 });
  });

  it("breaks exact half-step Nash rounding ties toward the even grid index without directional bias (FS-M4)", () => {
    const issue = { id: "x", label: "Units", unit: "u", min: 0, max: 10, step: 1, claimantPrefers: "higher" as const, obligor: "respondent" as const };
    // Continuous optimum 2.5 sits halfway between idx 2 (even) and idx 3 (odd) -> snaps to 2.
    assert.deepEqual(nashProposal([issue], { claimant: { weights: { x: 1 }, walkaway: { x: 1 } }, respondent: { weights: { x: 1 }, walkaway: { x: 4 } } }, 0.5), {
      x: 2,
    });
    // Continuous optimum 3.5 sits halfway between idx 3 (odd) and idx 4 (even) -> snaps to 4.
    assert.deepEqual(nashProposal([issue], { claimant: { weights: { x: 1 }, walkaway: { x: 2 } }, respondent: { weights: { x: 1 }, walkaway: { x: 5 } } }, 0.5), {
      x: 4,
    });
  });

  it("keeps Unix-ms integer grids exact without 1e9 float overflow and rejects sub-1e-6 steps (FS-H3)", () => {
    const deadlineIssue = {
      id: "deliveryAtMs",
      label: "Delivery Deadline",
      unit: "ms",
      min: 1_791_964_800_000,
      max: 1_791_964_800_300,
      step: 1,
      claimantPrefers: "lower" as const,
      obligor: "respondent" as const,
    };
    validateIssues([deadlineIssue]);
    const snapped = snap(deadlineIssue, 1_791_964_800_137, "nearest");
    assert.equal(snapped, 1_791_964_800_137);
    assert.equal(isOnGrid(deadlineIssue, snapped), true);
    assert.equal(Object.is(snap({ ...REFUND, min: -10, max: 10, step: 1 }, -1e-12, "nearest"), -0), false);

    assert.throws(() => validateIssues([{ ...REFUND, step: 2.5e-9 }]), /step must be at least 1e-6/);
    assert.throws(() => validateIssues([{ ...REFUND, min: 0, max: 2e15, step: 1e10 }]), /magnitude must not exceed 1e15/);
  });
});
