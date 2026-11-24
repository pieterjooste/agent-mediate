/**
 * Regression tests for RULES_VERSION 1.4.0 (Batch 3 — D130):
 *   - H-09: No-zone stand-in viewer-box isolation + full-grid secret-alpha paretoImproveTerms
 *   - H-10: Fractional (USD cents & 1e-6) and large-step (1e9) snapIdxTolerance + lossless ShareBox
 *   - M-10: Outage-extended mandate expiry guards in CONFIRM_ISSUES and resolveRound (no false TIMEOUT)
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  extendDeadlines,
  HISTORICAL_RULES_HASHES,
  isOnGrid,
  issuesHash,
  nashProposal,
  paretoImproveTerms,
  presentProposal,
  RULES_HASH,
  RULES_VERSION,
  snap,
  utility,
  validatePrivate,
  type Issue,
  type Mandate,
  type PrivateInputs,
} from "../src/index.ts";
import { CLAIMANT, Harness, mandate, REFUND, RESPONDENT, single, T0 } from "./helpers.ts";

const MIN = 60_000;
const issue = (id: string, overrides: Partial<Issue> = {}): Issue => ({
  id,
  label: id,
  unit: "units",
  min: 0,
  max: 1000,
  step: 1,
  claimantPrefers: "higher",
  obligor: "respondent",
  ...overrides,
});

describe("RULES_VERSION 1.4.0 mechanism hardening (H-09, H-10, M-10)", () => {
  it("pins 1.4.0 RULES_HASH and preserves historical 1.3.0 hash", () => {
    assert.equal(RULES_VERSION, "1.4.0");
    assert.equal(RULES_HASH, "10b48aa0d8a4a71808f5550f951ad128aa0af44b775b2c88c73ddb1dd1cee173");
    assert.equal(
      HISTORICAL_RULES_HASHES["1.3.0"],
      "8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4",
    );
  });

  it("H-09a: presentProposal optimizes no-zone stand-ins over viewer's own box, never clamping onto counterparty private.limits", () => {
    const i = issue("refundUsd", { min: 0, max: 1000, step: 1, claimantPrefers: "higher" });
    const basis: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 400 } },
      respondent: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 200 }, limits: { refundUsd: { min: 0, max: 450 } } },
    };

    const seen = new Set<number>();
    for (const alpha of [0.3, 0.4, 0.5, 0.6, 0.7]) {
      const p = presentProposal([i], basis, alpha);
      assert.equal(p.settles, false);
      // Before H-09, every alpha clamped Claimant's stand-in to Respondent's secret limit 450!
      assert.notEqual(p.views.claimant.refundUsd, 450, `alpha=${alpha} must not clamp Claimant onto Respondent's secret limit 450`);
      assert.ok(p.views.claimant.refundUsd > 450, `alpha=${alpha} should exceed 450 inside Claimant's own box`);
      assert.ok(p.views.respondent.refundUsd <= 200, "Respondent stand-in stays within Respondent's own limits & walkaway");
      seen.add(p.views.claimant.refundUsd);
    }
    assert.equal(seen.size, 5, "stand-in varies smoothly with secret split alpha instead of collapsing to 450");

    // Continuous across walkaway = 450 vs 451 (no zero-surplus collapse or discontinuity at Respondent's secret limit)
    const at450 = presentProposal([i], { claimant: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 450 } }, respondent: basis.respondent }, 0.5);
    const at451 = presentProposal([i], { claimant: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 451 } }, respondent: basis.respondent }, 0.5);
    assert.ok(at450.views.claimant.refundUsd > 450, "walkaway=450 must still show positive blinded surplus");
    assert.ok(Math.abs(at451.views.claimant.refundUsd - at450.views.claimant.refundUsd) <= 3, "no discontinuity across Respondent's secret limit");
  });

  it("H-09b: paretoImproveTerms optimizes on fullShareBox with post-hoc limit/mandate checks and uses secret split in settle()", () => {
    const i1 = issue("refundUsd", { min: 0, max: 1000, step: 1, claimantPrefers: "higher" });
    const i2 = issue("days", { min: 0, max: 100, step: 1, claimantPrefers: "lower" });
    const wideMandates = {
      claimant: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 }, days: { min: 0, max: 100 } }),
      respondent: mandate(RESPONDENT, { refundUsd: { min: 0, max: 1000 }, days: { min: 0, max: 100 } }),
    };
    const privNoLimits: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 0.9, days: 0.1 }, walkaway: { refundUsd: 200, days: 90 } },
      respondent: { weights: { refundUsd: 0.1, days: 0.9 }, walkaway: { refundUsd: 800, days: 10 } },
    };
    const privTightRespLimits: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: privNoLimits.claimant,
      respondent: {
        ...privNoLimits.respondent,
        limits: { refundUsd: { min: 0, max: 637 }, days: { min: 0, max: 100 } },
      },
    };
    const baseline = { refundUsd: 500, days: 50 };
    const unconstrained = paretoImproveTerms([i1, i2], baseline, privNoLimits, wideMandates, 0.5);
    assert.notEqual(unconstrained, null);
    assert.ok(unconstrained!.refundUsd > 637);

    // Before H-09, paretoImproveTerms optimized on limitsBox and returned { refundUsd: 637, days: 100 }, leaking 637!
    const withTightLimit = paretoImproveTerms([i1, i2], baseline, privTightRespLimits, wideMandates, 0.5);
    assert.equal(withTightLimit, null, "must reject full-grid optimum exceeding private.limits rather than clamping onto 637");

    // In settle(), the improvement uses the dispute's secret per-dispute split α (different salts yield different interior pivots)
    const sq1 = issue("refundUsd", { min: 0, max: 1000, step: 1, claimantPrefers: "higher" });
    const sq2 = issue("days", { min: 0, max: 1000, step: 1, claimantPrefers: "lower" });
    const sqPriv: Record<"claimant" | "respondent", PrivateInputs> = {
      claimant: { weights: { refundUsd: 0.8, days: 0.2 }, walkaway: { refundUsd: 200, days: 800 } },
      respondent: { weights: { refundUsd: 0.65, days: 0.35 }, walkaway: { refundUsd: 800, days: 200 } },
    };
    const pivots = new Set<number>();
    for (let k = 0; k < 12; k++) {
      const h = new Harness({
        issues: [sq1, sq2],
        proposalKey: `${String(k).padStart(2, "0")}${"a".repeat(62)}`,
        claimantBounds: { refundUsd: { min: 0, max: 1000 }, days: { min: 0, max: 1000 } },
        respondentBounds: { refundUsd: { min: 0, max: 1000 }, days: { min: 0, max: 1000 } },
      }).toBargaining();
      h.round(
        { offer: { refundUsd: 500, days: 200 }, private: sqPriv.claimant },
        { offer: { refundUsd: 500, days: 200 }, private: sqPriv.respondent },
      );
      const imp = h.state.execution?.improvement;
      assert.ok(imp, "Pareto improvement should still open when inside mandates and limits");
      pivots.add(imp.terms.refundUsd!);
    }
    assert.ok(pivots.size >= 3, "settle() must blind interior Pareto pivot with per-dispute secret split α");
  });

  it("H-10: snap() and ShareBox handle USD cents, 1e-6 fractional grids, and 1e9 large-step grids without false rejections", () => {
    // 1. Ordinary USD cents (min: 100000.01, max: 110000.01, step: 0.01)
    const usdCents: Issue = issue("priceUsd", { min: 100_000.01, max: 110_000.01, step: 0.01 });
    assert.equal(isOnGrid(usdCents, 100_000.07), true);
    assert.equal(snap(usdCents, 100_000.07, "floor"), 100_000.07);
    assert.equal(snap(usdCents, 100_000.07, "ceil"), 100_000.07);
    assert.equal(snap(usdCents, 100_000.07, "nearest"), 100_000.07);
    validatePrivate([usdCents], {
      weights: { priceUsd: 1 },
      walkaway: { priceUsd: 100_000.07 },
      limits: { priceUsd: { min: 100_000.07, max: 100_000.07 } },
    });

    // 2. Extreme valid 1e-6 fractional grid near 900000
    const microGrid: Issue = issue("micro", { min: 900_000.000001, max: 900_001.000001, step: 0.000001 });
    for (let k = 0; k < 50; k++) {
      const v = Number((900_000.000001 + k * 0.000001).toFixed(6));
      assert.equal(isOnGrid(microGrid, v), true);
      assert.equal(snap(microGrid, v, "floor"), v, `floor failed at k=${k} (${v})`);
      assert.equal(snap(microGrid, v, "ceil"), v, `ceil failed at k=${k} (${v})`);
    }
    validatePrivate([microGrid], {
      weights: { micro: 1 },
      walkaway: { micro: 900_000.000007 },
      limits: { micro: { min: 900_000.000007, max: 900_000.000007 } },
    });

    // 3. Large-step integer grid (min: 0, max: 999_999 * 1e9, step: 1e9, claimantPrefers: "lower")
    const largeStep: Issue = issue("wei", { min: 0, max: 999_999 * 1e9, step: 1e9, claimantPrefers: "lower" });
    for (let k = 1; k <= 100; k++) {
      const v = k * 1e9;
      const p = nashProposal(
        [largeStep],
        {
          claimant: { weights: { wei: 1 }, walkaway: { wei: v }, limits: { wei: { min: v, max: v + 1e9 } } },
          respondent: { weights: { wei: 1 }, walkaway: { wei: v }, limits: { wei: { min: v, max: v + 1e9 } } },
        },
        0.5,
      );
      assert.deepEqual(p, { wei: v }, `nashProposal must not return null on large-step grid at k=${k}`);
    }
  });

  it("M-10: post-outage expired mandates reset confirmation on CONFIRM_ISSUES and end NO_OVERLAP_AT_CAP (never TIMEOUT) in resolveRound", () => {
    // Part A: CONFIRM_ISSUES resets first confirmer whose mandate expired during a platform outage
    const h1 = new Harness({
      claimantMandateExpiry: T0 + 50 * MIN,
      respondentMandateExpiry: T0 + 300 * MIN,
      config: { stageTimeoutMs: 20 * MIN, bargainingWallClockMs: 15 * MIN },
    });
    h1.toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    const hash = issuesHash([REFUND]);
    h1.send({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash });

    // 60m outage shifts stageDeadline to T0 + 80m; at T0 + 75m Claimant's mandate (T0 + 50m) has expired.
    const ext1 = extendDeadlines(h1.state, { fromMs: h1.now, byMs: 60 * MIN, reason: "outage" }, h1.now + 60 * MIN);
    assert.equal(ext1.ok, true);
    if (!ext1.ok) throw new Error("unexpected");
    h1.state = ext1.state;
    h1.events.push(...ext1.events);
    h1.now += 75 * MIN;

    h1.send({ type: "CONFIRM_ISSUES", actor: "respondent", issuesHash: hash });
    assert.equal(h1.state.status, "ISSUE_CONFIRMATION", "must not enter BARGAINING with an already-expired first-confirmer mandate");
    assert.equal(h1.state.issueNegotiation.confirmed.claimant, false);
    assert.equal(h1.state.issueNegotiation.confirmed.respondent, true);

    // Part B: resolveRound after an outage shifts roundDeadline past a party's mandate expiry -> NO_OVERLAP_AT_CAP (not TIMEOUT / misses)
    const h2 = new Harness({
      claimantMandateExpiry: T0 + 60 * MIN,
      respondentMandateExpiry: T0 + 300 * MIN,
      config: { roundTimeoutMs: 5 * MIN, bargainingWallClockMs: 20 * MIN },
    }).toBargaining();
    // 90m outage shifts roundDeadline & wallClockDeadline past Claimant's T0 + 60m expiry
    const ext2 = extendDeadlines(h2.state, { fromMs: h2.now, byMs: 90 * MIN, reason: "outage" }, h2.now + 90 * MIN);
    assert.equal(ext2.ok, true);
    if (!ext2.ok) throw new Error("unexpected");
    h2.state = ext2.state;
    h2.events.push(...ext2.events);
    // Respondent submits validly; Claimant cannot submit because Claimant's mandate expired at T0 + 60m.
    h2.now = h2.state.bargaining!.roundDeadline - 10_000;
    h2.send({ type: "SUBMIT_ROUND", actor: "respondent", round: 1, offer: { refundUsd: 200 }, private: single(400) });
    // Advance to roundDeadline -> TICK resolves round
    h2.now = h2.state.bargaining!.roundDeadline + 1_000;
    h2.send({ type: "TICK", actor: "system" });

    assert.equal(h2.state.status, "UNRESOLVED");
    assert.equal(h2.state.outcome?.kind, "UNRESOLVED");
    if (h2.state.outcome?.kind === "UNRESOLVED") {
      assert.equal(h2.state.outcome.reason, "NO_OVERLAP_AT_CAP", "outage-expired mandate must not produce adverse TIMEOUT");
    }
    assert.equal(h2.state.bargaining!.misses.claimant, 0, "expired party must not be charged a missed round");
    assert.ok(utility([REFUND], { refundUsd: 1 }, { refundUsd: 500 }, "claimant") === 0.5);
  });
});
