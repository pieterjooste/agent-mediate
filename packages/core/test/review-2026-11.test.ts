/**
 * Regression tests for the 2026-11-07 comprehensive review findings that live in @agent-mediate/core
 * (CR-CORE-M1 documented limitation, CR-CORE-M2 Object.prototype issue ids, CR-CORE-M3 absolute grid tolerance).
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  canonicalJson,
  computeDeclaredInputCommitment,
  computeProposalKeyCommitment,
  createDispute,
  derivePartyInputSalt,
  findLeaks,
  GENESIS_HASH,
  mandateCovers,
  nashProposal,
  ownEntry,
  paretoImproveTerms,
  presentProposal,
  RESERVED_ISSUE_IDS,
  utility,
  validateIssues,
  verifyProposalOpening,
  verifyPublicAuditChain,
  withinDeterminationMandate,
  withinMandate,
  type Issue,
  type Mandate,
  type PublicAuditEntry,
} from "../src/index.ts";
import { gridTolerance, isOnGrid } from "../src/mechanism.ts";
import { requireMandateCovers, validatePackage } from "../src/validation.ts";
import { CLAIMANT, CONTRACT, Harness, mandate, RESPONDENT, SALT } from "./helpers.ts";

const issue = (id: string, over: Partial<Issue> = {}): Issue => ({
  id,
  label: id,
  unit: "u",
  min: 0,
  max: 100,
  step: 1,
  claimantPrefers: "higher",
  obligor: "respondent",
  ...over,
});

describe("CR-CORE-M2: Object.prototype-named issue ids", () => {
  it("rejects every reserved id at validation time", () => {
    for (const id of RESERVED_ISSUE_IDS) {
      assert.throws(() => validateIssues([issue("refundUsd"), issue(id)]), /reserved/, id);
    }
    assert.doesNotThrow(() => validateIssues([issue("refundUsd"), issue("valueAdd")]));
  });

  it("id-keyed lookups ignore inherited properties (defence in depth for stored legacy ids)", () => {
    const valueOf = issue("valueOf");
    const mandate = { bounds: { refundUsd: { min: 0, max: 100 } } } as unknown as Mandate;
    assert.equal(ownEntry(mandate.bounds, "valueOf"), undefined);
    assert.equal(ownEntry(mandate.bounds, "refundUsd")!.max, 100);
    assert.throws(() => requireMandateCovers(mandate, [issue("refundUsd"), valueOf]), /no bounds for issue valueOf/);
    assert.equal(mandateCovers(mandate, valueOf), false);
    assert.equal(withinMandate([valueOf], mandate, { valueOf: 1 }), false);
    assert.equal(withinDeterminationMandate([valueOf], mandate, { valueOf: 1 }), false);
    // An empty `limits` object no longer turns a prototype-named issue into a NaN share box.
    const issues = [issue("refundUsd"), issue("valueOf", { max: 10, claimantPrefers: "lower" })];
    const privates = {
      claimant: { weights: { refundUsd: 0.5, valueOf: 0.5 }, walkaway: { refundUsd: 40, valueOf: 6 }, limits: {} },
      respondent: { weights: { refundUsd: 0.5, valueOf: 0.5 }, walkaway: { refundUsd: 60, valueOf: 4 } },
    };
    const withoutLimits = { ...privates, claimant: { weights: privates.claimant.weights, walkaway: privates.claimant.walkaway } };
    assert.deepEqual(nashProposal(issues, privates, 0.5), nashProposal(issues, withoutLimits, 0.5));
    assert.notEqual(nashProposal(issues, privates, 0.5), null);
  });
});

describe("CR-CORE-M3: absolute on-grid tolerance", () => {
  const big = issue("x", { max: 1_000_000 });
  it("rejects values a fraction of a step off an integer grid, even at large indices", () => {
    assert.equal(isOnGrid(big, 999_999.0009), false);
    assert.throws(() => validatePackage([big], { x: 999_999.0009 }, "offer"), /steps of 1/);
    assert.equal(isOnGrid(big, 999_999), true);
    assert.equal(isOnGrid(big, 1_000_000), true);
  });

  it("rejects an off-grid max but still accepts floating-point noise on fractional grids", () => {
    assert.throws(() => validateIssues([issue("x", { max: 100_000.00005 })]), /multiple of step/);
    const frac = issue("rate", { min: 0.1, max: 0.7, step: 0.1 });
    assert.doesNotThrow(() => validateIssues([frac]));
    for (const v of [0.1, 0.2, 0.30000000000000004, 0.7, 0.1 + 0.2 + 0.1]) assert.equal(isOnGrid(frac, v), true, String(v));
    assert.equal(isOnGrid(frac, 0.35), false);
    const micro = issue("m", { min: 0, max: 0.5, step: 0.000001 });
    assert.doesNotThrow(() => validateIssues([micro]));
    assert.equal(isOnGrid(micro, 0.499999), true);
    assert.equal(isOnGrid(micro, 0.4999995), false);
  });
});

describe("CR-CORE-M1: best-effort proposal search (D125, documented limitation)", () => {
  it("pins today's result for the reviewer's narrow-zone, coarse-secondary-issue vector", () => {
    const issues = [issue("a"), issue("b", { step: 25 })];
    const privates = {
      claimant: { weights: { a: 0.7, b: 0.3 }, walkaway: { a: 40, b: 75 } },
      respondent: { weights: { a: 0.699, b: 0.301 }, walkaway: { a: 62, b: 25 } },
    };
    // A strictly acceptable grid point exists ...
    const rc = utility(issues, privates.claimant.weights, privates.claimant.walkaway, "claimant");
    const rr = utility(issues, privates.respondent.weights, privates.respondent.walkaway, "respondent");
    assert.ok(utility(issues, privates.claimant.weights, { a: 51, b: 50 }, "claimant") > rc);
    assert.ok(utility(issues, privates.respondent.weights, { a: 51, b: 50 }, "respondent") > rr);
    // ... but the RULES_VERSION 1.1.0 search does not visit it. Changing this result changes RULES_HASH outputs:
    // only do so together with a RULES_VERSION bump (planned exact search, 1.2.0).
    for (const split of [0.3, 0.5, 0.7]) assert.equal(nashProposal(issues, privates, split), null);
    assert.equal(presentProposal(issues, privates, 0.5).settles, false);
  });
});

describe("CR-SDK-L4 & JCS edge vectors in @agent-mediate/core", () => {
  it("canonicalizes RFC 8785 boundary numbers, line separators and lone surrogates deterministically", () => {
    assert.equal(canonicalJson(1e20), "100000000000000000000");
    assert.equal(canonicalJson(1e21), "1e+21");
    assert.equal(canonicalJson(1e-6), "0.000001");
    assert.equal(canonicalJson(1e-7), "1e-7");
    assert.equal(canonicalJson(5e-324), "5e-324");
    assert.equal(canonicalJson(0.1 + 0.2), "0.30000000000000004");
    assert.equal(canonicalJson({ z: [-0, { negZero: -0 }] }), '{"z":[0,{"negZero":0}]}');
    assert.equal(canonicalJson("\u2028\u2029"), '"\u2028\u2029"');
    assert.equal(canonicalJson("\ud800"), '"\\ud800"');
  });

  it("verifyPublicAuditChain rejects non-integer seq and non-true redacted flags", () => {
    const h = "a".repeat(64);
    assert.equal(verifyPublicAuditChain([{ seq: 1.5, redacted: true, prevHash: GENESIS_HASH, hash: h } as PublicAuditEntry]).ok, false);
    assert.equal(verifyPublicAuditChain([{ seq: true as unknown as number, redacted: true, prevHash: GENESIS_HASH, hash: h }]).ok, false);
    assert.equal(verifyPublicAuditChain([{ seq: 1, redacted: false as unknown as true, prevHash: GENESIS_HASH, hash: h }]).ok, false);
  });
});

describe("SA-CORE-M1, SA-CORE-M2, SA-CORE-L1..L3: 2026-11-09 security audit regressions", () => {
  it("SA-CORE-M1: exact integer grid checks on large-step issues (step >= 1000) and off-grid max rejection", () => {
    const largeStep = issue("refundUsd", { min: 0, max: 1_000_000, step: 1000 });
    assert.equal(gridTolerance(largeStep, 500_000), 0);
    assert.equal(isOnGrid(largeStep, 500_000), true);
    assert.equal(isOnGrid(largeStep, 500_001), false);
    assert.equal(isOnGrid(largeStep, 500_000.4), false);
    assert.throws(() => validatePackage([largeStep], { refundUsd: 500_001 }, "offer"), /steps of 1000/);
    assert.throws(() => validateIssues([issue("refundUsd", { min: 0, max: 1_000_500, step: 1000 })]), /multiple of step/);

    const hugeFrac = issue("hugeFrac", { min: 0, max: 10_000_000, step: 10_000.5 });
    assert.ok(gridTolerance(hugeFrac, 5_000_000) <= 0.25);
  });

  it("SA-CORE-M2 & SA-CORE-L2: paretoImproveTerms never optimizes against private mandate.bounds; findLeaks ignores protocol metadata and strips unit suffixes", () => {
    const i1 = issue("refundUsd", { min: 0, max: 1000, step: 10, claimantPrefers: "higher" });
    const i2 = issue("days", { min: 0, max: 100, step: 1, claimantPrefers: "lower" });
    const privates = {
      claimant: { weights: { refundUsd: 0.9, days: 0.1 }, walkaway: { refundUsd: 200, days: 90 } },
      respondent: { weights: { refundUsd: 0.1, days: 0.9 }, walkaway: { refundUsd: 800, days: 10 } },
    };
    const wideMandates = {
      claimant: { bounds: { refundUsd: { min: 0, max: 1000 }, days: { min: 0, max: 100 } } } as unknown as Mandate,
      respondent: { bounds: { refundUsd: { min: 0, max: 1000 }, days: { min: 0, max: 100 } } } as unknown as Mandate,
    };
    // Respondent's private mandate.bounds caps refundUsd at 450, which is tighter than the Nash optimum on [0, 1000] (~800).
    // Optimization must not snap to respondent's secret bound 450; instead it computes the Nash optimum on limitsBox and returns null if outside mandate.bounds.
    const tightRespondentMandates = {
      claimant: wideMandates.claimant,
      respondent: { bounds: { refundUsd: { min: 0, max: 450 }, days: { min: 0, max: 100 } } } as unknown as Mandate,
    };
    const baseline = { refundUsd: 300, days: 50 };
    const wideImproved = paretoImproveTerms([i1, i2], baseline, privates, wideMandates);
    assert.notEqual(wideImproved, null);
    assert.ok(wideImproved!.refundUsd > 450);
    const tightImproved = paretoImproveTerms([i1, i2], baseline, privates, tightRespondentMandates);
    assert.equal(tightImproved, null, "must reject out-of-mandate optimum rather than clamping to secret mandate.bounds");

    // SA-CORE-L2: findLeaks detects unit-suffixed numbers (e.g. "17days", "750.00USD") without breaking hex/did tokens.
    const h = new Harness({ issues: [i2], claimantBounds: { days: { min: 17, max: 90 } } });
    const leaked = findLeaks(JSON.stringify({ leakedText: "claimant minimum is 17days" }), h.state, "respondent");
    assert.ok(leaked.some((l) => l.token === "17" && l.source.includes("mandate.days.min")), "must detect leaked secret bound 17 when suffixed with 'days'");
    assert.equal(findLeaks(JSON.stringify({ text: "750.00USD or 1200days" }), h.state, "respondent").length, 0);
  });

  it("SA-CORE-L1 & SA-CORE-L3: requireNow rejects non-positive/float timestamps and verifyProposalOpening requires 64-hex partySalt/commitment", () => {
    const r = createDispute(
      {
        id: "dsp_now",
        auditSalt: SALT,
        claimantId: CLAIMANT,
        claimantMandate: mandate(CLAIMANT, { x: { min: 0, max: 100 } }),
        respondentId: RESPONDENT,
        contractHash: CONTRACT,
        claim: { summary: "S", requestedRemedy: "R" },
        feePaid: true,
        discloseGapOnFailure: false,
      },
      0,
    );
    assert.equal(r.ok, false);
    if (!r.ok) assert.match(r.error.message, /positive safe integer/);

    const iss = [issue("x")];
    const cPriv = { weights: { x: 1 }, walkaway: { x: 30 } };
    const rPriv = { weights: { x: 1 }, walkaway: { x: 70 } };
    const rSalt = derivePartyInputSalt("s", "dsp_v", "respondent");
    const badSaltRes = verifyProposalOpening({
      disputeId: "dsp_v",
      issues: iss,
      mode: "keyed",
      proposalKeyOrSalt: "k",
      proposalKeyCommitment: computeProposalKeyCommitment("dsp_v", "k", "keyed"),
      declared: {
        claimant: {
          private: cPriv,
          partySalt: "short_salt",
          commitment: computeDeclaredInputCommitment("dsp_v", "claimant", "short_salt", cPriv),
        },
        respondent: {
          private: rPriv,
          partySalt: rSalt,
          commitment: computeDeclaredInputCommitment("dsp_v", "respondent", rSalt, rPriv),
        },
      },
    });
    assert.equal(badSaltRes.ok, false);
  });
});
