import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  apply,
  extendDeadlines,
  issuesHash,
  RULES_HASH,
  RULES_VERSION,
  verifyAuditChain,
  viewFor,
} from "../src/index.ts";
import { CLAIMANT, CONTRACT, DAY, expectError, Harness, mandate, MIN, REFUND, RESPONDENT, single, T0 } from "./helpers.ts";

describe("CR3 core state-machine & audit-chain invariants", () => {
  it("preserves frozen RULES_VERSION and RULES_HASH invariants", () => {
    assert.equal(RULES_VERSION, "1.3.0");
    assert.equal(RULES_HASH, "8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4");
  });

  it("CR3-SVC-M1: UPDATE_MANDATE emits zero audit events, CONFIRM_ISSUES always emits MANDATE_REGISTERED, and ROUND_SUBMISSION / FINAL_OFFER fold mandate + mandateUpdates", () => {
    const h = new Harness({
      claimantBounds: { refundUsd: { min: 400, max: 1000 } },
      respondentBounds: { refundUsd: { min: 0, max: 600 } },
      determination: { claimant: true, respondent: true },
      config: { maxRounds: 3 },
    });

    h.toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    const hash = issuesHash([REFUND]);

    // Claimant replaces mandate at CONFIRM_ISSUES; respondent reuses existing mandate without replacement.
    // BOTH emit MANDATE_REGISTERED so event count is identical regardless of replacement!
    const preConfirmIdx = h.events.length;
    h.send({
      type: "CONFIRM_ISSUES",
      actor: "claimant",
      issuesHash: hash,
      mandate: mandate(CLAIMANT, { refundUsd: { min: 300, max: 1000 } }, T0 + 30 * DAY, T0 + 1_000, {
        determinationConsent: true,
        scope: { contractHash: CONTRACT, counterpartyId: RESPONDENT },
      }),
    });
    h.send({ type: "CONFIRM_ISSUES", actor: "respondent", issuesHash: hash });
    assert.equal(h.state.status, "BARGAINING");

    const confirmRegistrations = h.events
      .slice(preConfirmIdx)
      .filter((e) => e.type === "MANDATE_REGISTERED")
      .map((e) => e.data as { party: string; replaced?: boolean });
    assert.equal(confirmRegistrations.length, 2, "CONFIRM_ISSUES always emits MANDATE_REGISTERED for both parties");
    assert.equal(confirmRegistrations.find((x) => x.party === "claimant")?.replaced, true);
    assert.equal(confirmRegistrations.find((x) => x.party === "respondent")?.replaced, false);

    // Respondent widens mandate DURING BARGAINING -> 0 events emitted, counterparty view & audit seq unchanged.
    const claimantViewBefore = viewFor(h.state, "claimant");
    const seqBefore = h.state.audit.seq;
    const eventsBefore = h.events.length;
    h.advance(5_000);
    const updatedRespMandate = mandate(RESPONDENT, { refundUsd: { min: 0, max: 750 } }, T0 + 30 * DAY, T0 + 2_000, {
      determinationConsent: true,
      scope: { contractHash: CONTRACT, counterpartyId: CLAIMANT },
    });
    const rUpdate1 = apply(h.state, { type: "UPDATE_MANDATE", actor: "respondent", mandate: updatedRespMandate }, h.now);
    assert.equal(rUpdate1.ok, true);
    assert.equal(rUpdate1.events.length, 0, "UPDATE_MANDATE must emit zero audit events");
    h.state = rUpdate1.state;
    assert.equal(h.state.audit.seq, seqBefore, "audit.seq must stay invariant across UPDATE_MANDATE");
    assert.equal(h.events.length, eventsBefore);
    assert.deepEqual(viewFor(h.state, "claimant"), claimantViewBefore, "counterparty view must not reveal UPDATE_MANDATE");
    assert.equal(h.state.parties.respondent!.mandateUpdates, 1);

    // Exhaust 3 rounds without settlement -> advances to DETERMINATION.
    h.round({ offer: { refundUsd: 900 }, private: single(500) }, { offer: { refundUsd: 100 }, private: single(700) });
    h.round({ offer: { refundUsd: 850 }, response: "reject" }, { offer: { refundUsd: 150 }, response: "reject" });
    h.round({ offer: { refundUsd: 800 }, response: "reject" }, { offer: { refundUsd: 200 }, response: "reject" });
    assert.equal(h.state.status, "DETERMINATION");

    const respRoundSub = h.events.find(
      (e) => e.type === "ROUND_SUBMISSION" && (e.data as { party?: string }).party === "respondent",
    )!;
    const roundData = respRoundSub.data as {
      mandate: { issuedAt: number };
      mandateUpdates: number;
    };
    assert.equal(roundData.mandate.issuedAt, T0 + 2_000);
    assert.equal(roundData.mandateUpdates, 1);

    // Respondent widens mandate again in DETERMINATION -> 0 events emitted, folded into FINAL_OFFER.
    h.advance(5_000);
    const rUpdate2 = apply(
      h.state,
      {
        type: "UPDATE_MANDATE",
        actor: "respondent",
        mandate: mandate(RESPONDENT, { refundUsd: { min: 0, max: 850 } }, T0 + 30 * DAY, T0 + 3_000, {
          determinationConsent: true,
          scope: { contractHash: CONTRACT, counterpartyId: CLAIMANT },
        }),
      },
      h.now,
    );
    assert.equal(rUpdate2.ok, true);
    assert.equal(rUpdate2.events.length, 0);
    h.state = rUpdate2.state;

    h.send({ type: "SET_DETERMINATION_REFERENCE", actor: "system", terms: { refundUsd: 600 } });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "claimant", offer: { refundUsd: 650 } });
    h.send({ type: "SUBMIT_FINAL_OFFER", actor: "respondent", offer: { refundUsd: 550 } });
    assert.equal(h.state.status, "EXECUTION_PENDING");

    const respFinal = h.events.find(
      (e) => e.type === "FINAL_OFFER" && (e.data as { party?: string }).party === "respondent",
    )!;
    const finalData = respFinal.data as {
      mandate: { issuedAt: number };
      mandateUpdates: number;
    };
    assert.equal(finalData.mandate.issuedAt, T0 + 3_000);
    assert.equal(finalData.mandateUpdates, 2);
    assert.equal(verifyAuditChain(h.events).ok, true);
  });

  it("CR3-CORE-L1: pre-bargaining extendDeadlines never over-subtracts from BARGAINING or DETERMINATION UPDATE_MANDATE horizons", () => {
    const h = new Harness({
      determination: { claimant: true, respondent: true },
      claimantMandateExpiry: T0 + 180 * MIN,
      config: {
        maxRounds: 3,
        stageTimeoutMs: 20 * MIN,
        roundTimeoutMs: 10 * MIN,
        bargainingWallClockMs: 60 * MIN,
        determinationTimeoutMs: 30 * MIN,
      },
    });
    h.toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: [REFUND] });
    const hash = issuesHash([REFUND]);

    // 1. Claimant confirms FIRST at T0 (stageDeadline = T0 + 20m -> needs > T0 + 110m; T0 + 180m passes).
    h.send({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash });

    // 2. While awaiting respondent confirmation, a 120m outage shifts ISSUE_CONFIRMATION deadline (outageExtensionMs = 120m).
    const ext = extendDeadlines(h.state, { fromMs: h.now, byMs: 120 * MIN, reason: "maintenance" }, h.now + 120 * MIN);
    assert.equal(ext.ok, true);
    if (!ext.ok) throw new Error("unexpected");
    h.state = ext.state;
    h.events.push(...ext.events);
    h.now += 130 * MIN; // T0 + 130m (within shifted stageDeadline = T0 + 140m)

    // 3. Respondent confirms at T0 + 130m -> BARGAINING starts at startedAt = T0 + 130m.
    h.send({ type: "CONFIRM_ISSUES", actor: "respondent", issuesHash: hash });
    assert.equal(h.state.status, "BARGAINING");

    const startedAt = h.state.bargaining!.startedAt; // T0 + 130m
    const requiredBargainingHorizon = startedAt + 60 * MIN + 30 * MIN; // T0 + 220m

    // Claimant tries UPDATE_MANDATE with expiresAt = T0 + 200m (>= old T0 + 180m, yet <= required T0 + 220m).
    // Before CR3-CORE-L1, subtracting outageExtensionMs (120m) made requiredHorizon = T0 + 100m and let this slip through!
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }, T0 + 200 * MIN, T0 + 1_000, {
          determinationConsent: true,
          scope: { contractHash: CONTRACT, counterpartyId: RESPONDENT },
        }),
      }),
      "MANDATE_EXPIRED",
    );

    // Expiring at requiredBargainingHorizon + 1ms (T0 + 220m + 1) succeeds.
    h.send({
      type: "UPDATE_MANDATE",
      actor: "claimant",
      mandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }, T0 + 231 * MIN, T0 + 2_000, {
        determinationConsent: true,
        scope: { contractHash: CONTRACT, counterpartyId: RESPONDENT },
      }),
    });

    // 4. Extend BARGAINING deadlines by another 50m outage so bargaining ends at T0 + 200m -> detHorizon = T0 + 230m!
    const ext2 = extendDeadlines(h.state, { fromMs: h.now, byMs: 50 * MIN, reason: "maintenance-2" }, h.now + 50 * MIN);
    assert.equal(ext2.ok, true);
    if (!ext2.ok) throw new Error("unexpected");
    h.state = ext2.state;
    h.events.push(...ext2.events);
    h.now += 50 * MIN; // T0 + 180m

    h.advance(5 * MIN); // T0 + 185m (within shifted Round 1 deadline T0 + 190m)
    h.round({ offer: { refundUsd: 900 }, private: single(500) }, { offer: { refundUsd: 100 }, private: single(700) });
    h.advance(8 * MIN); // T0 + 193m
    h.round({ offer: { refundUsd: 850 }, response: "reject" }, { offer: { refundUsd: 150 }, response: "reject" });
    h.advance(7 * MIN); // T0 + 200m
    h.round({ offer: { refundUsd: 800 }, response: "reject" }, { offer: { refundUsd: 200 }, response: "reject" });
    assert.equal(h.state.status, "DETERMINATION");

    // Simulate a pre-CR3 state entering DETERMINATION with expiresAt = T0 + 225m (despite outageExtensionMs = 170m)
    // and verify DETERMINATION's startedAt-based horizon rejects <= detHorizon (T0 + 230m) and accepts detHorizon + 1.
    const detHorizon = h.state.determination!.startedAt! + 30 * MIN; // T0 + 230m
    h.state.parties.claimant.mandate.expiresAt = T0 + 225 * MIN;
    expectError(
      h.attempt({
        type: "UPDATE_MANDATE",
        actor: "claimant",
        mandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }, detHorizon, T0 + 3_000, {
          determinationConsent: true,
          scope: { contractHash: CONTRACT, counterpartyId: RESPONDENT },
        }),
      }),
      "MANDATE_EXPIRED",
    );
    h.send({
      type: "UPDATE_MANDATE",
      actor: "claimant",
      mandate: mandate(CLAIMANT, { refundUsd: { min: 0, max: 1000 } }, detHorizon + 1, T0 + 4_000, {
        determinationConsent: true,
        scope: { contractHash: CONTRACT, counterpartyId: RESPONDENT },
      }),
    });
  });
});
