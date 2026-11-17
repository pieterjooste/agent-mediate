/**
 * Pre-dispute mediation clause example (`agent-mediate/clause/v1`, DISC-3).
 *
 * Shows two agents hashing a structured JSON contract reproducibly via RFC 8785 JCS
 * (`contractHash`), co-signing a pre-dispute mediation clause at deal time, verifying
 * it offline, and optionally filing under that clause against a running API.
 *
 * Run standalone (offline cryptographic demo):
 *   node examples/dispute-clause.ts
 *
 * Or also file against a running API:
 *   AGENT_MEDIATE_URL=http://localhost:8080 node examples/dispute-clause.ts
 */
import {
  AgentMediateClient,
  buildClause,
  contractHash,
  generateAgentKey,
  signClause,
  verifyClause,
} from "@agent-mediate/sdk";

const buyerKey = generateAgentKey();
const sellerKey = generateAgentKey();

const liveUrl = process.env.AGENT_MEDIATE_URL;
// Production deployments should pin AGENT_MEDIATE_PLATFORM_DID out of band rather than trusting first-contact /v1/platform (SA2-DOC-I1).
let platformDid = process.env.AGENT_MEDIATE_PLATFORM_DID?.trim() || generateAgentKey().did;

if (liveUrl && !process.env.AGENT_MEDIATE_PLATFORM_DID?.trim()) {
  const probe = new AgentMediateClient({ baseUrl: liveUrl, agentKey: buyerKey });
  platformDid = (await probe.platform()).did;
}

// 1. Canonical contract hash via RFC 8785 JCS — key order does not matter!
const agreementFromBuyer = {
  service: "Realtime Search API",
  monthlyCapUsd: 500,
  p99LatencyMs: 250,
  parties: [buyerKey.did, sellerKey.did],
};
const agreementFromSeller = {
  parties: [buyerKey.did, sellerKey.did],
  p99LatencyMs: 250,
  monthlyCapUsd: 500,
  service: "Realtime Search API",
};

const hashA = contractHash(agreementFromBuyer);
const hashB = contractHash(agreementFromSeller);
if (hashA !== hashB) throw new Error("JCS contractHash mismatch");
console.log("Canonical RFC 8785 contractHash:", hashA);

// 2. Build and co-sign an agent-mediate/clause/v1 at contract formation time
const unsignedClause = buildClause({
  contract: agreementFromBuyer,
  platformDid,
  ...(liveUrl ? { platformBaseUrl: liveUrl } : {}),
  parties: [
    { agentId: buyerKey.did },
    { agentId: sellerKey.did },
  ],
  terms: {
    feeMode: "FILER_PAYS",
    determinationConsent: true,
    windows: { roundTimeoutMs: 600_000 },
  },
});

const buyerSigned = signClause(unsignedClause, buyerKey);
const coSignedClause = signClause(buyerSigned, sellerKey);

// 3. Verify offline before persisting with the contract
const verified = verifyClause(coSignedClause, {
  expectedPlatformDid: platformDid,
  expectedContractHash: hashA,
  claimantId: buyerKey.did,
  respondentId: sellerKey.did,
});
console.log("Offline clause verification:", verified);

// 4. Optional: file a dispute bound to the co-signed clause
if (liveUrl) {
  const buyer = new AgentMediateClient({
    baseUrl: liveUrl,
    agentKey: buyerKey,
    platformDid,
    defaultView: "compact",
  });
  const filed = await buyer.fileDispute({
    respondentId: sellerKey.did,
    contractHash: hashA,
    claim: {
      summary: "p99 latency exceeded 900ms for 3 hours on 2026-10-20.",
      requestedRemedy: "Service fee rebate.",
    },
    proposedIssues: [
      {
        id: "rebateUsd",
        label: "Latency SLA Rebate",
        unit: "USD",
        min: 0,
        max: 500,
        step: 10,
        claimantPrefers: "higher",
        obligor: "respondent",
      },
    ],
    bounds: { rebateUsd: { min: 100, max: 500 } },
    determinationConsent: true,
    config: { feeMode: "FILER_PAYS", roundTimeoutMs: 600_000 },
    clause: coSignedClause,
  });
  console.log("Filed under co-signed clause:", filed.disputeId, "nextActions:", filed.view.nextActions);
}
