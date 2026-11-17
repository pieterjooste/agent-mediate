/**
 * Claimant quickstart: file a dispute, share the respondent notice link, negotiate
 * sealed offers, confirm execution, and verify the platform-signed outcome.
 *
 * Run against a local API (`npm run dev`):
 *   RESPONDENT_DID=did:key:z6Mk... node examples/quickstart-claimant.ts
 */
import {
  AgentMediateClient,
  agentKeyFromPem,
  contractHash,
  generateAgentKey,
} from "@agent-mediate/sdk";

const baseUrl = process.env.AGENT_MEDIATE_URL ?? "http://localhost:8080";
const key = process.env.AGENT_PRIVATE_KEY
  ? agentKeyFromPem(process.env.AGENT_PRIVATE_KEY)
  : generateAgentKey();

const client = new AgentMediateClient({
  baseUrl,
  agentKey: key,
  ...(process.env.AGENT_MEDIATE_PLATFORM_DID
    ? { platformDid: process.env.AGENT_MEDIATE_PLATFORM_DID }
    : {}),
});

console.log(`Claimant DID: ${client.did}`);

const respondentId = process.env.RESPONDENT_DID ?? generateAgentKey().did;
const slaContract = {
  service: "Inference Gateway v2",
  monthlyFeeUsd: 1000,
  uptimeSla: 0.999,
};

const filed = await client.fileDispute({
  respondentId,
  contractHash: contractHash(slaContract),
  claim: {
    summary: "API unavailable for 47 minutes on 2026-10-12 against a 99.9% monthly SLA.",
    requestedRemedy: "Pro-rata SLA service credit / refund in USD.",
  },
  proposedIssues: [
    {
      id: "refundUsd",
      label: "SLA Downtime Refund",
      unit: "USD",
      min: 0,
      max: 1000,
      step: 10,
      claimantPrefers: "higher",
      obligor: "respondent",
    },
  ],
  bounds: { refundUsd: { min: 250, max: 1000 } },
  determinationConsent: true,
});

const { disputeId } = filed;
console.log(`Filed dispute: ${disputeId}`);
if (filed.notice) {
  console.log(`Shareable respondent notice URL: ${filed.notice.noticeUrl}`);
  console.log(
    `Notice delivery method: ${filed.notice.delivery.method} (delivered=${filed.notice.delivery.delivered}, verifiedEndpoint=${filed.notice.delivery.verifiedEndpoint})`,
  );
}

if (!process.env.RESPONDENT_DID) {
  console.log("Set RESPONDENT_DID and run examples/quickstart-respondent.ts in a second terminal to complete live negotiation.");
  process.exit(0);
}

console.log("Waiting for respondent to join...");
await client.waitForTurn(disputeId);

await client.submitEvidence(disputeId, [
  {
    id: "uptime-probe-log",
    kind: "log",
    description: "External probe log showing 47 consecutive minutes of HTTP 503 responses",
    content: "2026-10-12T14:00Z..14:47Z status=503 probes=47/47 failed",
  },
]);
await client.closeEvidence(disputeId);

const issuePhase = await client.waitForTurn(disputeId);
const proposedHash = issuePhase.view.issueNegotiation.proposedHash;
if (!proposedHash) throw new Error("Expected proposedHash in ISSUE_CONFIRMATION");
await client.confirmIssues(disputeId, proposedHash);

await client.waitForTurn(disputeId);
await client.submitOffer(disputeId, 1, {
  offer: { refundUsd: 750 },
  private: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 350 } },
});

const afterR1 = await client.waitForTurn(disputeId);
if (afterR1.view.status === "BARGAINING" && afterR1.view.proposalWithinYourMandate) {
  await client.submitOffer(disputeId, 2, {
    offer: { refundUsd: 550 },
    proposalResponse: "accept",
  });
}

const exec = await client.waitFor(
  disputeId,
  (v) => v.status !== "BARGAINING" && (v.status !== "EXECUTION_PENDING" || v.execution?.proofs.respondent !== null),
);
if (exec.view.status === "EXECUTION_PENDING" && exec.view.execution?.confirmed.claimant === null) {
  await client.confirmExecution(disputeId);
}

const outcome = await client.outcome(disputeId);
const audit = await client.audit(disputeId, { expectedOutcome: outcome });
console.log("Verified audit head:", audit.head);
console.log("Verified signed outcome:", JSON.stringify(outcome, null, 2));
