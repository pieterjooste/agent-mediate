/**
 * Respondent quickstart: register standing notification channels, discover open
 * disputes addressed to your DID, join, confirm issues, bargain within mandate
 * bounds, submit execution proof, and verify the signed outcome.
 *
 * Run against a local API (`npm run dev`):
 *   node examples/quickstart-respondent.ts
 */
import {
  AgentMediateClient,
  agentKeyFromPem,
  generateAgentKey,
} from "@agent-mediate/sdk";

const baseUrl = process.env.AGENT_MEDIATE_URL ?? "http://localhost:8080";
const key = process.env.RESPONDENT_PRIVATE_KEY
  ? agentKeyFromPem(process.env.RESPONDENT_PRIVATE_KEY)
  : generateAgentKey();

const client = new AgentMediateClient({
  baseUrl,
  agentKey: key,
  ...(process.env.AGENT_MEDIATE_PLATFORM_DID
    ? { platformDid: process.env.AGENT_MEDIATE_PLATFORM_DID }
    : {}),
});

console.log(`Respondent DID: ${client.did}`);

// Register standing notification settings so claimants reach us automatically.
if (process.env.RESPONDENT_WEBHOOK_URL || process.env.RESPONDENT_EMAIL) {
  const settings = await client.registerNotifications({
    ...(process.env.RESPONDENT_WEBHOOK_URL ? { webhookUrl: process.env.RESPONDENT_WEBHOOK_URL } : {}),
    ...(process.env.RESPONDENT_EMAIL ? { email: process.env.RESPONDENT_EMAIL } : {}),
  });
  console.log("Registered notification channels:", settings);
}

let { disputes } = await client.listDisputes({
  role: "respondent",
  status: "AWAITING_RESPONDENT",
});

if (disputes.length === 0) {
  if (process.env.ONCE === "1") {
    console.log("No pending disputes found. Pass RESPONDENT_DID=" + client.did + " to examples/quickstart-claimant.ts.");
    process.exit(0);
  }
  console.log(
    `Pass RESPONDENT_DID=${client.did} to examples/quickstart-claimant.ts in a second terminal — polling for incoming dispute...`,
  );
  const deadline = Date.now() + 5 * 60_000;
  while (disputes.length === 0 && Date.now() < deadline) {
    await new Promise((r) => setTimeout(r, 1500));
    ({ disputes } = await client.listDisputes({
      role: "respondent",
      status: "AWAITING_RESPONDENT",
    }));
  }
  if (disputes.length === 0) {
    console.log("Timed out waiting for an incoming dispute.");
    process.exit(0);
  }
}

const target = disputes[0]!;
const disputeId = target.disputeId;
console.log(`Joining dispute ${disputeId} from counterpart ${target.counterpartId}...`);

await client.join(disputeId, {
  bounds: { refundUsd: { min: 0, max: 650 } },
  determinationConsent: true,
});

await client.submitEvidence(disputeId, [
  {
    id: "incident-postmortem",
    kind: "report",
    description: "Gateway maintenance log confirming 47m regional failover delay",
    content: "Incident INC-2041: 47m degraded routing during upstream failover",
  },
]);
await client.closeEvidence(disputeId);

const issuePhase = await client.waitForTurn(disputeId);
const proposedHash = issuePhase.view.issueNegotiation.proposedHash;
if (!proposedHash) throw new Error("Expected proposedHash in ISSUE_CONFIRMATION");
await client.confirmIssues(disputeId, proposedHash);

await client.waitForTurn(disputeId);
await client.submitOffer(disputeId, 1, {
  offer: { refundUsd: 300 },
  private: { weights: { refundUsd: 1 }, walkaway: { refundUsd: 600 } },
});

const afterR1 = await client.waitForTurn(disputeId);
if (afterR1.view.status === "BARGAINING" && afterR1.view.proposalWithinYourMandate) {
  await client.submitOffer(disputeId, 2, {
    offer: { refundUsd: 550 },
    proposalResponse: "accept",
  });
}

const settled = await client.waitFor(disputeId, (v) => v.status !== "BARGAINING");
console.log("Agreed settlement terms:", settled.view.outcome);

// Submit on-chain / payment settlement reference as execution proof
if (settled.view.status === "EXECUTION_PENDING" && settled.view.execution?.proofs.respondent === null) {
  await client.submitExecutionProof(disputeId, "0x" + "ab".repeat(32));
}
const done = await client.waitFor(
  disputeId,
  (v) => v.status === "HONORED" || v.status === "BREACH_REPORTED" || v.status === "UNRESOLVED",
);
console.log("Final status:", done.view.status);

const outcome = await client.outcome(disputeId);
const audit = await client.audit(disputeId, { expectedOutcome: outcome });
console.log("Verified audit head:", audit.head);
console.log("Verified signed outcome:", JSON.stringify(outcome, null, 2));
