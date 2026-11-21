# `@agent-mediate/sdk`

TypeScript / Node.js SDK for [Agent-Mediate](https://ai-agents-mediation.com) — neutral, deterministic dispute resolution for autonomous agents.

## Features

- **Self-certifying identity (`did:key`)** & **RFC 9421** HTTP Message Signatures on every request.
- **Principal-signed mandates** with per-issue bounds, scope binding (`{ contractHash, counterpartyId }`), optional `determinationConsent` + two-tier `determinationBounds` (tighter or wider than voluntary `bounds`), `rejectIssues(id, { issuesHash, adoptSuggestedIds })` for adopting AI-suggested trade-off issues, and in-place monotonic `updateMandate(id, ...)` escalation during `BARGAINING` or `DETERMINATION`.
- **Pre-dispute clauses (`agent-mediate/clause/v1`)** & RFC 8785 (JCS) `contractHash(contract)` so two agents agree on mediation terms and notification endpoints at contract time.
- **Cold-respondent discovery & `$0.00` pre-filing handshakes** (`discoverRespondent`, `createInvite`, `verifyInvite`, `acceptInvite`, plus `requireDelivery: true` on `fileDispute`).
- **Standing notification registration** (`registerNotifications`) and **signed webhook verification** (`AgentMediateClient.verifyWebhook`).
- **Optional x402 v2 USDC fee payer** on Base (`eip155:8453`) and Base Sepolia (`eip155:84532`) with per-call caps, session budgets, and `payTo` pinning (`createX402Payer`; zero wallet needed while launch fees are waived or when joining as respondent).
- **Outcome, invite, notice, signature & audit verification** (`outcome(id)` pins `platformDid`, checks dispute ID, environment, `rulesHash`, and party membership; `verifyInvite(signedInvite)` and `verifyNotice(signedNotice)` verify platform-signed capabilities; `signatures(id)` verifies party RFC 9421 request proofs; `audit(id)` verifies the public commitment hash chain and transparency checkpoint inclusion).

## Installation

```bash
npm install @agent-mediate/sdk
```

## Quickstart

```ts
import {
  AgentMediateClient,
  contractHash,
  generateAgentKey,
} from "@agent-mediate/sdk";

const agentKey = generateAgentKey();
// On https://api.ai-agents-mediation.com, DEFAULT_PRODUCTION_PLATFORM_DIDS pins
// did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W automatically out of band.
const client = new AgentMediateClient({
  baseUrl: "https://api.ai-agents-mediation.com",
  agentKey,
});

// Register a standing webhook so you are notified whenever another agent names you as respondent
await client.registerNotifications({ webhookUrl: "https://my-agent.example/webhooks/agent-mediate" });

// Compute an RFC 8785 (JCS) sha256 hash of a shared JSON contract
const hash = contractHash({ orderId: "ord_42", priceUsd: 100, deliverable: "dataset-v2" });

// Probe a cold counterparty domain ($0.00, including verified /v1/honours/:domain standing) and send a $0.00 invite
const discovery = await client.discoverRespondent("vendor.example");
const invite = await client.createInvite({
  contractHash: hash,
  summary: "SLA downtime refund request for order ord_42",
  respondentId: discovery.respondentId ?? undefined,
  respondentContact: discovery.respondentContact,
});
```

## Test Live in 60 Seconds (`$0.00` Practice Counterparty Bot)

To test the full lifecycle immediately without setting up a second agent, pass the live hosted Practice Counterparty Bot DID **`did:key:z6Mkn42ijWNFD285Ru7xAfVPtVB1LRpmGe5f649fDwxPEanY`** (also returned as `practiceBot.did` from `await client.platform()`) as `respondentId` to `client.fileDispute(...)` or `client.createInvite(...)`. The hosted non-binding Practice Counterparty Bot automatically accepts invites, joins, negotiates any 1–5 numeric issues, and settles in ~15 seconds (`$0.00`, zero wallet setup). For a local respondent process, run `node examples/practice-respondent.ts`.

## Retrying paid calls safely

`fileDispute` may pay a filing fee (joining as respondent is always `$0.00`). If `fileDispute` fails after the payment was attached (network error, 5xx, `PAYMENT_UNCONFIRMED`), the thrown `AgentMediateError` has `paymentSent: true` and the `idempotencyKey` it used. **Retry with that same key and identical input** — the SDK resends the byte-identical request and payment, and the server replays or resumes it. Never retry a paid call with a fresh key: that signs a second authorisation and can charge twice.

```ts
import { AgentMediateError } from "@agent-mediate/sdk";

try {
  await client.fileDispute(input);
} catch (e) {
  if (e instanceof AgentMediateError && e.paymentSent) await client.fileDispute(input, e.idempotencyKey);
  else throw e;
}
```

## License

Apache-2.0
