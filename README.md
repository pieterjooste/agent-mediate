# Agent-Mediate — Open SDKs, MCP Server & Deterministic Mechanism

Neutral, zero-custody dispute resolution for autonomous AI agents. Two agents in a commercial or SLA dispute submit principal-bounded, sealed numerical offers; a deterministic mechanism ([docs/mechanism.md](docs/mechanism.md)) settles overlapping offers at the midpoint or proposes a fair split, returning an immutable `Ed25519Signature2026` settlement instruction or `UNRESOLVED` certificate while keeping confidential walkaways and issue weights private.

- **Human Web Portal & Browser Verifier:** https://ai-agents-mediation.com (verify signed outcomes locally at https://ai-agents-mediation.com/verify)
- **Production API & LLM Protocol Index:** https://api.ai-agents-mediation.com (`GET /llms.txt`, `GET /llms-full.txt`, `GET /openapi.json`)
- **Pinned Production Platform `did:key`:** `did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W`
- **Live Practice Counterparty Bot (`$0.00` test respondent):** `did:key:z6Mkn42ijWNFD285Ru7xAfVPtVB1LRpmGe5f649fDwxPEanY` (auto-accepts invites & settles 1–5 numeric issues in ~15 s; non-binding, zero custody)
- **Canonical Mechanism `RULES_HASH` (`v1.4.0`):** `10b48aa0d8a4a71808f5550f951ad128aa0af44b775b2c88c73ddb1dd1cee173`

---

## Published Packages (`Apache-2.0`)

Install directly from official **npm** or **PyPI** (never third-party MCP wrapper marketplaces):

| Package | Registry | Purpose |
|---|---|---|
| [`@agent-mediate/mcp`](packages/mcp) | [npm](https://www.npmjs.com/package/@agent-mediate/mcp) | Stdio Model Context Protocol server (`npx -y @agent-mediate/mcp`) with prompt-injection untrusted-text wrapping and principal mandate enforcement |
| [`@agent-mediate/sdk`](packages/sdk) | [npm](https://www.npmjs.com/package/@agent-mediate/sdk) | TypeScript client (Node 20+): RFC 9421 signing, idempotent retries, pre-dispute clauses, cold-start `$0.00` invites, x402 USDC payer, and outcome/audit verification |
| [`@agent-mediate/protocol`](packages/protocol) | [npm](https://www.npmjs.com/package/@agent-mediate/protocol) | Cryptographic wire primitives: `did:key`, `did:web`, JWKS, key-history rotation/revocation, RFC 9421 HTTP Message Signatures, mandates & clauses |
| [`@agent-mediate/core`](packages/core) | [npm](https://www.npmjs.com/package/@agent-mediate/core) | Pure deterministic state machine, bargaining/determination math, disclosure filter, RFC 8785 JCS `canonicalJson`, SHA-256 hash chains & RFC 6962 Merkle proofs |
| [`agent-mediate`](packages/python) | [PyPI](https://pypi.org/project/agent-mediate/) | Zero-dependency Python 3.9+ stdlib SDK with cross-language Ed25519, JCS, RFC 9421, mandate/clause, and client parity |

> **Local Coding Agents vs. Hosted Cloud Sandboxes:** Run real commercial mediations from local coding agents (**Antigravity**, **Claude Code**, **Cursor**, **Codex CLI**) or your own server so your Ed25519 private keys never leave your infrastructure. Hosted cloud chat sandboxes (e.g. Gemini Tasks) disable outbound internet and stdio MCP by default — use cloud VMs only with **ephemeral** keys for `$0.00` Practice Bot tests, or have them generate local setup commands for your machine.

---

## 60-Second Quickstart (`$0.00` Waived Launch Fees, Zero Wallet Setup)

1. **Test Against the Live Hosted Practice Bot (zero repo clone):** File any 1–5 numeric issue dispute (SLA credits, redelivery windows, invoice terms, API allowances, refunds) or `$0.00` invite naming `did:key:z6Mkn42ijWNFD285Ru7xAfVPtVB1LRpmGe5f649fDwxPEanY` as `respondentId` (also returned by `GET /v1/platform` -> `practiceBot.did`). It auto-joins, negotiates, and settles in ~15 seconds.
2. **Run a Local Practice Respondent:** `npm run build && node examples/practice-respondent.ts`
3. **2-Agent Cross-Language Demo (`<8s`):** `npm run build && node examples/e2e-sla-demo.ts` — Python (`agent-mediate`) buyer + TypeScript (`@agent-mediate/mcp`) vendor co-sign a clause, settle via sealed offers on `https://api.ai-agents-mediation.com`, and dual-verify the `Ed25519Signature2026` outcome (see [`examples/README.md`](examples/README.md)).
4. **AP2 + Stripe ACP Pre-Chargeback Adapter:** `npm run build && node examples/ap2-stripe-prechargeback.ts --offline` (or without `--offline` for live `$0.00` Mode A) — binds a Google AP2 Closed Payment Mandate + Stripe PaymentIntent via RFC 8785 JCS, settles an integrative cash + credit split, and executes an idempotent `POST /v1/refunds` after fail-closed `Ed25519Signature2026` verification.
5. **x402r + Coinbase AgentKit Escrow Adapter:** `npm run build && node examples/x402r-agentkit-escrow.ts --offline` (or without `--offline` for live `$0.00` Mode A) — binds an `x402r` `AuthCaptureEscrow` `PaymentInfo` via RFC 8785 JCS, negotiates a partial USDC refund + SLA patch window via an `AgentKit`-compatible `ActionProvider`, and verifies `Ed25519Signature2026` fail-closed before calling `refundInEscrow` + `releaseEscrow`.

### 1. MCP Server (Claude Desktop, Claude Code, Cursor, Antigravity)

```json
{
  "mcpServers": {
    "agent-mediate": {
      "command": "npx",
      "args": ["-y", "@agent-mediate/mcp"],
      "env": {
        "AGENT_MEDIATE_URL": "https://api.ai-agents-mediation.com",
        "AGENT_MEDIATE_PLATFORM_DID": "did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W",
        "AGENT_MEDIATE_AGENT_KEY_FILE": "./agent-ed25519.pem"
      }
    }
  }
}
```

### 2. TypeScript SDK (`npm install @agent-mediate/sdk`)

```ts
import {
  AgentMediateClient,
  contractHash,
  generateAgentKey,
} from "@agent-mediate/sdk";

const client = new AgentMediateClient({
  baseUrl: "https://api.ai-agents-mediation.com",
  agentKey: generateAgentKey(), // persist PEM locally in production
  platformDid: "did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W",
});

// File against the $0.00 Practice Bot -> closeEvidence -> confirmIssues -> submitOffer -> outcome
const { disputeId } = await client.fileDispute({
  respondentId: "did:key:z6Mkn42ijWNFD285Ru7xAfVPtVB1LRpmGe5f649fDwxPEanY",
  contractHash: contractHash({ orderId: "sla-demo-01", monthlyFeeUsd: 600 }),
  claim: {
    summary: "API unavailable for 42 minutes against a 99.9% monthly SLA.",
    requestedRemedy: "Pro-rata SLA service credit in USD.",
  },
  proposedIssues: [{
    id: "serviceCreditUsd",
    label: "SLA Service Credit",
    unit: "USD",
    min: 0,
    max: 600,
    step: 10,
    claimantPrefers: "higher",
    obligor: "respondent",
  }],
  bounds: { serviceCreditUsd: { min: 150, max: 600 } },
  determinationConsent: true,
});

await client.waitFor(disputeId, (v) => v.status === "EVIDENCE");
await client.closeEvidence(disputeId);

const { view: ic } = await client.waitFor(disputeId, (v) => Boolean(v.issueNegotiation.proposedHash));
await client.confirmIssues(disputeId, ic.issueNegotiation.proposedHash!);

await client.waitFor(disputeId, (v) => v.status === "BARGAINING");
await client.submitOffer(disputeId, 1, {
  offer: { serviceCreditUsd: 300 },
  private: { weights: { serviceCreditUsd: 1 }, walkaway: { serviceCreditUsd: 200 } },
});

const r2 = await client.waitForTurn(disputeId);
if (r2.view.status === "BARGAINING" && r2.view.proposalWithinYourMandate) {
  await client.submitOffer(disputeId, 2, { offer: { serviceCreditUsd: 260 }, proposalResponse: "accept" });
}

const exec = await client.waitFor(
  disputeId,
  (v) => v.status !== "BARGAINING" && (v.status !== "EXECUTION_PENDING" || Boolean(v.execution?.proofs.respondent)),
);
if (exec.view.status === "EXECUTION_PENDING") await client.confirmExecution(disputeId);
const signedOutcome = await client.outcome(disputeId);
```

### 3. Python SDK (`pip install agent-mediate`)

```python
from agent_mediate import AgentKey, AgentMediateClient, contract_hash

client = AgentMediateClient(
    base_url="https://api.ai-agents-mediation.com",
    agent_key=AgentKey.generate(),  # persist PEM locally in production
    platform_did="did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W",
)

filed = client.file_dispute(
    respondent_id="did:key:z6Mkn42ijWNFD285Ru7xAfVPtVB1LRpmGe5f649fDwxPEanY",
    contract_hash=contract_hash({"orderId": "sla-demo-01", "monthlyFeeUsd": 600}),
    claim={
        "summary": "API unavailable for 42 minutes against a 99.9% monthly SLA.",
        "requestedRemedy": "Pro-rata SLA service credit in USD.",
    },
    proposed_issues=[{
        "id": "serviceCreditUsd",
        "label": "SLA Service Credit",
        "unit": "USD",
        "min": 0,
        "max": 600,
        "step": 10,
        "claimantPrefers": "higher",
        "obligor": "respondent",
    }],
    bounds={"serviceCreditUsd": {"min": 150, "max": 600}},
    determination_consent=True,
)
dispute_id = filed["disputeId"]

client.wait_for(dispute_id, lambda v: v["status"] == "EVIDENCE")
client.close_evidence(dispute_id)

ic = client.wait_for(dispute_id, lambda v: bool(v["issueNegotiation"]["proposedHash"]))
client.confirm_issues(dispute_id, ic["view"]["issueNegotiation"]["proposedHash"])

client.wait_for(dispute_id, lambda v: v["status"] == "BARGAINING")
client.submit_offer(
    dispute_id,
    1,
    offer={"serviceCreditUsd": 300},
    private={"weights": {"serviceCreditUsd": 1}, "walkaway": {"serviceCreditUsd": 200}},
)

r2 = client.wait_for_turn(dispute_id)
if r2["view"]["status"] == "BARGAINING" and r2["view"].get("proposalWithinYourMandate"):
    client.submit_offer(dispute_id, 2, offer={"serviceCreditUsd": 260}, proposal_response="accept")

exec_res = client.wait_for(
    dispute_id,
    lambda v: v["status"] != "BARGAINING"
    and (v["status"] != "EXECUTION_PENDING" or bool((v.get("execution") or {}).get("proofs", {}).get("respondent"))),
)
if exec_res["view"]["status"] == "EXECUTION_PENDING":
    client.confirm_execution(dispute_id)
print("Verified outcome:", client.outcome(dispute_id)["document"]["terms"])
```

---

## Repository Layout

```
packages/core/          Pure deterministic bargaining & verifiability engine (zero dependencies, zero I/O)
packages/protocol/      did:key, did:web, JWKS, key-history, RFC 9421, mandates & pre-dispute clauses
packages/sdk/           TypeScript client SDK & x402 EIP-3009 USDC payer
packages/mcp/           Model Context Protocol stdio server + MCP Registry server.json
packages/python/        Zero-dependency Python 3.9+ SDK (agent-mediate on PyPI)
skills/agent-mediate/   Portable Agent Skill (SKILL.md) for Claude Code, Cursor, Codex & Antigravity
examples/               Runnable TypeScript & Python adapters (AP2/Stripe ACP, x402r/AgentKit), quickstarts, clauses & webhook receiver
testdata/               Cross-language JCS, Ed25519, RFC 9421, and Merkle conformance vectors
docs/mechanism.md       Formal mathematical mechanism specification (RULES_VERSION 1.4.0)
```

---

## Local Verification

```sh
npm ci --ignore-scripts
npm run check
```

## License

Apache License 2.0 — see [LICENSE](LICENSE) and [NOTICE](NOTICE).
