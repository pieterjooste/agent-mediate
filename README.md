# Agent-Mediate — Open SDKs, MCP Server & Deterministic Mechanism

Neutral, zero-custody dispute resolution for autonomous AI agents. Two agents in a commercial or SLA dispute submit principal-bounded, sealed numerical offers; a deterministic mechanism ([docs/mechanism.md](docs/mechanism.md)) settles overlapping offers at the midpoint or proposes a fair split, returning an immutable `Ed25519Signature2026` settlement instruction or `UNRESOLVED` certificate while keeping confidential walkaways and issue weights private.

- **Human Web Portal & Browser Verifier:** https://ai-agents-mediation.com (verify signed outcomes locally at https://ai-agents-mediation.com/verify)
- **Production API & LLM Protocol Index:** https://api.ai-agents-mediation.com (`GET /llms.txt`, `GET /llms-full.txt`, `GET /openapi.json`)
- **Pinned Production Platform `did:key`:** `did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W`
- **Canonical Mechanism `RULES_HASH` (`v1.3.0`):** `8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4`

---

## Published Packages (`Apache-2.0`)

| Package | Ecosystem | Purpose |
|---|---|---|
| [`@agent-mediate/mcp`](packages/mcp) | npm / MCP | Stdio Model Context Protocol server (`npx -y @agent-mediate/mcp`) with prompt-injection untrusted-text wrapping and principal mandate enforcement |
| [`@agent-mediate/sdk`](packages/sdk) | npm (Node 20+) | TypeScript client: RFC 9421 signing, idempotent retries, pre-dispute clauses, cold-start `$0.00` invites, x402 USDC payer, and outcome/audit verification |
| [`@agent-mediate/protocol`](packages/protocol) | npm (Node 20+) | Cryptographic wire primitives: `did:key`, `did:web`, JWKS, key-history rotation/revocation, RFC 9421 HTTP Message Signatures, mandates & clauses |
| [`@agent-mediate/core`](packages/core) | npm (Zero deps) | Pure deterministic state machine, bargaining/determination math, disclosure filter, RFC 8785 JCS `canonicalJson`, SHA-256 hash chains & RFC 6962 Merkle proofs |
| [`agent-mediate`](packages/python) | PyPI (Python 3.9+) | Zero-dependency Python stdlib SDK with cross-language Ed25519, JCS, RFC 9421, mandate/clause, and client parity |

---

## 60-Second Quickstart

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
  signMandate,
} from "@agent-mediate/sdk";

const agentKey = generateAgentKey();
const principalKey = generateAgentKey();

const client = new AgentMediateClient({
  baseUrl: "https://api.ai-agents-mediation.com",
  agentKey,
  platformDid: "did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W",
  defaultView: "compact",
});

const cHash = contractHash({ service: "Inference API", monthlyFeeUsd: 1000, uptimeSla: 0.999 });
const mandate = signMandate(
  {
    id: "mnd_01",
    principalId: principalKey.did,
    agentId: agentKey.did,
    bounds: { refundUsd: { min: 0, max: 800 } },
    issuedAt: Date.now(),
    expiresAt: Date.now() + 7 * 86_400_000,
  },
  principalKey,
);
```

### 3. Python SDK (`pip install agent-mediate`)

```python
from agent_mediate import AgentMediateClient, contract_hash, generate_agent_key

client = AgentMediateClient(
    base_url="https://api.ai-agents-mediation.com",
    agent_key=generate_agent_key(),
    default_view="compact",
)
print(client.platform())
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
examples/               Runnable TypeScript & Python quickstarts, clauses, and webhook receiver
testdata/               Cross-language JCS, Ed25519, RFC 9421, and Merkle conformance vectors
docs/mechanism.md       Formal mathematical mechanism specification (RULES_VERSION 1.3.0)
```

---

## Local Verification

```sh
npm ci --ignore-scripts
npm run check
```

## License

Apache License 2.0 — see [LICENSE](LICENSE).
