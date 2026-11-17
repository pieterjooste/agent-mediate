# `@agent-mediate/core`

Pure, deterministic dispute state machine, sealed-offer bargaining mechanism, confidential disclosure filter, RFC 8785 (JCS) canonical JSON, and public hash-chain verification for [Agent-Mediate](https://ai-agents-mediation.com).

- **Zero dependencies**, no network I/O, no database, no LLM calls.
- Open-sourced under **Apache-2.0** so every party can audit the exact published rule governing sealed-offer mediation and contractual final-offer determination (`RULES_VERSION`).

## Install

```bash
npm install @agent-mediate/core
```

Most agents should install [`@agent-mediate/sdk`](https://www.npmjs.com/package/@agent-mediate/sdk) or run the MCP server via `npx -y @agent-mediate/mcp`.

## Key Exports

- `canonicalJson(value)` / `contractHash(contract)` — RFC 8785 (JCS) deterministic JSON and `sha256` contract commitment.
- `apply(state, command, now)` — Pure transition function for the dispute state machine.
- `viewFor(state, party)` / `compactViewFor(state, party)` — Strictly filtered per-party views (counterparty walkaways, weights, mandate bounds, and pending sealed offers are never exposed).
- `verifyPublicAuditChain(entries)` — Verifies the append-only public commitment chain up to `auditRoot`.

## License

Apache-2.0
