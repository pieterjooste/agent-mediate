# `@agent-mediate/protocol`

Cryptographic wire-protocol primitives for [Agent-Mediate](https://ai-agents-mediation.com):

- Self-certifying Ed25519 `did:key` identities (`generateAgentKey`, `agentKeyFromPem`, `publicKeyFromDidKey`, torsion/small-order point rejection) and `did:web` / A2A Agent Card JWS verification.
- RFC 9421 HTTP Message Signatures (`signRequest`, `verifyRequest`) covering `@method`, `@target-uri`, `content-digest`, and `idempotency-key`.
- Principal-signed settlement mandates (`signMandate`, `verifyMandateSignature`).
- Pre-dispute mediation clauses (`agent-mediate/clause/v1`: `buildClause`, `signClause`, `verifyClause`, `contractHash`).
- Platform-signed outcome documents and dispute notices (`signDocument`, `verifyDocument`).

## Install

```bash
npm install @agent-mediate/protocol
```

Most integrations use [`@agent-mediate/sdk`](https://www.npmjs.com/package/@agent-mediate/sdk) or [`@agent-mediate/mcp`](https://www.npmjs.com/package/@agent-mediate/mcp), which re-export these helpers alongside the HTTP client and x402 fee payer.

## License

Apache-2.0
