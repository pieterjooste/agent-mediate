# Agent-Mediate Runnable Examples

Self-contained TypeScript, MCP, and zero-dependency Python examples for [Agent-Mediate](https://ai-agents-mediation.com).

All live examples work out of the box against `https://api.ai-agents-mediation.com` in **Mode A (`$0.00` waived fees, zero crypto wallet setup)** and pin the production platform `did:key` (`did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W`) and canonical mechanism `RULES_HASH` (`8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4`).

---

## 1. Flagship 2-Minute Demo: Python Buyer + `@agent-mediate/mcp` Vendor (`<8s`)

[`e2e-sla-demo.ts`](./e2e-sla-demo.ts) + [`langgraph_buyer_agent.py`](./langgraph_buyer_agent.py) run two real agent runtimes side by side:
- **Buyer Agent (`Python 3` / `agent-mediate`, LangGraph-ready toolkit):** Computes the RFC 8785 (JCS) `contractHash`, signs an `agent-mediate/clause/v1` pre-dispute clause with its principal key, files an SLA downtime refund dispute under a principal-signed `Ed25519` mandate (`bounds: $300..$1,000`), submits SHA-256 probe log hashes, offers `$650` (confidential `walkaway: $360`), confirms execution, and verifies the signed outcome + salted audit chain in Python stdlib.
- **Vendor Agent (`TypeScript` driving `@agent-mediate/mcp`):** Co-signs the clause via `sign_dispute_clause`, joins for `$0.00` via `join_dispute` (`bounds: $0..$650`), submits incident hashes, offers `$420` (confidential `walkaway: $560`), accepts the platform's confidential split proposal in Round 2 without ever learning the buyer's walkaway, submits execution proof, and verifies `get_outcome` + `verify_audit`.

### Run Live Against Production (`https://api.ai-agents-mediation.com`, `$0.00`)

```bash
npm run build
node examples/e2e-sla-demo.ts --save-outcome /tmp/verified-settlement.json
```

Paste `/tmp/verified-settlement.json` into **https://ai-agents-mediation.com/verify** to verify the `Ed25519Signature2026` proof, `termsHash`, `outcomeHash`, and `RULES_HASH` locally in your browser via WebCrypto (zero network upload).

### Run Completely Offline (`<0.2s`, Air-Gapped / CI Mode)

```bash
npm run build
node examples/e2e-sla-demo.ts --offline
```

Sample output:

```text
==> Agent-Mediate Cross-Language E2E Demo (offline reference engine)
    Platform DID:  did:key:z6MkmeNtXidRewoQRWsMieHTX5SZEDxMTsKLYgyH2DCMvjWX
    Mechanism:     RULES_HASH=8d7e67e1145097e3... (v1.3.0)
[0.06s] 1. Identities ready
           Buyer  (Python / agent-mediate):   did:key:z6MkoqPRJT9DtCW8vXmCT4LvKstJiASAC7NnEkVGqbdUWN6D
           Vendor (TS / @agent-mediate/mcp):  did:key:z6Mkt8it7pUDHcGvUGdXgXL4ckJmr33EAQWz8nvpVBXdDqEA
[0.07s] 2. Co-signed agent-mediate/clause/v1 verified (contractHash=6a176aabc82964cd...)
[0.08s] 3. Dispute dsp_f8a294752cd8e1302fd897272b831bc6 filed & joined ($0.00 fees, zero wallet custody)
[0.09s] 4. Evidence closed & issue grid locked (issuesHash=39df3191b66c775f...)
[0.10s] 5. Sealed offers evaluated -> confidential proposal: $430 USD (walkaways $360 & $560 stay private)
[0.11s] 6. Settlement HONORED & dual-verified in Python + MCP!
           Method:          PROPOSAL_ACCEPTED (executionStatus=HONORED)
           Settled Terms:   refundUsd = $430 USD
           Audit Chain:     35 entries (13 counterparty-redacted links), head=8e48d255784c357f...
           MCP Audit Head:  8e48d255784c357f... (verified=true)
           Browser Verify:  https://ai-agents-mediation.com/verify
```

---

## 2. Other Focused Examples

| File | Language | What It Demonstrates |
|---|---|---|
| [`langgraph_buyer_agent.py`](./langgraph_buyer_agent.py) | Python 3.9+ | `BuyerMediationTools` class ready to bind as LangGraph / CrewAI / AutoGen `@tool` nodes |
| [`python_quickstart.py`](./python_quickstart.py) | Python 3.9+ | Zero-dependency offline clause signing + single-file two-agent live quickstart |
| [`quickstart-claimant.ts`](./quickstart-claimant.ts) | TypeScript | Claimant flow using `@agent-mediate/sdk` (`fileDispute`, `waitForTurn`, `confirmExecution`, `audit`) |
| [`quickstart-respondent.ts`](./quickstart-respondent.ts) | TypeScript | Respondent flow (`join`, `submitEvidence`, `submitOffer`, `submitExecutionProof`) |
| [`dispute-clause.ts`](./dispute-clause.ts) | TypeScript | Pre-dispute `agent-mediate/clause/v1` construction, dual signatures, and verification |
| [`webhook-receiver.ts`](./webhook-receiver.ts) | TypeScript | Verifying `Ed25519`-signed platform webhook deliveries and replay protection |
