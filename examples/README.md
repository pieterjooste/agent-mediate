# Agent-Mediate Runnable Examples

Self-contained TypeScript, MCP, and zero-dependency Python examples for [Agent-Mediate](https://ai-agents-mediation.com).

All live examples work out of the box against `https://api.ai-agents-mediation.com` in **Mode A (`$0.00` waived fees, zero crypto wallet setup)** and pin the production platform `did:key` (`did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W`) and canonical mechanism `RULES_HASH` (`10b48aa0d8a4a71808f5550f951ad128aa0af44b775b2c88c73ddb1dd1cee173`, `v1.4.0`).

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

## 2. Zero-Crypto Pre-Chargeback Adapter: Google AP2 + Stripe ACP (`ap2-stripe-prechargeback.ts`)

[`ap2-stripe-prechargeback.ts`](./ap2-stripe-prechargeback.ts) is a copy-paste-ready TypeScript reference adapter and runnable end-to-end demo for commerce platforms using **Google AP2 Closed Payment Mandates (`vct: "mandate.payment.1"`)** and **Stripe ACP CheckoutSessions / PaymentIntents**:

- **Deterministic contract binding (`deriveAp2ContractHash`):** Hashes the AP2 `transaction_id`, `payee`, `payment_amount`, `payment_instrument`, and Stripe `checkoutSessionId`/`paymentIntentId` via RFC 8785 (JCS) into Agent-Mediate's `contractHash`.
- **Integrative multi-issue split (`refundCents` + `storeCreditCents`):** Resolves a `$500.00` SLA/partial-fulfillment dispute into a win-win partial cash refund + merchant account credit in `<10 s` (avoiding a `$15–$25` card chargeback fee and 30–90 day hold) while keeping both parties' walkaways and margin weights private.
- **Fail-closed Stripe execution (`verifySettlementForStripeRefund` + `executeVerifiedStripeRefund`):** Verifies the `Ed25519Signature2026` proof against the pinned `platformDid`, `RULES_HASH`, AP2 `contractHash`, `termsHash`, `outcomeHash`, and `refundCents <= payment_amount.amount` before calling `POST /v1/refunds` with a deterministic `Idempotency-Key: agent-mediate-refund:<disputeId>`.
- **Unresolved fallback (`buildChargebackEvidenceBundle`):** Packages the platform-signed `UNRESOLVED` certificate, audit root, AP2 Payment Mandate, and Stripe IDs if a dispute must escalate to a PSP/card chargeback.

```bash
# Run offline (<0.2s, zero network calls, mock Stripe endpoint):
npm run build && node examples/ap2-stripe-prechargeback.ts --offline

# Run live against https://api.ai-agents-mediation.com ($0.00 Mode A, zero crypto wallet):
node examples/ap2-stripe-prechargeback.ts --save-outcome /tmp/ap2-stripe-settlement.json
```

---

## 3. x402r (`AuthCaptureEscrow`) + Coinbase AgentKit Adapter (`x402r-agentkit-escrow.ts`)

[`x402r-agentkit-escrow.ts`](./x402r-agentkit-escrow.ts) is a copy-paste-ready TypeScript reference adapter and runnable end-to-end demo for **x402r refundable stablecoin escrows (`AuthCaptureEscrow`)** and **Coinbase AgentKit** wallets:

- **Deterministic `PaymentInfo` binding (`validateX402rPaymentInfo` + `deriveX402rContractHash`):** Validates `preApprovalExpiry <= authorizationExpiry <= refundExpiry`, `0 <= minFeeBps <= maxFeeBps <= 10000`, valid EVM addresses, and `0 < capturedAmount <= maxAmount <= uint120`, then hashes the normalized `PaymentInfo` + `escrowAddress` + `captureTxHash` via RFC 8785 (JCS) into Agent-Mediate's `contractHash`.
- **Integrative multi-issue split (`refundMicroUsdc` + `remediationHours`):** Replaces blunt `0% / 100%` binary slashing with a confidential partial USDC refund (6-decimal integer atomic units) paired with an SLA remediation window, without exposing either party's walkaways or weights.
- **Fail-closed escrow split (`verifySettlementForX402rEscrow` + `executeVerifiedX402rSettlement`):** Verifies the `Ed25519Signature2026` proof against the pinned `platformDid`, `RULES_HASH`, `PaymentInfo` `contractHash`, `termsHash`, `outcomeHash`, `refundExpiry`, and BigInt balance conservation (`refundAmountAtomic + merchantReleaseAtomic === capturedAmountAtomic`) before invoking `refundInEscrow` and `releaseEscrow` idempotently.
- **Zero-dependency Coinbase AgentKit `ActionProvider` (`createAgentKitX402rProvider`):** Exposes `mediate_x402r_escrow_dispute`, `verify_x402r_settlement_instruction`, and `settle_x402r_escrow_from_outcome` with EVM/Base network gating and wallet-to-`PaymentInfo.payer` binding checks.

```bash
# Run offline (<0.2s, zero network calls, simulated AuthCaptureEscrow):
npm run build && node examples/x402r-agentkit-escrow.ts --offline

# Run live against https://api.ai-agents-mediation.com ($0.00 Mode A, zero platform custody):
node examples/x402r-agentkit-escrow.ts --save-outcome /tmp/x402r-escrow-settlement.json
```

---

## 4. Practice Counterparty Bot (Test Your Own Agent in 60 Seconds, `$0.00`)

- **Hosted Cloud Bot (no repo clone):** Use `did:key:z6Mkn42ijWNFD285Ru7xAfVPtVB1LRpmGe5f649fDwxPEanY` (also returned as `practiceBot.did` from `GET https://api.ai-agents-mediation.com/v1/platform` and copyable from https://ai-agents-mediation.com). File any 1–5 numeric issue dispute or `$0.00` pre-filing invite naming it as `respondentId` and it will automatically join, negotiate, settle, and submit simulated execution proof in ~15 seconds.
- **Local CLI Bot ([`practice-respondent.ts`](./practice-respondent.ts)):** Run a local respondent process that prints its fresh `did:key` and mediates any dispute sent to it (supports `--invite <token>` and `--once`):

```bash
npm run build
node examples/practice-respondent.ts
```

---

## 5. Other Focused Examples

| File | Language | What It Demonstrates |
|---|---|---|
| [`ap2-stripe-prechargeback.ts`](./ap2-stripe-prechargeback.ts) | TypeScript | Zero-crypto Google AP2 (`mandate.payment.1`) + Stripe ACP pre-chargeback adapter with fail-closed Ed25519 refund verification & idempotent `POST /v1/refunds` |
| [`x402r-agentkit-escrow.ts`](./x402r-agentkit-escrow.ts) | TypeScript | `x402r` `AuthCaptureEscrow` + Coinbase `AgentKit` `ActionProvider` adapter with fail-closed Ed25519 verification & atomic BigInt `refundInEscrow`/`releaseEscrow` splits |
| [`practice-respondent.ts`](./practice-respondent.ts) | TypeScript | Local polling Practice Counterparty Bot: accepts `--invite <token>` and auto-mediates any 1–5 numeric issues |
| [`langgraph_buyer_agent.py`](./langgraph_buyer_agent.py) | Python 3.9+ | `BuyerMediationTools` class ready to bind as LangGraph / CrewAI / AutoGen `@tool` nodes |
| [`python_quickstart.py`](./python_quickstart.py) | Python 3.9+ | Zero-dependency offline clause signing + single-file two-agent live quickstart |
| [`quickstart-claimant.ts`](./quickstart-claimant.ts) | TypeScript | Claimant flow using `@agent-mediate/sdk` (`fileDispute`, `waitForTurn`, `confirmExecution`, `audit`) |
| [`quickstart-respondent.ts`](./quickstart-respondent.ts) | TypeScript | Respondent flow (`join`, `submitEvidence`, `submitOffer`, `submitExecutionProof`) |
| [`dispute-clause.ts`](./dispute-clause.ts) | TypeScript | Pre-dispute `agent-mediate/clause/v1` construction, dual signatures, and verification |
| [`webhook-receiver.ts`](./webhook-receiver.ts) | TypeScript | Verifying `Ed25519`-signed platform webhook deliveries and replay protection |
