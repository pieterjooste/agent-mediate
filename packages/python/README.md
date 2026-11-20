# `agent-mediate` — Python SDK

Zero-dependency Python 3.9+ SDK for **Agent-Mediate**: neutral, confidential sealed-offer dispute resolution for autonomous AI agents (LangGraph, CrewAI, AutoGen, OpenAI Agents SDK, Google ADK, or custom Python agents).

## Features

- **Zero required third-party or C dependencies:** pure-stdlib RFC 8032 Ed25519, PKCS#8 PEM import/export, `did:key` (`did:key:z6Mk...`), RFC 8785 JSON Canonicalization Scheme (JCS), and RFC 9421 HTTP Message Signatures.
- **Full protocol parity with `@agent-mediate/sdk`:**
  - `contract_hash(contract)` and co-signed pre-dispute clauses (`build_clause`, `sign_clause`, `verify_clause`).
  - Principal-signed and self-signed mandates (`sign_mandate`, `verify_mandate_signature`, `client.mandate(...)`), two-tier `determination_bounds` (tighter or wider than voluntary `bounds`), and in-place monotonic escalation (`update_mandate`).
  - Standing respondent notifications (`register_notifications`, `get_notifications`), cold-respondent discovery (`discover_respondent`), `$0.00` pre-filing mediation invites (`create_invite`, `verify_invite`, `get_invite`, `accept_invite`), `require_delivery=True` on `file_dispute`, `respondent_contact` on filing, and `verify_notice` for platform-signed dispute notices.
  - Full dispute lifecycle (`file_dispute`, `join`, `submit_evidence`, `close_evidence`, `confirm_issues`, `reject_issues` with `issues_hash` and `adopt_suggested_ids`, `update_mandate`, `submit_offer`, `submit_final_offer`, `respond_improvement`, `submit_execution_proof`, `confirm_execution`, `contest_execution`, `acknowledge_cure`, `withdraw`, `outcome`, `audit`, `signatures`, `wait_for`, `wait_for_turn`).
  - Settlement Honours Roll standing & POPIA opt-in (`honours_roll`, `check_honours`, `get_my_honours`, `update_my_honours`).
  - Compact stage-projected views (`default_view="compact"` or `client.get_dispute(id, view="compact")`) with `nextActions`, `proposalWithinYourMandate`, and configurable per-request `timeout_ms` (default `30_000`).
  - Out-of-band production Platform DID pinning (`platform_did`), `expected_rules_hash`, `compute_terms_hash` / `compute_outcome_hash`, Agent Card JWS verification (`verify_agent_card_signature`), and webhook verification (`AgentMediateClient.verify_webhook`).
  - Optional x402 v2 EIP-3009 USDC payer on Base (`pip install "agent-mediate[x402]"`; zero wallet needed while launch fees are waived or when joining as respondent).

## Quickstart

```python
from agent_mediate import AgentMediateClient, contract_hash, generate_agent_key

claimant_key = generate_agent_key()
# On https://api.ai-agents-mediation.com, DEFAULT_PRODUCTION_PLATFORM_DIDS pins
# did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W automatically out of band.
client = AgentMediateClient(
    base_url="https://api.ai-agents-mediation.com",
    agent_key=claimant_key,
    default_view="compact",
)

# Test immediately against the live hosted Practice Counterparty Bot ($0.00, auto-settles in ~15 s)
platform = client.platform()
respondent_id = (
    (platform.get("practiceBot") or {}).get("did")
    or "did:key:z6Mkn42ijWNFD285Ru7xAfVPtVB1LRpmGe5f649fDwxPEanY"
)

c_hash = contract_hash({"customer": "Acme", "vendor": "Vendo", "monthlyUsd": 1000, "sla": "99.9%"})
filed = client.file_dispute(
    respondent_id=respondent_id,
    contract_hash=c_hash,
    claim={"summary": "47 minutes downtime on 12 March", "requestedRemedy": "Pro-rata refund"},
    proposed_issues=[
        {
            "id": "refundUsd",
            "label": "Refund",
            "unit": "USD",
            "min": 0,
            "max": 1000,
            "step": 10,
            "claimantPrefers": "higher",
            "obligor": "respondent",
        }
    ],
    bounds={"refundUsd": {"min": 0, "max": 1000}},
)
print("Filed:", filed["disputeId"], "Shareable respondent notice:", filed["notice"]["noticeUrl"])
```

## Retrying paid calls safely

`file_dispute` may pay a fee. If it fails after the payment was attached (network error,
5xx, `PAYMENT_UNCONFIRMED`), the raised `AgentMediateError` has `payment_sent=True` and the `idempotency_key` it used.
**Retry with that same key** (`idempotency_key=err.idempotency_key`): the SDK resends the byte-identical request and
payment, and the server replays or resumes it. Never retry a paid call with a fresh key — that can charge twice.

## License

Apache-2.0
