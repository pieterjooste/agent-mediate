"""
Zero-dependency Python quickstart for Agent-Mediate (`packages/python`).

Run offline cryptographic + clause demo:
    PYTHONPATH=packages/python/src python3 examples/python_quickstart.py

Or run a full two-agent mediation against a live API (`npm run dev`):
    AGENT_MEDIATE_URL=http://localhost:8080 PYTHONPATH=packages/python/src python3 examples/python_quickstart.py
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

REPO_PY_SRC = Path(__file__).resolve().parents[1] / "packages" / "python" / "src"
if str(REPO_PY_SRC) not in sys.path:
    sys.path.insert(0, str(REPO_PY_SRC))

from agent_mediate import (  # noqa: E402
    AgentMediateClient,
    build_clause,
    contract_hash,
    generate_agent_key,
    sign_clause,
    verify_clause,
)


def main() -> None:
    claimant_key = generate_agent_key()
    respondent_key = generate_agent_key()
    print(f"Claimant DID:   {claimant_key.did}")
    print(f"Respondent DID: {respondent_key.did}")

    contract = {
        "service": "Vector Index Feed",
        "monthlyFeeUsd": 800,
        "freshnessSlaSeconds": 60,
    }
    c_hash = contract_hash(contract)
    print(f"RFC 8785 JCS contract_hash: {c_hash}")

    base_url = os.environ.get("AGENT_MEDIATE_URL")
    # Production deployments should pin AGENT_MEDIATE_PLATFORM_DID out of band rather than trusting first-contact /v1/platform (SA2-DOC-I1).
    pinned_did = (os.environ.get("AGENT_MEDIATE_PLATFORM_DID") or "").strip()
    platform_did = pinned_did or generate_agent_key().did
    if base_url and not pinned_did:
        probe = AgentMediateClient(base_url=base_url, agent_key=claimant_key)
        platform_did = probe.platform()["did"]

    clause = build_clause(
        contract=contract,
        platform_did=platform_did,
        platform_base_url=base_url,
        parties=[{"agentId": claimant_key.did}, {"agentId": respondent_key.did}],
        terms={"feeMode": "FILER_PAYS", "determinationConsent": True},
    )
    clause = sign_clause(sign_clause(clause, claimant_key), respondent_key)
    check = verify_clause(
        clause,
        expected_platform_did=platform_did,
        expected_contract_hash=c_hash,
        claimant_id=claimant_key.did,
        respondent_id=respondent_key.did,
    )
    print("Co-signed clause verified:", check["ok"])

    if not base_url:
        print("Set AGENT_MEDIATE_URL=http://localhost:8080 to execute the live two-agent dispute flow.")
        return

    claimant = AgentMediateClient(
        base_url=base_url,
        agent_key=claimant_key,
        platform_did=platform_did,
        default_view="compact",
    )
    respondent = AgentMediateClient(
        base_url=base_url,
        agent_key=respondent_key,
        platform_did=platform_did,
        default_view="compact",
    )

    filed = claimant.file_dispute(
        respondent_id=respondent.did,
        contract_hash=c_hash,
        claim={"summary": "Index feed lagged by 22 minutes.", "requestedRemedy": "Fee refund."},
        proposed_issues=[
            {
                "id": "refundUsd",
                "label": "Freshness SLA Refund",
                "unit": "USD",
                "min": 0,
                "max": 800,
                "step": 10,
                "claimantPrefers": "higher",
                "obligor": "respondent",
            }
        ],
        bounds={"refundUsd": {"min": 150, "max": 800}},
        determination_consent=True,
        clause=clause,
    )
    dispute_id = filed["disputeId"]
    print(f"Filed {dispute_id} | notice URL: {filed['notice']['noticeUrl']}")

    respondent.join(dispute_id, bounds={"refundUsd": {"min": 0, "max": 500}}, determination_consent=True)
    claimant.close_evidence(dispute_id)
    closed = respondent.close_evidence(dispute_id)
    issues_hash = closed["view"]["issueNegotiation"]["proposedHash"]

    claimant.confirm_issues(dispute_id, issues_hash)
    respondent.confirm_issues(dispute_id, issues_hash)

    claimant.submit_offer(dispute_id, 1, offer={"refundUsd": 400}, private={"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 200}})
    settled = respondent.submit_offer(dispute_id, 1, offer={"refundUsd": 400}, private={"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 450}})
    print("Bargaining result:", settled["view"]["status"])

    respondent.submit_execution_proof(dispute_id, "0x" + ("cd" * 32))
    claimant.confirm_execution(dispute_id)
    outcome = claimant.outcome(dispute_id)
    print("Verified platform-signed outcome:", outcome["document"]["terms"])


if __name__ == "__main__":
    main()
