"""
Buyer Agent for Agent-Mediate (`agent-mediate` zero-dependency Python SDK).

Designed both as:
1. Drop-in tool functions for LangGraph / CrewAI / AutoGen buyer agents (`BuyerMediationTools`), and
2. A persistent JSON-over-stdio worker (`--worker`) driven by `examples/e2e-sla-demo.ts` alongside a
   live `@agent-mediate/mcp` TypeScript vendor agent.

Standalone check:
    PYTHONPATH=packages/python/src python3 examples/langgraph_buyer_agent.py
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Dict, Mapping, Optional

REPO_PY_SRC = Path(__file__).resolve().parents[1] / "packages" / "python" / "src"
if REPO_PY_SRC.exists() and str(REPO_PY_SRC) not in sys.path:
    sys.path.insert(0, str(REPO_PY_SRC))

from agent_mediate import (  # noqa: E402
    AgentKey,
    AgentMediateClient,
    HttpResponse,
    RULES_HASH,
    TransportLike,
    build_clause,
    contract_hash,
    generate_agent_key,
    sign_clause,
    sign_mandate,
    verify_clause,
)


class BuyerMediationTools:
    """
    Stateful buyer-side mediation toolkit backed by principal-signed Ed25519 mandates.

    In a LangGraph `StateGraph`, bind each method as a `@tool` or graph node so the LLM
    chooses *when* to negotiate while the principal's numerical bounds stay cryptographically
    enforced outside the prompt.
    """

    def __init__(
        self,
        *,
        base_url: str,
        platform_did: str,
        expected_environment: Optional[str] = None,
        agent_key: Optional[AgentKey] = None,
        principal_key: Optional[AgentKey] = None,
        transport: Optional[TransportLike] = None,
    ) -> None:
        self.agent_key = agent_key or generate_agent_key()
        self.principal_key = principal_key or generate_agent_key()
        self.platform_did = platform_did
        self.base_url = base_url
        self.client = AgentMediateClient(
            base_url=base_url,
            agent_key=self.agent_key,
            platform_did=platform_did,
            expected_environment=expected_environment,
            expected_rules_hash=RULES_HASH,
            default_view="compact",
            transport=transport,
        )

    def draft_and_sign_clause(self, contract: Mapping[str, Any], vendor_did: str) -> Dict[str, Any]:
        """Compute RFC 8785 JCS contractHash and sign an `agent-mediate/clause/v1` pre-dispute clause."""
        c_hash = contract_hash(contract)
        clause = build_clause(
            contract=contract,
            platform_did=self.platform_did,
            platform_base_url=self.base_url,
            rules_hash=RULES_HASH,
            parties=[
                {"agentId": self.agent_key.did, "principalId": self.principal_key.did},
                {"agentId": vendor_did},
            ],
            terms={"feeMode": "FILER_PAYS", "determinationConsent": True},
        )
        signed = sign_clause(clause, self.principal_key)
        return {"contractHash": c_hash, "clause": signed}

    def verify_cosigned_clause(
        self,
        clause: Mapping[str, Any],
        expected_contract_hash: str,
        vendor_did: str,
    ) -> Dict[str, Any]:
        """Verify both buyer and vendor Ed25519 signatures plus platform/rulesHash pins."""
        result = verify_clause(
            clause,
            expected_platform_did=self.platform_did,
            expected_contract_hash=expected_contract_hash,
            claimant_id=self.agent_key.did,
            respondent_id=vendor_did,
        )
        if not result.get("ok"):
            raise RuntimeError(f"Co-signed clause verification failed: {result}")
        return dict(result)

    def file_sla_dispute(
        self,
        *,
        vendor_did: str,
        contract_hash_hex: str,
        clause: Mapping[str, Any],
        min_refund_usd: int = 300,
        max_refund_usd: int = 1000,
    ) -> Dict[str, Any]:
        """File an SLA downtime dispute bounded by a principal-signed Ed25519 mandate."""
        now_ms = int(__import__("time").time() * 1000)
        mandate = sign_mandate(
            {
                "id": f"mnd_buyer_{contract_hash_hex[:10]}",
                "principalId": self.principal_key.did,
                "agentId": self.agent_key.did,
                "scope": {
                    "contractHash": contract_hash_hex,
                    "counterpartyId": vendor_did,
                },
                "bounds": {"refundUsd": {"min": min_refund_usd, "max": max_refund_usd}},
                "determinationConsent": True,
                "issuedAt": now_ms - 1000,
                "expiresAt": now_ms + 7 * 86_400_000,
            },
            self.principal_key,
        )
        return self.client.file_dispute(
            respondent_id=vendor_did,
            contract_hash=contract_hash_hex,
            claim={
                "summary": "Inference API returned HTTP 503 for 47 minutes on 2026-11-15 against 99.9% SLA.",
                "requestedRemedy": "SLA service credit / refund in USD.",
            },
            proposed_issues=[
                {
                    "id": "refundUsd",
                    "label": "SLA Downtime Refund",
                    "unit": "USD",
                    "min": 0,
                    "max": 1000,
                    "step": 10,
                    "claimantPrefers": "higher",
                    "obligor": "respondent",
                }
            ],
            mandate=mandate,
            determination_consent=True,
            clause=clause,
        )

    def submit_evidence_and_close(self, dispute_id: str) -> Dict[str, Any]:
        """Hash probe telemetry locally (raw log never uploaded) and close buyer evidence."""
        self.client.submit_evidence(
            dispute_id,
            [
                {
                    "id": "buyer-probe-503-log",
                    "kind": "telemetry-log",
                    "description": "Multi-region synthetic health check log recording 47 consecutive 503 responses.",
                    "content": "2026-11-15T09:12:00Z..09:59:00Z region=eu-west1 status=503 failed_probes=47/47",
                }
            ],
        )
        return self.client.close_evidence(dispute_id)

    def confirm_issues(self, dispute_id: str) -> Dict[str, Any]:
        """Inspect proposed issue set and lock `proposedHash`."""
        state = self.client.get_dispute(dispute_id)
        proposed_hash = state["view"]["issueNegotiation"]["proposedHash"]
        if not proposed_hash:
            raise RuntimeError("Expected proposedHash in ISSUE_CONFIRMATION stage")
        return self.client.confirm_issues(dispute_id, proposed_hash)

    def submit_round_one_offer(
        self,
        dispute_id: str,
        *,
        offer_usd: int = 650,
        walkaway_usd: int = 360,
    ) -> Dict[str, Any]:
        """Submit sealed Round-1 demand and private walkaway (never revealed to vendor or LLMs)."""
        return self.client.submit_offer(
            dispute_id,
            1,
            offer={"refundUsd": offer_usd},
            private={
                "weights": {"refundUsd": 1},
                "walkaway": {"refundUsd": walkaway_usd},
            },
        )

    def respond_round_two_proposal(self, dispute_id: str, fallback_offer_usd: int = 600) -> Dict[str, Any]:
        """Accept the platform's confidential split proposal if it satisfies buyer mandate & walkaway."""
        snap = self.client.get_dispute(dispute_id)
        view = snap["view"]
        if view["status"] != "BARGAINING":
            return snap
        accept = bool(view.get("proposalWithinYourMandate") and view.get("proposalMeetsYourWalkaway"))
        return self.client.submit_offer(
            dispute_id,
            2,
            offer={"refundUsd": fallback_offer_usd},
            proposal_response="accept" if accept else "reject",
        )

    def confirm_execution_and_verify(self, dispute_id: str) -> Dict[str, Any]:
        """Confirm vendor settlement performance and verify Ed25519 outcome + salted SHA-256 audit chain."""
        self.client.confirm_execution(dispute_id)
        outcome = self.client.outcome(dispute_id)
        audit = self.client.audit(dispute_id, expected_outcome=outcome)
        return {
            "outcome": outcome,
            "auditHead": audit["head"],
            "auditEntries": len(audit["entries"]),
            "redactedCounterpartyLinks": audit["redacted"],
        }


def _make_stdio_bridge_transport() -> TransportLike:
    def _transport(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
        sys.stdout.write(
            json.dumps(
                {
                    "type": "http_request",
                    "method": method,
                    "url": url,
                    "headers": dict(headers),
                    "body": body.decode("utf-8") if body is not None else "",
                }
            )
            + "\n"
        )
        sys.stdout.flush()
        reply_line = sys.stdin.readline()
        if not reply_line:
            raise RuntimeError("Stdio HTTP bridge closed unexpectedly")
        reply = json.loads(reply_line)
        return HttpResponse(
            status=int(reply["status"]),
            headers=dict(reply.get("headers") or {}),
            body=str(reply.get("body") or ""),
        )

    return _transport


def _run_worker() -> None:
    tools: Optional[BuyerMediationTools] = None
    while True:
        raw_line = sys.stdin.readline()
        if not raw_line:
            break
        line = raw_line.strip()
        if not line:
            continue
        req = json.loads(line)
        cmd = req.get("cmd")
        try:
            if cmd == "init":
                use_stdio_http = bool(req.get("stdioHttpBridge"))
                tools = BuyerMediationTools(
                    base_url=req["baseUrl"],
                    platform_did=req["platformDid"],
                    expected_environment=req.get("expectedEnvironment"),
                    transport=_make_stdio_bridge_transport() if use_stdio_http else None,
                )
                res: Any = {
                    "buyerDid": tools.agent_key.did,
                    "buyerPrincipalDid": tools.principal_key.did,
                }
            else:
                if tools is None:
                    raise RuntimeError("Worker not initialized")
                if cmd == "draft_clause":
                    res = tools.draft_and_sign_clause(req["contract"], req["vendorDid"])
                elif cmd == "verify_clause":
                    res = tools.verify_cosigned_clause(req["clause"], req["contractHash"], req["vendorDid"])
                elif cmd == "file_dispute":
                    res = tools.file_sla_dispute(
                        vendor_did=req["vendorDid"],
                        contract_hash_hex=req["contractHash"],
                        clause=req["clause"],
                    )
                elif cmd == "submit_evidence":
                    res = tools.submit_evidence_and_close(req["disputeId"])
                elif cmd == "confirm_issues":
                    res = tools.confirm_issues(req["disputeId"])
                elif cmd == "round1_offer":
                    res = tools.submit_round_one_offer(req["disputeId"])
                elif cmd == "round2_respond":
                    res = tools.respond_round_two_proposal(req["disputeId"])
                elif cmd == "confirm_and_verify":
                    res = tools.confirm_execution_and_verify(req["disputeId"])
                else:
                    raise ValueError(f"Unknown worker command: {cmd}")
            sys.stdout.write(json.dumps({"ok": True, "result": res}) + "\n")
            sys.stdout.flush()
        except Exception as exc:  # noqa: BLE001
            sys.stdout.write(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}) + "\n")
            sys.stdout.flush()


def _self_check() -> None:
    platform_key = generate_agent_key()
    vendor_key = generate_agent_key()
    buyer = BuyerMediationTools(
        base_url="https://api.ai-agents-mediation.com",
        platform_did=platform_key.did,
    )
    contract = {"service": "Inference Gateway v2", "monthlyFeeUsd": 1000, "uptimeSla": 0.999}
    drafted = buyer.draft_and_sign_clause(contract, vendor_key.did)
    cosigned = sign_clause(drafted["clause"], vendor_key)
    verified = buyer.verify_cosigned_clause(cosigned, drafted["contractHash"], vendor_key.did)
    print(f"Buyer DID:        {buyer.agent_key.did}")
    print(f"Vendor DID:       {vendor_key.did}")
    print(f"Contract SHA-256: {drafted['contractHash']}")
    print(f"Clause verified:  {verified['ok']} (rulesHash={RULES_HASH[:16]}...)")
    print("Run the full Python Buyer + @agent-mediate/mcp Vendor E2E mediation with:")
    print("  node examples/e2e-sla-demo.ts")


if __name__ == "__main__":
    if "--worker" in sys.argv[1:]:
        _run_worker()
    else:
        _self_check()
