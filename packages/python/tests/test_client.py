from __future__ import annotations

import base64
import datetime
import email.utils
import hashlib
import json
import os
import sys
import threading
import time
import types
import unittest
import unittest.mock
import urllib.request
from pathlib import Path
from typing import Mapping, Optional

SRC_DIR = Path(__file__).resolve().parents[1] / "src"
if str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))

from agent_mediate import (  # noqa: E402
    AgentMediateClient,
    AgentMediateError,
    DEFAULT_PRODUCTION_PLATFORM_DIDS,
    HONOURS_ATTESTATION_TYPE,
    HttpResponse,
    KEY_HISTORY_TYPE,
    MECHANISM_SPEC,
    PRODUCTION_API_URL,
    PaymentPolicyError,
    RULES_HASH,
    RULES_VERSION,
    WEBHOOK_SIGNATURE_TAG,
    X402Payer,
    agent_key_from_pem,
    agent_key_from_seed,
    build_clause,
    build_did_web_document,
    build_jwks,
    canonical_json,
    checkpoint_leaf_hash,
    checkpoint_node_hash,
    compute_declared_input_commitment,
    compute_proposal_key_commitment,
    compute_request_proof_hash,
    contract_hash,
    decode_base_anchor_calldata,
    derive_party_input_salt,
    derive_proposal_salt,
    did_key_from_ed25519_jwk,
    did_key_from_raw_public_key,
    did_web_document_authorizes_key,
    ed25519_public_jwk_from_did_key,
    ed25519_sign,
    ed25519_verify,
    encode_base_anchor_calldata,
    generate_agent_key,
    is_did_key,
    sha256_hex,
    sign_agent_card,
    sign_clause,
    sign_document,
    sign_mandate,
    sign_request,
    url_from_did_web,
    verify_agent_card_signature,
    verify_checkpoint_inclusion,
    verify_clause,
    verify_dispute_action_target,
    verify_document,
    verify_document_with_key_history,
    verify_mandate_signature,
    verify_proposal_opening,
    verify_public_audit_chain,
    verify_request,
    verify_request_proof,
    weak_point_reason,
)
from agent_mediate.crypto import L, P, _clamp_seed, _encode_point, _point_add, _point_double, _scalar_mult  # noqa: E402
from agent_mediate.protocol import clause_signing_payload  # noqa: E402



class PythonClientAndPayerTests(unittest.TestCase):
    def test_x402_payer_hexbytes_v2_policy_and_thread_safety(self) -> None:
        pay_to = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
        asset = "0x036CbD53842c5426634e7929541eC2318f3dCF7e"

        class _MockHexBytes(bytes):
            """Simulates hexbytes < 1.0 (eth-account 0.11-0.12) where .hex() includes a '0x' prefix."""

            def hex(self, *args: object, **kwargs: object) -> str:  # type: ignore[override]
                return "0x" + super().hex()

        should_fail = [False]

        class _MockAccountInstance:
            address = "0x1111111111111111111111111111111111111111"

            def sign_typed_data(self, *, full_message: Mapping[str, object]) -> object:
                if should_fail[0]:
                    raise RuntimeError("hardware signer disconnected")
                assert isinstance(full_message, Mapping)
                res = types.SimpleNamespace()
                res.signature = _MockHexBytes(bytes.fromhex("ab" * 65))
                return res

        mock_eth_account = types.ModuleType("eth_account")
        mock_eth_account.Account = types.SimpleNamespace(from_key=lambda _pk: _MockAccountInstance())  # type: ignore[attr-defined]

        def _challenge(**overrides: object) -> dict:
            item = {
                "scheme": "exact",
                "network": "eip155:84532",
                "amount": "1000000",
                "asset": asset,
                "payTo": pay_to,
                "maxTimeoutSeconds": 120,
                "extra": {"name": "USDC", "version": "2"},
                **overrides,
            }
            return {
                "x402Version": 2,
                "resource": {"url": "https://api.mediate.example/v1/disputes", "description": "Dispute filing"},
                "accepts": [item],
            }

        with unittest.mock.patch.dict(sys.modules, {"eth_account": mock_eth_account}):
            payer = X402Payer(
                private_key="0x" + ("22" * 32),
                max_amount_atomic=2_000_000,
                budget_atomic=4_000_000,
                pay_to=pay_to,
                now_ms=lambda: 1800000000000,
            )
            encoded = payer.pay(_challenge(), operation="file")
            decoded = json.loads(base64.b64decode(encoded).decode("utf-8"))
            sig_hex = decoded["payload"]["signature"]
            self.assertTrue(sig_hex.startswith("0x") and not sig_hex.startswith("0x0x"))
            self.assertEqual(len(sig_hex), 132)
            self.assertEqual(decoded["resource"]["url"], "https://api.mediate.example/v1/disputes")
            self.assertEqual(decoded["accepted"]["maxTimeoutSeconds"], 120)
            self.assertEqual(decoded["accepted"]["extra"], {"name": "USDC", "version": "2"})
            self.assertEqual(decoded["payload"]["authorization"]["validAfter"], str(1800000000 - 600))

            # Policy rejections: wrong x402Version, wrong EIP-712 domain name, negative maxTimeoutSeconds
            with self.assertRaises(PaymentPolicyError):
                payer.pay({**_challenge(), "x402Version": 1}, operation="file")
            with self.assertRaises(PaymentPolicyError):
                payer.pay(_challenge(extra={"name": "FakeUSDC", "version": "2"}), operation="file")
            with self.assertRaises(PaymentPolicyError):
                payer.pay(_challenge(maxTimeoutSeconds=-5), operation="file")

            # Signer exception rolls back spent_atomic
            before_fail = payer.spent_atomic
            should_fail[0] = True
            with self.assertRaises(RuntimeError):
                payer.pay(_challenge(), operation="file")
            should_fail[0] = False
            self.assertEqual(payer.spent_atomic, before_fail)

            # Concurrent threads never exceed cumulative budget_atomic
            concurrent_payer = X402Payer(
                private_key="0x" + ("22" * 32),
                max_amount_atomic=1_000_000,
                budget_atomic=3_000_000,
                pay_to=pay_to,
                now_ms=lambda: 1800000000000,
            )
            barrier = threading.Barrier(8)
            successes = []
            failures = []
            res_lock = threading.Lock()

            def _worker() -> None:
                barrier.wait()
                try:
                    hdr = concurrent_payer.pay(_challenge(), operation="file")
                    with res_lock:
                        successes.append(hdr)
                except PaymentPolicyError as err:
                    with res_lock:
                        failures.append(str(err))

            threads = [threading.Thread(target=_worker) for _ in range(8)]
            for t in threads:
                t.start()
            for t in threads:
                t.join()
            self.assertEqual(len(successes), 3)
            self.assertEqual(len(failures), 5)
            self.assertEqual(concurrent_payer.spent_atomic, 3_000_000)

    def test_sdk_retry_after_http_date_key_history_replay_and_guards(self) -> None:
        a = generate_agent_key()
        platform = generate_agent_key()
        now_ms = 1800000000000

        # 1. JCS > 2^53 - 1 integer rejection & lone surrogate safety (FS-L10)
        with self.assertRaises(ValueError):
            canonical_json({"unsafe": (1 << 53)})
        surrogate_jcs = canonical_json({"lone": "a\ud800b"})
        self.assertIn("\\ud800", surrogate_jcs)

        # 2. Public GET retries 503 with RFC 9110 HTTP-date Retry-After without raising ValueError,
        # and key_history() rejects a cross-document replay (SignedOutcome at /.well-known/key-history.json) (FS-M13)
        calls = {"platform": 0}
        replayed_outcome = sign_document(
            {"type": "agent-mediate/settlement-instruction/v1", "disputeId": "dsp_replay"},
            platform,
            created_ms=now_ms,
        )

        def _transport(method: str, url: str, _h: Mapping[str, str], _b: Optional[bytes]) -> HttpResponse:
            if url.endswith("/v1/platform"):
                calls["platform"] += 1
                if calls["platform"] == 1:
                    retry_date = email.utils.format_datetime(
                        datetime.datetime.fromtimestamp((now_ms / 1000.0) + 0.01, tz=datetime.timezone.utc),
                        usegmt=True,
                    )
                    return HttpResponse(503, {"retry-after": retry_date}, json.dumps({"code": "BUSY", "detail": "busy"}))
                return HttpResponse(200, {}, json.dumps({"did": platform.did, "rulesHash": RULES_HASH}))
            if url.endswith("/.well-known/key-history.json"):
                return HttpResponse(200, {}, json.dumps(replayed_outcome))
            return HttpResponse(404, {}, "{}")

        c = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=platform.did,
            transport=_transport,
            now_ms=lambda: now_ms,
            max_retries=1,
        )
        self.assertEqual(c.platform()["did"], platform.did)
        self.assertEqual(calls["platform"], 2)

        with self.assertRaises(AgentMediateError) as err_kh:
            c.key_history()
        self.assertEqual(err_kh.exception.code, "INVALID_PLATFORM_SIGNATURE")

        # 3. verify_webhook rejects non-object JSON payloads ("null", "[]") and submit_offer rejects partial private inputs (FS-L9, FS-M15)
        for bad_body in ("null", "[]", "123"):
            url = "https://agent.example/hook"
            hdrs = sign_request(
                method="POST",
                target_uri=url,
                body=bad_body,
                key=platform,
                created=now_ms // 1000,
                nonce="wh_bad_json_nonce_012345",
                tag=WEBHOOK_SIGNATURE_TAG,
            )
            self.assertFalse(
                AgentMediateClient.verify_webhook(url=url, headers=hdrs, body=bad_body, platform_did=platform.did, now_ms=now_ms)["ok"]
            )
        with self.assertRaises(ValueError):
            c.submit_offer("dsp_1", 1, offer={"refundUsd": 500}, weights={"refundUsd": 1.0})
        with self.assertRaises(ValueError):
            c.submit_offer("dsp_1", 1, offer={"refundUsd": 500}, limits={"refundUsd": {"min": 0, "max": 800}})

    def test_lost_paid_response_retry_never_pays_twice(self) -> None:
        """CR-SDK-M1: error carries the key; a same-key retry resends the byte-identical request and payment."""
        a = generate_agent_key()
        platform = generate_agent_key()
        now = {"ms": 1800000000000}
        seen: list = []
        state = {"drop": True}

        class _Payer:
            network = "eip155:84532"
            address = "0x" + "11" * 20
            calls = 0

            def pay(self, _challenge: Mapping[str, object], *, operation: str, expected_pay_to: Optional[str] = None) -> str:
                type(self).calls += 1
                return f"pay-sig-{type(self).calls}"

        def _transport(method: str, url: str, h: Mapping[str, str], b: Optional[bytes]) -> HttpResponse:
            if url.endswith("/v1/platform"):
                return HttpResponse(200, {}, json.dumps({"did": platform.did, "rulesHash": RULES_HASH, "fees": {}}))
            if method == "POST" and url.endswith("/v1/disputes"):
                if "payment-signature" not in h:
                    return HttpResponse(402, {}, json.dumps({"code": "PAYMENT_REQUIRED", "paymentRequired": {"x402Version": 2, "accepts": []}}))
                seen.append((url, h["idempotency-key"], h["payment-signature"], b))
                if state["drop"]:
                    raise ConnectionResetError("socket hang up")
                return HttpResponse(201, {}, json.dumps({"disputeId": "dsp_1"}))
            return HttpResponse(404, {}, "{}")

        payer = _Payer()
        c = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=platform.did,
            transport=_transport,
            now_ms=lambda: now["ms"],
            max_retries=0,
            payer=payer,
        )
        file_kwargs = {
            "respondent_id": generate_agent_key().did,
            "contract_hash": "a" * 64,
            "claim": {"summary": "s", "requestedRemedy": "r"},
            "proposed_issues": [{"id": "refundUsd", "label": "Refund", "unit": "USD", "min": 0, "max": 100, "step": 1, "claimantPrefers": "higher", "obligor": "respondent"}],
            "bounds": {"refundUsd": {"min": 0, "max": 100}},
        }
        with self.assertRaises(AgentMediateError) as err:
            c.file_dispute(**file_kwargs)
        e = err.exception
        self.assertEqual(e.code, "NETWORK_ERROR")
        self.assertTrue(e.payment_sent)
        self.assertTrue((e.idempotency_key or "").startswith("pysdk-"))
        self.assertIn("retry with idempotency_key", str(e))
        self.assertEqual(_Payer.calls, 1)

        now["ms"] += 5_000
        state["drop"] = False
        self.assertEqual(c.file_dispute(**file_kwargs, idempotency_key=e.idempotency_key)["disputeId"], "dsp_1")
        self.assertEqual(_Payer.calls, 1, "no second payment authorisation")
        self.assertEqual(len(seen), 2)
        self.assertEqual(seen[0], seen[1], "byte-identical target, key, payment and body on retry")

    def test_production_readiness_2026_11_python_sdk_and_protocol(self) -> None:
        """PR-PROTO-H1, PR-PROTO-M1, PR-SDK-M1, PR-L8, PR-L10: Python protocol & SDK parity guards."""
        import agent_mediate as am
        from agent_mediate import (
            compute_outcome_hash,
            compute_terms_hash,
            did_web_from_url,
            ed25519_public_jwk_from_did_key,
            KEY_HISTORY_TYPE,
            url_from_did_web,
            verify_document_with_key_history,
            verify_key_history,
        )

        # 1. PR-L8: exported __version__, compute_terms_hash, compute_outcome_hash
        self.assertEqual(am.__version__, "0.2.1")
        terms_h = compute_terms_hash({"refundUsd": 420})
        self.assertEqual(len(terms_h), 64)
        outcome_h = compute_outcome_hash(
            {"kind": "UNRESOLVED", "reason": "NO_AGREEMENT", "at": 1800000000000, "roundsCompleted": 3},
            "UNRESOLVED",
        )
        self.assertEqual(len(outcome_h), 64)

        # 2. PR-PROTO-H1: non-finite / <= 0 `now_ms` rejected across all five time-sensitive verifiers
        a = generate_agent_key()
        b = generate_agent_key()
        platform = generate_agent_key()
        t0 = 1800000000000
        req_body = '{"hello":"world"}'
        base_hdrs = {"content-type": "application/json", "idempotency-key": "py-idem-proto-h1"}
        sig_hdrs = {
            **base_hdrs,
            **sign_request(
                method="POST",
                target_uri="https://api.mediate.example/v1/disputes",
                headers=base_hdrs,
                body=req_body,
                key=a,
                created=t0 // 1000,
                nonce="py-nonce-proto-h1-001",
            ),
        }
        clause = sign_clause(
            sign_clause(
                build_clause(
                    contract_hash_hex="a" * 64,
                    platform_did=platform.did,
                    rules_hash=RULES_HASH,
                    issued_at=t0,
                    expires_at=t0 + 60_000,
                    parties=[{"agentId": a.did}, {"agentId": b.did}],
                ),
                a,
                a.did,
            ),
            b,
            b.did,
        )
        doc = sign_document({"type": "test/v1", "v": 1}, platform, key_id=f"{platform.did}#key-1", created_ms=t0, expires_at_ms=t0 + 60_000)
        history = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "activeDid": platform.did,
                "activeKeyId": f"{platform.did}#key-1",
                "updatedAt": t0,
                "keys": [
                    {
                        "keyId": f"{platform.did}#key-1",
                        "did": platform.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(platform.did),
                        "status": "active",
                        "validFrom": t0 - 10_000,
                    }
                ],
            },
            platform,
            key_id=f"{platform.did}#key-1",
            created_ms=t0,
        )
        for bad_now in (float("nan"), float("inf"), float("-inf"), 0, -1):
            self.assertFalse(
                verify_request(
                    method="POST",
                    target_uri="https://api.mediate.example/v1/disputes",
                    headers=sig_hdrs,
                    body=req_body,
                    now_ms=bad_now,
                )["ok"]
            )
            self.assertFalse(verify_clause(clause, expected_platform_did=platform.did, now_ms=bad_now)["ok"])
            self.assertFalse(verify_document(doc, platform.did, now_ms=bad_now))
            self.assertFalse(verify_key_history(history, expected_active_did=platform.did, now_ms=bad_now)["ok"])
            self.assertFalse(verify_document_with_key_history(doc, history, expected_active_did=platform.did, now_ms=bad_now)["ok"])

        # 3. PR-PROTO-M1: strict did:web host/port validation
        for bad_url in ("https://[::1]/", "https://user:pass@example.com/", "https://example.com.:8443/", "ftp://example.com/"):
            with self.assertRaises(ValueError):
                did_web_from_url(bad_url)
        for bad_dw in ("did:web:[::1]", "did:web:example.com.", "did:web:example.com%3A0", "did:web:example.com%3A08080", "did:web:example.com%3A70000"):
            with self.assertRaises(ValueError):
                url_from_did_web(bad_dw)
        self.assertEqual(url_from_did_web(did_web_from_url("https://api.example.com:8443")), "https://api.example.com:8443/.well-known/did.json")

        # 4. PR-SDK-M1 & PR-L10: _pending_paid body-mismatch 422 IDEMPOTENCY_CONFLICT and verify_notice(...)
        state = {"drop": True}
        pay_calls = [0]
        signed_notice = sign_document(
            {
                "type": "agent-mediate/dispute-notice/v1",
                "disputeId": "dsp_py_pr",
                "environment": "production",
                "claimantId": a.did,
                "respondentId": b.did,
                "contractHash": "c" * 64,
                "issuedAt": t0,
                "noticeUrl": "https://api.mediate.example/n/tok_1",
            },
            platform,
            key_id=f"{platform.did}#key-1",
            created_ms=t0,
        )

        class _StubPayer:
            network = "eip155:84532"
            address = "0x" + ("11" * 20)

            def pay(self, _challenge: Mapping[str, object], *, operation: str, expected_pay_to: Optional[str] = None) -> str:
                pay_calls[0] += 1
                return f"pay-sig-{pay_calls[0]}"

        def _tx(method: str, url: str, h: Mapping[str, str], body_bytes: Optional[bytes]) -> HttpResponse:
            if url.endswith("/v1/platform"):
                return HttpResponse(200, {}, json.dumps({"did": platform.did, "rulesHash": RULES_HASH, "fees": {}}))
            if method == "POST" and url.endswith("/v1/disputes"):
                if "payment-signature" not in h:
                    return HttpResponse(402, {}, json.dumps({"code": "PAYMENT_REQUIRED", "paymentRequired": {"x402Version": 2, "accepts": []}}))
                if state["drop"]:
                    raise ConnectionResetError("dropped after settle")
                return HttpResponse(
                    201,
                    {},
                    json.dumps(
                        {
                            "disputeId": "dsp_py_pr",
                            "view": {"disputeId": "dsp_py_pr", "status": "AWAITING_RESPONDENT"},
                            "notice": {"noticeUrl": "https://api.mediate.example/n/tok_1", "signedNotice": signed_notice},
                        }
                    ),
                )
            return HttpResponse(404, {}, "{}")

        claimant_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=platform.did,
            expected_environment="production",
            payer=_StubPayer(),
            transport=_tx,
            now_ms=lambda: t0,
            max_retries=0,
        )
        respondent_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=b,
            platform_did=platform.did,
            expected_environment="production",
            transport=_tx,
            now_ms=lambda: t0,
        )
        issue = {"id": "refundUsd", "label": "Refund", "unit": "USD", "min": 0, "max": 1000, "step": 10, "claimantPrefers": "higher", "obligor": "respondent"}
        with self.assertRaises(AgentMediateError) as drop_ctx:
            claimant_client.file_dispute(
                respondent_id=b.did,
                contract_hash="c" * 64,
                claim={"summary": "Original summary", "requestedRemedy": "Refund"},
                proposed_issues=[issue],
                bounds={"refundUsd": {"min": 0, "max": 1000}},
            )
        idem = drop_ctx.exception.idempotency_key
        self.assertIsNotNone(idem)
        self.assertEqual(pay_calls[0], 1)

        with self.assertRaises(AgentMediateError) as conflict_ctx:
            claimant_client.file_dispute(
                respondent_id=b.did,
                contract_hash="c" * 64,
                claim={"summary": "Mutated summary", "requestedRemedy": "Refund"},
                proposed_issues=[issue],
                bounds={"refundUsd": {"min": 0, "max": 1000}},
                idempotency_key=idem,
            )
        self.assertEqual(conflict_ctx.exception.status, 422)
        self.assertEqual(conflict_ctx.exception.code, "IDEMPOTENCY_CONFLICT")
        self.assertTrue(conflict_ctx.exception.payment_sent)
        self.assertEqual(pay_calls[0], 1)

        state["drop"] = False
        filed = claimant_client.file_dispute(
            respondent_id=b.did,
            contract_hash="c" * 64,
            claim={"summary": "Original summary", "requestedRemedy": "Refund"},
            proposed_issues=[issue],
            bounds={"refundUsd": {"min": 0, "max": 1000}},
            idempotency_key=idem,
        )
        self.assertEqual(pay_calls[0], 1)
        verified_doc = respondent_client.verify_notice(
            filed["notice"]["signedNotice"],
            dispute_id="dsp_py_pr",
            claimant_id=a.did,
            contract_hash="c" * 64,
        )
        self.assertEqual(verified_doc["disputeId"], "dsp_py_pr")
        with self.assertRaises(AgentMediateError) as wrong_party_ctx:
            claimant_client.verify_notice(filed["notice"]["signedNotice"])
        self.assertEqual(wrong_party_ctx.exception.code, "NOTICE_MISMATCH")

    def test_non_overlapping_mandate_resolution_d126(self) -> None:
        """D126 (v1.2.0/v1.3.0): Python SDK update_mandate, reject_issues(issues_hash, adopt_suggested_ids=...), and confidential signature target parity."""
        from agent_mediate import verify_dispute_action_target, verify_mandate_signature

        self.assertEqual(RULES_VERSION, "1.4.0")
        self.assertIs(MECHANISM_SPEC["issueNegotiation"]["adoptSuggestedOnReject"], True)
        self.assertIs(MECHANISM_SPEC["issueNegotiation"]["rejectRequiresIssuesHash"], True)
        self.assertEqual(MECHANISM_SPEC["mandateEscalation"]["maxUpdatesPerParty"], 3)
        self.assertIs(MECHANISM_SPEC["mandateEscalation"]["freezesDeterminationConsentAtBargainingStart"], True)

        self.assertTrue(
            verify_dispute_action_target(
                {"method": "POST", "targetUri": "https://api.mediate.example/v1/disputes/dsp_1/mandate?view=compact"},
                expected_dispute_id="dsp_1",
                expected_action="update_mandate",
                expected_base_url="https://api.mediate.example",
            )["ok"]
        )
        self.assertFalse(
            verify_dispute_action_target(
                {"method": "GET", "targetUri": "https://api.mediate.example/v1/disputes/dsp_1/mandate"},
                expected_dispute_id="dsp_1",
                expected_action="update_mandate",
                expected_base_url="https://api.mediate.example",
            )["ok"]
        )

        a = generate_agent_key()
        b = generate_agent_key()
        seen: list[tuple[str, str, dict[str, object]]] = []
        t0 = 1800000000000

        file_body = '{"claim":"S"}'
        file_hdrs = {"content-type": "application/json", "idempotency-key": "idem-file-d126"}
        file_signed = {
            **file_hdrs,
            **sign_request(
                method="POST",
                target_uri="https://api.mediate.example/v1/disputes",
                headers=file_hdrs,
                body=file_body,
                key=a,
                created=t0 // 1000,
                nonce="py-nonce-file-d126-001",
            ),
        }
        file_verified = verify_request(
            method="POST",
            target_uri="https://api.mediate.example/v1/disputes",
            headers=file_signed,
            body=file_body,
            now_ms=t0,
        )
        file_proof = file_verified["proof"]

        def _tx(method: str, url: str, headers: Mapping[str, str], body: Optional[str]) -> HttpResponse:
            parsed = json.loads(body) if body else {}
            seen.append((method, url, parsed))
            if method == "GET" and "/v1/disputes/dsp_d126" in url and "/signatures" not in url:
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "view": {
                                "disputeId": "dsp_d126",
                                "status": "BARGAINING",
                                "contractHash": "a" * 64,
                                "counterpartId": b.did,
                                "determinationEnabled": True,
                                "yourMandate": {
                                    "id": "mnd_prev",
                                    "principalId": a.did,
                                    "agentId": a.did,
                                    "issuedAt": t0 + 500,
                                    "expiresAt": t0 + 90 * 86_400_000,
                                    "determinationConsent": True,
                                },
                            }
                        }
                    ),
                )
            if method == "GET" and url.endswith("/v1/disputes/dsp_d126/signatures"):
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "disputeId": "dsp_d126",
                            "signatures": [
                                {
                                    "id": 1,
                                    "seqRange": [1, 2],
                                    "action": "file_dispute",
                                    "party": "claimant",
                                    "agentId": a.did,
                                    "redacted": False,
                                    "proofHash": compute_request_proof_hash(file_proof),
                                    "proof": file_proof,
                                    "recordedAt": t0,
                                },
                                {
                                    "id": 2,
                                    "seqRange": [3, 3],
                                    "action": "confidential_action",
                                    "party": None,
                                    "agentId": None,
                                    "redacted": True,
                                    "proofHash": "b" * 64,
                                    "recordedAt": t0,
                                },
                            ],
                        }
                    ),
                )
            return HttpResponse(200, {}, json.dumps({"view": {"disputeId": "dsp_d126", "status": "BARGAINING"}}))

        c = AgentMediateClient(base_url="https://api.mediate.example", agent_key=a, transport=_tx, now_ms=lambda: t0)
        c.reject_issues("dsp_d126", "f" * 64, adopt_suggested_ids=["serviceCreditUsd"])
        rej_call = [x for x in seen if x[0] == "POST" and "/issues/reject" in x[1]][0]
        self.assertEqual(rej_call[2], {"issuesHash": "f" * 64, "adoptSuggestedIds": ["serviceCreditUsd"]})

        c.update_mandate("dsp_d126", bounds={"refundUsd": {"min": 450, "max": 1000}})
        upd_call = [x for x in seen if x[0] == "POST" and x[1].endswith("/v1/disputes/dsp_d126/mandate")][0]
        mnd = upd_call[2]["mandate"]
        assert isinstance(mnd, dict)
        self.assertTrue(verify_mandate_signature(mnd))
        self.assertEqual(mnd["issuedAt"], t0 + 501, "issuedAt advances strictly past previous issuedAt")
        self.assertEqual(mnd["expiresAt"], t0 + 90 * 86_400_000, "expiresAt preserves longer previous horizon")
        self.assertIs(mnd["determinationConsent"], True, "determinationConsent preserved automatically")
        self.assertEqual(set(mnd["scope"].keys()), {"contractHash", "counterpartyId"})

        # Counterparty redacted confidential_action signature is accepted without leaking action/party/agentId (SEC-1)
        sigs = c.signatures("dsp_d126")
        self.assertTrue(sigs["signatures"][1]["redacted"])
        self.assertEqual(sigs["signatures"][1]["action"], "confidential_action")

    def test_security_audit_v1_3_0_python_hardening(self) -> None:
        """SA2-PROTO-M1, SA2-PROTO-M2, SA2-SDK-H1, SA2-SDK-H2 & SA2-SDK-M1 Python parity regressions."""
        from agent_mediate.protocol import compute_outcome_hash, compute_terms_hash, ed25519_public_jwk_from_did_key

        # 1. SA2-PROTO-M1: RFC 8785 JCS ES6 boundary numbers match Node V8 byte-for-byte
        self.assertEqual(
            canonical_json({"a": 1e18, "b": 1e20, "c": 1e21, "d": 1e-6, "e": 1e-7, "z": -0.0}),
            '{"a":1000000000000000000,"b":100000000000000000000,"c":1e+21,"d":0.000001,"e":1e-7,"z":0}',
        )

        # 2. SA2-PROTO-M1: verify_request rejects raw dot-segments in target_uri
        signer = generate_agent_key()
        now_sec = 1_750_000_000
        req_headers = sign_request(
            method="POST",
            target_uri="https://api.mediate.example/v1/disputes",
            headers={"content-type": "application/json"},
            body="{}",
            key=signer,
            created=now_sec,
            nonce="py-dot-seg-000001",
        )
        dot_verdict = verify_request(
            method="POST",
            target_uri="https://api.mediate.example/v1/admin/../disputes",
            headers={"content-type": "application/json", **req_headers},
            body="{}",
            now_ms=now_sec * 1000,
        )
        self.assertFalse(dot_verdict["ok"])

        # 3. SA2-PROTO-M2: compromisedAfter on key-history rejects even backdated documents from compromised retired keys
        active = generate_agent_key()
        retired = generate_agent_key()
        t0 = 1_750_000_000_000
        kh_clean = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "platformDidWeb": "did:web:api.mediate.example",
                "activeDid": active.did,
                "activeKeyId": f"{active.did}#key-1",
                "updatedAt": t0,
                "keys": [
                    {
                        "keyId": f"{active.did}#key-1",
                        "did": active.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(active.did),
                        "status": "active",
                        "validFrom": t0 - 5_000,
                    },
                    {
                        "keyId": f"{retired.did}#key-1",
                        "did": retired.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(retired.did),
                        "status": "retired",
                        "validFrom": t0 - 100_000,
                        "validUntil": t0 - 5_000,
                    },
                ],
            },
            active,
            key_id=f"{active.did}#key-1",
            created_ms=t0,
        )
        kh = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "platformDidWeb": "did:web:api.mediate.example",
                "activeDid": active.did,
                "activeKeyId": f"{active.did}#key-1",
                "updatedAt": t0,
                "keys": [
                    {
                        "keyId": f"{active.did}#key-1",
                        "did": active.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(active.did),
                        "status": "active",
                        "validFrom": t0 - 5_000,
                    },
                    {
                        "keyId": f"{retired.did}#key-1",
                        "did": retired.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(retired.did),
                        "status": "retired",
                        "validFrom": t0 - 100_000,
                        "validUntil": t0 - 5_000,
                        "compromisedAfter": t0 - 20_000,
                    },
                ],
            },
            active,
            key_id=f"{active.did}#key-1",
            created_ms=t0,
        )
        retired_doc = sign_document({"type": "test/v1"}, retired, key_id=f"{retired.did}#key-1", created_ms=t0 - 50_000)
        self.assertTrue(verify_document_with_key_history(retired_doc, kh_clean, expected_active_did=active.did, now_ms=t0)["ok"])
        self.assertFalse(verify_document_with_key_history(retired_doc, kh, expected_active_did=active.did, now_ms=t0)["ok"])

        # 4. SA2-SDK-H1, SA2-SDK-H2 & SA2-SDK-M1: tampered outcome method -> OUTCOME_MISMATCH, 307 redirect -> UNEXPECTED_REDIRECT, >4 MiB -> RESPONSE_TOO_LARGE, missing signedNotice -> NOTICE_MISMATCH
        terms = {"refundUsd": 300}
        terms_hash = compute_terms_hash(terms)
        real_outcome_hash = compute_outcome_hash(
            {"kind": "SETTLED", "terms": terms, "method": "PROPOSAL_ACCEPTED", "at": t0, "roundsCompleted": 2},
            "HONORED",
        )
        mode = ["tampered_outcome"]

        def _tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            if url.endswith("/.well-known/key-history.json"):
                return HttpResponse(200, {"content-type": "application/json"}, json.dumps(kh))
            if mode[0] == "redirect":
                return HttpResponse(307, {"location": "http://169.254.169.254/"}, "")
            if mode[0] == "oversized":
                return HttpResponse(200, {"content-type": "application/json"}, "x" * (4 * 1024 * 1024 + 32))
            if mode[0] == "missing_notice":
                return HttpResponse(
                    201,
                    {"content-type": "application/json"},
                    json.dumps(
                        {
                            "disputeId": "dsp_py_sa2",
                            "view": {"disputeId": "dsp_py_sa2", "status": "AWAITING_RESPONDENT"},
                            "notice": {"noticeUrl": "https://api.mediate.example/n/tok"},
                        }
                    ),
                )
            tampered_doc = sign_document(
                {
                    "type": "agent-mediate/settlement-instruction/v1",
                    "rulesVersion": RULES_VERSION,
                    "rulesHash": RULES_HASH,
                    "environment": "production",
                    "disputeId": "dsp_py_sa2",
                    "contractHash": "a" * 64,
                    "status": "SETTLED",
                    "executionStatus": "HONORED",
                    "method": "FINAL_OFFER_DETERMINATION",  # forged method!
                    "settledAt": t0,
                    "roundsCompleted": 2,
                    "parties": {"claimant": {"agentId": signer.did}, "respondent": {"agentId": active.did}},
                    "issues": [{"id": "refundUsd", "label": "Refund", "unit": "USD", "min": 0, "max": 500, "step": 10, "claimantPrefers": "higher", "obligor": "respondent"}],
                    "terms": terms,
                    "termsHash": terms_hash,
                    "auditRoot": "b" * 64,
                    "outcomeHash": real_outcome_hash,
                },
                active,
                key_id=f"{active.did}#key-1",
                created_ms=t0,
            )
            return HttpResponse(200, {"content-type": "application/json"}, json.dumps(tampered_doc))

        py_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=signer,
            platform_did=active.did,
            expected_environment="production",
            transport=_tx,
            now_ms=lambda: t0,
            max_retries=0,
        )
        with self.assertRaises(AgentMediateError) as out_err:
            py_client.outcome("dsp_py_sa2")
        self.assertEqual(out_err.exception.code, "OUTCOME_MISMATCH")

        mode[0] = "redirect"
        with self.assertRaises(AgentMediateError) as redir_err:
            py_client.platform()
        self.assertEqual(redir_err.exception.code, "UNEXPECTED_REDIRECT")

        mode[0] = "oversized"
        with self.assertRaises(AgentMediateError) as big_err:
            py_client.platform()
        self.assertEqual(big_err.exception.code, "RESPONSE_TOO_LARGE")

        mode[0] = "missing_notice"
        issue = {"id": "refundUsd", "label": "Refund", "unit": "USD", "min": 0, "max": 500, "step": 10, "claimantPrefers": "higher", "obligor": "respondent"}
        with self.assertRaises(AgentMediateError) as notice_err:
            py_client.file_dispute(
                respondent_id=active.did,
                contract_hash="c" * 64,
                claim={"summary": "s", "requestedRemedy": "r"},
                proposed_issues=[issue],
                bounds={"refundUsd": {"min": 0, "max": 500}},
            )
        self.assertEqual(notice_err.exception.code, "NOTICE_MISMATCH")

    def test_mode_a_production_did_pinning_and_discover_ssrf_isolation(self) -> None:
        """H-1 & M-2: Python client enforces platform_did in production and keeps DNS SSRF vetting on client.discover_respondent."""
        signer = generate_agent_key()
        attacker_platform = generate_agent_key()
        real_platform = generate_agent_key()
        t0 = 1_762_000_000_000

        self.assertEqual(
            DEFAULT_PRODUCTION_PLATFORM_DIDS[PRODUCTION_API_URL],
            "did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W",
        )
        default_pinned = AgentMediateClient(
            base_url=PRODUCTION_API_URL,
            agent_key=signer,
            transport=lambda m, u, h, b: HttpResponse(200, {"content-type": "application/json"}, json.dumps({"did": attacker_platform.did})),
        )
        with self.assertRaises(AgentMediateError) as mismatch_err:
            default_pinned.platform()
        self.assertEqual(mismatch_err.exception.code, "PLATFORM_DID_MISMATCH")

        with self.assertRaisesRegex(ValueError, "platform_did must be pinned out of band"):
            AgentMediateClient(base_url="https://custom-prod.example", agent_key=signer, expected_environment="production")

        probe = AgentMediateClient(
            base_url="https://custom-prod.example",
            agent_key=signer,
            expected_environment="production",
            allow_unpinned_platform_did=True,
        )
        self.assertEqual(probe.base_url, "https://custom-prod.example")

        # Unpinned client rejects TOFU when a signed document declares environment == "production"
        forged_invite = sign_document(
            {
                "type": "agent-mediate/dispute-invite/v1",
                "rulesVersion": RULES_VERSION,
                "rulesHash": RULES_HASH,
                "environment": "production",
                "inviteId": "inv_py_tofu",
                "claimantId": signer.did,
                "respondentId": None,
                "contractHash": "a" * 64,
                "feeMode": "FILER_PAYS",
                "respondentFeeUsd": "0.00",
                "invitedAt": t0,
                "expiresAt": t0 + 3_600_000,
                "inviteUrl": "https://mirror.example/i/tok_py_tofu",
                "acceptEndpoint": "https://mirror.example/v1/invites/tok_py_tofu/accept",
                "inviteEndpoint": "https://mirror.example/v1/invites/inv_py_tofu",
            },
            attacker_platform,
            key_id=f"{attacker_platform.did}#key-1",
            created_ms=t0,
            expires_at_ms=t0 + 3_600_000,
        )
        unpinned = AgentMediateClient(
            base_url="https://mirror.example",
            agent_key=signer,
            now_ms=lambda: t0,
            transport=lambda m, u, h, b: HttpResponse(200, {"content-type": "application/json"}, json.dumps({"did": attacker_platform.did})),
        )
        with self.assertRaises(AgentMediateError) as tofu_err:
            unpinned.verify_invite(forged_invite)
        self.assertEqual(tofu_err.exception.code, "UNPINNED_PLATFORM_DID")

        # M-2: client constructed with custom `transport` passes it ONLY as `api_transport` for /v1/honours/:domain,
        # never bypassing DNS SSRF checks on third-party `target` domains!
        api_calls: list[str] = []

        def _api_tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            api_calls.append(url)
            return HttpResponse(200, {"content-type": "application/json"}, json.dumps({"listed": False}))

        pinned_client = AgentMediateClient(
            base_url="https://api.ai-agents-mediation.com",
            agent_key=signer,
            platform_did=real_platform.did,
            transport=_api_tx,
        )
        with self.assertRaisesRegex(ValueError, "target must resolve exclusively to public IP addresses"):
            pinned_client.discover_respondent(
                "internal-rebind.example",
                resolve_host=lambda host: ["127.0.0.1"],
            )
        self.assertEqual(api_calls, [])

    def test_p1_key_rotation_roll_forward_base_url_normalization_and_discover_parity(self) -> None:
        """P1-1, P1-2, P1-3: Python forward key-rotation roll-forward, normalize_base_url, check_honours guard, and discover_respondent parity."""
        from agent_mediate import (
            HONOURS_ATTESTATION_TYPE,
            KEY_HISTORY_TYPE,
            PRODUCTION_APEX_URL,
            PRODUCTION_API_URL,
            RULES_HASH,
            RULES_VERSION,
            build_did_web_document,
            discover_respondent,
            ed25519_public_jwk_from_did_key,
            normalize_base_url,
            sign_agent_card,
            sign_document,
            sign_key_rotation,
        )

        # P1-2: normalize_base_url rewrites apex, uppercase scheme/host, :443, and trailing slashes
        self.assertEqual(normalize_base_url(PRODUCTION_APEX_URL), PRODUCTION_API_URL)
        self.assertEqual(normalize_base_url("HTTPS://ai-agents-mediation.com:443/"), PRODUCTION_API_URL)
        self.assertEqual(normalize_base_url("HTTPS://API.AI-AGENTS-MEDIATION.COM:443///"), PRODUCTION_API_URL)

        t0 = 1_800_000_000_000
        k_old = generate_agent_key()
        k_new = generate_agent_key()
        signer = generate_agent_key()
        resp_key = generate_agent_key()

        rotation = sign_key_rotation(
            base_url="https://mirror.example",
            from_key=k_old,
            to_did=k_new.did,
            rotated_at_ms=t0 + 5_000,
            from_key_id=f"{k_old.did}#key-1",
        )
        kh_retired = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "platformDidWeb": "did:web:mirror.example",
                "activeDid": k_new.did,
                "activeKeyId": f"{k_new.did}#key-1",
                "updatedAt": t0 + 5_000,
                "keys": [
                    {
                        "keyId": f"{k_new.did}#key-1",
                        "did": k_new.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(k_new.did),
                        "status": "active",
                        "validFrom": t0 + 5_000,
                    },
                    {
                        "keyId": f"{k_old.did}#key-1",
                        "did": k_old.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(k_old.did),
                        "status": "retired",
                        "validFrom": t0 - 86_400_000,
                        "validUntil": t0 + 5_000,
                    },
                ],
                "rotations": [rotation],
            },
            k_new,
            key_id=f"{k_new.did}#key-1",
            created_ms=t0 + 5_000,
            expires_at_ms=t0 + 605_000,
        )
        prod_att = sign_document(
            {
                "type": HONOURS_ATTESTATION_TYPE,
                "rulesVersion": RULES_VERSION,
                "rulesHash": RULES_HASH,
                "environment": "production",
                "domain": "peer.example",
                "didWeb": "did:web:peer.example",
                "agentIds": [resp_key.did],
                "memberSince": t0,
                "verifiedAt": t0,
                "qualifiedHonoredCount": 3,
                "totalHonoredObligations": 3,
                "confirmedByCounterpartyCount": 3,
                "distinctCounterparties": 3,
                "verifiedDomainCounterparties": 2,
                "curedLateCount": 0,
                "fulfilmentRate": 1,
                "lastHonoredAt": t0,
                "issuedAt": t0 + 6_000,
            },
            k_new,
            key_id=f"{k_new.did}#key-1",
            created_ms=t0 + 6_000,
            expires_at_ms=t0 + 3_606_000,
        )

        def _tx_retired(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            if url == "https://mirror.example/v1/platform":
                return HttpResponse(200, {"content-type": "application/json"}, json.dumps({"did": k_new.did}))
            if url == "https://mirror.example/.well-known/key-history.json":
                return HttpResponse(200, {"content-type": "application/json"}, json.dumps(kh_retired))
            if url == "https://mirror.example/v1/honours/peer.example":
                return HttpResponse(
                    200,
                    {"content-type": "application/json"},
                    json.dumps({
                        "domain": "peer.example",
                        "listed": True,
                        "inGoodStanding": True,
                        "entry": prod_att["document"],
                        "signedAttestation": prod_att,
                    }),
                )
            return HttpResponse(404, {}, "not found")

        # 1. Pinned to k_old -> rolls forward cleanly to k_new!
        pinned_old = AgentMediateClient(
            base_url="https://mirror.example",
            agent_key=signer,
            platform_did=k_old.did,
            expected_environment="production",
            now_ms=lambda: t0 + 7_000,
            transport=_tx_retired,
        )
        self.assertEqual(pinned_old.platform()["did"], k_new.did)
        self.assertTrue(pinned_old.check_honours("peer.example")["verified"])

        # 2. Unpinned check_honours rejects environment=="production"
        unpinned_mirror = AgentMediateClient(
            base_url="https://mirror.example",
            agent_key=signer,
            now_ms=lambda: t0 + 7_000,
            transport=_tx_retired,
        )
        with self.assertRaises(AgentMediateError) as unpinned_honours_err:
            unpinned_mirror.check_honours("peer.example")
        self.assertEqual(unpinned_honours_err.exception.code, "UNPINNED_PLATFORM_DID")

        # 3. Honours-only domain without notice channels -> recommendedAction == "send_invite"
        disc_no_channel = discover_respondent(
            "peer.example",
            base_url="https://mirror.example",
            platform_did=k_old.did,
            expected_environment="production",
            api_transport=_tx_retired,
            transport=lambda m, u, h, b: HttpResponse(404, {}, "not found"),
            resolve_host=lambda host: ["93.184.216.34"],
            now_ms=lambda: t0 + 7_000,
        )
        self.assertEqual(disc_no_channel["respondentId"], resp_key.did)
        self.assertTrue(disc_no_channel["verifiedStanding"])
        self.assertEqual(disc_no_channel["recommendedAction"], "send_invite")

        # 4. With AgentMediateNotice in signed did.json -> "file_dispute"
        base_did_doc = build_did_web_document(base_url="https://peer.example", platform_did=resp_key.did)
        signed_did_doc = sign_agent_card(
            {
                **base_did_doc,
                "service": [{"id": "#notice", "type": "AgentMediateNotice", "serviceEndpoint": "https://peer.example/webhooks/mediate"}],
            },
            resp_key,
            kid=base_did_doc["verificationMethod"][0]["id"],
        )
        disc_with_did_notice = discover_respondent(
            "peer.example",
            base_url="https://mirror.example",
            platform_did=k_old.did,
            expected_environment="production",
            api_transport=_tx_retired,
            transport=lambda m, u, h, b: (
                HttpResponse(200, {"content-type": "application/json"}, json.dumps(signed_did_doc))
                if u == "https://peer.example/.well-known/did.json"
                else HttpResponse(404, {}, "not found")
            ),
            resolve_host=lambda host: ["93.184.216.34"],
            now_ms=lambda: t0 + 7_000,
        )
        self.assertEqual(disc_with_did_notice["recommendedAction"], "file_dispute")
        self.assertEqual(disc_with_did_notice["respondentContact"].get("webhookUrl"), "https://peer.example/webhooks/mediate")

        # 5. Revoked k_old fails closed even with rotation endorsement!
        kh_revoked = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "platformDidWeb": "did:web:mirror.example",
                "activeDid": k_new.did,
                "activeKeyId": f"{k_new.did}#key-1",
                "updatedAt": t0 + 5_000,
                "keys": [
                    {
                        "keyId": f"{k_new.did}#key-1",
                        "did": k_new.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(k_new.did),
                        "status": "active",
                        "validFrom": t0 + 5_000,
                    },
                    {
                        "keyId": f"{k_old.did}#key-1",
                        "did": k_old.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(k_old.did),
                        "status": "revoked",
                        "validFrom": t0 - 86_400_000,
                        "revokedAt": t0 + 5_000,
                        "compromisedAfter": t0 + 4_000,
                    },
                ],
                "rotations": [rotation],
            },
            k_new,
            key_id=f"{k_new.did}#key-1",
            created_ms=t0 + 5_000,
            expires_at_ms=t0 + 605_000,
        )
        revoked_client = AgentMediateClient(
            base_url="https://mirror.example",
            agent_key=signer,
            platform_did=k_old.did,
            expected_environment="production",
            now_ms=lambda: t0 + 7_000,
            transport=lambda m, u, h, b: (
                HttpResponse(200, {"content-type": "application/json"}, json.dumps({"did": k_new.did}))
                if u.endswith("/v1/platform")
                else HttpResponse(200, {"content-type": "application/json"}, json.dumps(kh_revoked))
            ),
        )
        with self.assertRaises(AgentMediateError) as rev_err:
            revoked_client.platform()
        self.assertEqual(rev_err.exception.code, "PLATFORM_DID_MISMATCH")

    def test_batch2_v0_1_2_python_sdk_and_protocol_regressions(self) -> None:
        """H-04, H-05, M-09a, M-09c, M-11a, L-08, L-09: Python v0.1.2 parity regressions."""
        from agent_mediate import (
            DISPUTE_NOTICE_TYPE,
            KEY_HISTORY_TYPE,
            PaymentPolicyError,
            RULES_HASH,
            RULES_VERSION,
            build_clause,
            discover_respondent,
            ed25519_public_jwk_from_did_key,
            loads_jcs_json,
            sign_agent_card,
            sign_clause,
            sign_document,
            sign_key_rotation,
            sign_mandate,
            sign_request,
            validate_issues_against_clause_templates,
            verify_agent_card_signature,
            verify_clause,
            verify_dispute_action_target,
            verify_key_history,
            verify_request,
        )

        # L-08: loads_jcs_json rejects NaN / Infinity / -Infinity
        for non_json in ("NaN", "Infinity", "-Infinity", '{"x":NaN}'):
            with self.assertRaises(ValueError):
                loads_jcs_json(non_json)

        k_old = generate_agent_key()
        k_new = generate_agent_key()
        claimant = generate_agent_key()
        respondent = generate_agent_key()
        t0 = 1_800_000_000_000
        pay_to = "0x1111111111111111111111111111111111111111"

        rot = sign_key_rotation(
            base_url="https://api.mediate.example",
            from_key=k_old,
            to_did=k_new.did,
            rotated_at_ms=t0 + 1_000,
        )
        kh_rotated = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "platformDidWeb": "did:web:api.mediate.example",
                "activeDid": k_new.did,
                "activeKeyId": f"{k_new.did}#key-1",
                "updatedAt": t0 + 1_000,
                "keys": [
                    {
                        "keyId": f"{k_new.did}#key-1",
                        "did": k_new.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(k_new.did),
                        "status": "active",
                        "validFrom": t0 + 1_000,
                    },
                    {
                        "keyId": f"{k_old.did}#key-1",
                        "did": k_old.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(k_old.did),
                        "status": "retired",
                        "validFrom": t0 - 86_400_000,
                        "validUntil": t0 + 1_000,
                    },
                ],
                "rotations": [rot],
            },
            k_new,
            key_id=f"{k_new.did}#key-1",
            created_ms=t0 + 1_000,
            expires_at_ms=t0 + 601_000,
        )
        card_new = sign_agent_card(
            {
                "name": "Agent-Mediate",
                "url": "https://api.mediate.example",
                "provider": {"organization": "Agent-Mediate", "url": "https://api.mediate.example"},
                "capabilities": {
                    "extensions": [
                        {"uri": "urn:agent-mediate:ext:rest-api:v1", "params": {"baseUrl": "https://api.mediate.example"}},
                        {"uri": "urn:agent-mediate:ext:x402-fees:v1", "params": {"payTo": pay_to}},
                    ]
                },
            },
            k_new,
            kid="did:web:api.mediate.example#key-1",
        )
        challenge_b64 = base64.b64encode(
            json.dumps(
                {"x402Version": 2, "accepts": [{"scheme": "exact", "network": "eip155:84532", "amount": "2000000", "payTo": pay_to}]}
            ).encode("utf-8")
        ).decode("ascii")

        released: list[str] = []
        mode = {"v": "ok"}

        class _MockPayer:
            network = "eip155:84532"

            def pay(self, challenge: object, *, operation: str, expected_pay_to: str | None = None) -> str:
                self.last_pay_to = expected_pay_to
                return f"py-pay-{mode['v']}"

            def release_unsettled(self, sig: str) -> None:
                released.append(sig)

        def paid_transport(method: str, url: str, headers: dict[str, str], body: bytes | None) -> HttpResponse:
            if url.endswith("/v1/platform"):
                return HttpResponse(
                    200,
                    {"content-type": "application/json"},
                    json.dumps(
                        {
                            "did": k_new.did,
                            "rulesVersion": RULES_VERSION,
                            "rulesHash": RULES_HASH,
                            "fees": {"payTo": pay_to, "network": "eip155:84532", "fullFeeAtomic": "2000000"},
                        }
                    ),
                )
            if url.endswith("/.well-known/key-history.json"):
                return HttpResponse(200, {"content-type": "application/json"}, json.dumps(kh_rotated))
            if url.endswith("/.well-known/agent-card.json"):
                return HttpResponse(200, {"content-type": "application/json"}, json.dumps(card_new))
            if url.endswith("/v1/disputes"):
                if "payment-signature" not in headers:
                    return HttpResponse(
                        402,
                        {"content-type": "application/json", "payment-required": challenge_b64},
                        json.dumps({"code": "PAYMENT_REQUIRED"}),
                    )
                if mode["v"] == "reject_402":
                    return HttpResponse(402, {"content-type": "application/json"}, json.dumps({"code": "INVALID_PAYMENT", "detail": "bad"}))
                if mode["v"] == "ambiguous_503":
                    return HttpResponse(503, {"content-type": "application/json"}, json.dumps({"code": "FACILITATOR_UNAVAILABLE"}))
                notice = sign_document(
                    {
                        "type": DISPUTE_NOTICE_TYPE,
                        "disputeId": "dsp_py_rot_1",
                        "environment": "production",
                        "rulesVersion": RULES_VERSION,
                        "rulesHash": RULES_HASH,
                        "claimantId": claimant.did,
                        "respondentId": respondent.did,
                        "contractHash": "a" * 64,
                        "feeMode": "FILER_PAYS",
                        "respondentJoinFeeUsd": "0.00",
                        "joinDeadline": t0 + 86_400_000,
                        "noticeUrl": "https://api.mediate.example/n/tok_py_1",
                        "issuedAt": t0 + 5_000,
                    },
                    k_new,
                    created_ms=t0 + 5_000,
                    expires_at_ms=t0 + 86_400_000,
                )
                return HttpResponse(
                    201,
                    {"content-type": "application/json"},
                    json.dumps(
                        {
                            "disputeId": "dsp_py_rot_1",
                            "view": {"status": "AWAITING_RESPONDENT"},
                            "notice": {
                                "token": "tok_py_1",
                                "noticeUrl": "https://api.mediate.example/n/tok_py_1",
                                "signedNotice": notice,
                                "delivery": {"delivered": False, "attempts": []},
                            },
                        }
                    ),
                )
            return HttpResponse(404, {}, "not found")

        def make_client() -> AgentMediateClient:
            return AgentMediateClient(
                base_url="https://api.mediate.example",
                agent_key=claimant,
                platform_did=k_old.did,
                expected_environment="production",
                payer=_MockPayer(),
                now_ms=lambda: t0 + 5_000,
                max_retries=0,
                transport=paid_transport,
            )

        file_args = dict(
            respondent_id=respondent.did,
            contract_hash="a" * 64,
            claim={"summary": "SLA", "requestedRemedy": "Credit"},
            proposed_issues=[
                {
                    "id": "creditUsd",
                    "label": "Credit",
                    "unit": "USD",
                    "min": 0,
                    "max": 500,
                    "step": 25,
                    "claimantPrefers": "higher",
                    "obligor": "respondent",
                }
            ],
            bounds={"creditUsd": {"min": 0, "max": 500}},
        )

        # H-04: Paid file_dispute succeeds after K_old -> K_new rotation
        res_ok = make_client().file_dispute(**file_args, idempotency_key="py-rot-ok")
        self.assertEqual(res_ok["disputeId"], "dsp_py_rot_1")
        self.assertEqual(released, [])

        # H-05: Definitive 402 INVALID_PAYMENT sets payment_sent=False and calls release_unsettled
        mode["v"] = "reject_402"
        with self.assertRaises(AgentMediateError) as rej_ctx:
            make_client().file_dispute(**file_args, idempotency_key="py-rej-402")
        self.assertEqual(rej_ctx.exception.code, "INVALID_PAYMENT")
        self.assertFalse(rej_ctx.exception.payment_sent)
        self.assertEqual(released, ["py-pay-reject_402"])

        # H-05: Ambiguous 503 FACILITATOR_UNAVAILABLE keeps payment_sent=True and does NOT release
        mode["v"] = "ambiguous_503"
        with self.assertRaises(AgentMediateError) as amb_ctx:
            make_client().file_dispute(**file_args, idempotency_key="py-amb-503")
        self.assertTrue(amb_ctx.exception.payment_sent)
        self.assertEqual(released, ["py-pay-reject_402"])

        # M-09a: Bare signed mandate dict passed as bounds raises ValueError
        bare_mnd = sign_mandate(
            {
                "id": "mnd_py_bare",
                "principalId": claimant.did,
                "agentId": claimant.did,
                "bounds": {"creditUsd": {"min": 0, "max": 500}},
                "issuedAt": t0,
                "expiresAt": t0 + 86_400_000,
            },
            claimant,
        )
        with self.assertRaises(ValueError):
            make_client().confirm_issues("dsp_1", "b" * 64, bounds=bare_mnd)  # type: ignore[arg-type]

        # M-09c & L-08: discover_respondent JSON-RPC binding & cross-origin Agent Card suppression
        jrpc_card = sign_agent_card(
            {"name": "Vendor", "supportedInterfaces": [{"url": "https://vendor.example/a2a", "protocolBinding": "JSON-RPC"}]},
            respondent,
            kid=respondent.did,
        )
        disc_jrpc = discover_respondent(
            "vendor.example",
            resolve_host=lambda _h: ["93.184.216.34"],
            transport=lambda _m, u, _h, _b: (
                HttpResponse(200, {"content-type": "application/json"}, json.dumps(jrpc_card))
                if u == "https://vendor.example/.well-known/agent-card.json"
                else HttpResponse(404, {}, "")
            ),
        )
        self.assertEqual(disc_jrpc["respondentId"], respondent.did)
        self.assertTrue(disc_jrpc["hasVerifiedNoticeChannel"])

        disc_foreign = discover_respondent(
            "cold.example",
            resolve_host=lambda _h: ["93.184.216.34"],
            transport=lambda _m, u, _h, _b: (
                HttpResponse(
                    200,
                    {"content-type": "application/json"},
                    json.dumps(
                        {
                            "name": "Foreign",
                            "url": "https://evil.example/a2a",
                            "provider": {"url": "https://evil.example", "email": "evil@evil.example"},
                        }
                    ),
                )
                if u == "https://cold.example/.well-known/agent-card.json"
                else HttpResponse(200, {"content-type": "text/plain"}, "Contact: mailto:security@cold.example\n")
                if u == "https://cold.example/.well-known/security.txt"
                else HttpResponse(404, {}, "")
            ),
        )
        self.assertNotIn("a2aCardUrl", disc_foreign["respondentContact"])
        self.assertEqual(disc_foreign["respondentContact"].get("email"), "security@cold.example")
        self.assertEqual(disc_foreign["sources"], ["security_txt"])

        # M-11a: verify_clause forward rotation & revocation + verify_key_history rotatedAt > validUntil
        clause_old = sign_clause(
            sign_clause(
                build_clause(
                    contract_hash_hex="c" * 64,
                    platform_did=k_old.did,
                    platform_base_url="https://api.mediate.example",
                    rules_hash=RULES_HASH,
                    issued_at=t0 - 10_000,
                    parties=[{"agentId": claimant.did}, {"agentId": respondent.did}],
                ),
                claimant,
            ),
            respondent,
        )
        self.assertTrue(
            verify_clause(clause_old, expected_platform_did=k_old.did, key_history=kh_rotated, now_ms=t0 + 5_000)["ok"]
        )
        kh_late = sign_document(
            {
                **kh_rotated["document"],
                "keys": [
                    kh_rotated["document"]["keys"][0],
                    {**kh_rotated["document"]["keys"][1], "validUntil": t0 + 500},
                ],
            },
            k_new,
            key_id=f"{k_new.did}#key-1",
            created_ms=t0 + 1_000,
            expires_at_ms=t0 + 601_000,
        )
        self.assertFalse(verify_key_history(kh_late, expected_active_did=k_old.did, now_ms=t0 + 5_000)["ok"])

        # L-09: @target-uri trailing whitespace, expected_round, exact step, and >16 card signatures
        hdrs = {
            "content-type": "application/json",
            **sign_request(
                method="POST",
                target_uri="https://api.mediate.example/v1/disputes/dsp_1/rounds/2/offer",
                headers={"content-type": "application/json"},
                body="{}",
                key=claimant,
                created=t0 // 1000,
                nonce="py-b2-nonce-00001",
            ),
        }
        self.assertFalse(
            verify_request(
                method="POST",
                target_uri="https://api.mediate.example/v1/disputes/dsp_1/rounds/2/offer ",
                headers=hdrs,
                body="{}",
                now_ms=t0,
            )["ok"]
        )
        self.assertTrue(
            verify_dispute_action_target(
                {"method": "POST", "targetUri": "https://api.mediate.example/v1/disputes/dsp_1/rounds/2/offer"},
                expected_base_url="https://api.mediate.example",
                expected_dispute_id="dsp_1",
                expected_action="submit_offer",
                expected_round=2,
            )["ok"]
        )
        self.assertFalse(
            verify_dispute_action_target(
                {"method": "POST", "targetUri": "https://api.mediate.example/v1/disputes/dsp_1/rounds/2/offer"},
                expected_base_url="https://api.mediate.example",
                expected_dispute_id="dsp_1",
                expected_action="submit_offer",
                expected_round=1,
            )["ok"]
        )
        self.assertFalse(
            validate_issues_against_clause_templates(
                [
                    {
                        "id": "creditUsd",
                        "label": "Credit",
                        "unit": "USD",
                        "min": 0,
                        "max": 100,
                        "step": 1.0000000000000002,
                        "claimantPrefers": "higher",
                        "obligor": "respondent",
                    }
                ],
                [
                    {
                        "id": "creditUsd",
                        "label": "Credit",
                        "unit": "USD",
                        "min": 0,
                        "max": 100,
                        "step": 1,
                        "claimantPrefers": "higher",
                        "obligor": "respondent",
                    }
                ],
            )["ok"]
        )
        self.assertFalse(
            verify_agent_card_signature(
                {"name": "Flooded", "signatures": [{"protected": "e30", "signature": "AA"}] * 17},
                k_new.did,
            )
        )


if __name__ == "__main__":
    unittest.main()
