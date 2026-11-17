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
    HONOURS_ATTESTATION_TYPE,
    HttpResponse,
    KEY_HISTORY_TYPE,
    MECHANISM_SPEC,
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
    discover_respondent,
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



class PythonProtocolTests(unittest.TestCase):
    def test_rfc9421_mandate_clause_and_webhook_helpers(self) -> None:
        a = generate_agent_key()
        b = generate_agent_key()
        platform = generate_agent_key()

        # Mandate
        m = sign_mandate(
            {
                "id": "mnd_1",
                "principalId": a.did,
                "agentId": a.did,
                "bounds": {"refundUsd": {"min": 0, "max": 1000}},
                "expiresAt": 1900000000000,
                "issuedAt": 1800000000000,
            },
            a,
        )
        self.assertTrue(verify_mandate_signature(m))

        # Pre-dispute clause
        draft = build_clause(
            contract={"service": "API", "sla": "99.9%"},
            platform_did=platform.did,
            parties=[{"agentId": a.did}, {"agentId": b.did}],
            terms={"feeMode": "FILER_PAYS", "determinationConsent": True},
            issued_at=1800000000000,
        )
        cosigned = sign_clause(sign_clause(draft, a), b)
        verdict = verify_clause(cosigned, expected_platform_did=platform.did, claimant_id=a.did, respondent_id=b.did)
        self.assertTrue(verdict["ok"])

        # Signed document (v2 with keyId, created, expiresAt + downgrade resistance)
        sdoc = sign_document(
            {"type": "agent-mediate/settlement-instruction/v1", "disputeId": "dsp_1"},
            platform,
            created_ms=1800000000000,
            expires_at_ms=1800086400000,
        )
        self.assertTrue(verify_document(sdoc, platform.did, now_ms=1800000001000))
        self.assertFalse(verify_document(sdoc, platform.did, now_ms=1800086400000), "expired proof rejected")
        self.assertFalse(verify_document(sdoc, a.did))
        stripped = {"document": sdoc["document"], "proof": {k: v for k, v in sdoc["proof"].items() if k != "expiresAt"}}
        self.assertFalse(verify_document(stripped, platform.did), "stripping expiresAt invalidates v2 signature")

        # Key history verification (retired accepted within window; revoked unconditionally rejected)
        retired_key = generate_agent_key()
        revoked_key = generate_agent_key()
        key_hist = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "platformDidWeb": "did:web:mediate.example",
                "activeDid": platform.did,
                "activeKeyId": f"{platform.did}#key-1",
                "updatedAt": 1800005000000,
                "keys": [
                    {
                        "keyId": f"{platform.did}#key-1",
                        "did": platform.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(platform.did),
                        "status": "active",
                        "validFrom": 1800002000000,
                    },
                    {
                        "keyId": f"{retired_key.did}#key-1",
                        "did": retired_key.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(retired_key.did),
                        "status": "retired",
                        "validFrom": 1800000000000,
                        "validUntil": 1800002000000,
                    },
                    {
                        "keyId": f"{revoked_key.did}#key-1",
                        "did": revoked_key.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(revoked_key.did),
                        "status": "revoked",
                        "validFrom": 1799000000000,
                        "validUntil": 1800000000000,
                    },
                ],
            },
            platform,
            created_ms=1800005000000,
            expires_at_ms=1800090000000,
        )
        retired_doc = sign_document({"disputeId": "dsp_old"}, retired_key, created_ms=1800001000000)
        self.assertTrue(
            verify_document_with_key_history(retired_doc, key_hist, expected_active_did=platform.did, now_ms=1800005000000)["ok"]
        )
        revoked_doc = sign_document({"disputeId": "dsp_compromised"}, revoked_key, created_ms=1799500000000)
        self.assertFalse(
            verify_document_with_key_history(revoked_doc, key_hist, expected_active_did=platform.did, now_ms=1800005000000)["ok"]
        )

        # Base anchor calldata & bilateral proposal opening verification
        calldata = encode_base_anchor_calldata(42, "ab" * 32)
        self.assertEqual(decode_base_anchor_calldata(calldata), {"checkpointSeq": 42, "merkleRoot": "ab" * 32})
        issue = {"id": "refundUsd", "label": "Refund", "unit": "USD", "min": 0, "max": 1000, "step": 10, "claimantPrefers": "higher", "obligor": "respondent"}
        c_priv = {"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 300}}
        r_priv = {"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 700}}
        c_salt = derive_party_input_salt("salt_123", "dsp_1", "claimant")
        r_salt = derive_party_input_salt("salt_123", "dsp_1", "respondent")
        opened = verify_proposal_opening(
            {
                "disputeId": "dsp_1",
                "issues": [issue],
                "mode": "keyed",
                "proposalKeyOrSalt": "pkey_secret_hex",
                "proposalKeyCommitment": compute_proposal_key_commitment("dsp_1", "pkey_secret_hex", "keyed"),
                "declared": {
                    "claimant": {"private": c_priv, "partySalt": c_salt, "commitment": compute_declared_input_commitment("dsp_1", "claimant", c_salt, c_priv)},
                    "respondent": {"private": r_priv, "partySalt": r_salt, "commitment": compute_declared_input_commitment("dsp_1", "respondent", r_salt, r_priv)},
                },
            }
        )
        self.assertTrue(opened["ok"])
        self.assertTrue(420 <= opened["expectedProposal"]["views"]["claimant"]["refundUsd"] <= 580)
        self.assertEqual(opened["expectedDeterminationReference"], {"refundUsd": 500.0})

        # Webhook RFC 9421 verification
        hook_url = "https://agent.example/webhooks/mediate"
        hook_body = json.dumps(
            {
                "disputeId": "dsp_1",
                "seq": 1,
                "type": "DISPUTE_FILED",
                "at": 1800000000000,
                "data": {},
                "recipient": {"party": "respondent", "agentId": b.did},
            }
        )
        hook_headers = sign_request(
            method="POST",
            target_uri=hook_url,
            body=hook_body,
            key=platform,
            created=1800000000,
            nonce="wh_nonce_0123456789abcdef",
            tag=WEBHOOK_SIGNATURE_TAG,
        )
        verified_hook = AgentMediateClient.verify_webhook(
            url=hook_url,
            headers=hook_headers,
            body=hook_body,
            platform_did=platform.did,
            now_ms=1800000000 * 1000,
            agent_id=b.did,
            dispute_id="dsp_1",
        )
        self.assertTrue(verified_hook["ok"])
        # API verify_request rejects webhook tag
        self.assertFalse(
            verify_request(method="POST", target_uri=hook_url, headers=hook_headers, body=hook_body, now_ms=1800000000 * 1000)["ok"]
        )

    def test_phase4_hardening_and_parity(self) -> None:
        a = generate_agent_key()
        b = generate_agent_key()
        platform = generate_agent_key()

        # 1. verify_document parity: rejects expiresAt=None, float created, and created > 2^53 - 1
        valid_doc = sign_document({"disputeId": "dsp_1"}, platform, created_ms=1800000000000)
        null_exp = {"document": valid_doc["document"], "proof": {**valid_doc["proof"], "expiresAt": None}}
        self.assertFalse(verify_document(null_exp, platform.did))
        float_created = {"document": valid_doc["document"], "proof": {**valid_doc["proof"], "created": 1800000000000.0}}
        self.assertFalse(verify_document(float_created, platform.did))
        huge_created = {"document": valid_doc["document"], "proof": {**valid_doc["proof"], "created": 9007199254740992}}
        self.assertFalse(verify_document(huge_created, platform.did))

        # 2. Base anchor calldata safe-integer (2^53 - 1) cap
        max_safe = 9007199254740991
        max_cd = encode_base_anchor_calldata(max_safe, "cd" * 32)
        self.assertEqual(decode_base_anchor_calldata(max_cd), {"checkpointSeq": max_safe, "merkleRoot": "cd" * 32})
        with self.assertRaises(ValueError):
            encode_base_anchor_calldata(max_safe + 1, "cd" * 32)
        unsafe_cd = "0x414d4350" + (max_safe + 1).to_bytes(8, "big").hex() + ("cd" * 32)
        self.assertIsNone(decode_base_anchor_calldata(unsafe_cd))

        # 3. build_clause defaults rules_hash to RULES_HASH; verify_clause rejects missing rulesHash when expected_rules_hash is set
        default_clause = sign_clause(
            sign_clause(
                build_clause(
                    contract={"id": 1},
                    platform_did=platform.did,
                    parties=[{"agentId": a.did}, {"agentId": b.did}],
                    terms={"feeMode": "FILER_PAYS"},
                ),
                a,
            ),
            b,
        )
        self.assertEqual(default_clause["platform"]["rulesHash"], RULES_HASH)
        self.assertTrue(
            verify_clause(
                default_clause,
                expected_platform_did=platform.did,
                expected_rules_hash=RULES_HASH,
                claimant_id=a.did,
                respondent_id=b.did,
            )["ok"]
        )
        no_rh_clause = sign_clause(
            sign_clause(
                build_clause(
                    contract={"id": 1},
                    platform_did=platform.did,
                    rules_hash=None,
                    parties=[{"agentId": a.did}, {"agentId": b.did}],
                    terms={"feeMode": "FILER_PAYS"},
                ),
                a,
            ),
            b,
        )
        self.assertNotIn("rulesHash", no_rh_clause["platform"])
        self.assertFalse(
            verify_clause(
                no_rh_clause,
                expected_platform_did=platform.did,
                expected_rules_hash=RULES_HASH,
                claimant_id=a.did,
                respondent_id=b.did,
            )["ok"]
        )

        # 4. verify_document_with_key_history rejects string keys & unknown key status without raising
        bad_keys_hist = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "activeDid": platform.did,
                "activeKeyId": f"{platform.did}#key-1",
                "updatedAt": 1800005000000,
                "keys": "not-an-array",
            },
            platform,
            created_ms=1800005000000,
        )
        self.assertFalse(
            verify_document_with_key_history(valid_doc, bad_keys_hist, expected_active_did=platform.did, now_ms=1800005000000)["ok"]
        )
        unknown_key = generate_agent_key()
        unknown_status_hist = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "activeDid": platform.did,
                "activeKeyId": f"{platform.did}#key-1",
                "updatedAt": 1800005000000,
                "keys": [
                    {
                        "keyId": f"{platform.did}#key-1",
                        "did": platform.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(platform.did),
                        "status": "active",
                        "validFrom": 1800000000000,
                    },
                    {
                        "keyId": f"{unknown_key.did}#key-1",
                        "did": unknown_key.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(unknown_key.did),
                        "status": "suspended",
                        "validFrom": 1799000000000,
                        "validUntil": 1800002000000,
                    },
                ],
            },
            platform,
            created_ms=1800005000000,
        )
        unknown_doc = sign_document({"disputeId": "dsp_u"}, unknown_key, created_ms=1800000000000)
        self.assertFalse(
            verify_document_with_key_history(
                unknown_doc, unknown_status_hist, expected_active_did=platform.did, now_ms=1800005000000
            )["ok"]
        )

        # 5. Salted proposal opening requires derived proposalSalt (never raw audit.salt), binds expectedIssuesHash, and never raises (M8, Low)
        issue = {
            "id": "refundUsd",
            "label": "Refund",
            "unit": "USD",
            "min": 0,
            "max": 1000,
            "step": 10,
            "claimantPrefers": "higher",
            "obligor": "respondent",
        }
        c_priv = {"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 300}}
        r_priv = {"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 700}}
        master_salt = "master_audit_salt_do_not_reveal"
        p_salt = derive_proposal_salt(master_salt, "dsp_salted")
        c_salt = derive_party_input_salt(master_salt, "dsp_salted", "claimant")
        r_salt = derive_party_input_salt(master_salt, "dsp_salted", "respondent")
        salted_opening = {
            "disputeId": "dsp_salted",
            "issues": [issue],
            "expectedIssuesHash": sha256_hex(canonical_json([issue])),
            "mode": "salted",
            "proposalKeyOrSalt": p_salt,
            "proposalKeyCommitment": compute_proposal_key_commitment("dsp_salted", p_salt, "salted"),
            "declared": {
                "claimant": {
                    "private": c_priv,
                    "partySalt": c_salt,
                    "commitment": compute_declared_input_commitment("dsp_salted", "claimant", c_salt, c_priv),
                },
                "respondent": {
                    "private": r_priv,
                    "partySalt": r_salt,
                    "commitment": compute_declared_input_commitment("dsp_salted", "respondent", r_salt, r_priv),
                },
            },
        }
        self.assertTrue(verify_proposal_opening(salted_opening)["ok"])
        self.assertFalse(verify_proposal_opening({**salted_opening, "proposalKeyOrSalt": master_salt})["ok"])
        self.assertFalse(verify_proposal_opening({**salted_opening, "expectedIssuesHash": "0" * 64})["ok"])
        self.assertFalse(verify_proposal_opening(None)["ok"])  # type: ignore[arg-type]
        self.assertFalse(verify_proposal_opening({})["ok"])

        # 6. Hand-computed 5-leaf Merkle vector + expected_total_leaves swap rejection + malformed input guard (M3b, Low)
        leaves = [
            {
                "disputeId": f"dsp_{i}",
                "status": "HONORED",
                "auditSeq": i + 1,
                "auditHead": f"{i + 1:064x}",
                "outcomeHash": f"{i + 10:064x}",
            }
            for i in range(5)
        ]
        lh = [checkpoint_leaf_hash(lf) for lf in leaves]
        left_sub = checkpoint_node_hash(checkpoint_node_hash(lh[0], lh[1]), checkpoint_node_hash(lh[2], lh[3]))
        root5 = checkpoint_node_hash(left_sub, lh[4])
        proof_idx4 = {
            "leafHash": lh[4],
            "leafIndex": 4,
            "totalLeaves": 5,
            "siblings": [{"side": "left", "hash": left_sub}],
        }
        self.assertTrue(verify_checkpoint_inclusion(leaves[4], proof_idx4, root5, expected_total_leaves=5))
        swapped_n2 = {**proof_idx4, "leafIndex": 1, "totalLeaves": 2}
        self.assertFalse(verify_checkpoint_inclusion(leaves[4], swapped_n2, root5, expected_total_leaves=5))
        flipped_side = {**proof_idx4, "siblings": [{"side": "right", "hash": left_sub}]}
        self.assertFalse(verify_checkpoint_inclusion(leaves[4], flipped_side, root5, expected_total_leaves=5))
        self.assertFalse(verify_checkpoint_inclusion(None, None, "bad"))  # type: ignore[arg-type]

        # 7. Request covered-component allowlist (M1) & dispute/action target binding (M6)
        withdraw_url = "https://api.mediate.example/v1/disputes/dsp_a/withdraw"
        req_headers = sign_request(
            method="POST",
            target_uri=withdraw_url,
            body="{}",
            key=a,
            headers={"idempotency-key": "idem_withdraw_12345"},
            created=1800000000,
            nonce="nonce_withdraw_0123456789",
        )
        verified_req = verify_request(
            method="POST",
            target_uri=withdraw_url,
            headers={"idempotency-key": "idem_withdraw_12345", **req_headers},
            body="{}",
            now_ms=1800000000 * 1000,
        )
        self.assertTrue(verified_req["ok"])
        proof = verified_req["proof"]
        proof_hash = compute_request_proof_hash(proof)
        self.assertTrue(
            verify_request_proof(
                proof,
                expected_agent_id=a.did,
                expected_proof_hash=proof_hash,
                expected_base_url="https://api.mediate.example",
                expected_dispute_id="dsp_a",
                expected_action="withdraw",
            )["ok"]
        )
        self.assertFalse(
            verify_request_proof(
                proof,
                expected_agent_id=a.did,
                expected_base_url="https://api.mediate.example",
                expected_dispute_id="dsp_b",
                expected_action="withdraw",
            )["ok"]
        )
        self.assertFalse(
            verify_dispute_action_target(
                proof,
                expected_dispute_id="dsp_a",
                expected_action="close_evidence",
                expected_base_url="https://api.mediate.example",
            )["ok"]
        )
        # Covering an unstored header ("x-junk") is rejected at auth time (M1)
        extra_sig_params = f'("@method" "@target-uri" "x-junk");created=1800000000;keyid="{a.did}";alg="ed25519";nonce="nonce_xjunk_0123456789ab"'
        extra_base = f'"@method": GET\n"@target-uri": {withdraw_url}\n"x-junk": poison\n"@signature-params": {extra_sig_params}'
        extra_sig = base64.b64encode(ed25519_sign(a.seed, extra_base.encode("utf-8"))).decode("ascii")
        extra_res = verify_request(
            method="GET",
            target_uri=withdraw_url,
            headers={
                "x-junk": "poison",
                "signature-input": f"sig1={extra_sig_params}",
                "signature": f"sig1=:{extra_sig}:",
            },
            body="",
            now_ms=1800000000 * 1000,
        )
        self.assertFalse(extra_res["ok"])
        self.assertIn("unsupported component", extra_res["reason"])

        # 8. Python SDK client fail-closed envelope & strict=False signature checks (M1, M5, M6, Low)
        notice_doc = sign_document(
            {"type": "agent-mediate/dispute-notice/v1", "disputeId": "dsp_a"},
            platform,
            created_ms=1800000000000,
        )
        bad_cp_doc = sign_document(
            {
                "type": "agent-mediate/transparency-checkpoint/v1",
                "checkpointSeq": 1,
                "disputeCount": 1,
                "merkleRoot": "ab" * 32,
                "prevCheckpointHash": "00" * 32,
                "baseAnchorCalldata": encode_base_anchor_calldata(99, "ab" * 32),
                "rulesHash": RULES_HASH,
                "environment": "development",
            },
            platform,
            created_ms=1800000000000,
        )
        tampered_proof = {**proof, "targetUri": "https://api.mediate.example/v1/disputes/dsp_other/withdraw"}
        file_proof = {
            "method": "POST",
            "targetUri": "https://api.mediate.example/v1/disputes",
            "signatureInput": f'sig1=("@method" "@target-uri");created=1800000000;keyid="{a.did}";alg="ed25519";nonce="nonce_file_0123456789abcdef"',
            "signature": "sig1=:"
            + base64.b64encode(
                ed25519_sign(
                    a.seed,
                    (
                        '"@method": POST\n'
                        '"@target-uri": https://api.mediate.example/v1/disputes\n'
                        f'"@signature-params": ("@method" "@target-uri");created=1800000000;keyid="{a.did}";alg="ed25519";nonce="nonce_file_0123456789abcdef"'
                    ).encode("utf-8"),
                )
            ).decode("ascii")
            + ":",
        }
        file_proof_hash = compute_request_proof_hash(file_proof)

        def _mock_transport(method: str, url: str, _headers: Mapping[str, str], _body: Optional[bytes]) -> HttpResponse:
            if url.endswith("/v1/platform"):
                return HttpResponse(200, {}, json.dumps({"did": platform.did}))
            if url.endswith("/outcome"):
                return HttpResponse(200, {}, json.dumps(notice_doc))
            if url.endswith("/v1/transparency/checkpoint"):
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "signedCheckpoint": bad_cp_doc,
                            "checkpointHash": sha256_hex("agent-mediate/checkpoint-chain/v1\n" + canonical_json(bad_cp_doc["document"])),
                            "anchor": None,
                        }
                    ),
                )
            if url.endswith("/audit"):
                entry_hash = sha256_hex("agent-mediate/audit/v1\n" + ("0" * 64) + "\n1\nDISPUTE_FILED\n1800000000000\n{}")
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "head": entry_hash,
                            "entries": [
                                {
                                    "seq": 1,
                                    "type": "DISPUTE_FILED",
                                    "at": 1800000000000,
                                    "prevHash": "0" * 64,
                                    "data": {},
                                    "hash": entry_hash,
                                }
                            ],
                        }
                    ),
                )
            if url.endswith("/signatures"):
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "disputeId": "dsp_a",
                            "signatures": [
                                {
                                    "id": 0,
                                    "party": "claimant",
                                    "agentId": a.did,
                                    "action": "file_dispute",
                                    "seqRange": [1, 1],
                                    "proofHash": file_proof_hash,
                                    "redacted": False,
                                    "proof": file_proof,
                                },
                                {
                                    "id": 1,
                                    "party": "claimant",
                                    "agentId": a.did,
                                    "action": "withdraw",
                                    "seqRange": [2, 2],
                                    "proofHash": proof_hash,
                                    "redacted": False,
                                    "proof": proof,
                                },
                                {
                                    "id": 2,
                                    "party": "respondent",
                                    "agentId": b.did,
                                    "action": "withdraw",
                                    "seqRange": [3, 3],
                                    "proofHash": compute_request_proof_hash(tampered_proof),
                                    "redacted": False,
                                    "proof": tampered_proof,
                                },
                            ],
                        }
                    ),
                )
            return HttpResponse(404, {}, "{}")

        strict_rh_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=platform.did,
            expected_rules_hash=RULES_HASH,
            transport=_mock_transport,
            now_ms=lambda: 1800000000000,
        )
        with self.assertRaises(AgentMediateError) as err_plat:
            strict_rh_client.platform()
        self.assertEqual(err_plat.exception.code, "RULES_HASH_MISMATCH")

        mock_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=platform.did,
            transport=_mock_transport,
            now_ms=lambda: 1800000000000,
        )
        with self.assertRaises(AgentMediateError) as err_out:
            mock_client.outcome("dsp_a")
        self.assertEqual(err_out.exception.code, "OUTCOME_MISMATCH")

        with self.assertRaises(AgentMediateError) as err_cp:
            mock_client.transparency_checkpoint()
        self.assertEqual(err_cp.exception.code, "CHECKPOINT_MISMATCH")

        with self.assertRaises(AgentMediateError) as err_aud:
            mock_client.audit("dsp_a", require_checkpoint=True)
        self.assertEqual(err_aud.exception.code, "INVALID_AUDIT_CHAIN")

        with self.assertRaises(AgentMediateError) as err_sig:
            mock_client.signatures("dsp_a")
        self.assertEqual(err_sig.exception.code, "INVALID_REQUEST_PROOF")

        non_strict = mock_client.signatures("dsp_a", strict=False)
        self.assertTrue(non_strict["signatures"][1]["verified"])
        self.assertFalse(non_strict["signatures"][2]["verified"])
        self.assertIsInstance(non_strict["signatures"][2]["verifyReason"], str)

        # 9. did:web document key authorization, %5C rejection, & JWS builder parity (MECH-15, H1, H4, M1, L1)
        self.assertEqual(url_from_did_web("did:web:acme.example"), "https://acme.example/.well-known/did.json")
        self.assertEqual(url_from_did_web("did:web:acme.example:agents:v1"), "https://acme.example/agents/v1/did.json")
        for bad_dw in (
            "did:web:shared.example%5Ctenants%5Cevil",
            "did:web:shared.example%2Ftenants",
            "did:web:.shared.example",
            "did:web:shared.example.",
            "did:web:shared.example:..",
            "did:web:shared.example:a%5Cb",
        ):
            with self.assertRaises(ValueError):
                url_from_did_web(bad_dw)

        built_did_doc = build_did_web_document(
            base_url="https://acme.example",
            platform_did=a.did,
            historical_keys=[{"did": b.did, "status": "retired"}],
        )
        self.assertTrue(did_web_document_authorizes_key(built_did_doc, "did:web:acme.example", a.did))
        self.assertFalse(did_web_document_authorizes_key(built_did_doc, "did:web:acme.example", b.did), "retired assertionMethod-only key rejected")
        self.assertFalse(
            did_web_document_authorizes_key({**built_did_doc, "authentication": []}, "did:web:acme.example", a.did),
            "empty authentication[] rejected (H4)",
        )
        jwks = build_jwks(
            base_url="https://acme.example",
            platform_did=a.did,
            historical_keys=[{"did": b.did, "status": "retired"}],
        )
        self.assertEqual(len(jwks["keys"]), 2)
        self.assertEqual(did_key_from_ed25519_jwk(ed25519_public_jwk_from_did_key(a.did)), a.did)
        signed_card = sign_agent_card({"name": "Py Agent", "url": "https://acme.example"}, a, kid=f"{a.did}#key-1")
        self.assertTrue(verify_agent_card_signature(signed_card, a.did))
        self.assertFalse(verify_agent_card_signature(signed_card, b.did))

        # Active-key-only check_honours + tamper/TTL rejection + IDN/:443 normalization in Python (M1)
        honours_entry = {
            "domain": "xn--bcher-kva.example",
            "didWeb": "did:web:xn--bcher-kva.example",
            "agentIds": [a.did],
            "verificationMethods": ["did_web"],
            "memberSince": 1800000000000,
            "verifiedAt": 1800000000000,
            "qualifiedHonoredCount": 2,
            "totalHonoredObligations": 2,
            "confirmedByCounterpartyCount": 2,
            "distinctCounterparties": 2,
            "verifiedDomainCounterparties": 1,
            "curedLateCount": 1,
            "fulfilmentRate": 1,
            "lastHonoredAt": 1800000000000,
            "lookupUrl": "https://api.mediate.example/v1/honours/xn--bcher-kva.example",
        }
        honours_att_doc = {
            "type": HONOURS_ATTESTATION_TYPE,
            "rulesVersion": RULES_VERSION,
            "rulesHash": RULES_HASH,
            "environment": "development",
            "domain": "xn--bcher-kva.example",
            "didWeb": "did:web:xn--bcher-kva.example",
            "agentIds": [a.did],
            "memberSince": 1800000000000,
            "verifiedAt": 1800000000000,
            "qualifiedHonoredCount": 2,
            "totalHonoredObligations": 2,
            "confirmedByCounterpartyCount": 2,
            "distinctCounterparties": 2,
            "verifiedDomainCounterparties": 1,
            "curedLateCount": 1,
            "fulfilmentRate": 1,
            "lastHonoredAt": 1800000000000,
            "issuedAt": 1800000000000,
        }
        retired_plat = generate_agent_key()
        retired_key_hist = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "activeDid": platform.did,
                "activeKeyId": f"{platform.did}#key-1",
                "updatedAt": 1800000000000,
                "keys": [
                    {
                        "keyId": f"{platform.did}#key-1",
                        "did": platform.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(platform.did),
                        "status": "active",
                        "validFrom": 1790000000000,
                    },
                    {
                        "keyId": f"{retired_plat.did}#key-1",
                        "did": retired_plat.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(retired_plat.did),
                        "status": "retired",
                        "validFrom": 1780000000000,
                        "validUntil": 1800005000000,
                    },
                ],
            },
            platform,
            created_ms=1800000000000,
        )
        valid_att = sign_document(honours_att_doc, platform, created_ms=1800000000000, expires_at_ms=1800000000000 + 3_600_000)
        retired_att = sign_document(honours_att_doc, retired_plat, created_ms=1800000000000, expires_at_ms=1800000000000 + 3_600_000)
        honours_payload = {
            "subject": "xn--bcher-kva.example",
            "listed": True,
            "checkedAt": 1800000000000,
            "entry": honours_entry,
            "signedAttestation": valid_att,
        }

        def _honours_transport(method: str, url: str, _h: Mapping[str, str], _b: Optional[bytes]) -> HttpResponse:
            if url.endswith("/.well-known/key-history.json"):
                return HttpResponse(200, {}, json.dumps(retired_key_hist))
            if "/v1/honours/" in url:
                return HttpResponse(200, {}, json.dumps(honours_payload))
            return HttpResponse(404, {}, "{}")

        py_h_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=platform.did,
            transport=_honours_transport,
            now_ms=lambda: 1800000000000,
        )
        for subj in ("bücher.example", "BÜCHER.EXAMPLE.", "xn--bcher-kva.example:443", "did:web:xn--bcher-kva.example%3A443"):
            checked_py = py_h_client.check_honours(subj)
            self.assertTrue(checked_py["verified"])
            self.assertEqual(checked_py["entry"]["curedLateCount"], 1)

        honours_payload["signedAttestation"] = retired_att
        with self.assertRaises(AgentMediateError) as err_ret:
            py_h_client.check_honours("bücher.example")
        self.assertEqual(err_ret.exception.code, "INVALID_PLATFORM_SIGNATURE")

        honours_payload["signedAttestation"] = valid_att
        honours_payload["entry"] = {**honours_entry, "curedLateCount": 0}
        with self.assertRaises(AgentMediateError) as err_tamp:
            py_h_client.check_honours("bücher.example")
        self.assertEqual(err_tamp.exception.code, "HONOURS_MISMATCH")

    def test_comprehensive_review_parity_and_hardening(self) -> None:
        # 1. JCS RFC 8785 boundary numbers, line separators, nested -0, and lone surrogates
        self.assertEqual(canonical_json(1e20), "100000000000000000000")
        self.assertEqual(canonical_json(1e21), "1e+21")
        self.assertEqual(canonical_json(1e-6), "0.000001")
        self.assertEqual(canonical_json(1e-7), "1e-7")
        self.assertEqual(canonical_json(5e-324), "5e-324")
        self.assertEqual(canonical_json(1.7976931348623157e308), "1.7976931348623157e+308")
        self.assertEqual(canonical_json(0.1 + 0.2), "0.30000000000000004")
        self.assertEqual(canonical_json({"arr": [-0.0, {"k": -0.0}]}), '{"arr":[0,{"k":0}]}')
        self.assertEqual(canonical_json("a\u2028b\u2029c"), '"a\u2028b\u2029c"')
        self.assertEqual(canonical_json("\ud800"), '"\\ud800"')

        # 2. CR-SDK-L9: MECHANISM_SPEC is deeply immutable (MappingProxyType + tuple)
        with self.assertRaises(TypeError):
            MECHANISM_SPEC["rulesVersion"] = "9.9.9"  # type: ignore[index]
        with self.assertRaises(TypeError):
            MECHANISM_SPEC["windowLimitsMs"]["joinTimeoutMs"]["max"] = 999  # type: ignore[index]
        self.assertIsInstance(MECHANISM_SPEC["platformProposal"]["splitRange"], tuple)

        # 3. CR-CORE-L3 & CR-SDK-L10: verify_document_with_key_history requires expected_active_did and rejects compromisedAfter=None
        plat = generate_agent_key()
        doc = sign_document({"disputeId": "dsp_1"}, plat, created_ms=1800000000000)
        kh = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "activeDid": plat.did,
                "activeKeyId": f"{plat.did}#key-1",
                "updatedAt": 1800000000000,
                "keys": [
                    {
                        "keyId": f"{plat.did}#key-1",
                        "did": plat.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(plat.did),
                        "status": "active",
                        "validFrom": 1790000000000,
                    }
                ],
            },
            plat,
            created_ms=1800000000000,
        )
        self.assertFalse(verify_document_with_key_history(doc, kh, expected_active_did="", now_ms=1800000000000)["ok"])
        with self.assertRaises(TypeError):
            verify_document_with_key_history(doc, kh, now_ms=1800000000000)  # type: ignore[call-arg]
        kh_null_comp = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "activeDid": plat.did,
                "activeKeyId": f"{plat.did}#key-1",
                "updatedAt": 1800000000000,
                "keys": [
                    {
                        "keyId": f"{plat.did}#key-1",
                        "did": plat.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(plat.did),
                        "status": "active",
                        "validFrom": 1790000000000,
                        "compromisedAfter": None,
                    }
                ],
            },
            plat,
            created_ms=1800000000000,
        )
        self.assertFalse(
            verify_document_with_key_history(doc, kh_null_comp, expected_active_did=plat.did, now_ms=1800000000000)["ok"]
        )

        # 4. CR-CORE-M1..M3 & CR-CORE-L1: Python verifiers reject reserved issue ids, off-grid values, prototype clause windows, and match M1
        a = generate_agent_key()
        b = generate_agent_key()
        raw_clause = build_clause(
            contract={"id": 1},
            platform_did=plat.did,
            parties=[{"agentId": a.did}, {"agentId": b.did}],
            terms={"feeMode": "FILER_PAYS"},
        )
        tampered_win = {**raw_clause, "terms": {"feeMode": "FILER_PAYS", "windows": {"constructor": 5}}}
        tampered_signed = sign_clause(sign_clause(tampered_win, a), b)
        self.assertFalse(
            verify_clause(tampered_signed, expected_platform_did=plat.did, claimant_id=a.did, respondent_id=b.did)["ok"]
        )

        def _opening_for(issues: list, c_priv: dict, r_priv: dict) -> dict:
            c_s = derive_party_input_salt("s", "dsp_m", "claimant")
            r_s = derive_party_input_salt("s", "dsp_m", "respondent")
            return verify_proposal_opening(
                {
                    "disputeId": "dsp_m",
                    "issues": issues,
                    "mode": "keyed",
                    "proposalKeyOrSalt": "pkey_m",
                    "proposalKeyCommitment": compute_proposal_key_commitment("dsp_m", "pkey_m", "keyed"),
                    "declared": {
                        "claimant": {
                            "private": c_priv,
                            "partySalt": c_s,
                            "commitment": compute_declared_input_commitment("dsp_m", "claimant", c_s, c_priv),
                        },
                        "respondent": {
                            "private": r_priv,
                            "partySalt": r_s,
                            "commitment": compute_declared_input_commitment("dsp_m", "respondent", r_s, r_priv),
                        },
                    },
                }
            )

        proto_issue = {
            "id": "valueOf",
            "label": "v",
            "unit": "u",
            "min": 0,
            "max": 100,
            "step": 1,
            "claimantPrefers": "higher",
            "obligor": "respondent",
        }
        self.assertFalse(
            _opening_for([proto_issue], {"weights": {"valueOf": 1}, "walkaway": {"valueOf": 20}}, {"weights": {"valueOf": 1}, "walkaway": {"valueOf": 80}})["ok"]
        )
        big_issue = {**proto_issue, "id": "x", "max": 1_000_000}
        self.assertFalse(
            _opening_for([big_issue], {"weights": {"x": 1}, "walkaway": {"x": 999999.0009}}, {"weights": {"x": 1}, "walkaway": {"x": 1000000}})["ok"]
        )
        off_max_issue = {**proto_issue, "id": "x", "max": 100000.00005}
        self.assertFalse(
            _opening_for([off_max_issue], {"weights": {"x": 1}, "walkaway": {"x": 10}}, {"weights": {"x": 1}, "walkaway": {"x": 20}})["ok"]
        )
        m1_issues = [{**proto_issue, "id": "a"}, {**proto_issue, "id": "b", "step": 25}]
        m1_open = _opening_for(
            m1_issues,
            {"weights": {"a": 0.7, "b": 0.3}, "walkaway": {"a": 40, "b": 75}},
            {"weights": {"a": 0.699, "b": 0.301}, "walkaway": {"a": 62, "b": 25}},
        )
        self.assertTrue(m1_open["ok"])
        self.assertFalse(m1_open["expectedProposal"]["settles"])

        # 5. CR-SDK-L4: verify_public_audit_chain rejects bool/float seq and non-True redacted; audit() wraps malformed leaf
        h64 = "a" * 64
        g64 = "0" * 64
        self.assertFalse(verify_public_audit_chain([{"seq": True, "redacted": True, "prevHash": g64, "hash": h64}])["ok"])
        self.assertFalse(verify_public_audit_chain([{"seq": 1.0, "redacted": True, "prevHash": g64, "hash": h64}])["ok"])
        self.assertFalse(verify_public_audit_chain([{"seq": 1, "redacted": False, "prevHash": g64, "hash": h64}])["ok"])

        entry_hash = sha256_hex(canonical_json([1, "DISPUTE_FILED", 1800000000000, "both", h64, g64]))
        cp_doc = sign_document(
            {
                "type": "agent-mediate/transparency-checkpoint/v1",
                "checkpointSeq": 1,
                "disputeCount": 1,
                "merkleRoot": h64,
                "prevCheckpointHash": g64,
                "baseAnchorCalldata": encode_base_anchor_calldata(1, h64),
                "rulesHash": RULES_HASH,
                "environment": "development",
            },
            plat,
            created_ms=1800000000000,
        )
        cp_hash = sha256_hex("agent-mediate/checkpoint-chain/v1\n" + canonical_json(cp_doc["document"]))

        def _bad_leaf_transport(_m: str, url: str, _h: Mapping[str, str], _b: Optional[bytes]) -> HttpResponse:
            if url.endswith("/audit"):
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "head": entry_hash,
                            "entries": [
                                {
                                    "seq": 1,
                                    "type": "DISPUTE_FILED",
                                    "at": 1800000000000,
                                    "visibility": "both",
                                    "dataCommitment": h64,
                                    "prevHash": g64,
                                    "data": {},
                                    "hash": entry_hash,
                                }
                            ],
                            "checkpoint": {
                                "signedCheckpoint": cp_doc,
                                "checkpointHash": cp_hash,
                                "anchor": None,
                                "leaf": ["not-a-dict"],
                                "inclusionProof": {"leafHash": h64, "leafIndex": 0, "totalLeaves": 1, "siblings": []},
                            },
                        }
                    ),
                )
            return HttpResponse(200, {}, "[]")

        bad_audit_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=plat.did,
            transport=_bad_leaf_transport,
            now_ms=lambda: 1800000000000,
        )
        with self.assertRaises(AgentMediateError) as err_leaf:
            bad_audit_client.audit("dsp_1")
        self.assertEqual(err_leaf.exception.code, "INVALID_AUDIT_CHAIN")
        self.assertIn("inclusion proof", str(err_leaf.exception))
        with self.assertRaises(AgentMediateError) as err_arr:
            bad_audit_client.rules()
        self.assertEqual(err_arr.exception.code, "HTTP_ERROR")

        # 6. CR-SDK-L3 & CR-SVC-L6: UTS46 non-transitional IDN ("faß.de" -> "xn--fa-hia.de") and a2a_card-only didWeb=None
        fass_att = sign_document(
            {
                "type": HONOURS_ATTESTATION_TYPE,
                "rulesVersion": RULES_VERSION,
                "rulesHash": RULES_HASH,
                "environment": "development",
                "domain": "xn--fa-hia.de",
                "didWeb": None,
                "agentIds": [a.did],
                "memberSince": 1800000000000,
                "verifiedAt": 1800000000000,
                "qualifiedHonoredCount": 1,
                "totalHonoredObligations": 1,
                "confirmedByCounterpartyCount": 1,
                "distinctCounterparties": 1,
                "verifiedDomainCounterparties": 0,
                "curedLateCount": 0,
                "fulfilmentRate": 1,
                "lastHonoredAt": 1800000000000,
                "issuedAt": 1800000000000,
            },
            plat,
            created_ms=1800000000000,
            expires_at_ms=1800003600000,
        )
        fass_entry = {
            **{k: v for k, v in fass_att["document"].items() if k not in ("type", "rulesVersion", "rulesHash", "environment", "issuedAt")},
            "verificationMethods": ["a2a_card"],
            "lookupUrl": "https://api.mediate.example/v1/honours/xn--fa-hia.de",
        }

        def _fass_transport(_m: str, url: str, _h: Mapping[str, str], _b: Optional[bytes]) -> HttpResponse:
            if url.endswith("/.well-known/key-history.json"):
                return HttpResponse(200, {}, json.dumps(kh))
            return HttpResponse(
                200,
                {},
                json.dumps({"subject": "xn--fa-hia.de", "listed": True, "checkedAt": 1800000000000, "entry": fass_entry, "signedAttestation": fass_att}),
            )

        fass_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=plat.did,
            transport=_fass_transport,
            now_ms=lambda: 1800000000000,
        )
        self.assertTrue(fass_client.check_honours("faß.de")["verified"])
        with self.assertRaises(AgentMediateError) as err_dw_null:
            fass_client.check_honours("did:web:faß.de")
        self.assertEqual(err_dw_null.exception.code, "HONOURS_MISMATCH")

        # 7. CR-SDK-L6 & CR-SDK-L7: custom payer without .network on mainnet requires platform_did; malformed payment-required raises AgentMediateError
        class _NetworklessMainnetPayer:
            def pay(self, _c: Mapping[str, object]) -> str:
                return "sig"

        mainnet_challenge = base64.b64encode(
            json.dumps({"x402Version": 2, "accepts": [{"network": "eip155:8453", "amount": "2000000"}]}).encode("utf-8")
        ).decode("ascii")

        def _402_mainnet(_m: str, url: str, _h: Mapping[str, str], _b: Optional[bytes]) -> HttpResponse:
            if url.endswith("/v1/platform"):
                return HttpResponse(200, {}, json.dumps({"did": plat.did}))
            return HttpResponse(402, {"payment-required": mainnet_challenge}, '{"code":"PAYMENT_REQUIRED"}')

        unpinned_mainnet = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            payer=_NetworklessMainnetPayer(),  # type: ignore[arg-type]
            transport=_402_mainnet,
            now_ms=lambda: 1800000000000,
        )
        file_kwargs = {
            "respondent_id": b.did,
            "contract_hash": "a" * 64,
            "claim": {"summary": "s", "requestedRemedy": "r"},
            "proposed_issues": [{"id": "refundUsd", "label": "Refund", "unit": "USD", "min": 0, "max": 100, "step": 1, "claimantPrefers": "higher", "obligor": "respondent"}],
            "bounds": {"refundUsd": {"min": 0, "max": 100}},
        }
        with self.assertRaises(PaymentPolicyError):
            unpinned_mainnet.file_dispute(**file_kwargs)

        def _402_malformed(_m: str, _url: str, _h: Mapping[str, str], _b: Optional[bytes]) -> HttpResponse:
            return HttpResponse(402, {"payment-required": "!!!not-base64!!!"}, '{"code":"PAYMENT_REQUIRED"}')

        malformed_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=plat.did,
            payer=_NetworklessMainnetPayer(),  # type: ignore[arg-type]
            transport=_402_malformed,
            now_ms=lambda: 1800000000000,
        )
        with self.assertRaises(AgentMediateError) as err_mal:
            malformed_client.file_dispute(**file_kwargs)
        self.assertEqual(err_mal.exception.code, "MALFORMED_PAYMENT_REQUIRED")

    def test_external_security_audit_2026_11(self) -> None:
        a = generate_agent_key()
        b = generate_agent_key()
        platform = generate_agent_key()

        # SA-CORE-M1: exact integer grid checks on large-step issues (step >= 1000) and off-grid max rejection
        large_step_issue = {
            "id": "refundUsd",
            "label": "Refund",
            "unit": "USD",
            "min": 0,
            "max": 1_000_000,
            "step": 1000,
            "claimantPrefers": "higher",
            "obligor": "respondent",
        }
        c_salt = derive_party_input_salt("salt_sa", "dsp_sa", "claimant")
        r_salt = derive_party_input_salt("salt_sa", "dsp_sa", "respondent")
        off_grid_priv = {"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 500_001}}
        on_grid_priv = {"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 600_000}}
        off_grid_open = verify_proposal_opening(
            {
                "disputeId": "dsp_sa",
                "issues": [large_step_issue],
                "mode": "keyed",
                "proposalKeyOrSalt": "pkey_sa",
                "proposalKeyCommitment": compute_proposal_key_commitment("dsp_sa", "pkey_sa", "keyed"),
                "declared": {
                    "claimant": {
                        "private": off_grid_priv,
                        "partySalt": c_salt,
                        "commitment": compute_declared_input_commitment("dsp_sa", "claimant", c_salt, off_grid_priv),
                    },
                    "respondent": {
                        "private": on_grid_priv,
                        "partySalt": r_salt,
                        "commitment": compute_declared_input_commitment("dsp_sa", "respondent", r_salt, on_grid_priv),
                    },
                },
            }
        )
        self.assertFalse(off_grid_open["ok"], "500001 on step=1000 grid must be rejected (SA-CORE-M1)")
        self.assertIn("walkaway", off_grid_open["reason"])

        off_grid_max_issue = {**large_step_issue, "max": 1_000_500}
        c_priv_ok = {"weights": {"refundUsd": 1}, "walkaway": {"refundUsd": 300_000}}
        bad_max_open = verify_proposal_opening(
            {
                "disputeId": "dsp_sa",
                "issues": [off_grid_max_issue],
                "mode": "keyed",
                "proposalKeyOrSalt": "pkey_sa",
                "proposalKeyCommitment": compute_proposal_key_commitment("dsp_sa", "pkey_sa", "keyed"),
                "declared": {
                    "claimant": {
                        "private": c_priv_ok,
                        "partySalt": c_salt,
                        "commitment": compute_declared_input_commitment("dsp_sa", "claimant", c_salt, c_priv_ok),
                    },
                    "respondent": {
                        "private": on_grid_priv,
                        "partySalt": r_salt,
                        "commitment": compute_declared_input_commitment("dsp_sa", "respondent", r_salt, on_grid_priv),
                    },
                },
            }
        )
        self.assertFalse(bad_max_open["ok"], "off-grid issue.max on integer grid must be rejected (SA-CORE-M1)")

        # SA-CORE-L1 & SA-CORE-L3: verify_mandate_signature / verify_document / verify_clause / verify_proposal_opening never raise on NaN/Infinity or malformed hex
        nan_mandate = {
            "id": "mnd_nan",
            "principalId": a.did,
            "agentId": a.did,
            "bounds": {"refundUsd": {"min": 0, "max": float("nan")}},
            "issuedAt": 1800000000000,
            "expiresAt": 1800090000000,
            "signature": "00" * 64,
        }
        self.assertFalse(verify_mandate_signature(nan_mandate))
        nan_doc = {
            "document": {"val": float("inf")},
            "proof": {
                "type": "Ed25519Signature2026",
                "version": 2,
                "verificationMethod": platform.did,
                "keyId": f"{platform.did}#key-1",
                "created": 1800000000000,
                "signature": "00" * 64,
            },
        }
        self.assertFalse(verify_document(nan_doc, platform.did))
        nan_clause = {
            "type": "agent-mediate/clause/v1",
            "contractHash": "a" * 64,
            "platform": {"did": platform.did, "extra": float("nan")},
            "parties": [{"agentId": a.did}, {"agentId": b.did}],
            "terms": {"feeMode": "FILER_PAYS"},
            "issuedAt": 1800000000000,
            "signatures": [],
        }
        self.assertFalse(verify_clause(nan_clause, expected_platform_did=platform.did, claimant_id=a.did, respondent_id=b.did)["ok"])
        bad_salt_open = verify_proposal_opening(
            {
                "disputeId": "dsp_sa",
                "issues": [large_step_issue],
                "mode": "keyed",
                "proposalKeyOrSalt": "pkey_sa",
                "proposalKeyCommitment": compute_proposal_key_commitment("dsp_sa", "pkey_sa", "keyed"),
                "declared": {
                    "claimant": {
                        "private": c_priv_ok,
                        "partySalt": "not_64_hex",
                        "commitment": compute_declared_input_commitment("dsp_sa", "claimant", "not_64_hex", c_priv_ok),
                    },
                    "respondent": {
                        "private": on_grid_priv,
                        "partySalt": r_salt,
                        "commitment": compute_declared_input_commitment("dsp_sa", "respondent", r_salt, on_grid_priv),
                    },
                },
            }
        )
        self.assertFalse(bad_salt_open["ok"], "non-64-hex partySalt rejected (SA-CORE-L1)")

        # SA-PROTO-L1: verify_key_history rejects duplicate did/keyId and mismatched publicKeyJwk; did_web_from_url strips :443; url_from_did_web rejects invalid %XX; verify_agent_card_signature rejects non-canonical base64url
        dup_kh = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "activeDid": platform.did,
                "activeKeyId": f"{platform.did}#key-1",
                "updatedAt": 1800000000000,
                "keys": [
                    {
                        "keyId": f"{platform.did}#key-1",
                        "did": platform.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(platform.did),
                        "status": "active",
                        "validFrom": 1790000000000,
                    },
                    {
                        "keyId": f"{platform.did}#key-2",
                        "did": platform.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(platform.did),
                        "status": "revoked",
                        "validFrom": 1780000000000,
                    },
                ],
            },
            platform,
            created_ms=1800000000000,
        )
        from agent_mediate.protocol import did_web_from_url, verify_key_history
        self.assertFalse(verify_key_history(dup_kh, expected_active_did=platform.did, now_ms=1800000000000)["ok"])
        bad_jwk_kh = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "activeDid": platform.did,
                "activeKeyId": f"{platform.did}#key-1",
                "updatedAt": 1800000000000,
                "keys": [
                    {
                        "keyId": f"{platform.did}#key-1",
                        "did": platform.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(a.did),
                        "status": "active",
                        "validFrom": 1790000000000,
                    }
                ],
            },
            platform,
            created_ms=1800000000000,
        )
        self.assertFalse(verify_key_history(bad_jwk_kh, expected_active_did=platform.did, now_ms=1800000000000)["ok"])
        self.assertEqual(did_web_from_url("https://acme.example:443"), "did:web:acme.example")
        with self.assertRaises(ValueError):
            url_from_did_web("did:web:acme.example%ZZ")
        card = sign_agent_card({"name": "Canon", "url": "https://acme.example"}, a, kid=f"{a.did}#key-1")
        self.assertTrue(verify_agent_card_signature(card, a.did))
        padded_card = {**card, "signatures": [{**card["signatures"][0], "signature": card["signatures"][0]["signature"] + "="}]}
        self.assertFalse(verify_agent_card_signature(padded_card, a.did))

        # SA-SDK-M1 & SA-SDK-L1: mandate cache across same-key retries + notice verification + redacted non-confidential signature rejection
        seen_bodies: list[str] = []
        valid_notice = sign_document(
            {
                "type": "agent-mediate/dispute-notice/v1",
                "rulesVersion": RULES_VERSION,
                "rulesHash": RULES_HASH,
                "environment": "development",
                "disputeId": "dsp_retry",
                "claimantId": a.did,
                "respondentId": b.did,
                "contractHash": "c" * 64,
                "claimSummary": "S",
                "requestedRemedy": "R",
                "issueCount": 1,
                "joinBy": 1800086400000,
                "feeMode": "FILER_PAYS",
                "respondentJoinFeeUsd": "0.00",
                "filingFeePaid": True,
                "joinEndpoint": "https://api.mediate.example/v1/disputes/dsp_retry/join",
                "noticeUrl": "https://api.mediate.example/d/dsp_retry",
                "issuedAt": 1800000000000,
            },
            platform,
            created_ms=1800000000000,
        )
        call_idx = [0]

        def _retry_transport(method: str, url: str, _h: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            if method == "POST" and url.endswith("/v1/disputes"):
                call_idx[0] += 1
                seen_bodies.append((body or b"").decode("utf-8"))
                if call_idx[0] == 1:
                    return HttpResponse(503, {}, json.dumps({"code": "FACILITATOR_UNAVAILABLE", "detail": "busy"}))
                return HttpResponse(
                    201,
                    {},
                    json.dumps(
                        {
                            "disputeId": "dsp_retry",
                            "view": {"id": "dsp_retry", "status": "AWAITING_RESPONDENT"},
                            "notice": {"noticeUrl": "https://api.mediate.example/d/dsp_retry", "signedNotice": valid_notice},
                        }
                    ),
                )
            return HttpResponse(404, {}, "{}")

        retry_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=a,
            platform_did=platform.did,
            transport=_retry_transport,
            now_ms=lambda: 1800000000000,
            max_retries=0,
        )
        with self.assertRaises(AgentMediateError) as first_err:
            retry_client.file_dispute(
                respondent_id=b.did,
                contract_hash="c" * 64,
                claim={"summary": "S", "requestedRemedy": "R"},
                proposed_issues=[large_step_issue],
                bounds={"refundUsd": {"min": 0, "max": 500_000}},
            )
        self.assertIsNotNone(first_err.exception.idempotency_key)
        filed_ok = retry_client.file_dispute(
            respondent_id=b.did,
            contract_hash="c" * 64,
            claim={"summary": "S", "requestedRemedy": "R"},
            proposed_issues=[large_step_issue],
            bounds={"refundUsd": {"min": 0, "max": 500_000}},
            idempotency_key=first_err.exception.idempotency_key,
        )
        self.assertEqual(filed_ok["disputeId"], "dsp_retry")
        self.assertEqual(len(seen_bodies), 2)
        self.assertEqual(seen_bodies[0], seen_bodies[1], "same-key retry with bounds must reuse identical signed mandate (SA-SDK-M1)")

    def test_audit_v130_python_parity_and_conformance_vectors(self) -> None:
        """v1.3.0 audit regressions: conformance-vectors.json, PKCS#8 v1, SEC-5, SEC-9, BUG-4, BUG-9, ARCH-3, PERF-5, TEST-3."""
        from pathlib import Path
        from agent_mediate import (
            KEY_HISTORY_TYPE,
            PaymentPolicyError,
            sign_agent_card,
            validate_issues_against_clause_templates,
            verify_proposal_opening,
            verify_request_proof,
        )

        # 1. Shared cross-language conformance vectors (ARCH-3, TEST-3)
        vectors_path = Path(__file__).resolve().parents[3] / "testdata" / "conformance-vectors.json"
        vectors = json.loads(vectors_path.read_text(encoding="utf-8"))
        self.assertEqual(RULES_VERSION, vectors["rules"]["rulesVersion"])
        self.assertEqual(RULES_HASH, vectors["rules"]["rulesHash"])
        self.assertEqual(agent_key_from_pem(vectors["keys"]["pkcs8V1PemA"]).did, vectors["keys"]["didA"])

        for item in vectors["jcs"]:
            self.assertEqual(canonical_json(item["input"]), item["canonical"], item["label"])
            self.assertEqual(contract_hash(item["input"]), item["sha256"], item["label"])

        for v in vectors["didWeb"]["valid"]:
            self.assertEqual(url_from_did_web(v["didWeb"]), v["url"])
        for bad_did_web in vectors["didWeb"]["invalid"]:
            with self.assertRaises(ValueError, msg=bad_did_web):
                url_from_did_web(bad_did_web)

        for wp in vectors["weakPoints"]:
            self.assertEqual(weak_point_reason(bytes.fromhex(wp["hex"])), wp["reason"])

        for po in vectors["proposalOpenings"]:
            res = verify_proposal_opening(po["opening"])
            self.assertTrue(res["ok"], f"{po['label']}: {res.get('reason')}")
            self.assertEqual(canonical_json(res["expectedProposal"]), canonical_json(po["expectedProposal"]), po["label"])
            self.assertEqual(
                canonical_json(res["expectedDeterminationReference"]),
                canonical_json(po["expectedDeterminationReference"]),
                po["label"],
            )

        self.assertTrue(
            verify_clause(
                vectors["clause"]["valid"],
                expected_platform_did=vectors["clause"]["expectedPlatformDid"],
                expected_platform_base_url=vectors["clause"]["expectedPlatformBaseUrl"],
            )["ok"]
        )
        for mut in vectors["clause"]["invalidMutations"]:
            mutated = {**vectors["clause"]["valid"], **mut["patch"]}
            self.assertFalse(
                verify_clause(mutated, expected_platform_did=vectors["clause"]["expectedPlatformDid"])["ok"],
                mut["label"],
            )

        rp = vectors["requestProof"]
        self.assertTrue(
            verify_request_proof(
                rp["proof"],
                expected_agent_id=rp["agentId"],
                expected_proof_hash=rp["proofHash"],
                expected_base_url=rp["baseUrl"],
                expected_dispute_id=rp["disputeId"],
                expected_action=rp["action"],
                expected_content_digest=rp["contentDigest"],
                expected_idempotency_key=rp["idempotencyKey"],
            )["ok"]
        )

        # 2. BUG-9: PKCS#8 v1 with [0] attributes + [1] EXPLICIT BIT STRING (0xA1) and mismatched embedded pubkey rejection
        seed = bytes([0x44]) * 32
        expected_key = agent_key_from_seed(seed)
        inner_explicit = (
            bytes.fromhex("020101")
            + bytes.fromhex("300506032b6570")
            + bytes.fromhex("04220420")
            + seed
            + bytes.fromhex("a0020500")  # [0] attributes
            + bytes.fromhex("a123032100")  # [1] EXPLICIT BIT STRING
            + expected_key.public_key
        )
        der_explicit = bytes([0x30, len(inner_explicit)]) + inner_explicit
        pem_explicit = f"-----BEGIN PRIVATE KEY-----\n{base64.b64encode(der_explicit).decode('ascii')}\n-----END PRIVATE KEY-----\n"
        self.assertEqual(agent_key_from_pem(pem_explicit).did, expected_key.did)

        wrong_pub = bytearray(expected_key.public_key)
        wrong_pub[0] ^= 0x01
        inner_bad_pub = (
            bytes.fromhex("020101300506032b657004220420")
            + seed
            + bytes.fromhex("812100")
            + bytes(wrong_pub)
        )
        der_bad_pub = bytes([0x30, len(inner_bad_pub)]) + inner_bad_pub
        pem_bad_pub = f"-----BEGIN PRIVATE KEY-----\n{base64.b64encode(der_bad_pub).decode('ascii')}\n-----END PRIVATE KEY-----\n"
        with self.assertRaisesRegex(ValueError, "mismatches private seed"):
            agent_key_from_pem(pem_bad_pub)

        # 3. ARCH-3: PaymentPolicyError hierarchy
        pol_err = PaymentPolicyError("policy denied")
        self.assertIsInstance(pol_err, AgentMediateError)
        self.assertIsInstance(pol_err, ValueError)
        self.assertEqual(pol_err.status, 0)
        self.assertEqual(pol_err.code, "PAYMENT_POLICY_ERROR")

        # 4. SEC-2: validate_issues_against_clause_templates
        tmpl = {
            "id": "refundUsd",
            "label": "Refund",
            "unit": "USD",
            "min": 0,
            "max": 1000,
            "step": 10,
            "claimantPrefers": "higher",
            "obligor": "respondent",
        }
        self.assertTrue(validate_issues_against_clause_templates([{**tmpl, "min": 100, "max": 800}], [tmpl])["ok"])
        self.assertFalse(validate_issues_against_clause_templates([{**tmpl, "max": 1200}], [tmpl])["ok"])

        # 5. SEC-5: unpinned client rejects attacker-signed filing notice & cross-checks signed agent-card.json payTo
        platform_key = generate_agent_key()
        attacker_key = generate_agent_key()
        claimant_key = generate_agent_key()
        respondent_key = generate_agent_key()
        t_now = 1_800_000_000_000
        forged_notice = sign_document(
            {
                "type": "agent-mediate/dispute-notice/v1",
                "disputeId": "dsp_forged",
                "claimantId": claimant_key.did,
                "respondentId": respondent_key.did,
                "contractHash": "4" * 64,
                "issuedAt": t_now,
            },
            attacker_key,
            created_ms=t_now,
        )

        def _forged_notice_tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            if method == "GET" and url.endswith("/v1/platform"):
                return HttpResponse(200, {}, json.dumps({"did": platform_key.did, "rulesHash": RULES_HASH}))
            return HttpResponse(
                201,
                {},
                json.dumps(
                    {
                        "disputeId": "dsp_forged",
                        "view": {"disputeId": "dsp_forged", "status": "AWAITING_RESPONDENT"},
                        "notice": {"signedNotice": forged_notice},
                    }
                ),
            )

        unpinned = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=claimant_key,
            transport=_forged_notice_tx,
            now_ms=lambda: t_now,
        )
        with self.assertRaises(AgentMediateError) as fn_err:
            unpinned.file_dispute(
                respondent_id=respondent_key.did,
                contract_hash="4" * 64,
                claim={"summary": "S", "requestedRemedy": "R"},
                proposed_issues=[tmpl],
                bounds={"refundUsd": {"min": 0, "max": 1000}},
            )
        self.assertEqual(fn_err.exception.code, "INVALID_PLATFORM_SIGNATURE")

        real_pay_to = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C"
        evil_pay_to = "0x000000000000000000000000000000000000dEaD"
        signed_card = sign_agent_card(
            {
                "name": "Agent-Mediate",
                "capabilities": {"extensions": [{"uri": "urn:agent-mediate:ext:x402-fees:v1", "params": {"payTo": real_pay_to}}]},
            },
            platform_key,
            kid=f"did:web:api.mediate.example#key-1",
        )

        class _DummyPayer:
            network = "eip155:84532"

            def pay(self, challenge: Mapping[str, Any], *, operation: str, expected_pay_to: Optional[str] = None) -> str:
                return f"paid:{expected_pay_to}"

        def _mitm_payto_tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            if url.endswith("/v1/platform"):
                return HttpResponse(200, {}, json.dumps({"did": platform_key.did, "fees": {"network": "eip155:84532", "payTo": evil_pay_to}}))
            if url.endswith("/.well-known/agent-card.json"):
                return HttpResponse(200, {}, json.dumps(signed_card))
            return HttpResponse(402, {}, json.dumps({"code": "PAYMENT_REQUIRED", "paymentRequired": {"x402Version": 2, "accepts": []}}))

        mitm_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=claimant_key,
            payer=_DummyPayer(),  # type: ignore[arg-type]
            transport=_mitm_payto_tx,
            now_ms=lambda: t_now,
        )
        with self.assertRaises(PaymentPolicyError):
            mitm_client.file_dispute(
                respondent_id=respondent_key.did,
                contract_hash="5" * 64,
                claim={"summary": "S", "requestedRemedy": "R"},
                proposed_issues=[tmpl],
                bounds={"refundUsd": {"min": 0, "max": 1000}},
            )

        # 6. SEC-9 & PERF-5: verify_webhook retired key via key_history + key_history() 60s cache
        from agent_mediate.protocol import ed25519_public_jwk_from_did_key

        old_plat = generate_agent_key()
        revoked_plat = generate_agent_key()
        kh_doc = sign_document(
            {
                "type": KEY_HISTORY_TYPE,
                "platformDidWeb": "did:web:api.mediate.example",
                "activeDid": platform_key.did,
                "activeKeyId": "key-2",
                "updatedAt": t_now,
                "keys": [
                    {
                        "keyId": "key-2",
                        "did": platform_key.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(platform_key.did),
                        "status": "active",
                        "validFrom": t_now - 10_000,
                    },
                    {
                        "keyId": "key-1",
                        "did": old_plat.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(old_plat.did),
                        "status": "retired",
                        "validFrom": t_now - 100_000,
                        "validUntil": t_now - 5_000,
                    },
                    {
                        "keyId": "key-0",
                        "did": revoked_plat.did,
                        "publicKeyJwk": ed25519_public_jwk_from_did_key(revoked_plat.did),
                        "status": "revoked",
                        "validFrom": t_now - 200_000,
                        "validUntil": t_now - 5_000,
                        "revokedAt": t_now - 5_000,
                    },
                ],
            },
            platform_key,
            created_ms=t_now,
            key_id="key-2",
        )
        hook_url = "https://agent.example/webhook"
        hook_body = json.dumps({"disputeId": "dsp_w", "seq": 1, "recipient": {"party": "claimant", "agentId": claimant_key.did}})
        retired_hdrs = sign_request(
            method="POST",
            target_uri=hook_url,
            body=hook_body,
            key=old_plat,
            created=(t_now - 6_000) // 1000,
            nonce="py-webhook-retired-0001",
            tag="agent-mediate-webhook-v1",
        )
        self.assertFalse(
            AgentMediateClient.verify_webhook(url=hook_url, headers=retired_hdrs, body=hook_body, platform_did=platform_key.did, now_ms=t_now)["ok"]
        )
        self.assertTrue(
            AgentMediateClient.verify_webhook(
                url=hook_url,
                headers=retired_hdrs,
                body=hook_body,
                platform_did=platform_key.did,
                now_ms=t_now,
                key_history=kh_doc,
            )["ok"]
        )
        revoked_hdrs = sign_request(
            method="POST",
            target_uri=hook_url,
            body=hook_body,
            key=revoked_plat,
            created=(t_now - 6_000) // 1000,
            nonce="py-webhook-revoked-0001",
            tag="agent-mediate-webhook-v1",
        )
        self.assertFalse(
            AgentMediateClient.verify_webhook(
                url=hook_url,
                headers=revoked_hdrs,
                body=hook_body,
                platform_did=platform_key.did,
                now_ms=t_now,
                key_history=kh_doc,
            )["ok"]
        )

        kh_fetches = [0]
        kh_clock = [t_now]

        def _kh_tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            kh_fetches[0] += 1
            return HttpResponse(200, {}, json.dumps(kh_doc))

        kh_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=claimant_key,
            platform_did=platform_key.did,
            transport=_kh_tx,
            now_ms=lambda: kh_clock[0],
        )
        kh_client.key_history()
        kh_client.key_history()
        self.assertEqual(kh_fetches[0], 1)
        kh_clock[0] += 61_000
        kh_doc_refreshed = sign_document(
            {**kh_doc["document"], "updatedAt": kh_clock[0]},
            platform_key,
            created_ms=kh_clock[0],
            key_id="key-2",
        )

        def _kh_tx2(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            kh_fetches[0] += 1
            return HttpResponse(200, {}, json.dumps(kh_doc_refreshed))

        kh_client._transport = _kh_tx2
        kh_client.key_history()
        self.assertEqual(kh_fetches[0], 2)

        # 7. BUG-4, PERF-5, TEST-3: update_mandate preserves determinationBounds, uses ?view=compact, wait_for_turn, and IPv4 check_honours rejection
        seen_urls: list[str] = []
        sent_mandates: list[dict[str, Any]] = []
        turn_polls = [0]
        honours_entry = {
            "domain": "93.184.216.34",
            "didWeb": None,
            "agentIds": [respondent_key.did],
            "memberSince": t_now - 10_000,
            "verifiedAt": t_now,
            "qualifiedHonoredCount": 1,
            "totalHonoredObligations": 1,
            "confirmedByCounterpartyCount": 1,
            "distinctCounterparties": 1,
            "verifiedDomainCounterparties": 0,
            "curedLateCount": 0,
            "fulfilmentRate": 1,
            "lastHonoredAt": t_now - 1_000,
        }
        honours_att = sign_document(
            {
                "type": HONOURS_ATTESTATION_TYPE,
                "issuedAt": t_now,
                "environment": "test",
                "rulesHash": RULES_HASH,
                **honours_entry,
            },
            platform_key,
            created_ms=t_now,
            expires_at_ms=t_now + 3_600_000,
        )

        def _bug4_tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            seen_urls.append(url)
            if method == "GET" and "/v1/honours/" in url:
                return HttpResponse(200, {}, json.dumps({"listed": True, "entry": honours_entry, "signedAttestation": honours_att}))
            if method == "GET" and "/v1/disputes/dsp_b4" in url:
                turn_polls[0] += 1
                next_act = ["wait_for_change"] if turn_polls[0] == 1 else ["submit_offer"]
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "view": {
                                "disputeId": "dsp_b4",
                                "status": "BARGAINING",
                                "contractHash": "9" * 64,
                                "counterpartId": respondent_key.did,
                                "nextActions": next_act,
                                "yourMandate": {
                                    "issuedAt": t_now,
                                    "expiresAt": t_now + 86_400_000,
                                    "determinationConsent": True,
                                    "bounds": {"refundUsd": {"min": 600, "max": 1000}},
                                    "determinationBounds": {"refundUsd": {"min": 450, "max": 1000}},
                                },
                            }
                        }
                    ),
                )
            if method == "POST" and url.endswith("/v1/disputes/dsp_b4/mandate"):
                assert body is not None
                sent_mandates.append(json.loads(body.decode("utf-8"))["mandate"])
                return HttpResponse(200, {}, json.dumps({"view": {"disputeId": "dsp_b4", "status": "BARGAINING"}}))
            return HttpResponse(404, {}, json.dumps({"code": "NOT_FOUND"}))

        b4_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=claimant_key,
            platform_did=platform_key.did,
            transport=_bug4_tx,
            now_ms=lambda: t_now,
        )
        turn_res = b4_client.wait_for_turn("dsp_b4", interval_ms=1, timeout_ms=5_000)
        self.assertEqual(turn_res["view"]["nextActions"][0], "submit_offer")
        b4_client.update_mandate("dsp_b4", bounds={"refundUsd": {"min": 550, "max": 1000}})
        self.assertTrue(any("view=compact" in u for u in seen_urls))
        self.assertEqual(sent_mandates[0]["determinationBounds"], {"refundUsd": {"min": 450, "max": 1000}})

        for bad_subject in ("93.184.216.34", "did:web:93.184.216.34", "did:key:not-a-valid-key"):
            with self.assertRaises(AgentMediateError, msg=bad_subject) as hon_err:
                b4_client.check_honours(bad_subject)
            self.assertEqual(hon_err.exception.code, "HONOURS_MISMATCH")

        # 8. SEC-9 & BUG-4: X402Payer rejects missing/non-positive maxTimeoutSeconds & pending_paid survives >256 mandate_cache evictions
        from agent_mediate.client import BASE_SEPOLIA, USDC_ON_BASE, X402Payer

        raw_payer = object.__new__(X402Payer)
        raw_payer.network = BASE_SEPOLIA
        raw_payer._pinned_pay_to = real_pay_to
        raw_payer._max_amount = 5_000_000
        raw_payer._budget = 10_000_000
        raw_payer._spent = 0
        raw_payer._lock = __import__("threading").Lock()
        raw_payer._validity_seconds = 120
        raw_payer._now_ms = lambda: t_now
        base_accept = {
            "scheme": "exact",
            "network": BASE_SEPOLIA,
            "asset": USDC_ON_BASE[BASE_SEPOLIA]["asset"],
            "payTo": real_pay_to,
            "amount": "1000000",
        }
        for bad_timeout in ({}, {"maxTimeoutSeconds": 0}, {"maxTimeoutSeconds": -5}, {"maxTimeoutSeconds": True}):
            with self.assertRaisesRegex(PaymentPolicyError, "maxTimeoutSeconds"):
                raw_payer.pay(
                    {"x402Version": 2, "accepts": [{**base_accept, **bad_timeout}]},
                    operation="file",
                    expected_pay_to=real_pay_to,
                )

        pay_calls = [0]
        paid_attempts = [0]
        valid_notice = sign_document(
            {
                "type": "agent-mediate/dispute-notice/v1",
                "disputeId": "dsp_paid_evict",
                "claimantId": claimant_key.did,
                "respondentId": respondent_key.did,
                "contractHash": "7" * 64,
                "issuedAt": t_now,
            },
            platform_key,
            created_ms=t_now,
        )

        class _CountingPayer:
            network = BASE_SEPOLIA

            def pay(self, challenge: Mapping[str, Any], *, operation: str, expected_pay_to: Optional[str] = None) -> str:
                pay_calls[0] += 1
                return "x402-sig-evict-test"

        def _evict_tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            if url.endswith("/v1/platform"):
                return HttpResponse(200, {}, json.dumps({"did": platform_key.did, "fees": {"network": BASE_SEPOLIA, "payTo": real_pay_to}}))
            if url.endswith("/.well-known/agent-card.json"):
                signed_evict_card = sign_agent_card(
                    {
                        "name": "Agent-Mediate",
                        "capabilities": {"extensions": [{"uri": "urn:agent-mediate:ext:x402-fees:v1", "params": {"payTo": real_pay_to}}]},
                    },
                    platform_key,
                    kid="did:web:api.mediate.example#key-1",
                )
                return HttpResponse(200, {}, json.dumps(signed_evict_card))
            if "payment-signature" not in {k.lower() for k in headers}:
                return HttpResponse(402, {}, json.dumps({"code": "PAYMENT_REQUIRED", "paymentRequired": {"x402Version": 2, "accepts": [base_accept]}}))
            paid_attempts[0] += 1
            if paid_attempts[0] == 1:
                return HttpResponse(503, {}, json.dumps({"code": "UNAVAILABLE", "detail": "upstream timeout"}))
            return HttpResponse(
                201,
                {},
                json.dumps(
                    {
                        "disputeId": "dsp_paid_evict",
                        "view": {"disputeId": "dsp_paid_evict", "status": "AWAITING_RESPONDENT"},
                        "notice": {"signedNotice": valid_notice},
                    }
                ),
            )

        evict_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=claimant_key,
            platform_did=platform_key.did,
            payer=_CountingPayer(),  # type: ignore[arg-type]
            transport=_evict_tx,
            now_ms=lambda: t_now,
            max_retries=0,
        )
        with self.assertRaises(AgentMediateError) as first_paid_err:
            evict_client.file_dispute(
                respondent_id=respondent_key.did,
                contract_hash="7" * 64,
                claim={"summary": "S", "requestedRemedy": "R"},
                proposed_issues=[tmpl],
                bounds={"refundUsd": {"min": 100, "max": 900}},
                idempotency_key="idem-evict-paid",
            )
        self.assertTrue(first_paid_err.exception.payment_sent)
        self.assertEqual(pay_calls[0], 1)
        # Churn >256 mandate cache entries to evict the original mandate from _mandate_cache
        for idx in range(300):
            evict_client._resolve_mandate(
                mandate=None,
                bounds={"refundUsd": {"min": 0, "max": float(100 + idx)}},
                determination_consent=None,
                determination_bounds=None,
                scope={"contractHash": "8" * 64, "counterpartyId": respondent_key.did},
                idempotency_key=f"churn-{idx}",
            )
        recovered = evict_client.file_dispute(
            respondent_id=respondent_key.did,
            contract_hash="7" * 64,
            claim={"summary": "S", "requestedRemedy": "R"},
            proposed_issues=[tmpl],
            bounds={"refundUsd": {"min": 100, "max": 900}},
            idempotency_key="idem-evict-paid",
        )
        self.assertEqual(recovered["disputeId"], "dsp_paid_evict")
        self.assertEqual(pay_calls[0], 1, "must reuse cached payment and mandate without charging twice")

    def test_cr3_python_cold_start_and_security_regressions(self) -> None:
        platform_key = generate_agent_key()
        claimant_key = generate_agent_key()
        respondent_key = generate_agent_key()
        attacker_key = generate_agent_key()
        t_now = 1_785_000_000_000

        # 1.AgentKey.to_pem ends with a trailing newline and round-trips cleanly
        pem = claimant_key.to_pem()
        self.assertTrue(pem.endswith("\n"))
        self.assertEqual(agent_key_from_pem(pem).did, claimant_key.did)

        # 2. CR3-SDK-H1 & CR3-MCP-H1 & CR3-SDK-M1: discover_respondent security & A2A v1.0 / #fragment kid checks
        replayed_card = sign_agent_card(
            {
                "name": "Attacker Card",
                "url": "https://attacker.example/a2a",
                "capabilities": {
                    "extensions": [
                        {
                            "uri": "urn:agent-mediate:ext:dispute-notice:v1",
                            "params": {"agentId": attacker_key.did, "noticeWebhookUrl": "https://attacker.example/hook"},
                        }
                    ]
                },
            },
            attacker_key,
            kid="did:web:attacker.example#key-1",
        )
        honest_att = sign_document(
            {
                "type": HONOURS_ATTESTATION_TYPE,
                "environment": "production",
                "platformDid": platform_key.did,
                "rulesVersion": RULES_VERSION,
                "rulesHash": RULES_HASH,
                "domain": "victim.example",
                "didWeb": "did:web:victim.example",
                "agentIds": [respondent_key.did],
                "honouredCount": 2,
                "fulfilmentRate": 1,
                "medianFulfilmentSeconds": 12,
                "memberSince": t_now - 86_400_000,
                "issuedAt": t_now,
            },
            platform_key,
            created_ms=t_now,
            expires_at_ms=t_now + 3_600_000,
        )

        def _victim_tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            if url == "https://api.mediate.example/v1/honours/victim.example":
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "listed": True,
                            "inGoodStanding": True,
                            "entry": {
                                "domain": "victim.example",
                                "didWeb": "did:web:victim.example",
                                "agentIds": [attacker_key.did],
                                "fulfilmentRate": 1,
                            },
                            "signedAttestation": honest_att,
                        }
                    ),
                )
            if url == "https://victim.example/.well-known/agent-card.json":
                return HttpResponse(200, {}, json.dumps(replayed_card))
            return HttpResponse(404, {}, "{}")

        victim_res = discover_respondent(
            "victim.example",
            base_url="https://api.mediate.example",
            platform_did=platform_key.did,
            transport=_victim_tx,
            resolve_host=lambda _h: ["93.184.216.34"],
            now_ms=lambda: t_now,
        )
        self.assertIsNone(victim_res["respondentId"])
        self.assertEqual(victim_res["recommendedAction"], "send_invite")

        for bad_ip in ("127.0.0.1", "169.254.169.254", "fd00::1"):
            with self.assertRaisesRegex(ValueError, "public IP"):
                discover_respondent("rebind.example", transport=_victim_tx, resolve_host=lambda _h, ip=bad_ip: [ip])

        a2a_v1_card = sign_agent_card(
            {"name": "A2A v1", "supportedInterfaces": [{"url": "https://a2av1.example/rpc", "protocolBinding": "JSONRPC"}]},
            respondent_key,
            kid="#key-1",
        )
        a2a_v1_did = sign_agent_card(
            build_did_web_document(base_url="https://a2av1.example", platform_did=respondent_key.did),
            respondent_key,
            kid="#key-1",
        )
        a2a_v1_disc = discover_respondent(
            "a2av1.example",
            transport=lambda _m, url, _h, _b: (
                HttpResponse(200, {}, json.dumps(a2a_v1_card))
                if url == "https://a2av1.example/.well-known/agent-card.json"
                else HttpResponse(200, {}, json.dumps(a2a_v1_did))
                if url == "https://a2av1.example/.well-known/did.json"
                else HttpResponse(404, {}, "{}")
            ),
            resolve_host=lambda _h: ["93.184.216.34"],
            now_ms=lambda: t_now,
        )
        self.assertEqual(a2a_v1_disc["respondentId"], respondent_key.did)
        self.assertTrue(a2a_v1_disc["hasVerifiedNoticeChannel"])
        self.assertEqual(a2a_v1_disc["recommendedAction"], "file_dispute")

        # 3. Cold-start create_invite / get_invite / accept_invite + file_dispute(invite_id=..., require_delivery=True) & RESPONDENT_UNREACHABLE payment_sent=False
        invite_token = "tok_cold_start_0123456789abcdef"
        invite_url = f"https://api.mediate.example/i/{invite_token}"
        signed_invite = sign_document(
            {
                "type": "agent-mediate/dispute-invite/v1",
                "environment": "production",
                "platformDid": platform_key.did,
                "rulesVersion": RULES_VERSION,
                "rulesHash": RULES_HASH,
                "inviteId": "inv_py_1",
                "claimantId": claimant_key.did,
                "respondentId": None,
                "contractHash": "a" * 64,
                "inviteUrl": invite_url,
                "acceptEndpoint": f"https://api.mediate.example/v1/invites/{invite_token}/accept",
                "inviteEndpoint": "https://api.mediate.example/v1/invites/inv_py_1",
                "issuedAt": t_now,
                "expiresAt": t_now + 86_400_000,
            },
            platform_key,
            created_ms=t_now,
            expires_at_ms=t_now + 86_400_000,
        )
        signed_notice = sign_document(
            {
                "type": "agent-mediate/dispute-notice/v1",
                "environment": "production",
                "platformDid": platform_key.did,
                "rulesVersion": RULES_VERSION,
                "rulesHash": RULES_HASH,
                "disputeId": "dsp_py_cold",
                "claimantId": claimant_key.did,
                "respondentId": respondent_key.did,
                "contractHash": "a" * 64,
                "feeMode": "FILER_PAYS",
                "joinCostUsdc": "0.00",
                "joinEndpoint": "https://api.mediate.example/v1/disputes/dsp_py_cold/join",
                "noticeUrl": "https://api.mediate.example/n/tok_notice_py",
                "joinDeadline": t_now + 86_400_000,
                "issuedAt": t_now,
            },
            platform_key,
            created_ms=t_now,
            expires_at_ms=t_now + 86_400_000,
        )
        base_accept = {
            "scheme": "exact",
            "network": "eip155:84532",
            "amount": "2000000",
            "asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e",
            "payTo": "0x209693Bc6afc0C5328bA36FaF03C514EF312287C",
            "maxTimeoutSeconds": 120,
            "extra": {"name": "USDC", "version": "2"},
        }
        released_headers: list[str] = []
        unreachable_mode = [True]

        class _TrackingPayer:
            address = "0x1111111111111111111111111111111111111111"
            network = "eip155:84532"
            spent_atomic = 0

            def pay(self, challenge: Mapping[str, Any], *, operation: str, expected_pay_to: Optional[str] = None) -> str:
                return "paid-header-cold-1"

            def release_unsettled(self, hdr: str) -> None:
                released_headers.append(hdr)

        def _cold_api_tx(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
            if method == "GET" and url.endswith("/v1/platform"):
                return HttpResponse(200, {}, json.dumps({"did": platform_key.did, "rulesHash": RULES_HASH, "rulesVersion": RULES_VERSION}))
            if method == "POST" and url.endswith("/v1/invites"):
                return HttpResponse(
                    201,
                    {},
                    json.dumps(
                        {
                            "inviteId": "inv_py_1",
                            "token": invite_token,
                            "inviteUrl": invite_url,
                            "expiresAt": t_now + 86_400_000,
                            "signedInvite": signed_invite,
                            "delivery": {"method": "email", "delivered": True, "verifiedEndpoint": False, "attempted": [], "at": t_now},
                        }
                    ),
                )
            if method == "GET" and "/v1/invites/inv_py_1" in url:
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "inviteId": "inv_py_1",
                            "status": "PENDING",
                            "claimantId": claimant_key.did,
                            "respondentId": None,
                            "contractHash": "a" * 64,
                            "summary": "SLA dispute",
                            "createdAt": t_now,
                            "expiresAt": t_now + 86_400_000,
                        }
                    ),
                )
            if method == "POST" and f"/v1/invites/{invite_token}/accept" in url:
                return HttpResponse(
                    200,
                    {},
                    json.dumps(
                        {
                            "inviteId": "inv_py_1",
                            "status": "ACCEPTED",
                            "claimantId": claimant_key.did,
                            "respondentId": respondent_key.did,
                            "contractHash": "a" * 64,
                            "summary": "SLA dispute",
                            "acceptedAt": t_now,
                            "expiresAt": t_now + 86_400_000,
                            "webhookRegistered": True,
                        }
                    ),
                )
            if method == "POST" and url.endswith("/v1/disputes"):
                hdr_lower = {k.lower(): v for k, v in headers.items()}
                if "payment-signature" not in hdr_lower:
                    return HttpResponse(
                        402,
                        {},
                        json.dumps({"code": "PAYMENT_REQUIRED", "paymentRequired": {"x402Version": 2, "accepts": [base_accept]}}),
                    )
                req_json = json.loads((body or b"{}").decode("utf-8"))
                self.assertEqual(req_json.get("inviteId"), "inv_py_1")
                self.assertTrue(req_json.get("requireDelivery"))
                if unreachable_mode[0]:
                    return HttpResponse(422, {}, json.dumps({"code": "RESPONDENT_UNREACHABLE", "detail": "unreachable"}))
                return HttpResponse(
                    201,
                    {},
                    json.dumps(
                        {
                            "disputeId": "dsp_py_cold",
                            "view": {"disputeId": "dsp_py_cold", "status": "AWAITING_RESPONDENT"},
                            "notice": {
                                "noticeUrl": "https://api.mediate.example/n/tok_notice_py",
                                "signedNotice": signed_notice,
                            },
                        }
                    ),
                )
            return HttpResponse(404, {}, "{}")

        claimant_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=claimant_key,
            platform_did=platform_key.did,
            payer=_TrackingPayer(),  # type: ignore[arg-type]
            transport=_cold_api_tx,
            now_ms=lambda: t_now,
        )
        respondent_client = AgentMediateClient(
            base_url="https://api.mediate.example",
            agent_key=respondent_key,
            platform_did=platform_key.did,
            transport=_cold_api_tx,
            now_ms=lambda: t_now,
        )

        created_inv = claimant_client.create_invite(
            contract_hash="a" * 64,
            summary="SLA dispute",
            respondent_contact={"email": "ops@vendor.example"},
        )
        self.assertEqual(created_inv["inviteId"], "inv_py_1")
        fetched_inv = respondent_client.get_invite("inv_py_1", token=invite_token)
        self.assertEqual(fetched_inv["status"], "PENDING")
        accepted_inv = respondent_client.accept_invite(invite_token, webhook_url="https://vendor.example/hook")
        self.assertEqual(accepted_inv["respondentId"], respondent_key.did)

        tmpl = {
            "id": "refundUsd",
            "label": "Refund",
            "unit": "USD",
            "min": 0,
            "max": 1000,
            "step": 1,
            "claimantPrefers": "higher",
            "obligor": "respondent",
        }
        with self.assertRaises(AgentMediateError) as unreach_err:
            claimant_client.file_dispute(
                respondent_id=respondent_key.did,
                contract_hash="a" * 64,
                claim={"summary": "S", "requestedRemedy": "R"},
                proposed_issues=[tmpl],
                bounds={"refundUsd": {"min": 0, "max": 800}},
                invite_id="inv_py_1",
                require_delivery=True,
                idempotency_key="py-cold-unreach-1",
            )
        self.assertEqual(unreach_err.exception.code, "RESPONDENT_UNREACHABLE")
        self.assertFalse(unreach_err.exception.payment_sent)
        self.assertEqual(released_headers, ["paid-header-cold-1"])

        unreachable_mode[0] = False
        filed_cold = claimant_client.file_dispute(
            respondent_id=respondent_key.did,
            contract_hash="a" * 64,
            claim={"summary": "S", "requestedRemedy": "R"},
            proposed_issues=[tmpl],
            bounds={"refundUsd": {"min": 0, "max": 800}},
            invite_id="inv_py_1",
            require_delivery=True,
            idempotency_key="py-cold-ok-2",
        )
        self.assertEqual(filed_cold["disputeId"], "dsp_py_cold")

        # 4. CR3-PY-M1 & CR3-SDK-M2: _mandate_cache reuses signed mandates without re-signing on cache hits, and verify_webhook handles allow_unbound_invite
        with unittest.mock.patch("agent_mediate.client.sign_mandate", wraps=sign_mandate) as spy_sign:
            m1 = claimant_client._resolve_mandate(
                mandate=None,
                bounds={"refundUsd": {"min": 0, "max": 500}},
                determination_consent=None,
                determination_bounds=None,
                scope={"contractHash": "b" * 64, "counterpartyId": respondent_key.did},
                idempotency_key="py-cache-hit-idem",
            )
            m2 = claimant_client._resolve_mandate(
                mandate=None,
                bounds={"refundUsd": {"min": 0, "max": 500}},
                determination_consent=None,
                determination_bounds=None,
                scope={"contractHash": "b" * 64, "counterpartyId": respondent_key.did},
                idempotency_key="py-cache-hit-idem",
            )
            self.assertEqual(m1["id"], m2["id"])
            self.assertEqual(spy_sign.call_count, 1)

        unbound_body = json.dumps(
            {
                "inviteId": "inv_py_1",
                "seq": 1,
                "type": "DISPUTE_INVITE",
                "at": t_now,
                "data": {"inviteUrl": invite_url},
                "recipient": {"party": "respondent"},
            }
        )
        unbound_hdrs = sign_request(
            key=platform_key,
            method="POST",
            target_uri="https://vendor.example/hook",
            body=unbound_body,
            created=t_now // 1000,
            nonce="nonce-py-unbound-1",
            tag=WEBHOOK_SIGNATURE_TAG,
        )
        self.assertTrue(
            AgentMediateClient.verify_webhook(
                url="https://vendor.example/hook",
                headers=unbound_hdrs,
                body=unbound_body,
                platform_did=platform_key.did,
                now_ms=t_now,
                agent_id=respondent_key.did,
                allow_unbound_invite=True,
                invite_id="inv_py_1",
            )["ok"]
        )
        self.assertFalse(
            AgentMediateClient.verify_webhook(
                url="https://vendor.example/hook",
                headers=unbound_hdrs,
                body=unbound_body,
                platform_did=platform_key.did,
                now_ms=t_now,
                agent_id=respondent_key.did,
                allow_unbound_invite=False,
                invite_id="inv_py_1",
            )["ok"]
        )



if __name__ == "__main__":
    unittest.main()
