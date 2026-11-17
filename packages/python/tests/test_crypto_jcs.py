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



def _make_torsion_r_signature(seed: bytes, message: bytes) -> bytes:
    """
    Construct an Ed25519 signature whose commitment point R' = [r]B + T_2 includes the exact order-2
    torsion point T_2 = (0, P - 1, 1, 0), recomputing k = H(enc(R') || A || M) mod L and S = (r + k*a) mod L.
    Cofactored verification [8]([S]B - R' - [k]A) == O would accept this signature, whereas strict cofactorless
    verification [S]B == R' + [k]A (Node/OpenSSL and fixed Python) rejects it (`FS-H4`).
    """
    a_scalar, prefix, pub = _clamp_seed(seed)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    t2 = (0, P - 1, 1, 0)
    r_prime = _point_add(_scalar_mult(r), t2)
    r_prime_bytes = _encode_point(r_prime)
    k = int.from_bytes(hashlib.sha512(r_prime_bytes + pub + message).digest(), "little") % L
    s = (r + k * a_scalar) % L
    return r_prime_bytes + s.to_bytes(32, "little")



class PythonCryptoAndJcsTests(unittest.TestCase):
    def test_rfc8032_test_vectors(self) -> None:
        # RFC 8032 §7.1 TEST 1 (empty message) & TEST 2 (1-byte 0x72)
        seed1 = bytes.fromhex("9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60")
        pub1 = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
        sig1 = bytes.fromhex(
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
            "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"
        )
        key1 = agent_key_from_seed(seed1)
        self.assertEqual(key1.public_key, pub1)
        self.assertEqual(ed25519_sign(seed1, b""), sig1)
        self.assertTrue(ed25519_verify(pub1, b"", sig1))
        self.assertFalse(ed25519_verify(pub1, b"x", sig1))

        seed2 = bytes.fromhex("4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb")
        pub2 = bytes.fromhex("3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c")
        sig2 = bytes.fromhex(
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da"
            "085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"
        )
        self.assertEqual(agent_key_from_seed(seed2).public_key, pub2)
        self.assertEqual(ed25519_sign(seed2, b"\x72"), sig2)
        self.assertTrue(ed25519_verify(pub2, b"\x72", sig2))

    def test_pkcs8_pem_and_weak_point_rejection(self) -> None:
        key = generate_agent_key()
        self.assertTrue(is_did_key(key.did))
        restored = agent_key_from_pem(key.to_pem())
        self.assertEqual(restored.did, key.did)
        self.assertEqual(restored.seed, key.seed)
        # CR-SDK-M2: repr/str (logging %r, pytest diffs, Sentry locals) must never expose the private seed.
        for rendered in (repr(key), str(key), f"{key!r}"):
            self.assertIn(key.did, rendered)
            self.assertNotIn("seed", rendered)
            self.assertNotIn(key.seed.hex(), rendered)
            self.assertNotIn(repr(key.seed), rendered)

        # Identity point (y = 1, x = 0): small-order 8-torsion point must be rejected!
        identity_raw = b"\x01" + (b"\x00" * 31)
        self.assertEqual(weak_point_reason(identity_raw), "small-order point")
        bad_did = did_key_from_raw_public_key(identity_raw)
        self.assertFalse(is_did_key(bad_did))

    def test_rfc8785_jcs_canonicalization(self) -> None:
        # Negative zero, key ordering (including supplementary plane surrogate ordering U+1F600 < U+E000), control chars
        doc = {"b": 1, "a": -0.0, "\ue000": "bmp_high", "\U0001f600": "emoji", "ctrl": "line1\n\x07"}
        self.assertEqual(canonical_json(doc), '{"a":0,"b":1,"ctrl":"line1\\n\\u0007","\U0001f600":"emoji","\ue000":"bmp_high"}')
        self.assertEqual(len(contract_hash(doc)), 64)
        # RFC 8785 §3.2.3 integer-like keys must sort lexicographically by UTF-16 code units, not JS array-index order (review H7)
        num_keys = {"10": 1, "9": 2, "01": 3, "a": 4, "__proto__": 9, "nested": {"2": "two", "10": "ten"}}
        self.assertEqual(
            canonical_json(num_keys),
            '{"01":3,"10":1,"9":2,"__proto__":9,"a":4,"nested":{"10":"ten","2":"two"}}',
        )
        # Pin golden RULES_HASH (D118, D126, v1.3.0, review M9)
        self.assertEqual(RULES_HASH, "8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4")

    def test_ed25519_torsion_r_signature_split_rejected(self) -> None:
        a = generate_agent_key()
        b = generate_agent_key()
        platform = generate_agent_key()
        msg = b"agent-mediate torsion-R cross-runtime check"
        torsion_sig = _make_torsion_r_signature(b.seed, msg)

        # Verify mathematically that [8]([S]B - R' - [k]A) is the identity, while [S]B - R' - [k]A != O.
        from agent_mediate.crypto import _decode_point
        a_pt = _decode_point(b.public_key)
        r_pt = _decode_point(torsion_sig[:32])
        assert a_pt is not None and r_pt is not None
        s_val = int.from_bytes(torsion_sig[32:], "little")
        k_val = int.from_bytes(hashlib.sha512(torsion_sig[:32] + b.public_key + msg).digest(), "little") % L
        neg_a = ((-a_pt[0]) % P, a_pt[1], a_pt[2], (-a_pt[3]) % P)
        rhs_zero = _point_add(
            _scalar_mult(s_val),
            _point_add(((-r_pt[0]) % P, r_pt[1], r_pt[2], (-r_pt[3]) % P), _scalar_mult(k_val, neg_a)),
        )
        z8 = _point_double(_point_double(_point_double(rhs_zero)))
        self.assertTrue(z8[0] == 0 and z8[1] == z8[2], "cofactored [8] check would accept torsion-R signature")
        self.assertFalse(rhs_zero[0] == 0 and rhs_zero[1] == rhs_zero[2])
        self.assertFalse(ed25519_verify(b.public_key, msg, torsion_sig))

        # Verify verify_clause also rejects a counterparty torsion-R signature.
        draft = build_clause(
            contract={"service": "API", "tier": "gold"},
            platform_did=platform.did,
            parties=[{"agentId": a.did}, {"agentId": b.did}],
            issued_at=1800000000000,
        )
        signed_a = sign_clause(draft, a)
        payload_bytes = clause_signing_payload(signed_a).encode("utf-8")
        bad_b_sig = base64.b64encode(_make_torsion_r_signature(b.seed, payload_bytes)).decode("ascii")
        torsion_clause = {
            **signed_a,
            "signatures": [*signed_a["signatures"], {"partyAgentId": b.did, "signerId": b.did, "signature": bad_b_sig}],
        }
        verdict = verify_clause(torsion_clause, expected_platform_did=platform.did, claimant_id=a.did, respondent_id=b.did)
        self.assertFalse(verdict["ok"])

    def test_review_2026_11_core_parity(self) -> None:
        """CR-CORE-M1/M2/M3: reserved ids, absolute grid tolerance and the pinned best-effort search vector."""
        from agent_mediate import protocol as p

        def issue(iid: str, **over: object) -> dict:
            base = {"id": iid, "label": iid, "unit": "u", "min": 0, "max": 100, "step": 1, "claimantPrefers": "higher", "obligor": "respondent"}
            base.update(over)
            return base

        for iid in ("constructor", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString", "toString", "valueOf"):
            self.assertIn(iid, p.RESERVED_ISSUE_IDS)
            with self.assertRaisesRegex(ValueError, "reserved"):
                p._validate_issues([issue("refundUsd"), issue(iid)])
        big = issue("x", max=1_000_000)
        self.assertFalse(p._is_on_grid(big, 999_999.0009))
        self.assertTrue(p._is_on_grid(big, 999_999))
        with self.assertRaisesRegex(ValueError, "multiple of step"):
            p._validate_issues([issue("x", max=100_000.00005)])
        frac = issue("rate", min=0.1, max=0.7, step=0.1)
        p._validate_issues([frac])
        for v in (0.1, 0.30000000000000004, 0.7, 0.1 + 0.2 + 0.1):
            self.assertTrue(p._is_on_grid(frac, v), v)
        self.assertFalse(p._is_on_grid(frac, 0.35))

        issues = [issue("a"), issue("b", step=25)]
        privates = {
            "claimant": {"weights": {"a": 0.7, "b": 0.3}, "walkaway": {"a": 40, "b": 75}},
            "respondent": {"weights": {"a": 0.699, "b": 0.301}, "walkaway": {"a": 62, "b": 25}},
        }
        for split in (0.3, 0.5, 0.7):
            self.assertIsNone(p._nash_proposal(issues, privates, split))
        self.assertFalse(p._present_proposal(issues, privates, 0.5)["settles"])



if __name__ == "__main__":
    unittest.main()
