"""
Agent-Mediate wire protocol helpers:
- RFC 9421 HTTP Message Signatures + RFC 9530 Content-Digest (Ed25519 `did:key`)
- Principal mandates (`agent-mediate/mandate/v1`)
- Co-signed pre-dispute clauses (`agent-mediate/clause/v1`)
- Platform-signed outcomes & notices (`Ed25519Signature2026`, `agent-mediate/document/v1`)
- A2A Agent Card EdDSA JWS verification (`verify_agent_card_signature`)
- Hash-chained public audit verification (`verify_public_audit_chain`)
"""
from __future__ import annotations

import base64
import copy
import hashlib
import hmac
import ipaddress
import json
import math
import re
import sys
import time
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence
from urllib.parse import quote, unquote, urlsplit

from .crypto import AgentKey, did_key_from_raw_public_key, ed25519_verify, is_did_key, raw_public_key_from_did_key, verify_text
from .jcs import MECHANISM_SPEC, RULES_HASH, RULES_VERSION, canonical_json, contract_hash, loads_jcs_json, sha256_hex

MAX_CLOCK_SKEW_SECONDS = 300
WEBHOOK_SIGNATURE_TAG = "agent-mediate-webhook-v1"
CLAUSE_TYPE = "agent-mediate/clause/v1"
DISPUTE_NOTICE_TYPE = "agent-mediate/dispute-notice/v1"
DISPUTE_INVITE_TYPE = "agent-mediate/dispute-invite/v1"
KEY_HISTORY_TYPE = "agent-mediate/key-history/v1"
KEY_ROTATION_TYPE = "agent-mediate/key-rotation/v1"
MAX_KEY_ROTATION_HOPS = 8
HONOURS_ATTESTATION_TYPE = "agent-mediate/honours-attestation/v1"
DEFAULT_KEY_HISTORY_TTL_MS = 7 * 86_400_000
GENESIS_HASH = "0" * 64

DOCUMENT_DOMAIN_V1 = "agent-mediate/document/v1\n"
DOCUMENT_DOMAIN_V2 = "agent-mediate/document/v2\n"
REQUEST_PROOF_HASH_DOMAIN = "agent-mediate/request-proof/v1\n"
PROPOSAL_KEY_COMMIT_DOMAIN = "agent-mediate/proposal-key-commit/v1\n"
DECLARED_INPUT_COMMIT_DOMAIN = "agent-mediate/declared-input-commit/v1\n"
CHECKPOINT_LEAF_DOMAIN = "agent-mediate/checkpoint-leaf/v1\n"
CHECKPOINT_NODE_DOMAIN = "agent-mediate/checkpoint-node/v1\n"
EMPTY_MERKLE_ROOT = sha256_hex("agent-mediate/checkpoint-empty/v1\n")
BASE_ANCHOR_MAGIC = "414d4350"

_MANDATE_DOMAIN = "agent-mediate/mandate/v1\n"
_DOCUMENT_DOMAIN = DOCUMENT_DOMAIN_V1
_CLAUSE_DOMAIN = "agent-mediate/clause/v1\n"

_TAG_RE = re.compile(r"^[A-Za-z0-9_.:-]{1,64}$")
_ALLOWED_COMPONENTS = {"@method", "@target-uri", "content-digest", "idempotency-key"}
_MAX_SAFE_INT = 9007199254740991
_UNSET = object()
_NONCE_RE = re.compile(r"^[A-Za-z0-9_\-:.]{16,128}$")
_SIG_INPUT_RE = re.compile(r'^sig1=\(((?:"[^"\s]+"(?: "[^"\s]+")*)?)\)((?:;[a-z]+=(?:"[^"\\]*"|\d+))*)$')
_PARAM_RE = re.compile(r';([a-z]+)=("[^"\\]*"|\d+)')
_SIGNATURE_RE = re.compile(r"^sig1=:([A-Za-z0-9+/]+={0,2}):$")
_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]+$")
_HAS_CTL_RE = re.compile(r"[\x00-\x08\x0a-\x1f\x7f]")
_HAS_WS_OR_CTL_RE = re.compile(r"[\s\x00-\x1f\x7f]")


def _trim_ows(s: str) -> str:
    return re.sub(r"^[ \t]+|[ \t]+$", "", s)


def _parse_sig_params(raw_params: str) -> Dict[str, Any]:
    params: Dict[str, str] = {}
    for pm in _PARAM_RE.finditer(raw_params):
        pkey, pval = pm.group(1), pm.group(2)
        if pkey in params:
            return {"ok": False, "reason": f"duplicate parameter {pkey}"}
        if pkey not in ("created", "keyid", "alg", "nonce", "tag"):
            return {"ok": False, "reason": f"unsupported parameter {pkey}"}
        if pkey == "created":
            if pval.startswith('"') or not pval.isdigit():
                return {"ok": False, "reason": "created must be an unquoted RFC 8941 integer"}
            params[pkey] = pval
        else:
            if not (pval.startswith('"') and pval.endswith('"')):
                return {"ok": False, "reason": f"parameter {pkey} must be an RFC 8941 quoted string"}
            params[pkey] = pval[1:-1]
    return {"ok": True, "params": params}


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(text: str) -> bytes:
    pad = "=" * ((4 - (len(text) % 4)) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _is_valid_now_ms(now_ms: Any) -> bool:
    return not isinstance(now_ms, bool) and isinstance(now_ms, (int, float)) and math.isfinite(now_ms) and now_ms > 0


def _normalize_expected_base_url(raw: Any) -> Optional[str]:
    if not isinstance(raw, str):
        return None
    trimmed = raw.strip()
    if not trimmed or re.search(r"[\x00-\x20\x7f\\]", trimmed):
        return None
    try:
        parsed = urlsplit(trimmed)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    if (
        scheme not in ("http", "https")
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query != ""
        or parsed.fragment != ""
    ):
        return None
    raw_host = parsed.hostname
    if ":" in raw_host:
        try:
            addr = ipaddress.ip_address(raw_host)
        except ValueError:
            return None
        host_str = f"[{addr.compressed}]"
    else:
        host_str = raw_host.lower()
    default_port = 443 if scheme == "https" else 80
    netloc = host_str if (port is None or port == default_port) else f"{host_str}:{port}"
    clean_path = "" if parsed.path in ("", "/") else parsed.path.rstrip("/")
    normalized = f"{scheme}://{netloc}{clean_path}"
    return "https://api.ai-agents-mediation.com" if normalized == "https://ai-agents-mediation.com" else normalized


def content_digest(body: str | bytes) -> str:
    raw = body.encode("utf-8") if isinstance(body, str) else body
    b64 = base64.b64encode(hashlib.sha256(raw).digest()).decode("ascii")
    return f"sha-256=:{b64}:"


def _signature_base(
    components: Sequence[str],
    method: str,
    target_uri: str,
    lookup: Callable[[str], Optional[str]],
    signature_params: str,
) -> str:
    lines: List[str] = []
    for comp in components:
        if comp == "@method":
            if not isinstance(method, str) or not re.fullmatch(r"[A-Za-z]+", method):
                raise ValueError("@method must be an ASCII HTTP method token")
            lines.append(f'"@method": {method.upper()}')
            continue
        if comp == "@target-uri":
            if not isinstance(target_uri, str) or len(target_uri) == 0 or _HAS_WS_OR_CTL_RE.search(target_uri):
                raise ValueError("@target-uri must not contain whitespace or control characters")
            lines.append(f'"@target-uri": {target_uri}')
            continue
        val = lookup(comp)
        if val is None:
            raise ValueError(f"covered header {comp} is missing")
        if _HAS_CTL_RE.search(val):
            raise ValueError(f"covered header {comp} contains control characters")
        lines.append(f'"{comp}": {_trim_ows(val)}')
    lines.append(f'"@signature-params": {signature_params}')
    return "\n".join(lines)


def sign_request(
    *,
    method: str,
    target_uri: str,
    key: AgentKey,
    created: int,
    nonce: str,
    headers: Optional[Mapping[str, str]] = None,
    body: Optional[str] = None,
    tag: Optional[str] = None,
) -> Dict[str, str]:
    if isinstance(created, bool) or not isinstance(created, int) or created < 0 or created > _MAX_SAFE_INT:
        raise ValueError("created must be a non-negative integer timestamp")
    if not isinstance(nonce, str) or not _NONCE_RE.fullmatch(nonce):
        raise ValueError("nonce must be 16-128 URL-safe characters")
    hdrs: Dict[str, str] = {k.lower(): v for k, v in (headers or {}).items()}
    components: List[str] = ["@method", "@target-uri"]
    if body is not None and len(body) > 0:
        hdrs["content-digest"] = content_digest(body)
        components.append("content-digest")
    if "idempotency-key" in hdrs:
        if not isinstance(hdrs["idempotency-key"], str) or len(hdrs["idempotency-key"].strip()) == 0:
            raise ValueError("idempotency-key must be non-empty")
        components.append("idempotency-key")
    if tag is not None and (not isinstance(tag, str) or not _TAG_RE.fullmatch(tag)):
        raise ValueError("invalid signature tag")

    comp_list = " ".join(f'"{c}"' for c in components)
    tag_part = f';tag="{tag}"' if tag is not None else ""
    sig_params = f'({comp_list});created={created};keyid="{key.did}";alg="ed25519";nonce="{nonce}"{tag_part}'
    base = _signature_base(components, method, target_uri, lambda n: hdrs.get(n), sig_params)
    sig_b64 = key.sign_text(base)

    out: Dict[str, str] = {
        "signature-input": f"sig1={sig_params}",
        "signature": f"sig1=:{sig_b64}:",
    }
    if "content-digest" in hdrs:
        out["content-digest"] = hdrs["content-digest"]
    return out


def verify_request(
    *,
    method: str,
    target_uri: str,
    headers: Mapping[str, str],
    body: str,
    now_ms: Optional[int] = None,
    expect_tag: Optional[str] = None,
) -> Dict[str, Any]:
    lower = {k.lower(): v for k, v in headers.items()}
    sig_input = lower.get("signature-input")
    sig_header = lower.get("signature")
    if not sig_input or not sig_header:
        return {"ok": False, "reason": "missing Signature-Input or Signature header"}
    if _HAS_CTL_RE.search(sig_input) or _HAS_CTL_RE.search(sig_header):
        return {"ok": False, "reason": "Signature-Input or Signature contains control characters"}
    clean_sig_input = _trim_ows(sig_input)
    clean_sig_header = _trim_ows(sig_header)

    m = _SIG_INPUT_RE.fullmatch(clean_sig_input)
    if not m:
        return {"ok": False, "reason": "malformed Signature-Input (expected a single sig1 entry)"}
    components = [c[1:-1] for c in m.group(1).split(" ")] if m.group(1) else []
    parsed_params = _parse_sig_params(m.group(2))
    if not parsed_params.get("ok"):
        return parsed_params
    params: Dict[str, str] = parsed_params["params"]

    tag = params.get("tag")
    if tag != expect_tag:
        if expect_tag:
            return {"ok": False, "reason": f'signature tag must be "{expect_tag}"'}
        return {"ok": False, "reason": f'unexpected signature tag "{tag}"'}

    if len(set(components)) != len(components):
        return {"ok": False, "reason": "duplicate covered component"}
    for comp in components:
        if comp not in _ALLOWED_COMPONENTS:
            return {"ok": False, "reason": f"unsupported component {comp}"}

    for req in ("@method", "@target-uri"):
        if req not in components:
            return {"ok": False, "reason": f"{req} must be covered"}

    if len(body) > 0 and "content-digest" not in components:
        return {"ok": False, "reason": "content-digest must be covered for requests with a body"}
    if "content-digest" in lower and "content-digest" not in components:
        return {"ok": False, "reason": "content-digest must be covered when present"}
    if "content-digest" in components:
        raw_cd = lower.get("content-digest")
        if raw_cd is None or _HAS_CTL_RE.search(raw_cd) or _trim_ows(raw_cd) != content_digest(body):
            return {"ok": False, "reason": "content-digest does not match body"}

    if "idempotency-key" in lower and "idempotency-key" not in components:
        return {"ok": False, "reason": "idempotency-key must be covered when present"}
    if "idempotency-key" in components:
        raw_ik = lower.get("idempotency-key")
        if raw_ik is None or _HAS_CTL_RE.search(raw_ik) or len(_trim_ows(raw_ik)) == 0:
            return {"ok": False, "reason": "covered idempotency-key must be non-empty"}

    if params.get("alg") != "ed25519":
        return {"ok": False, "reason": 'alg must be "ed25519"'}
    if now_ms is not None and not _is_valid_now_ms(now_ms):
        return {"ok": False, "reason": "now_ms must be a positive finite timestamp"}
    try:
        created = int(params.get("created", ""))
    except ValueError:
        return {"ok": False, "reason": "created is required"}
    if created < -_MAX_SAFE_INT or created > _MAX_SAFE_INT:
        return {"ok": False, "reason": "created is outside IEEE-754 safe integer range"}

    current_ms = int(time.time() * 1000) if now_ms is None else now_ms
    if abs((current_ms / 1000.0) - created) > MAX_CLOCK_SKEW_SECONDS:
        return {"ok": False, "reason": "created is outside the allowed clock skew"}

    nonce = params.get("nonce", "")
    if not _NONCE_RE.fullmatch(nonce):
        return {"ok": False, "reason": "nonce is required (16-128 URL-safe characters)"}

    keyid = params.get("keyid", "")
    if not is_did_key(keyid):
        return {"ok": False, "reason": "keyid must be an Ed25519 did:key"}

    sm = _SIGNATURE_RE.fullmatch(clean_sig_header)
    if not sm:
        return {"ok": False, "reason": "malformed Signature header"}
    sig_params = clean_sig_input[len("sig1=") :]
    try:
        base = _signature_base(components, method, target_uri, lambda n: lower.get(n), sig_params)
    except ValueError as err:
        return {"ok": False, "reason": str(err)}

    if not verify_text(keyid, base, sm.group(1)):
        return {"ok": False, "reason": "signature verification failed"}
    proof: Dict[str, Any] = {
        "method": method.upper(),
        "targetUri": target_uri,
        "contentDigest": _trim_ows(lower["content-digest"]) if "content-digest" in components and "content-digest" in lower else None,
        "idempotencyKey": _trim_ows(lower["idempotency-key"]) if "idempotency-key" in components and "idempotency-key" in lower else None,
        "signatureInput": clean_sig_input,
        "signature": clean_sig_header,
        "created": created,
        "nonce": nonce,
        "keyid": keyid,
    }
    return {"ok": True, "keyid": keyid, "nonce": nonce, "created": created, "tag": tag, "proof": proof}


def compute_request_proof_hash(proof: Mapping[str, Any]) -> str:
    return sha256_hex(REQUEST_PROOF_HASH_DOMAIN + canonical_json(proof))


def verify_dispute_action_target(
    proof: Mapping[str, Any],
    *,
    expected_dispute_id: str,
    expected_action: str,
    expected_base_url: Optional[str] = None,
    expected_round: Optional[int] = None,
) -> Dict[str, Any]:
    if not isinstance(proof, Mapping):
        return {"ok": False, "reason": "invalid proof object"}
    if not isinstance(expected_dispute_id, str) or len(expected_dispute_id) == 0:
        return {"ok": False, "reason": "expected_dispute_id must be a non-empty string"}
    method = proof.get("method")
    target_uri = proof.get("targetUri")
    if not isinstance(method, str) or not isinstance(target_uri, str):
        return {"ok": False, "reason": "invalid proof method or targetUri"}
    if _HAS_WS_OR_CTL_RE.search(method) or _HAS_WS_OR_CTL_RE.search(target_uri):
        return {"ok": False, "reason": "proof method or targetUri contains whitespace or control characters"}
    if method.upper() != "POST":
        return {"ok": False, "reason": f"dispute action proof method must be POST, got {method}"}

    if expected_base_url is not None:
        base = _normalize_expected_base_url(expected_base_url)
        if base is None:
            return {"ok": False, "reason": "expected_base_url is not a valid HTTP(S) base URL"}
        if not target_uri.startswith(f"{base}/"):
            return {"ok": False, "reason": "proof targetUri does not match expected baseUrl"}
        rest = target_uri[len(base) :]
    else:
        parsed = urlsplit(target_uri)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            return {"ok": False, "reason": "proof targetUri is not a valid URL"}
        rest = parsed.path + (f"?{parsed.query}" if parsed.query else "") + (f"#{parsed.fragment}" if parsed.fragment else "")

    if "#" in rest:
        return {"ok": False, "reason": "proof targetUri must not contain a fragment"}
    if "?" in rest:
        path_part, query_part = rest.split("?", 1)
        if query_part not in ("view=full", "view=compact"):
            return {"ok": False, "reason": "proof targetUri carries unexpected query parameters"}
    else:
        path_part = rest

    if any(seg in (".", "..") for seg in path_part.split("/")):
        return {"ok": False, "reason": "proof targetUri must not contain dot-segments"}

    enc_id = quote(expected_dispute_id, safe="~!*'()")
    prefix = f"/v1/disputes/{enc_id}"
    exact_map = {
        "file_dispute": "/v1/disputes",
        "join_dispute": f"{prefix}/join",
        "submit_evidence": f"{prefix}/evidence",
        "close_evidence": f"{prefix}/evidence/close",
        "confirm_issues": f"{prefix}/issues/confirm",
        "reject_issues": f"{prefix}/issues/reject",
        "update_mandate": f"{prefix}/mandate",
        "submit_final_offer": f"{prefix}/determination/final-offer",
        "respond_improvement": f"{prefix}/execution/improvement",
        "submit_execution_proof": f"{prefix}/execution/proof",
        "confirm_execution": f"{prefix}/execution/confirm",
        "contest_execution": f"{prefix}/execution/contest",
        "acknowledge_cure": f"{prefix}/cure",
        "withdraw": f"{prefix}/withdraw",
    }
    if expected_action == "submit_offer":
        rounds_prefix = f"{prefix}/rounds/"
        if not path_part.startswith(rounds_prefix) or not path_part.endswith("/offer"):
            return {"ok": False, "reason": "submit_offer targetUri mismatch"}
        round_seg = path_part[len(rounds_prefix) : -len("/offer")]
        if not re.fullmatch(r"^[1-9][0-9]*$", round_seg):
            return {"ok": False, "reason": "submit_offer round segment invalid"}
        round_num = int(round_seg)
        if round_num > _MAX_SAFE_INT:
            return {"ok": False, "reason": "submit_offer round segment invalid"}
        if expected_round is not None:
            if isinstance(expected_round, bool) or not isinstance(expected_round, int) or expected_round < 1 or expected_round > _MAX_SAFE_INT:
                return {"ok": False, "reason": "expected_round must be a positive integer"}
            if round_num != expected_round:
                return {"ok": False, "reason": f"submit_offer round mismatch (expected {expected_round}, got {round_num})"}
        return {"ok": True}
    expected_path = exact_map.get(expected_action)
    if expected_path is None:
        return {"ok": False, "reason": f"unknown dispute action {expected_action}"}
    if path_part != expected_path:
        return {"ok": False, "reason": f"{expected_action} targetUri mismatch"}
    return {"ok": True}


BODY_REQUIRED_DISPUTE_ACTIONS = frozenset(
    {
        "file_dispute",
        "join_dispute",
        "submit_evidence",
        "confirm_issues",
        "reject_issues",
        "update_mandate",
        "submit_offer",
        "submit_final_offer",
        "respond_improvement",
        "submit_execution_proof",
        "contest_execution",
    }
)


def verify_request_proof(
    proof: Mapping[str, Any],
    *,
    expected_agent_id: Optional[str] = None,
    expected_proof_hash: Optional[str] = None,
    expected_base_url: Optional[str] = None,
    expected_dispute_id: Optional[str] = None,
    expected_action: Optional[str] = None,
    expected_round: Optional[int] = None,
    expect_tag: Optional[str] = None,
    expected_content_digest: Optional[str] = None,
    expected_idempotency_key: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(proof, Mapping):
        return {"ok": False, "reason": "invalid proof object"}
    if not isinstance(proof.get("method"), str) or not isinstance(proof.get("targetUri"), str):
        return {"ok": False, "reason": "invalid method or targetUri"}
    if _HAS_WS_OR_CTL_RE.search(proof["method"]) or _HAS_WS_OR_CTL_RE.search(proof["targetUri"]):
        return {"ok": False, "reason": "proof method or targetUri contains whitespace or control characters"}
    if (
        not isinstance(proof.get("signatureInput"), str)
        or not isinstance(proof.get("signature"), str)
        or not isinstance(proof.get("keyid"), str)
    ):
        return {"ok": False, "reason": "invalid signatureInput, signature or keyid"}
    if _HAS_CTL_RE.search(proof["signatureInput"]) or _HAS_CTL_RE.search(proof["signature"]):
        return {"ok": False, "reason": "signatureInput or signature contains control characters"}
    for opt_str_field in ("contentDigest", "idempotencyKey"):
        if opt_str_field not in proof:
            return {"ok": False, "reason": f"missing {opt_str_field} field"}
        if proof[opt_str_field] is not None and (not isinstance(proof[opt_str_field], str) or _HAS_CTL_RE.search(proof[opt_str_field])):
            return {"ok": False, "reason": f"invalid {opt_str_field}"}
    if expected_agent_id is not None and proof.get("keyid") != expected_agent_id:
        return {"ok": False, "reason": "proof keyid does not match expected agentId"}
    if expected_dispute_id is not None or expected_action is not None:
        if not expected_dispute_id or not expected_action:
            return {"ok": False, "reason": "both expected_dispute_id and expected_action are required for target binding"}
        target_ok = verify_dispute_action_target(
            proof,
            expected_dispute_id=expected_dispute_id,
            expected_action=expected_action,
            expected_base_url=expected_base_url,
            expected_round=expected_round,
        )
        if not target_ok.get("ok"):
            return target_ok
        if expected_action in BODY_REQUIRED_DISPUTE_ACTIONS and proof.get("contentDigest") is None:
            return {"ok": False, "reason": f"{expected_action} proof must cover content-digest"}
    elif expected_base_url is not None:
        base = _normalize_expected_base_url(expected_base_url)
        if base is None:
            return {"ok": False, "reason": "expected_base_url is not a valid HTTP(S) base URL"}
        if not str(proof.get("targetUri")).startswith(f"{base}/"):
            return {"ok": False, "reason": "proof targetUri does not match expected baseUrl"}

    if expected_content_digest is not None:
        actual_cd = proof.get("contentDigest")
        if not isinstance(actual_cd, str) or _trim_ows(actual_cd) != _trim_ows(expected_content_digest):
            return {"ok": False, "reason": "proof contentDigest does not match expected_content_digest"}
    if expected_idempotency_key is not None:
        actual_ik = proof.get("idempotencyKey")
        if not isinstance(actual_ik, str) or _trim_ows(actual_ik) != _trim_ows(expected_idempotency_key):
            return {"ok": False, "reason": "proof idempotencyKey does not match expected_idempotency_key"}

    sig_input = _trim_ows(proof["signatureInput"])
    m = _SIG_INPUT_RE.fullmatch(sig_input)
    if not m:
        return {"ok": False, "reason": "malformed Signature-Input"}
    components = [c[1:-1] for c in m.group(1).split(" ")] if m.group(1) else []
    parsed_params = _parse_sig_params(m.group(2))
    if not parsed_params.get("ok"):
        return parsed_params
    params: Dict[str, str] = parsed_params["params"]
    tag = params.get("tag")
    if tag != expect_tag:
        if expect_tag:
            return {"ok": False, "reason": f'signature tag must be "{expect_tag}"'}
        return {"ok": False, "reason": f'unexpected signature tag "{str(tag)[:64]}"'}
    if len(set(components)) != len(components):
        return {"ok": False, "reason": "duplicate covered component"}
    allowed_components = {"@method", "@target-uri", "content-digest", "idempotency-key"}
    for comp in components:
        if comp not in allowed_components:
            return {"ok": False, "reason": f"unsupported component {comp}"}
    for req in ("@method", "@target-uri"):
        if req not in components:
            return {"ok": False, "reason": f"{req} must be covered"}

    raw_digest = proof.get("contentDigest")
    c_digest: Optional[str] = None
    if "content-digest" in components:
        if not isinstance(raw_digest, str) or not re.fullmatch(r"^sha-256=:[A-Za-z0-9+/]+={0,2}:$", _trim_ows(raw_digest)):
            return {"ok": False, "reason": "invalid covered content-digest"}
        c_digest = _trim_ows(raw_digest)
    elif raw_digest is not None:
        return {"ok": False, "reason": "contentDigest must be null when not covered"}

    raw_idem = proof.get("idempotencyKey")
    idem_key: Optional[str] = None
    if "idempotency-key" in components:
        if not isinstance(raw_idem, str) or len(_trim_ows(raw_idem)) == 0:
            return {"ok": False, "reason": "invalid covered idempotency-key"}
        idem_key = _trim_ows(raw_idem)
    elif raw_idem is not None:
        return {"ok": False, "reason": "idempotencyKey must be null when not covered"}

    if params.get("alg") != "ed25519":
        return {"ok": False, "reason": 'alg must be "ed25519"'}
    try:
        created = int(params.get("created", ""))
    except ValueError:
        return {"ok": False, "reason": "created mismatch"}
    raw_created = proof.get("created")
    if (
        not isinstance(raw_created, int)
        or isinstance(raw_created, bool)
        or created < -_MAX_SAFE_INT
        or created > _MAX_SAFE_INT
        or raw_created != created
    ):
        return {"ok": False, "reason": "created mismatch"}

    nonce = params.get("nonce", "")
    if not _NONCE_RE.fullmatch(nonce) or proof.get("nonce") != nonce:
        return {"ok": False, "reason": "nonce mismatch"}
    keyid = params.get("keyid", "")
    if proof.get("keyid") != keyid or not is_did_key(keyid):
        return {"ok": False, "reason": "keyid mismatch"}

    sig_header = _trim_ows(str(proof.get("signature") or ""))
    sm = _SIGNATURE_RE.fullmatch(sig_header)
    if not sm:
        return {"ok": False, "reason": "malformed Signature"}
    method = proof.get("method")
    target_uri = proof.get("targetUri")
    if not isinstance(method, str) or not isinstance(target_uri, str):
        return {"ok": False, "reason": "invalid method or targetUri"}

    sig_params = sig_input[len("sig1=") :]
    lookup = lambda name: c_digest if name == "content-digest" else (idem_key if name == "idempotency-key" else None)
    try:
        base = _signature_base(components, method, target_uri, lookup, sig_params)
    except ValueError as err:
        return {"ok": False, "reason": str(err)}
    if not verify_text(keyid, base, sm.group(1)):
        return {"ok": False, "reason": "signature verification failed"}

    normalized: Dict[str, Any] = {
        "method": method.upper(),
        "targetUri": target_uri,
        "contentDigest": c_digest,
        "idempotencyKey": idem_key,
        "signatureInput": sig_input,
        "signature": sig_header,
        "created": created,
        "nonce": nonce,
        "keyid": keyid,
    }
    proof_hash = compute_request_proof_hash(normalized)
    if expected_proof_hash is not None and proof_hash != expected_proof_hash:
        return {"ok": False, "reason": "proofHash mismatch"}
    return {"ok": True, "proofHash": proof_hash}


# --- Mandates & Signed Documents ----------------------------------------------


def mandate_signing_payload(mandate: Mapping[str, Any]) -> str:
    unsigned = {k: v for k, v in mandate.items() if k != "signature"}
    return _MANDATE_DOMAIN + canonical_json(unsigned)


def sign_mandate(unsigned: Mapping[str, Any], principal: AgentKey) -> Dict[str, Any]:
    if unsigned.get("principalId") != principal.did:
        raise ValueError("principalId must equal the signing key's did")
    doc = dict(unsigned)
    doc["signature"] = principal.sign_text(mandate_signing_payload(doc))
    return doc


def verify_mandate_signature(mandate: Mapping[str, Any]) -> bool:
    try:
        if not isinstance(mandate, Mapping):
            return False
        sig = mandate.get("signature")
        principal_id = mandate.get("principalId")
        if not isinstance(sig, str) or not isinstance(principal_id, str):
            return False
        return verify_text(principal_id, mandate_signing_payload(mandate), sig)
    except Exception:
        return False


def default_platform_key_id(did: str) -> str:
    return f"{did}#key-1"


def sign_document(
    document: Mapping[str, Any],
    signer: AgentKey,
    *,
    key_id: Optional[str] = None,
    created_ms: Optional[int] = None,
    expires_at_ms: Optional[int] = None,
) -> Dict[str, Any]:
    kid = key_id if key_id is not None else default_platform_key_id(signer.did)
    created = int(time.time() * 1000) if created_ms is None else created_ms
    if not isinstance(kid, str) or len(kid) == 0:
        raise ValueError("key_id must be a non-empty string")
    if not isinstance(created, int) or isinstance(created, bool) or created <= 0 or created > _MAX_SAFE_INT:
        raise ValueError("created_ms must be a positive safe integer timestamp")
    if expires_at_ms is not None and (
        not isinstance(expires_at_ms, int)
        or isinstance(expires_at_ms, bool)
        or expires_at_ms <= created
        or expires_at_ms > _MAX_SAFE_INT
    ):
        raise ValueError("expires_at_ms must be a safe integer timestamp after created_ms")

    doc_copy = copy.deepcopy(dict(document))
    proof_without_sig: Dict[str, Any] = {
        "type": "Ed25519Signature2026",
        "verificationMethod": signer.did,
        "keyId": kid,
        "created": created,
    }
    if expires_at_ms is not None:
        proof_without_sig["expiresAt"] = expires_at_ms
    payload = DOCUMENT_DOMAIN_V2 + canonical_json({"document": doc_copy, "proof": proof_without_sig})
    return {
        "document": doc_copy,
        "proof": {
            **proof_without_sig,
            "signatureValue": signer.sign_text(payload),
        },
    }


def verify_document(
    signed: Mapping[str, Any],
    expected_signer: str,
    *,
    now_ms: Optional[int] = None,
    expected_key_id: Optional[str] = None,
) -> bool:
    try:
        if not isinstance(signed, Mapping):
            return False
        proof = signed.get("proof")
        doc = signed.get("document")
        if not isinstance(proof, Mapping) or not isinstance(doc, Mapping):
            return False
        if proof.get("type") != "Ed25519Signature2026":
            return False
        if proof.get("verificationMethod") != expected_signer:
            return False
        sig = proof.get("signatureValue")
        if not isinstance(sig, str):
            return False
        if now_ms is not None and not _is_valid_now_ms(now_ms):
            return False
        if expected_key_id is not None and proof.get("keyId") != expected_key_id:
            return False

        has_v2 = ("keyId" in proof) or ("created" in proof) or ("expiresAt" in proof)
        if has_v2:
            kid = proof.get("keyId")
            created = proof.get("created")
            if not isinstance(kid, str) or len(kid) == 0:
                return False
            if not isinstance(created, int) or isinstance(created, bool) or created <= 0 or created > _MAX_SAFE_INT:
                return False
            if "expiresAt" in proof:
                exp = proof.get("expiresAt")
                if not isinstance(exp, int) or isinstance(exp, bool) or exp <= created or exp > _MAX_SAFE_INT:
                    return False
                if now_ms is not None and now_ms >= exp:
                    return False
            allowed_keys = {"type", "verificationMethod", "keyId", "created", "expiresAt", "signatureValue"}
            if any(k not in allowed_keys for k in proof.keys()):
                return False
            proof_without_sig = {k: v for k, v in proof.items() if k != "signatureValue"}
            payload = DOCUMENT_DOMAIN_V2 + canonical_json({"document": doc, "proof": proof_without_sig})
            return verify_text(expected_signer, payload, sig)

        v1_keys = {"type", "verificationMethod", "signatureValue"}
        if any(k not in v1_keys for k in proof.keys()):
            return False
        return verify_text(expected_signer, DOCUMENT_DOMAIN_V1 + canonical_json(doc), sig)
    except Exception:
        return False


def sign_key_rotation(
    *,
    base_url: str,
    from_key: AgentKey,
    to_did: str,
    rotated_at_ms: int,
    from_key_id: Optional[str] = None,
) -> Dict[str, Any]:
    if not isinstance(to_did, str) or not is_did_key(to_did):
        raise ValueError("to_did must be a valid Ed25519 did:key")
    if to_did == from_key.did:
        raise ValueError("to_did must differ from from_key.did")
    if not isinstance(rotated_at_ms, int) or isinstance(rotated_at_ms, bool) or rotated_at_ms <= 0 or rotated_at_ms > _MAX_SAFE_INT:
        raise ValueError("rotated_at_ms must be a positive safe integer timestamp")
    kid = from_key_id if from_key_id is not None else default_platform_key_id(from_key.did)
    doc = {
        "type": KEY_ROTATION_TYPE,
        "platformDidWeb": did_web_from_url(base_url),
        "fromDid": from_key.did,
        "toDid": to_did,
        "rotatedAt": rotated_at_ms,
    }
    return sign_document(doc, from_key, key_id=kid, created_ms=rotated_at_ms)


def verify_key_history(
    key_history: Mapping[str, Any],
    *,
    expected_active_did: Optional[str] = None,
    now_ms: Optional[int] = None,
    max_age_ms: Optional[int] = None,
    min_updated_at: Optional[int] = None,
) -> Dict[str, Any]:
    hist_doc = key_history.get("document") if isinstance(key_history, Mapping) else None
    if not isinstance(hist_doc, Mapping) or hist_doc.get("type") != KEY_HISTORY_TYPE:
        return {"ok": False, "reason": f"key history document type must be {KEY_HISTORY_TYPE}"}
    active_did = hist_doc.get("activeDid")
    active_key_id = hist_doc.get("activeKeyId")
    if not isinstance(active_did, str) or not is_did_key(active_did) or not isinstance(active_key_id, str) or len(active_key_id) == 0:
        return {"ok": False, "reason": "invalid key history activeDid/activeKeyId"}
    if expected_active_did is not None and (not isinstance(expected_active_did, str) or not is_did_key(expected_active_did)):
        return {"ok": False, "reason": "expected_active_did must be a valid Ed25519 did:key"}
    try:
        url_from_did_web(hist_doc.get("platformDidWeb"))  # type: ignore[arg-type]
    except Exception:
        return {"ok": False, "reason": "invalid key history platformDidWeb"}
    updated_at = hist_doc.get("updatedAt")
    if not isinstance(updated_at, int) or isinstance(updated_at, bool) or updated_at <= 0 or updated_at > _MAX_SAFE_INT:
        return {"ok": False, "reason": "invalid key history updatedAt"}
    if min_updated_at is not None:
        if not isinstance(min_updated_at, int) or isinstance(min_updated_at, bool) or min_updated_at <= 0 or min_updated_at > _MAX_SAFE_INT:
            return {"ok": False, "reason": "invalid min_updated_at"}
        if updated_at < min_updated_at:
            return {"ok": False, "reason": "key history updatedAt precedes min_updated_at (rollback)"}
    if max_age_ms is not None:
        if isinstance(max_age_ms, bool) or not isinstance(max_age_ms, (int, float)) or not math.isfinite(max_age_ms) or max_age_ms < 0:
            return {"ok": False, "reason": "invalid max_age_ms"}
        if now_ms is None or not _is_valid_now_ms(now_ms):
            return {"ok": False, "reason": "now_ms is required when max_age_ms is set"}
        if now_ms - updated_at > max_age_ms:
            return {"ok": False, "reason": "key history exceeds max_age_ms"}
    hist_proof = key_history.get("proof") if isinstance(key_history, Mapping) else None
    hist_created = hist_proof.get("created") if isinstance(hist_proof, Mapping) else None
    if not isinstance(hist_created, int) or isinstance(hist_created, bool) or hist_created <= 0 or hist_created > _MAX_SAFE_INT:
        return {"ok": False, "reason": "key history requires a v2 proof with created timestamp"}
    if not verify_document(key_history, active_did, now_ms=now_ms, expected_key_id=active_key_id):
        return {"ok": False, "reason": "key history signature is invalid or expired"}

    keys = hist_doc.get("keys")
    if not isinstance(keys, Sequence) or isinstance(keys, (str, bytes, bytearray)):
        return {"ok": False, "reason": "key history keys missing"}
    seen_dids: set[str] = set()
    seen_key_ids: set[str] = set()
    entry_by_did: Dict[str, Mapping[str, Any]] = {}
    active_count = 0
    for k in keys:
        if (
            not isinstance(k, Mapping)
            or not isinstance(k.get("did"), str)
            or not is_did_key(k["did"])
            or not isinstance(k.get("keyId"), str)
            or len(k["keyId"]) == 0
        ):
            return {"ok": False, "reason": "key history contains malformed key entry"}
        status = k.get("status")
        if status not in ("active", "retired", "revoked"):
            return {"ok": False, "reason": "key history contains invalid key status"}
        if status == "active":
            active_count += 1
        if k["did"] in seen_dids or k["keyId"] in seen_key_ids:
            return {"ok": False, "reason": "key history contains duplicate key did or keyId"}
        seen_dids.add(k["did"])
        seen_key_ids.add(k["keyId"])
        entry_by_did[k["did"]] = k
        try:
            if did_key_from_ed25519_jwk(k.get("publicKeyJwk")) != k["did"]:
                return {"ok": False, "reason": f"key history publicKeyJwk does not match {k['did']}"}
        except Exception:
            return {"ok": False, "reason": f"key history publicKeyJwk is invalid for {k['did']}"}
    if active_count != 1:
        return {"ok": False, "reason": "key history must contain exactly one active key entry"}
    active_in_list = next(
        (k for k in keys if isinstance(k, Mapping) and k.get("did") == active_did and k.get("keyId") == active_key_id and k.get("status") == "active"),
        None,
    )
    if active_in_list is None:
        return {"ok": False, "reason": "key history missing active key entry"}
    active_valid_from = active_in_list.get("validFrom")
    has_active_valid_until = "validUntil" in active_in_list
    active_valid_until = active_in_list.get("validUntil")
    if (
        not isinstance(active_valid_from, int)
        or isinstance(active_valid_from, bool)
        or active_valid_from <= 0
        or active_valid_from > _MAX_SAFE_INT
        or "compromisedAfter" in active_in_list
        or "revokedAt" in active_in_list
        or (
            has_active_valid_until
            and (
                not isinstance(active_valid_until, int)
                or isinstance(active_valid_until, bool)
                or active_valid_until < active_valid_from
                or active_valid_until > _MAX_SAFE_INT
            )
        )
        or hist_created < active_valid_from
    ):
        return {"ok": False, "reason": "key history active key entry is invalid"}
    if isinstance(active_valid_until, int) and (
        hist_created > active_valid_until or (now_ms is not None and now_ms >= active_valid_until)
    ):
        return {"ok": False, "reason": "key history active key entry has expired"}

    rotations = hist_doc.get("rotations")
    rotation_by_from_did: Dict[str, Mapping[str, Any]] = {}
    if rotations is not None:
        if not isinstance(rotations, Sequence) or isinstance(rotations, (str, bytes, bytearray)) or len(rotations) > MAX_KEY_ROTATION_HOPS * 2:
            return {"ok": False, "reason": "key history rotations is malformed or exceeds maximum length"}
        for rot in rotations:
            rdoc = rot.get("document") if isinstance(rot, Mapping) else None
            rproof = rot.get("proof") if isinstance(rot, Mapping) else None
            rot_at = rdoc.get("rotatedAt") if isinstance(rdoc, Mapping) else None
            from_did = rdoc.get("fromDid") if isinstance(rdoc, Mapping) else None
            to_did = rdoc.get("toDid") if isinstance(rdoc, Mapping) else None
            if (
                not isinstance(rot, Mapping)
                or not isinstance(rdoc, Mapping)
                or rdoc.get("type") != KEY_ROTATION_TYPE
                or rdoc.get("platformDidWeb") != hist_doc.get("platformDidWeb")
                or not isinstance(from_did, str)
                or not is_did_key(from_did)
                or not isinstance(to_did, str)
                or not is_did_key(to_did)
                or from_did == to_did
                or not isinstance(rot_at, int)
                or isinstance(rot_at, bool)
                or rot_at <= 0
                or rot_at > updated_at
            ):
                return {"ok": False, "reason": "key history contains malformed rotation endorsement"}
            if from_did in rotation_by_from_did:
                return {"ok": False, "reason": "key history contains duplicate rotation endorsement fromDid"}
            from_entry = entry_by_did.get(from_did)
            to_entry = entry_by_did.get(to_did)
            from_vf = from_entry.get("validFrom") if isinstance(from_entry, Mapping) else None
            from_has_vu = isinstance(from_entry, Mapping) and "validUntil" in from_entry
            from_vu = from_entry.get("validUntil") if isinstance(from_entry, Mapping) else None
            if (
                from_entry is None
                or to_entry is None
                or from_entry.get("status") != "retired"
                or "revokedAt" in from_entry
                or "compromisedAfter" in from_entry
                or not isinstance(from_vf, int)
                or isinstance(from_vf, bool)
                or from_vf <= 0
                or from_vf > _MAX_SAFE_INT
                or (
                    from_has_vu
                    and (
                        not isinstance(from_vu, int)
                        or isinstance(from_vu, bool)
                        or from_vu < from_vf
                        or from_vu > _MAX_SAFE_INT
                        or rot_at > from_vu
                    )
                )
                or rot_at < from_vf
            ):
                return {"ok": False, "reason": "key history rotation endorsement references non-retired or invalid key"}
            if (
                not isinstance(rproof, Mapping)
                or rproof.get("created") != rot_at
                or not verify_document(rot, from_did, now_ms=now_ms, expected_key_id=str(from_entry["keyId"]))
            ):
                return {"ok": False, "reason": "key history rotation endorsement signature is invalid"}
            rotation_by_from_did[from_did] = rdoc

    if expected_active_did is not None and active_did != expected_active_did:
        curr = expected_active_did
        prev_rot_at = 0
        visited = {curr}
        hops = 0
        while curr != active_did and hops < MAX_KEY_ROTATION_HOPS:
            step = rotation_by_from_did.get(curr)
            if step is None:
                break
            next_did = str(step["toDid"])
            step_rot_at = int(step["rotatedAt"])
            if next_did in visited or step_rot_at < prev_rot_at:
                break
            target_entry = entry_by_did.get(next_did)
            if (
                target_entry is None
                or target_entry.get("status") == "revoked"
                or "revokedAt" in target_entry
                or "compromisedAfter" in target_entry
            ):
                break
            visited.add(next_did)
            prev_rot_at = step_rot_at
            curr = next_did
            hops += 1
        if curr != active_did:
            return {"ok": False, "reason": "key history activeDid does not match pinned active platformDid"}
        return {"ok": True, "activeKey": dict(active_in_list), "rotatedFromDid": expected_active_did}

    return {"ok": True, "activeKey": dict(active_in_list)}


def verify_document_with_key_history(
    signed: Mapping[str, Any],
    key_history: Mapping[str, Any],
    *,
    expected_active_did: str,
    now_ms: Optional[int] = None,
    max_age_ms: Optional[int] = None,
    min_updated_at: Optional[int] = None,
) -> Dict[str, Any]:
    if not isinstance(expected_active_did, str) or not is_did_key(expected_active_did):
        return {"ok": False, "reason": "expected_active_did is required and must be a valid Ed25519 did:key"}
    verified_hist = verify_key_history(
        key_history,
        expected_active_did=expected_active_did,
        now_ms=now_ms,
        max_age_ms=max_age_ms,
        min_updated_at=min_updated_at,
    )
    if not verified_hist.get("ok"):
        return verified_hist
    keys = key_history["document"]["keys"]

    proof = signed.get("proof") if isinstance(signed, Mapping) else None
    signer_did = proof.get("verificationMethod") if isinstance(proof, Mapping) else None
    if not isinstance(signer_did, str):
        return {"ok": False, "reason": "missing document proof.verificationMethod"}
    proof_key_id = proof.get("keyId") if isinstance(proof, Mapping) else None
    entry = next(
        (k for k in keys if isinstance(k, Mapping) and k.get("did") == signer_did and (proof_key_id is None or k.get("keyId") == proof_key_id)),
        None,
    )
    if entry is None:
        return {"ok": False, "reason": "document signing key not present in key history"}
    status = entry.get("status")
    if status == "revoked" or "revokedAt" in entry:
        return {"ok": False, "reason": f"signing key {entry.get('did')} has been revoked"}
    if "compromisedAfter" in entry:
        return {"ok": False, "reason": f"signing key {entry.get('did')} has a recorded compromise"}
    if status not in ("active", "retired"):
        return {"ok": False, "reason": f"unknown signing key status {status}"}
    valid_from = entry.get("validFrom")
    has_valid_until = "validUntil" in entry
    valid_until = entry.get("validUntil")
    if not isinstance(valid_from, int) or isinstance(valid_from, bool) or valid_from <= 0 or valid_from > _MAX_SAFE_INT:
        return {"ok": False, "reason": "signing key validFrom is invalid"}
    if has_valid_until and (
        not isinstance(valid_until, int) or isinstance(valid_until, bool) or valid_until < valid_from or valid_until > _MAX_SAFE_INT
    ):
        return {"ok": False, "reason": "signing key validUntil is invalid"}
    created = proof.get("created") if isinstance(proof, Mapping) else None
    if not isinstance(created, int) or isinstance(created, bool) or created <= 0 or created > _MAX_SAFE_INT:
        return {"ok": False, "reason": "key-history verification requires a v2 proof with created timestamp"}
    if not verify_document(signed, str(entry["did"]), now_ms=now_ms):
        return {"ok": False, "reason": "document signature is invalid or expired"}

    if created < valid_from:
        return {"ok": False, "reason": "document proof.created precedes signing key validFrom"}
    if isinstance(valid_until, int) and created > valid_until:
        return {"ok": False, "reason": "document proof.created exceeds retired signing key validUntil"}
    return {"ok": True, "key": dict(entry)}


# --- Pre-dispute Clauses (agent-mediate/clause/v1) ----------------------------

_ISSUE_ID_RE = re.compile(r"^[a-z][A-Za-z0-9]{0,23}$")
# Object.prototype member names (CR-CORE-M2): refused for parity with the TypeScript verifier, where record[id]
# lookups would resolve them to inherited functions.
RESERVED_ISSUE_IDS = frozenset(
    {"constructor", "hasOwnProperty", "isPrototypeOf", "propertyIsEnumerable", "toLocaleString", "toString", "valueOf"}
)
_MAX_ISSUES = 5
_MAX_GRID_POINTS = 1_000_000
_MAX_ISSUE_MAGNITUDE = 1e15
_MAX_FRACTIONAL_ISSUE_MAGNITUDE = 1e6
_MIN_ISSUE_STEP = 1e-6


def _is_exact_int_number(v: Any) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return False
    return float(v).is_integer() and -_MAX_SAFE_INT <= int(v) <= _MAX_SAFE_INT


_ISSUE_KEYS = frozenset({"id", "label", "unit", "min", "max", "step", "claimantPrefers", "obligor"})
_CLAUSE_KEYS = frozenset({"type", "contractHash", "platform", "parties", "terms", "issuedAt", "expiresAt", "signatures"})
_CLAUSE_PLATFORM_KEYS = frozenset({"did", "baseUrl", "rulesVersion", "rulesHash"})
_CLAUSE_PARTY_KEYS = frozenset({"agentId", "principalId", "notice"})
_PARTY_CONTACT_KEYS = frozenset({"webhookUrl", "a2aCardUrl", "didWeb", "email"})
_CLAUSE_TERMS_KEYS = frozenset({"feeMode", "windows", "determinationConsent", "discloseGapOnFailure", "issueTemplates"})
_CLAUSE_SIGNATURE_KEYS = frozenset({"partyAgentId", "signerId", "signature"})


def _unknown_key_in(obj: Mapping[str, Any], allowed: frozenset[str]) -> Optional[str]:
    for k in obj.keys():
        if k not in allowed:
            return str(k)
    return None


def _is_valid_http_url(raw: str) -> bool:
    if not isinstance(raw, str) or len(raw) == 0 or re.search(r"[\x00-\x20\x7f\\]", raw):
        return False
    m = re.match(r"^https?://([^/?#]+)", raw, re.IGNORECASE)
    if not m:
        return False
    authority = m.group(1)
    if "@" in authority:
        return False
    port_part: Optional[str] = None
    if authority.startswith("["):
        close_idx = authority.find("]")
        if close_idx <= 1:
            return False
        ipv6_text = authority[1:close_idx]
        try:
            addr = ipaddress.ip_address(ipv6_text)
        except ValueError:
            return False
        if addr.version != 6:
            return False
        rest = authority[close_idx + 1 :]
        if rest:
            if not rest.startswith(":"):
                return False
            port_part = rest[1:]
        host_part = authority[: close_idx + 1]
    else:
        colon_idx = authority.find(":")
        if colon_idx != -1:
            if authority.find(":", colon_idx + 1) != -1:
                return False
            host_part = authority[:colon_idx]
            port_part = authority[colon_idx + 1 :]
        else:
            host_part = authority
        lower_host = host_part.lower()
        if not lower_host or lower_host.startswith(".") or lower_host.endswith(".") or ".." in lower_host:
            return False
        if not re.fullmatch(r"^[a-z0-9.-]+$", lower_host):
            return False
        labels = lower_host.split(".")
        all_numeric_or_hex = all(bool(re.fullmatch(r"^(?:0x[0-9a-f]+|\d+)$", lbl, re.IGNORECASE)) for lbl in labels)
        if all_numeric_or_hex:
            if not re.fullmatch(r"^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$", lower_host):
                return False
            try:
                if ipaddress.ip_address(lower_host).version != 4:
                    return False
            except ValueError:
                return False
        elif not all(bool(re.fullmatch(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$", lbl)) for lbl in labels):
            return False
    if port_part is not None and len(port_part) > 0:
        if not re.fullmatch(r"^[1-9][0-9]{0,4}$", port_part) or int(port_part) > 65535:
            return False
    try:
        u = urlsplit(raw)
        _ = u.port
    except ValueError:
        return False
    return u.scheme.lower() in ("http", "https") and bool(host_part) and u.username is None and u.password is None


def _validate_issues(issues: Any) -> None:
    if not isinstance(issues, Sequence) or isinstance(issues, (str, bytes, bytearray)) or not (1 <= len(issues) <= _MAX_ISSUES):
        raise ValueError(f"between 1 and {_MAX_ISSUES} issues required")
    seen: set[str] = set()
    for issue in issues:
        if not isinstance(issue, Mapping) or isinstance(issue, (list, tuple)) or _unknown_key_in(issue, _ISSUE_KEYS) is not None:
            raise ValueError("each issue must be a plain object with only the supported Issue fields")
        iid = issue.get("id")
        if not isinstance(iid, str) or not _ISSUE_ID_RE.fullmatch(iid):
            raise ValueError(f'invalid issue id "{str(iid)[:32]}"')
        if iid in RESERVED_ISSUE_IDS:
            raise ValueError(f'issue id "{iid}" is reserved; choose another name')
        if iid in seen:
            raise ValueError(f'duplicate issue id "{iid}"')
        seen.add(iid)
        label = issue.get("label")
        unit = issue.get("unit")
        if not isinstance(label, str) or not (1 <= len(label) <= 200):
            raise ValueError(f"issue {iid} label must be 1-200 characters")
        if not isinstance(unit, str) or not (1 <= len(unit) <= 32):
            raise ValueError(f"issue {iid} unit must be 1-32 characters")
        mn, mx, st = issue.get("min"), issue.get("max"), issue.get("step")
        for val in (mn, mx, st):
            if isinstance(val, bool) or not isinstance(val, (int, float)) or not math.isfinite(val):
                raise ValueError(f"issue {iid} bounds must be finite numbers")
        f_min, f_max, f_step = float(mn), float(mx), float(st)
        if abs(f_min) > _MAX_ISSUE_MAGNITUDE or abs(f_max) > _MAX_ISSUE_MAGNITUDE:
            raise ValueError(f"issue {iid}: min and max magnitude must not exceed 1e15")
        if not (f_max > f_min):
            raise ValueError(f"issue {iid}: max must exceed min")
        if not (f_step >= _MIN_ISSUE_STEP):
            raise ValueError(f"issue {iid}: step must be at least 1e-6")
        if not (_is_exact_int_number(mn) and _is_exact_int_number(st)):
            if abs(f_min) > _MAX_FRACTIONAL_ISSUE_MAGNITUDE or abs(f_max) > _MAX_FRACTIONAL_ISSUE_MAGNITUDE:
                raise ValueError(f"issue {iid}: fractional-grid min and max magnitude must not exceed 1e6")
            if abs(round(f_step * 1e6) - f_step * 1e6) > 1e-9 or abs(round(f_min * 1e6) - f_min * 1e6) > 1e-9:
                raise ValueError(f"issue {iid}: fractional min and step must have at most 6 decimal places")
        points = (f_max - f_min) / f_step
        if _is_exact_int_number(mn) and _is_exact_int_number(st):
            if not _is_exact_int_number(mx) or (int(mx) - int(mn)) % int(st) != 0:
                raise ValueError(f"issue {iid}: (max - min) must be a multiple of step")
        elif abs(points - round(points)) > _grid_tolerance(f_min, f_step, f_max):
            raise ValueError(f"issue {iid}: (max - min) must be a multiple of step")
        if points > _MAX_GRID_POINTS:
            raise ValueError(f"issue {iid}: grid too fine")
        if issue.get("claimantPrefers") not in ("higher", "lower"):
            raise ValueError(f"issue {iid}: claimantPrefers must be higher or lower")
        if issue.get("obligor") not in ("claimant", "respondent"):
            raise ValueError(f"issue {iid}: obligor must be claimant or respondent")


def validate_issues_against_clause_templates(
    issues: Sequence[Mapping[str, Any]],
    templates: Sequence[Mapping[str, Any]],
) -> Dict[str, Any]:
    if not isinstance(templates, Sequence) or isinstance(templates, (str, bytes, bytearray)) or len(templates) == 0:
        return {"ok": True}
    if not isinstance(issues, Sequence) or isinstance(issues, (str, bytes, bytearray)) or len(issues) == 0:
        return {"ok": False, "reason": "proposedIssues must be a non-empty subset of clause.terms.issueTemplates"}
    by_id: Dict[str, Mapping[str, Any]] = {str(t["id"]): t for t in templates if isinstance(t, Mapping) and "id" in t}
    seen: set[str] = set()
    for issue in issues:
        if not isinstance(issue, Mapping) or not isinstance(issue.get("id"), str):
            return {"ok": False, "reason": "proposed issue is missing id"}
        iid = issue["id"]
        if iid in seen:
            return {"ok": False, "reason": f'duplicate proposed issue id "{iid}"'}
        seen.add(iid)
        tmpl = by_id.get(iid)
        if tmpl is None:
            return {"ok": False, "reason": f'issue "{iid}" is not permitted by clause.terms.issueTemplates'}
        try:
            i_step = float(issue["step"])
            i_min = float(issue["min"])
            i_max = float(issue["max"])
        except Exception:
            return {"ok": False, "reason": f'issue "{iid}" bounds must be finite numbers'}
        if (
            issue.get("claimantPrefers") != tmpl.get("claimantPrefers")
            or issue.get("obligor") != tmpl.get("obligor")
            or issue.get("unit") != tmpl.get("unit")
            or i_step != float(tmpl["step"])
            or _is_exact_int_number(issue.get("min")) != _is_exact_int_number(tmpl.get("min"))
        ):
            return {
                "ok": False,
                "reason": f'issue "{iid}" must match clause template unit, step, claimantPrefers, and obligor',
            }
        if (
            i_min < float(tmpl["min"]) - 1e-9
            or i_max > float(tmpl["max"]) + 1e-9
            or not (i_max > i_min)
            or not _is_on_grid(tmpl, issue.get("min"))
            or not _is_on_grid(tmpl, issue.get("max"))
        ):
            return {
                "ok": False,
                "reason": f'issue "{iid}" range [{issue.get("min")}, {issue.get("max")}] must lie on-grid within clause template [{tmpl["min"]}, {tmpl["max"]}]',
            }
    return {"ok": True}


def _validate_clause_terms(terms: Any) -> None:
    if not isinstance(terms, Mapping) or isinstance(terms, (list, tuple)):
        raise ValueError("terms must be an object")
    extra_key = _unknown_key_in(terms, _CLAUSE_TERMS_KEYS)
    if extra_key is not None:
        raise ValueError(f"terms.{extra_key} is not a supported terms field")
    if "feeMode" in terms and terms["feeMode"] != "FILER_PAYS":
        raise ValueError("terms.feeMode must be FILER_PAYS")
    if "determinationConsent" in terms and not isinstance(terms["determinationConsent"], bool):
        raise ValueError("terms.determinationConsent must be a boolean")
    if "discloseGapOnFailure" in terms and not isinstance(terms["discloseGapOnFailure"], bool):
        raise ValueError("terms.discloseGapOnFailure must be a boolean")
    if "windows" in terms:
        windows = terms["windows"]
        if not isinstance(windows, Mapping) or isinstance(windows, (list, tuple)):
            raise ValueError("terms.windows must be an object")
        limits_map = MECHANISM_SPEC["windowLimitsMs"]
        for k, v in windows.items():
            lim = limits_map.get(k)
            if lim is None:
                raise ValueError(f"terms.windows.{k} is not a supported window field")
            if not isinstance(v, int) or isinstance(v, bool) or v < lim["min"] or v > lim["max"]:
                raise ValueError(f"terms.windows.{k} is outside platform limits")
        bw = windows.get("bargainingWallClockMs")
        rt = windows.get("roundTimeoutMs")
        if isinstance(bw, int) and isinstance(rt, int) and bw < rt:
            raise ValueError("terms.windows.bargainingWallClockMs must be at least roundTimeoutMs")
    if "issueTemplates" in terms:
        issue_templates = terms["issueTemplates"]
        if (
            not isinstance(issue_templates, Sequence)
            or isinstance(issue_templates, (str, bytes, bytearray))
            or len(issue_templates) > _MAX_ISSUES
        ):
            raise ValueError(f"terms.issueTemplates must be an array of at most {_MAX_ISSUES} issues")
        if len(issue_templates) > 0:
            _validate_issues(issue_templates)


def _party_contact_problem(contact: Any, label: str) -> Optional[str]:
    if not isinstance(contact, Mapping) or isinstance(contact, (list, tuple)):
        return f"{label} must be an object"
    extra_key = _unknown_key_in(contact, _PARTY_CONTACT_KEYS)
    if extra_key is not None:
        return f"{label}.{extra_key} is not a supported contact field"
    for k, v in contact.items():
        max_len = 2048 if k in ("webhookUrl", "a2aCardUrl") else (320 if k == "email" else 512)
        if not isinstance(v, str) or len(v.strip()) == 0 or len(v) > max_len:
            return f"{label}.{k} must be a non-empty string (<= {max_len} chars)"
        if k in ("webhookUrl", "a2aCardUrl"):
            if not _is_valid_http_url(v):
                return f"{label}.{k} must be a valid HTTP(S) URL"
        elif k == "didWeb":
            try:
                url_from_did_web(v)
            except Exception:
                return f"{label}.didWeb must be a valid did:web identifier"
        elif k == "email":
            if not re.fullmatch(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", v):
                return f"{label}.email must be a valid email address"
    return None


def build_clause(
    *,
    platform_did: str,
    parties: Sequence[Mapping[str, Any]],
    contract: Any = None,
    contract_hash_hex: Optional[str] = None,
    platform_base_url: Optional[str] = None,
    rules_version: str = RULES_VERSION,
    rules_hash: Any = _UNSET,
    terms: Optional[Mapping[str, Any]] = None,
    issued_at: Optional[int] = None,
    expires_at: Optional[int] = None,
) -> Dict[str, Any]:
    c_hash = contract_hash_hex if contract_hash_hex is not None else (contract_hash(contract) if contract is not None else "")
    if not isinstance(c_hash, str) or not _SHA256_HEX_RE.fullmatch(c_hash):
        raise ValueError("provide contract or a 64-char lowercase hex contract_hash_hex")
    if not is_did_key(platform_did):
        raise ValueError("platform_did must be a valid Ed25519 did:key")
    if not isinstance(rules_version, str) or len(rules_version.strip()) == 0 or len(rules_version) > 64:
        raise ValueError("rules_version must be a non-empty string")
    if platform_base_url is not None and (
        not isinstance(platform_base_url, str)
        or len(platform_base_url) > 2048
        or not _is_valid_http_url(platform_base_url.rstrip("/"))
    ):
        raise ValueError("platform_base_url must be a valid HTTP(S) URL")
    resolved_rules_hash: Optional[str] = (RULES_HASH if rules_version == RULES_VERSION else None) if rules_hash is _UNSET else rules_hash
    if resolved_rules_hash is not None and (not isinstance(resolved_rules_hash, str) or not _SHA256_HEX_RE.fullmatch(resolved_rules_hash)):
        raise ValueError("rules_hash must be 64 lowercase hex characters")
    if len(parties) != 2:
        raise ValueError("parties must have exactly 2 ClauseParty entries")
    if (
        not isinstance(parties[0], Mapping)
        or isinstance(parties[0], (list, tuple))
        or not isinstance(parties[1], Mapping)
        or isinstance(parties[1], (list, tuple))
    ):
        raise ValueError("both clause parties must be objects")
    p0, p1 = dict(parties[0]), dict(parties[1])
    for idx, p in enumerate((p0, p1)):
        extra_party_key = _unknown_key_in(p, _CLAUSE_PARTY_KEYS)
        if extra_party_key is not None:
            raise ValueError(f"party[{idx}].{extra_party_key} is not a supported party field")
    if not is_did_key(p0.get("agentId")) or not is_did_key(p1.get("agentId")):
        raise ValueError("both clause parties must have valid Ed25519 did:key agentIds")
    if p0["agentId"] == p1["agentId"]:
        raise ValueError("clause parties must have distinct agentIds")
    for idx, p in enumerate((p0, p1)):
        if "principalId" in p and not is_did_key(p["principalId"]):
            raise ValueError(f"party[{idx}].principalId must be a valid Ed25519 did:key")
        if "notice" in p:
            prob = _party_contact_problem(p["notice"], f"party[{idx}].notice")
            if prob:
                raise ValueError(prob)
    ts = int(time.time() * 1000) if issued_at is None else issued_at
    if not isinstance(ts, int) or isinstance(ts, bool) or ts <= 0 or ts > _MAX_SAFE_INT:
        raise ValueError("issued_at must be a positive safe integer")
    if expires_at is not None and (
        not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= ts or expires_at > _MAX_SAFE_INT
    ):
        raise ValueError("expires_at must be a safe integer after issued_at")
    if terms is not None:
        _validate_clause_terms(terms)

    platform: Dict[str, Any] = {"did": platform_did, "rulesVersion": rules_version}
    if resolved_rules_hash is not None:
        platform["rulesHash"] = resolved_rules_hash
    if platform_base_url:
        platform["baseUrl"] = platform_base_url.rstrip("/")

    clause: Dict[str, Any] = {
        "type": CLAUSE_TYPE,
        "contractHash": c_hash,
        "platform": platform,
        "parties": [copy.deepcopy(p0), copy.deepcopy(p1)],
        "issuedAt": ts,
        "signatures": [],
    }
    if terms is not None:
        clause["terms"] = copy.deepcopy(dict(terms))
    if expires_at is not None:
        clause["expiresAt"] = expires_at
    return clause


def clause_signing_payload(clause: Mapping[str, Any]) -> str:
    unsigned = {k: v for k, v in clause.items() if k != "signatures"}
    return _CLAUSE_DOMAIN + canonical_json(unsigned)


def sign_clause(clause: Mapping[str, Any], signer: AgentKey, party_agent_id: Optional[str] = None) -> Dict[str, Any]:
    parties = clause.get("parties")
    if not isinstance(parties, Sequence):
        raise ValueError("clause.parties is required")
    matching = [
        p
        for p in parties
        if (
            p.get("agentId") == party_agent_id and (p.get("principalId") or p.get("agentId")) == signer.did
            if party_agent_id
            else (p.get("principalId") or p.get("agentId")) == signer.did
        )
    ]
    if not matching:
        raise ValueError(f"signer {signer.did} does not match any party's principalId/agentId in this clause")
    if len(matching) > 1:
        raise ValueError("same principal represents both parties; specify party_agent_id explicitly")
    target = matching[0]
    payload = clause_signing_payload(clause)
    existing = [s for s in (clause.get("signatures") or []) if s.get("partyAgentId") != target["agentId"]]
    out = copy.deepcopy({k: v for k, v in clause.items() if k != "signatures"})
    out["signatures"] = [
        *existing,
        {"partyAgentId": target["agentId"], "signerId": signer.did, "signature": signer.sign_text(payload)},
    ]
    return out


def verify_clause(
    clause: Mapping[str, Any],
    *,
    expected_platform_did: Optional[str] = None,
    expected_platform_base_url: Optional[str] = None,
    key_history: Optional[Mapping[str, Any]] = None,
    expected_contract_hash: Optional[str] = None,
    expected_rules_hash: Optional[str] = None,
    claimant_id: Optional[str] = None,
    respondent_id: Optional[str] = None,
    now_ms: Optional[int] = None,
) -> Dict[str, Any]:
    if not isinstance(clause, Mapping) or isinstance(clause, (list, tuple)) or clause.get("type") != CLAUSE_TYPE:
        return {"ok": False, "reason": f"clause.type must be {CLAUSE_TYPE}"}
    extra_clause_key = _unknown_key_in(clause, _CLAUSE_KEYS)
    if extra_clause_key is not None:
        return {"ok": False, "reason": f"clause.{extra_clause_key} is not a supported clause field"}
    if now_ms is not None and not _is_valid_now_ms(now_ms):
        return {"ok": False, "reason": "now_ms must be a positive finite timestamp"}
    c_hash = clause.get("contractHash")
    if not isinstance(c_hash, str) or not _SHA256_HEX_RE.fullmatch(c_hash):
        return {"ok": False, "reason": "clause.contractHash must be 64 lowercase hex characters"}
    if expected_contract_hash is not None and c_hash != expected_contract_hash:
        return {"ok": False, "reason": "clause.contractHash does not match filing contractHash"}
    platform = clause.get("platform")
    if not isinstance(platform, Mapping) or isinstance(platform, (list, tuple)) or not is_did_key(platform.get("did")):
        return {"ok": False, "reason": "clause.platform.did must be a valid Ed25519 did:key"}
    extra_plat_key = _unknown_key_in(platform, _CLAUSE_PLATFORM_KEYS)
    if extra_plat_key is not None:
        return {"ok": False, "reason": f"clause.platform.{extra_plat_key} is not a supported platform field"}
    p_rules_ver = platform.get("rulesVersion")
    if not isinstance(p_rules_ver, str) or len(p_rules_ver.strip()) == 0 or len(p_rules_ver) > 64:
        return {"ok": False, "reason": "clause.platform.rulesVersion must be a non-empty string"}
    if "baseUrl" in platform:
        p_base = platform["baseUrl"]
        if not isinstance(p_base, str) or len(p_base) > 2048 or not _is_valid_http_url(p_base):
            return {"ok": False, "reason": "clause.platform.baseUrl must be a valid HTTP(S) URL"}
        if expected_platform_base_url is not None and p_base.rstrip("/") != expected_platform_base_url.rstrip("/"):
            return {"ok": False, "reason": "clause.platform.baseUrl does not match this platform"}
    issued_at = clause.get("issuedAt")
    if not isinstance(issued_at, int) or isinstance(issued_at, bool) or issued_at <= 0 or issued_at > _MAX_SAFE_INT:
        return {"ok": False, "reason": "clause.issuedAt must be a positive safe integer"}
    if key_history is not None:
        vh = verify_key_history(key_history, expected_active_did=expected_platform_did, now_ms=now_ms)
        if not vh.get("ok"):
            return {"ok": False, "reason": f"clause.platform.did key history invalid: {vh.get('reason')}"}
        hist_keys = key_history["document"]["keys"]
        hist_key = next((k for k in hist_keys if isinstance(k, Mapping) and k.get("did") == platform.get("did")), None)
        if (
            hist_key is None
            or hist_key.get("status") not in ("active", "retired")
            or "revokedAt" in hist_key
            or "compromisedAfter" in hist_key
            or issued_at < int(hist_key["validFrom"])
            or ("validUntil" in hist_key and issued_at > int(hist_key["validUntil"]))
        ):
            return {"ok": False, "reason": "clause.platform.did does not match this platform"}
    elif expected_platform_did is not None and platform.get("did") != expected_platform_did:
        return {"ok": False, "reason": "clause.platform.did does not match this platform"}
    if "rulesHash" in platform:
        p_rules_hash = platform["rulesHash"]
        if not isinstance(p_rules_hash, str) or not _SHA256_HEX_RE.fullmatch(p_rules_hash):
            return {"ok": False, "reason": "clause.platform.rulesHash must be 64 lowercase hex characters"}
        if expected_rules_hash is not None and p_rules_hash != expected_rules_hash:
            return {"ok": False, "reason": "clause.platform.rulesHash does not match this platform's active rulesHash"}
    elif expected_rules_hash is not None:
        return {"ok": False, "reason": "clause.platform.rulesHash is missing"}
    if "expiresAt" in clause:
        expires_at = clause["expiresAt"]
        if not isinstance(expires_at, int) or isinstance(expires_at, bool) or expires_at <= issued_at or expires_at > _MAX_SAFE_INT:
            return {"ok": False, "reason": "clause.expiresAt must be after issuedAt"}
        if now_ms is not None and now_ms >= expires_at:
            return {"ok": False, "reason": "clause has expired"}

    parties = clause.get("parties")
    if not isinstance(parties, Sequence) or isinstance(parties, (str, bytes, bytearray)) or len(parties) != 2:
        return {"ok": False, "reason": "clause.parties must contain 2 entries"}
    p0, p1 = parties[0], parties[1]
    if not isinstance(p0, Mapping) or isinstance(p0, (list, tuple)) or not isinstance(p1, Mapping) or isinstance(p1, (list, tuple)):
        return {"ok": False, "reason": "invalid clause.parties"}
    if not is_did_key(p0.get("agentId")) or not is_did_key(p1.get("agentId")) or p0["agentId"] == p1["agentId"]:
        return {"ok": False, "reason": "clause.parties must have two distinct Ed25519 did:key agentIds"}
    for idx, p in enumerate((p0, p1)):
        extra_party_key = _unknown_key_in(p, _CLAUSE_PARTY_KEYS)
        if extra_party_key is not None:
            return {"ok": False, "reason": f"clause.parties[{idx}].{extra_party_key} is not a supported party field"}
        if "principalId" in p and not is_did_key(p["principalId"]):
            return {"ok": False, "reason": "clause party principalId must be a valid Ed25519 did:key"}
        if "notice" in p:
            prob = _party_contact_problem(p["notice"], f"clause.parties[{idx}].notice")
            if prob:
                return {"ok": False, "reason": prob}

    if "terms" in clause:
        try:
            _validate_clause_terms(clause["terms"])
        except Exception as err:
            return {"ok": False, "reason": f"clause.{err}"}

    if claimant_id is not None and claimant_id not in (p0["agentId"], p1["agentId"]):
        return {"ok": False, "reason": "claimant is not a party to this clause"}
    if respondent_id is not None and respondent_id not in (p0["agentId"], p1["agentId"]):
        return {"ok": False, "reason": "respondent is not a party to this clause"}

    sigs = clause.get("signatures")
    if not isinstance(sigs, Sequence) or isinstance(sigs, (str, bytes, bytearray)) or len(sigs) != 2:
        return {"ok": False, "reason": "clause requires signatures from both parties"}
    for idx, s in enumerate(sigs):
        if not isinstance(s, Mapping) or isinstance(s, (list, tuple)):
            return {"ok": False, "reason": f"clause.signatures[{idx}] must be an object"}
        extra_sig_key = _unknown_key_in(s, _CLAUSE_SIGNATURE_KEYS)
        if extra_sig_key is not None:
            return {"ok": False, "reason": f"clause.signatures[{idx}].{extra_sig_key} is not a supported signature field"}
    try:
        payload = clause_signing_payload(clause)
    except Exception as exc:
        return {"ok": False, "reason": f"clause payload invalid: {exc}"}
    for party in (p0, p1):
        expected_signer = party["principalId"] if "principalId" in party else party["agentId"]
        entry = next((s for s in sigs if isinstance(s, Mapping) and s.get("partyAgentId") == party["agentId"]), None)
        if entry is None:
            return {"ok": False, "reason": f"missing signature for party {party['agentId']}"}
        if entry.get("signerId") != expected_signer:
            return {"ok": False, "reason": f"signerId mismatch for party {party['agentId']}"}
        if not isinstance(entry.get("signature"), str) or not verify_text(expected_signer, payload, entry["signature"]):
            return {"ok": False, "reason": f"invalid signature for party {party['agentId']}"}

    res: Dict[str, Any] = {"ok": True, "parties": [dict(p0), dict(p1)]}
    if claimant_id is not None:
        res["claimantParty"] = dict(p0 if p0["agentId"] == claimant_id else p1)
    if respondent_id is not None:
        res["respondentParty"] = dict(p0 if p0["agentId"] == respondent_id else p1)
    return res


# --- Domain Identity (did:web & A2A Agent Card JWS) ---------------------------


_ALLOWED_DID_VM_TYPES = frozenset({"JsonWebKey2020", "Multikey", "Ed25519VerificationKey2020"})


def _is_valid_ascii_dns_or_ipv4_host(host: str) -> bool:
    if not host or re.search(r"[^\x21-\x7e]", host):
        return False
    labels = host.split(".")
    if any(not lbl for lbl in labels):
        return False
    if all(re.fullmatch(r"(?:0x[0-9a-fA-F]+|\d+)", lbl) for lbl in labels):
        if not re.fullmatch(r"(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}", host):
            return False
        return all(0 <= int(lbl) <= 255 for lbl in labels)
    return all(re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", lbl) is not None for lbl in labels) and bool(
        re.search(r"[a-z]", labels[-1])
    )


def _strict_unquote(s: str) -> str:
    if "%" in s and re.search(r"%(?![0-9A-Fa-f]{2})", s):
        raise ValueError("invalid percent-encoding")
    return unquote(s, errors="strict")


def did_web_from_url(base_url: str) -> str:
    if not isinstance(base_url, str) or re.search(r"[^\x21-\x7e]", base_url):
        raise ValueError("baseUrl must be an HTTP(S) URL")
    try:
        parsed = urlsplit(base_url)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("baseUrl must be an HTTP(S) URL") from exc
    if (
        parsed.scheme not in ("http", "https")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query != ""
        or parsed.fragment != ""
    ):
        raise ValueError("baseUrl must be an HTTP(S) URL without credentials, query or fragment")
    hostname = (parsed.hostname or "").lower()
    if (
        not hostname
        or hostname == "."
        or ".." in hostname
        or hostname.startswith(".")
        or hostname.endswith(".")
        or "[" in parsed.netloc
        or "]" in parsed.netloc
        or re.search(r'[/?#@\\\s\x00-\x1f\x7f\[\]%<>"{}|^`]', hostname)
        or not _is_valid_ascii_dns_or_ipv4_host(hostname)
        or (port is not None and (port < 1 or port > 65535))
    ):
        raise ValueError("baseUrl must use a valid DNS hostname or IPv4 address")
    if (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80):
        port = None
    host = f"{hostname}%3A{port}" if port else hostname
    segments = [quote(_strict_unquote(s), safe="") for s in parsed.path.split("/") if s]
    return f"did:web:{host}:{':'.join(segments)}" if segments else f"did:web:{host}"


def url_from_did_web(did_web: str) -> str:
    if not isinstance(did_web, str) or not did_web.startswith("did:web:"):
        raise ValueError("not a did:web identifier")
    rest = did_web[len("did:web:") :]
    if not rest:
        raise ValueError("empty did:web identifier")
    parts = rest.split(":")
    if any(len(p) == 0 for p in parts):
        raise ValueError("invalid did:web segment")
    if re.search(r"[A-Z]", re.sub(r"%[0-9A-Fa-f]{2}", "", parts[0])):
        raise ValueError("invalid did:web host")
    host = _strict_unquote(parts[0])
    if (
        not host
        or ".." in host
        or re.search(r'[A-Z/?#@\\\s\x00-\x1f\x7f\[\]%<>"{}|^`]', host)
        or host.startswith(".")
        or host.endswith(".")
    ):
        raise ValueError("invalid did:web host")
    if ":" in host:
        colon_parts = host.split(":")
        if len(colon_parts) != 2 or not colon_parts[0] or colon_parts[0].endswith("."):
            raise ValueError("invalid did:web host")
        port_str = colon_parts[1]
        if not re.fullmatch(r"^[1-9][0-9]{0,4}$", port_str) or int(port_str) > 65535:
            raise ValueError("invalid did:web host")
    host_only = host.split(":")[0] if ":" in host else host
    if not _is_valid_ascii_dns_or_ipv4_host(host_only):
        raise ValueError("invalid did:web host")
    try:
        parsed = urlsplit(f"https://{host}")
        port = parsed.port
    except ValueError as exc:
        raise ValueError("invalid did:web host") from exc
    if (
        not parsed.hostname
        or parsed.hostname in (".", "..")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path != ""
        or parsed.query != ""
        or parsed.fragment != ""
        or (port is not None and (port < 1 or port > 65535))
    ):
        raise ValueError("invalid did:web host")
    path_segments: List[str] = []
    for p in parts[1:]:
        decoded = _strict_unquote(p)
        if not decoded or decoded in (".", "..") or re.search(r"[/?#\\\x00-\x1f\x7f]", decoded):
            raise ValueError("invalid did:web path segment")
        path_segments.append(quote(decoded, safe=""))
    path = f"/{'/'.join(path_segments)}/did.json" if path_segments else "/.well-known/did.json"
    return f"https://{host}{path}"


def ed25519_public_jwk_from_did_key(did: str) -> Dict[str, str]:
    raw = raw_public_key_from_did_key(did)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64url_encode(raw)}


def did_key_from_ed25519_jwk(jwk: Mapping[str, Any]) -> str:
    if not isinstance(jwk, Mapping) or jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519":
        raise ValueError("not an Ed25519 OKP JWK")
    x_val = jwk.get("x")
    if not isinstance(x_val, str) or not re.fullmatch(r"[A-Za-z0-9_-]{43}", x_val):
        raise ValueError("invalid Ed25519 JWK x coordinate")
    raw = _b64url_decode(x_val)
    if len(raw) != 32 or _b64url_encode(raw) != x_val:
        raise ValueError("non-canonical Ed25519 JWK x coordinate")
    did = did_key_from_raw_public_key(raw)
    raw_public_key_from_did_key(did)
    return did


def build_did_web_document(
    *,
    base_url: str,
    platform_did: str,
    services: Optional[Sequence[Mapping[str, Any]]] = None,
    historical_keys: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    did_web = did_web_from_url(base_url)
    jwk = ed25519_public_jwk_from_did_key(platform_did)
    multibase = platform_did[len("did:key:") :]
    key_jwk_id = f"{did_web}#key-1"
    key_multi_id = f"{did_web}#key-1-multikey"
    retired = [
        h
        for h in (historical_keys or [])
        if isinstance(h, Mapping)
        and h.get("status") == "retired"
        and h.get("did") != platform_did
        and h.get("revokedAt") is None
        and h.get("compromisedAfter") is None
    ]

    verification_method: List[Dict[str, Any]] = [
        {
            "id": key_jwk_id,
            "type": "JsonWebKey2020",
            "controller": did_web,
            "publicKeyJwk": jwk,
        },
        {
            "id": key_multi_id,
            "type": "Multikey",
            "controller": did_web,
            "publicKeyMultibase": multibase,
        },
    ]
    assertion_method: List[str] = [key_jwk_id, key_multi_id]
    for idx, h in enumerate(retired):
        r_did = str(h["did"])
        r_jwk_id = f"{did_web}#retired-{idx + 1}"
        r_multi_id = f"{did_web}#retired-{idx + 1}-multikey"
        verification_method.extend(
            [
                {
                    "id": r_jwk_id,
                    "type": "JsonWebKey2020",
                    "controller": did_web,
                    "publicKeyJwk": ed25519_public_jwk_from_did_key(r_did),
                },
                {
                    "id": r_multi_id,
                    "type": "Multikey",
                    "controller": did_web,
                    "publicKeyMultibase": r_did[len("did:key:") :],
                },
            ]
        )
        assertion_method.extend([r_jwk_id, r_multi_id])

    doc: Dict[str, Any] = {
        "@context": [
            "https://www.w3.org/ns/did/v1",
            "https://w3id.org/security/suites/jws-2020/v1",
            "https://w3id.org/security/multikey/v1",
        ],
        "id": did_web,
        "alsoKnownAs": [platform_did, *[str(r["did"]) for r in retired]],
        "verificationMethod": verification_method,
        "authentication": [key_jwk_id, key_multi_id],
        "assertionMethod": assertion_method,
    }
    if services:
        doc["service"] = [dict(s) for s in services]
    return doc


def build_jwks(
    *,
    base_url: str,
    platform_did: str,
    historical_keys: Optional[Sequence[Mapping[str, Any]]] = None,
) -> Dict[str, Any]:
    did_web = did_web_from_url(base_url)
    jwk = ed25519_public_jwk_from_did_key(platform_did)
    retired = [
        h
        for h in (historical_keys or [])
        if isinstance(h, Mapping)
        and h.get("status") == "retired"
        and h.get("did") != platform_did
        and h.get("revokedAt") is None
        and h.get("compromisedAfter") is None
    ]
    return {
        "keys": [
            {**jwk, "alg": "EdDSA", "use": "sig", "kid": f"{did_web}#key-1"},
            *[
                {
                    **ed25519_public_jwk_from_did_key(str(h["did"])),
                    "alg": "EdDSA",
                    "use": "sig",
                    "kid": f"{did_web}#retired-{idx + 1}",
                }
                for idx, h in enumerate(retired)
            ],
        ]
    }


def sign_agent_card(
    card: Mapping[str, Any],
    signer: AgentKey,
    *,
    kid: str,
    jku: Optional[str] = None,
) -> Dict[str, Any]:
    unsigned = {k: copy.deepcopy(v) for k, v in card.items() if k != "signatures"}
    protected_header: Dict[str, str] = {"alg": "EdDSA", "kid": kid, "typ": "JOSE"}
    if jku:
        protected_header["jku"] = jku
    protected_b64 = _b64url_encode(canonical_json(protected_header).encode("utf-8"))
    payload_b64 = _b64url_encode(canonical_json(unsigned).encode("utf-8"))
    signing_input = f"{protected_b64}.{payload_b64}".encode("ascii")
    sig_b64 = _b64url_encode(signer.sign_bytes(signing_input))
    return {
        **unsigned,
        "signatures": [{"protected": protected_b64, "signature": sig_b64}],
    }


def did_web_document_authorizes_key(doc: Mapping[str, Any], expected_did_web: str, expected_did_key: str) -> bool:
    try:
        if not isinstance(doc, Mapping) or isinstance(doc, (list, tuple)):
            return False
        if not isinstance(expected_did_web, str) or not expected_did_web.startswith("did:web:"):
            return False
        url_from_did_web(expected_did_web)
        raw_public_key_from_did_key(expected_did_key)
        if doc.get("id") != expected_did_web:
            return False
        auth = doc.get("authentication")
        if not isinstance(auth, list) or len(auth) == 0:
            return False
        vms = doc.get("verificationMethod")
        if vms is not None and not isinstance(vms, list):
            return False

        expected_multibase = expected_did_key[len("did:key:") :]
        normalize_id = lambda mid: f"{expected_did_web}{mid}" if mid.startswith("#") else mid

        def method_matches(vm: Any) -> bool:
            if not isinstance(vm, Mapping) or isinstance(vm, (list, tuple)):
                return False
            if vm.get("controller") != expected_did_web:
                return False
            vm_type = vm.get("type")
            if not isinstance(vm_type, str) or vm_type not in _ALLOWED_DID_VM_TYPES:
                return False
            has_jwk = "publicKeyJwk" in vm and vm.get("publicKeyJwk") is not None
            has_mb = "publicKeyMultibase" in vm and vm.get("publicKeyMultibase") is not None
            if not has_jwk and not has_mb:
                return False
            if vm_type == "JsonWebKey2020" and not has_jwk:
                return False
            if vm_type == "Multikey" and not has_mb:
                return False
            if has_jwk:
                jwk = vm.get("publicKeyJwk")
                if not isinstance(jwk, Mapping) or isinstance(jwk, (list, tuple)):
                    return False
                try:
                    if did_key_from_ed25519_jwk(jwk) != expected_did_key:
                        return False
                except Exception:
                    return False
            if has_mb:
                mb = vm.get("publicKeyMultibase")
                if not isinstance(mb, str) or mb != expected_multibase:
                    return False
            return True

        methods_by_id: Dict[str, Mapping[str, Any]] = {}
        if isinstance(vms, list):
            for vm in vms:
                if not isinstance(vm, Mapping) or isinstance(vm, (list, tuple)):
                    return False
                vm_id = vm.get("id")
                if not isinstance(vm_id, str) or len(vm_id) == 0:
                    return False
                norm_id = normalize_id(vm_id)
                if norm_id in methods_by_id:
                    return False
                methods_by_id[norm_id] = vm

        inline_ids: set[str] = set()
        matched_auth = False
        for entry in auth:
            if isinstance(entry, str) and len(entry) > 0:
                resolved = methods_by_id.get(normalize_id(entry))
                if resolved is not None and method_matches(resolved):
                    matched_auth = True
            elif isinstance(entry, Mapping) and not isinstance(entry, (list, tuple)):
                vm_id = entry.get("id")
                if not isinstance(vm_id, str) or len(vm_id) == 0:
                    return False
                norm_id = normalize_id(vm_id)
                if norm_id in methods_by_id or norm_id in inline_ids:
                    return False
                inline_ids.add(norm_id)
                if method_matches(entry):
                    matched_auth = True
            else:
                return False
        return matched_auth
    except Exception:
        return False


def verify_agent_card_signature(card: Mapping[str, Any], expected_did_key: str) -> bool:
    try:
        if not isinstance(card, Mapping) or isinstance(card, (list, tuple)):
            return False
        sigs = card.get("signatures")
        if not isinstance(sigs, list) or len(sigs) == 0 or len(sigs) > 16:
            return False
        pub = raw_public_key_from_did_key(expected_did_key)
        unsigned = {k: v for k, v in card.items() if k != "signatures"}
        payload_b64 = _b64url_encode(canonical_json(unsigned).encode("utf-8"))
        for entry in sigs:
            if not isinstance(entry, Mapping) or isinstance(entry, (list, tuple)):
                continue
            prot = entry.get("protected")
            sig = entry.get("signature")
            if not isinstance(prot, str) or not isinstance(sig, str):
                continue
            if not _B64URL_RE.fullmatch(prot) or not _B64URL_RE.fullmatch(sig):
                continue
            try:
                header = json.loads(_b64url_decode(prot).decode("utf-8"))
            except Exception:
                continue
            if not isinstance(header, dict) or header.get("alg") != "EdDSA" or "crit" in header:
                continue
            try:
                sig_bytes = _b64url_decode(sig)
            except Exception:
                continue
            if len(sig_bytes) != 64 or _b64url_encode(sig_bytes) != sig:
                continue
            if ed25519_verify(pub, f"{prot}.{payload_b64}".encode("ascii"), sig_bytes):
                return True
        return False
    except Exception:
        return False


# --- Public Hash-Chained Audit Verification -----------------------------------


def verify_public_audit_chain(entries: Sequence[Mapping[str, Any]]) -> Dict[str, Any]:
    if not isinstance(entries, Sequence) or isinstance(entries, (str, bytes, bytearray)):
        return {"ok": False, "atSeq": 0, "reason": "entries must be an array"}
    head = GENESIS_HASH
    seq = 0
    redacted = 0
    for e in entries:
        if not isinstance(e, Mapping) or isinstance(e, (list, tuple)):
            return {"ok": False, "atSeq": seq + 1, "reason": "malformed entry"}
        e_seq = e.get("seq")
        if isinstance(e_seq, bool) or not isinstance(e_seq, int) or e_seq < 1 or e_seq > _MAX_SAFE_INT or e_seq != seq + 1:
            return {"ok": False, "atSeq": e_seq if (isinstance(e_seq, int) and not isinstance(e_seq, bool)) else seq + 1, "reason": "sequence gap"}
        if not isinstance(e.get("prevHash"), str) or e.get("prevHash") != head:
            return {"ok": False, "atSeq": e_seq, "reason": "prevHash mismatch"}
        e_hash = e.get("hash")
        if "redacted" in e:
            if e.get("redacted") is not True:
                return {"ok": False, "atSeq": e_seq, "reason": "invalid redacted flag"}
            if any(k in e for k in ("type", "at", "visibility", "dataCommitment")):
                return {"ok": False, "atSeq": e_seq, "reason": "redacted entry carries unredacted fields"}
            if not isinstance(e_hash, str) or not _SHA256_HEX_RE.fullmatch(e_hash):
                return {"ok": False, "atSeq": e_seq, "reason": "malformed hash"}
            redacted += 1
        else:
            e_at = e.get("at")
            e_vis = e.get("visibility")
            e_dc = e.get("dataCommitment")
            if (
                not isinstance(e.get("type"), str)
                or isinstance(e_at, bool)
                or not isinstance(e_at, int)
                or e_at < -_MAX_SAFE_INT
                or e_at > _MAX_SAFE_INT
                or e_vis not in ("both", "claimant", "respondent", "internal")
                or not isinstance(e_dc, str)
                or not _SHA256_HEX_RE.fullmatch(e_dc)
                or not isinstance(e_hash, str)
                or not _SHA256_HEX_RE.fullmatch(e_hash)
            ):
                return {"ok": False, "atSeq": e_seq, "reason": "malformed entry fields"}
            try:
                computed = sha256_hex(
                    canonical_json([e_seq, e.get("type"), e_at, e_vis, e_dc, e.get("prevHash")])
                )
            except (ValueError, TypeError):
                return {"ok": False, "atSeq": e_seq, "reason": "malformed entry fields"}
            if computed != e_hash:
                return {"ok": False, "atSeq": e_seq, "reason": "hash mismatch"}
        head = e_hash
        seq = e_seq
    return {"ok": True, "head": head, "redacted": redacted}


# --- Transparency Checkpoints, Base Calldata & Proposal Opening Verification --


def checkpoint_leaf_hash(leaf: Mapping[str, Any]) -> str:
    return sha256_hex(CHECKPOINT_LEAF_DOMAIN + canonical_json(leaf))


def compute_terms_hash(terms: Mapping[str, Any]) -> str:
    return sha256_hex(canonical_json(terms))


def compute_outcome_hash(outcome: Mapping[str, Any], status: str) -> str:
    return sha256_hex(canonical_json({"status": status, "outcome": outcome}))


def checkpoint_node_hash(left: str, right: str) -> str:
    return sha256_hex(f"{CHECKPOINT_NODE_DOMAIN}{left}\n{right}")


def _expected_merkle_sides(total_leaves: int, leaf_index: int) -> List[str]:
    if total_leaves <= 1:
        return []
    k = 1 << ((total_leaves - 1).bit_length() - 1)
    if leaf_index < k:
        return [*_expected_merkle_sides(k, leaf_index), "right"]
    return [*_expected_merkle_sides(total_leaves - k, leaf_index - k), "left"]


def verify_checkpoint_inclusion(
    leaf: Mapping[str, Any],
    proof: Mapping[str, Any],
    expected_merkle_root: str,
    *,
    expected_total_leaves: Optional[int] = None,
) -> bool:
    try:
        if not isinstance(leaf, Mapping) or not isinstance(proof, Mapping):
            return False
        if not isinstance(leaf.get("disputeId"), str) or not isinstance(leaf.get("status"), str):
            return False
        audit_seq = leaf.get("auditSeq")
        if not isinstance(audit_seq, int) or isinstance(audit_seq, bool) or audit_seq < 1 or audit_seq > _MAX_SAFE_INT:
            return False
        audit_head = leaf.get("auditHead")
        if not isinstance(audit_head, str) or not _SHA256_HEX_RE.fullmatch(audit_head):
            return False
        outcome_hash = leaf.get("outcomeHash")
        if outcome_hash is not None and (not isinstance(outcome_hash, str) or not _SHA256_HEX_RE.fullmatch(outcome_hash)):
            return False
        if not isinstance(expected_merkle_root, str) or not _SHA256_HEX_RE.fullmatch(expected_merkle_root):
            return False
        total = proof.get("totalLeaves")
        idx = proof.get("leafIndex")
        if not isinstance(total, int) or isinstance(total, bool) or total < 1 or total > _MAX_SAFE_INT:
            return False
        if expected_total_leaves is not None:
            if not isinstance(expected_total_leaves, int) or isinstance(expected_total_leaves, bool) or total != expected_total_leaves:
                return False
        if not isinstance(idx, int) or isinstance(idx, bool) or idx < 0 or idx >= total:
            return False
        siblings = proof.get("siblings")
        if not isinstance(siblings, Sequence) or isinstance(siblings, (str, bytes, bytearray)):
            return False
        expected_sides = _expected_merkle_sides(total, idx)
        if len(siblings) != len(expected_sides):
            return False
        computed_leaf = checkpoint_leaf_hash(leaf)
        if computed_leaf != proof.get("leafHash"):
            return False
        acc = computed_leaf
        for i, sib in enumerate(siblings):
            if not isinstance(sib, Mapping):
                return False
            side = sib.get("side")
            h = sib.get("hash")
            if side != expected_sides[i] or not isinstance(h, str) or not _SHA256_HEX_RE.fullmatch(h):
                return False
            acc = checkpoint_node_hash(h, acc) if side == "left" else checkpoint_node_hash(acc, h)
        return acc == expected_merkle_root
    except Exception:
        return False


def encode_base_anchor_calldata(checkpoint_seq: int, merkle_root: str) -> str:
    if not isinstance(checkpoint_seq, int) or isinstance(checkpoint_seq, bool) or checkpoint_seq < 1 or checkpoint_seq > _MAX_SAFE_INT:
        raise ValueError("checkpoint_seq must be a positive safe integer")
    if not isinstance(merkle_root, str) or not _SHA256_HEX_RE.fullmatch(merkle_root):
        raise ValueError("merkle_root must be 64 lowercase hex characters")
    return f"0x{BASE_ANCHOR_MAGIC}{checkpoint_seq:016x}{merkle_root}"


def decode_base_anchor_calldata(calldata: str) -> Optional[Dict[str, Any]]:
    if not isinstance(calldata, str):
        return None
    m = re.fullmatch(r"^0x414d4350([0-9a-f]{16})([0-9a-f]{64})$", calldata, re.IGNORECASE)
    if not m:
        return None
    seq = int(m.group(1), 16)
    if seq < 1 or seq > _MAX_SAFE_INT:
        return None
    return {"checkpointSeq": seq, "merkleRoot": m.group(2).lower()}


def derive_proposal_salt(audit_salt: str, dispute_id: str) -> str:
    return sha256_hex(f"{audit_salt}:{dispute_id}:proposal-split")


def derive_proposal_key(platform_secret: str, party_a: str, party_b: str, contract_hash_hex: str) -> str:
    x, y = sorted((party_a, party_b))
    return hmac.new(
        platform_secret.encode("utf-8"),
        f"agent-mediate/proposal-key/v1\n{x}\n{y}\n{contract_hash_hex}".encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def compute_proposal_key_commitment(dispute_id: str, proposal_key_or_salt: str, mode: str = "keyed") -> str:
    return sha256_hex(f"{PROPOSAL_KEY_COMMIT_DOMAIN}{dispute_id}\n{mode}\n{proposal_key_or_salt}")


def derive_party_input_salt(audit_salt: str, dispute_id: str, party: str) -> str:
    return sha256_hex(f"{DECLARED_INPUT_COMMIT_DOMAIN}salt\n{dispute_id}\n{party}\n{audit_salt}")


def compute_declared_input_commitment(
    dispute_id: str,
    party: str,
    party_salt: str,
    priv: Mapping[str, Any],
) -> str:
    return sha256_hex(f"{DECLARED_INPUT_COMMIT_DOMAIN}commit\n{dispute_id}\n{party}\n{party_salt}\n{canonical_json(priv)}")


_EPS = 1e-9
_SPLIT_MIN = 0.3
_SPLIT_MAX = 0.7


def _js_round(y: float) -> int:
    f = math.floor(y)
    return f + 1 if (y - f) >= 0.5 else f


def _clean(x: float) -> float:
    if _is_exact_int_number(x):
        return 0 if x == 0 else int(x)
    if abs(x) <= _MAX_SAFE_INT:
        nearest_int = _js_round(x)
        if abs(nearest_int) <= _MAX_SAFE_INT and abs(x - nearest_int) <= _EPS:
            return 0 if nearest_int == 0 else nearest_int
    if abs(x) > 1e6:
        return 0.0 if x == 0 else x
    r = _js_round(x * 1e9) / 1e9
    return 0 if r == 0 else (int(r) if _is_exact_int_number(r) else r)


def _issue_range(issue: Mapping[str, Any]) -> float:
    return float(issue["max"]) - float(issue["min"])


def _claimant_share(issue: Mapping[str, Any], v: float) -> float:
    s = (v - float(issue["min"])) / _issue_range(issue)
    return s if issue["claimantPrefers"] == "higher" else 1.0 - s


def _value_for_share(issue: Mapping[str, Any], share: float) -> float:
    s = share if issue["claimantPrefers"] == "higher" else 1.0 - share
    return _clean(float(issue["min"]) + s * _issue_range(issue))


def _utility(issues: Sequence[Mapping[str, Any]], weights: Mapping[str, float], pkg: Mapping[str, float], party: str) -> float:
    u = 0.0
    for issue in issues:
        iid = str(issue["id"])
        share = _claimant_share(issue, float(pkg[iid]))
        u += float(weights[iid]) * (share if party == "claimant" else (1.0 - share))
    return u


def _snap_idx_tolerance(issue: Mapping[str, Any], idx: float) -> float:
    return min(_EPS, _EPS / float(issue["step"]) + 8.0 * sys.float_info.epsilon * max(1.0, abs(idx)))


def _snap(issue: Mapping[str, Any], v: float, mode: str) -> float:
    idx = (v - float(issue["min"])) / float(issue["step"])
    tol = _snap_idx_tolerance(issue, idx)
    if mode == "floor":
        i = math.floor(idx + tol)
    elif mode == "ceil":
        i = math.ceil(idx - tol)
    else:
        f = math.floor(idx)
        frac = idx - f
        if abs(frac - 0.5) < tol:
            i = f if f % 2 == 0 else f + 1
        else:
            i = _js_round(idx)
    max_idx = _js_round(_issue_range(issue) / float(issue["step"]))
    i = min(max(i, 0), max_idx)
    if _is_exact_int_number(issue["min"]) and _is_exact_int_number(issue["step"]):
        r_int = int(issue["min"]) + i * int(issue["step"])
        return 0 if r_int == 0 else r_int
    return _clean(float(issue["min"]) + i * float(issue["step"]))


def _midpoint_package(issues: Sequence[Mapping[str, Any]], a: Mapping[str, float], b: Mapping[str, float]) -> Dict[str, float]:
    return {
        str(issue["id"]): _snap(issue, (float(a[str(issue["id"])]) + float(b[str(issue["id"])])) / 2.0, "nearest")
        for issue in issues
    }


def _full_share_box(issues: Sequence[Mapping[str, Any]]) -> Dict[str, Dict[str, float]]:
    return {str(issue["id"]): {"lo": 0.0, "hi": 1.0} for issue in issues}


def _share_box_from_limits(
    issues: Sequence[Mapping[str, Any]],
    limits: Optional[Mapping[str, Mapping[str, float]]],
) -> Optional[Dict[str, Dict[str, float]]]:
    if not limits:
        return _full_share_box(issues)
    box: Dict[str, Dict[str, float]] = {}
    for issue in issues:
        iid = str(issue["id"])
        b = limits.get(iid)
        if not b:
            box[iid] = {"lo": 0.0, "hi": 1.0}
            continue
        g_min = _snap(issue, max(float(issue["min"]), float(b["min"])), "ceil")
        g_max = _snap(issue, min(float(issue["max"]), float(b["max"])), "floor")
        if g_min > g_max + _EPS:
            return None
        s_min = _claimant_share(issue, g_min)
        s_max = _claimant_share(issue, g_max)
        box[iid] = {"lo": min(s_min, s_max), "hi": max(s_min, s_max)}
    return box


def _intersect_share_boxes(
    issues: Sequence[Mapping[str, Any]],
    a: Optional[Mapping[str, Mapping[str, float]]],
    b: Optional[Mapping[str, Mapping[str, float]]],
) -> Optional[Dict[str, Dict[str, float]]]:
    if a is None or b is None:
        return None
    out: Dict[str, Dict[str, float]] = {}
    for issue in issues:
        iid = str(issue["id"])
        lo = max(float(a[iid]["lo"]), float(b[iid]["lo"]))
        hi = min(float(a[iid]["hi"]), float(b[iid]["hi"]))
        if lo > hi + _EPS:
            return None
        out[iid] = {"lo": min(lo, hi), "hi": hi}
    return out


def _sort_issues_by_ratio(
    issues: Sequence[Mapping[str, Any]],
    w_num: Mapping[str, float],
    w_den: Mapping[str, float],
) -> List[Mapping[str, Any]]:
    def ratio(i: Mapping[str, Any]) -> float:
        iid = str(i["id"])
        den = float(w_den[iid])
        return float("inf") if den <= _EPS else float(w_num[iid]) / den

    return sorted(issues, key=lambda i: (-ratio(i), str(i["id"])))


def _frontier_max_on_box(
    issues: Sequence[Mapping[str, Any]],
    w_me: Mapping[str, float],
    w_them: Mapping[str, float],
    r_me: float,
    me_party: str,
    box: Mapping[str, Mapping[str, float]],
) -> float:
    u_me = 0.0
    u_them = 0.0
    for issue in issues:
        iid = str(issue["id"])
        iv = box[iid]
        me_lo = float(iv["lo"]) if me_party == "claimant" else (1.0 - float(iv["hi"]))
        u_me += float(w_me[iid]) * me_lo
        u_them += float(w_them[iid]) * (1.0 - me_lo)
    if r_me <= u_me + _EPS:
        return u_them
    for issue in _sort_issues_by_ratio(issues, w_me, w_them):
        iid = str(issue["id"])
        iv = box[iid]
        delta = float(iv["hi"]) - float(iv["lo"])
        if delta <= _EPS:
            continue
        a = float(w_me[iid]) * delta
        b = float(w_them[iid]) * delta
        if u_me + a >= r_me - _EPS:
            t = min(1.0, max(0.0, (r_me - u_me) / a)) if a > _EPS else 0.0
            return u_them - b * t
        u_me += a
        u_them -= b
    return -1.0


def _nash_on_box(
    issues: Sequence[Mapping[str, Any]],
    wc: Mapping[str, float],
    wr: Mapping[str, float],
    rc: float,
    rr: float,
    split: float,
    box: Mapping[str, Mapping[str, float]],
) -> Optional[Dict[str, float]]:
    movable_weighted = [
        i
        for i in issues
        if (float(box[str(i["id"])]["hi"]) - float(box[str(i["id"])]["lo"])) > _EPS
        and (float(wc[str(i["id"])]) > _EPS or float(wr[str(i["id"])]) > _EPS)
    ]
    fixed_issues = [i for i in issues if (float(box[str(i["id"])]["hi"]) - float(box[str(i["id"])]["lo"])) <= _EPS]
    zero_weight_movable = [
        i
        for i in issues
        if (float(box[str(i["id"])]["hi"]) - float(box[str(i["id"])]["lo"])) > _EPS
        and not (float(wc[str(i["id"])]) > _EPS or float(wr[str(i["id"])]) > _EPS)
    ]
    order = _sort_issues_by_ratio(movable_weighted, wc, wr)

    uc_base = sum(float(wc[str(i["id"])]) * float(box[str(i["id"])]["lo"]) for i in issues)
    ur_base = sum(float(wr[str(i["id"])]) * (1.0 - float(box[str(i["id"])]["hi"])) for i in issues)

    def nash(uc: float, ur: float) -> float:
        return (max(0.0, uc - rc) ** split) * (max(0.0, ur - rr) ** (1.0 - split))

    def feasible(uc: float, ur: float) -> bool:
        return uc >= rc - _EPS and ur >= rr - _EPS

    def box_value_bounds(issue: Mapping[str, Any]) -> Optional[Dict[str, float]]:
        iv = box[str(issue["id"])]
        v_lo = _value_for_share(issue, float(iv["lo"]))
        v_hi = _value_for_share(issue, float(iv["hi"]))
        raw_min = min(v_lo, v_hi)
        raw_max = max(v_lo, v_hi)
        b_min = _snap(issue, raw_min, "ceil")
        b_max = _snap(issue, raw_max, "floor")
        if b_min > b_max + _EPS:
            if abs(raw_max - raw_min) <= _EPS:
                pt = _snap(issue, (raw_min + raw_max) / 2.0, "nearest")
                if abs(pt - raw_min) <= _EPS:
                    return {"min": pt, "max": pt}
            return None
        return {"min": b_min, "max": b_max}

    def order_like(pkg: Mapping[str, float]) -> Dict[str, float]:
        out: Dict[str, float] = {}
        for i in issues:
            val = pkg[str(i["id"])]
            out[str(i["id"])] = int(val) if _is_exact_int_number(val) else float(val)
        return out

    if len(order) == 0:
        single: Dict[str, float] = {}
        for issue in fixed_issues:
            single[str(issue["id"])] = _snap(issue, _value_for_share(issue, float(box[str(issue["id"])]["lo"])), "nearest")
        for issue in zero_weight_movable:
            vb = box_value_bounds(issue)
            if vb is None:
                return None
            single[str(issue["id"])] = min(vb["max"], max(vb["min"], _snap(issue, (vb["min"] + vb["max"]) / 2.0, "nearest")))
        return order_like(single) if feasible(_utility(issues, wc, single, "claimant"), _utility(issues, wr, single, "respondent")) else None

    best: Optional[Dict[str, Any]] = None
    for k, pivot_issue in enumerate(order):
        pid = str(pivot_issue["id"])
        delta_k = float(box[pid]["hi"]) - float(box[pid]["lo"])
        a = float(wc[pid]) * delta_k
        b = float(wr[pid]) * delta_k
        ak = sum(float(wc[str(order[j]["id"])]) * (float(box[str(order[j]["id"])]["hi"]) - float(box[str(order[j]["id"])]["lo"])) for j in range(k))
        bk = sum(
            float(wr[str(order[j]["id"])]) * (float(box[str(order[j]["id"])]["hi"]) - float(box[str(order[j]["id"])]["lo"]))
            for j in range(k + 1, len(order))
        )
        candidates = [0.0, 1.0]
        if a > _EPS and b > _EPS:
            t_opt = (split * a * (ur_base + bk + b - rr) - (1.0 - split) * b * (uc_base + ak - rc)) / (a * b)
            candidates.append(min(1.0, max(0.0, t_opt)))
        for t in candidates:
            uc = uc_base + ak + a * t
            ur = ur_base + bk + b * (1.0 - t)
            if not feasible(uc, ur):
                continue
            n_val = nash(uc, ur)
            if best is None or n_val > best["n"] + _EPS:
                best = {"k": k, "t": t, "n": n_val}
    if best is None:
        return None

    base_pkg: Dict[str, float] = {}
    for j, issue in enumerate(order):
        iid = str(issue["id"])
        iv = box[iid]
        share = float(iv["hi"]) if j < best["k"] else (float(iv["lo"]) if j > best["k"] else float(iv["lo"]) + (float(iv["hi"]) - float(iv["lo"])) * float(best["t"]))
        base_pkg[iid] = _value_for_share(issue, share) if j == best["k"] else _snap(issue, _value_for_share(issue, share), "nearest")
    for issue in fixed_issues:
        base_pkg[str(issue["id"])] = _snap(issue, _value_for_share(issue, float(box[str(issue["id"])]["lo"])), "nearest")
    for issue in zero_weight_movable:
        vb = box_value_bounds(issue)
        if vb is None:
            return None
        base_pkg[str(issue["id"])] = min(vb["max"], max(vb["min"], _snap(issue, (vb["min"] + vb["max"]) / 2.0, "nearest")))

    pivot = order[best["k"]]
    pid = str(pivot["id"])
    p_bounds = box_value_bounds(pivot)
    if p_bounds is None:
        return None
    exact = base_pkg[pid]
    snapped_floor = min(p_bounds["max"], max(p_bounds["min"], _snap(pivot, exact, "floor")))
    snapped_ceil = min(p_bounds["max"], max(p_bounds["min"], _snap(pivot, exact, "ceil")))
    snapped_values = [snapped_floor] if abs(snapped_floor - snapped_ceil) <= _EPS else [snapped_floor, snapped_ceil]
    chosen: Optional[Dict[str, Any]] = None
    for snapped in snapped_values:
        if len(snapped_values) == 1:
            pkg: Optional[Dict[str, float]] = {**base_pkg, pid: snapped}
        else:
            s_share = min(float(box[pid]["hi"]), max(float(box[pid]["lo"]), _claimant_share(pivot, snapped)))
            pkg = _nash_on_box(issues, wc, wr, rc, rr, split, {**box, pid: {"lo": s_share, "hi": s_share}})
        if pkg is None:
            continue
        uc = _utility(issues, wc, pkg, "claimant")
        ur = _utility(issues, wr, pkg, "respondent")
        if not feasible(uc, ur):
            continue
        n_val = nash(uc, ur)
        dist = abs(float(pkg[pid]) - float(exact))
        grid_idx = _js_round((float(pkg[pid]) - float(pivot["min"])) / float(pivot["step"]))
        even_idx = (abs(grid_idx) % 2) == 0
        better_nash = chosen is not None and n_val > chosen["n"] + _EPS
        tied_nash = chosen is not None and abs(n_val - chosen["n"]) <= _EPS
        better_dist = tied_nash and dist < chosen["dist"] - _EPS
        better_parity = tied_nash and abs(dist - chosen["dist"]) <= _EPS and even_idx and not chosen["evenIdx"]
        if chosen is None or better_nash or better_dist or better_parity:
            chosen = {"pkg": pkg, "n": n_val, "dist": dist, "evenIdx": even_idx}
    return None if chosen is None else order_like(chosen["pkg"])


def _nash_proposal(issues: Sequence[Mapping[str, Any]], privates: Mapping[str, Mapping[str, Any]], split: float = 0.5) -> Optional[Dict[str, float]]:
    box_c = _share_box_from_limits(issues, privates["claimant"].get("limits"))
    box_r = _share_box_from_limits(issues, privates["respondent"].get("limits"))
    joint = _intersect_share_boxes(issues, box_c, box_r)
    if joint is None:
        return None
    wc = privates["claimant"]["weights"]
    wr = privates["respondent"]["weights"]
    rc = _utility(issues, wc, privates["claimant"]["walkaway"], "claimant")
    rr = _utility(issues, wr, privates["respondent"]["walkaway"], "respondent")
    return _nash_on_box(issues, wc, wr, rc, rr, split, joint)


def _present_proposal(issues: Sequence[Mapping[str, Any]], basis: Mapping[str, Mapping[str, Any]], split: float) -> Dict[str, Any]:
    real = _nash_proposal(issues, basis, split)
    if real is not None:
        return {"views": {"claimant": dict(real), "respondent": dict(real)}, "settles": True}

    wc = basis["claimant"]["weights"]
    wr = basis["respondent"]["weights"]
    rc = _utility(issues, wc, basis["claimant"]["walkaway"], "claimant")
    rr = _utility(issues, wr, basis["respondent"]["walkaway"], "respondent")
    box_c = _share_box_from_limits(issues, basis["claimant"].get("limits")) or _full_share_box(issues)
    box_r = _share_box_from_limits(issues, basis["respondent"].get("limits")) or _full_share_box(issues)
    joint = _intersect_share_boxes(issues, box_c, box_r)

    ur_at_rc_joint = _frontier_max_on_box(issues, wc, wr, rc, "claimant", joint) if joint is not None else -1.0
    if joint is not None and ur_at_rc_joint >= 0:
        rr_ref = max(0.0, ur_at_rc_joint - max(0.0, rr - ur_at_rc_joint))
        for_claimant = _nash_on_box(issues, wc, wr, rc, rr_ref, split, joint) or _nash_on_box(issues, wc, wr, rc, 0.0, split, joint) or dict(basis["claimant"]["walkaway"])
    else:
        ur_at_rc = _frontier_max_on_box(issues, wc, wr, rc, "claimant", box_c)
        box_deficit = sum(
            float(wr[str(i["id"])]) * max(0.0, box_c[str(i["id"])]["lo"] - box_r[str(i["id"])]["hi"], box_r[str(i["id"])]["lo"] - box_c[str(i["id"])]["hi"])
            for i in issues
        )
        max_uc_joint = _frontier_max_on_box(issues, wr, wc, 0.0, "respondent", joint) if joint is not None else 0.0
        deficit = max(0.0, rr - ur_at_rc) + box_deficit + (max(0.0, rc - max_uc_joint) if joint is not None else 0.0)
        rr_ref = max(0.0, ur_at_rc - deficit)
        for_claimant = _nash_on_box(issues, wc, wr, rc, rr_ref, split, box_c) or _nash_on_box(issues, wc, wr, rc, 0.0, split, box_c) or dict(basis["claimant"]["walkaway"])

    uc_at_rr_joint = _frontier_max_on_box(issues, wr, wc, rr, "respondent", joint) if joint is not None else -1.0
    if joint is not None and uc_at_rr_joint >= 0:
        rc_ref = max(0.0, uc_at_rr_joint - max(0.0, rc - uc_at_rr_joint))
        for_respondent = _nash_on_box(issues, wc, wr, rc_ref, rr, split, joint) or _nash_on_box(issues, wc, wr, 0.0, rr, split, joint) or dict(basis["respondent"]["walkaway"])
    else:
        uc_at_rr = _frontier_max_on_box(issues, wr, wc, rr, "respondent", box_r)
        box_deficit = sum(
            float(wc[str(i["id"])]) * max(0.0, box_c[str(i["id"])]["lo"] - box_r[str(i["id"])]["hi"], box_r[str(i["id"])]["lo"] - box_c[str(i["id"])]["hi"])
            for i in issues
        )
        max_ur_joint = _frontier_max_on_box(issues, wc, wr, 0.0, "claimant", joint) if joint is not None else 0.0
        deficit = max(0.0, rc - uc_at_rr) + box_deficit + (max(0.0, rr - max_ur_joint) if joint is not None else 0.0)
        rc_ref = max(0.0, uc_at_rr - deficit)
        for_respondent = _nash_on_box(issues, wc, wr, rc_ref, rr, split, box_r) or _nash_on_box(issues, wc, wr, 0.0, rr, split, box_r) or dict(basis["respondent"]["walkaway"])

    return {"views": {"claimant": for_claimant, "respondent": for_respondent}, "settles": False}


def _is_on_grid(issue: Mapping[str, Any], v: Any) -> bool:
    if isinstance(v, bool) or not isinstance(v, (int, float)) or not math.isfinite(v):
        return False
    fv, mn, mx, st = float(v), float(issue["min"]), float(issue["max"]), float(issue["step"])
    if fv < mn - _EPS or fv > mx + _EPS:
        return False
    if _is_exact_int_number(issue["min"]) and _is_exact_int_number(issue["step"]):
        return (
            _is_exact_int_number(v)
            and int(v) >= int(issue["min"])
            and int(v) <= int(issue["max"])
            and (int(v) - int(issue["min"])) % int(issue["step"]) == 0
        )
    idx = (fv - mn) / st
    return abs(idx - _js_round(idx)) <= _grid_tolerance(mn, st, fv)


def _grid_tolerance(mn: float, st: float, v: float) -> float:
    """Absolute on-grid tolerance in index units (CR-CORE-M3, SA-CORE-M1); mirrors TS gridTolerance."""
    if _is_exact_int_number(mn) and _is_exact_int_number(st):
        return 0.0
    return min(0.25, 1e-9 + (8 * sys.float_info.epsilon * (abs(v) + abs(mn))) / st)


_PRIVATE_INPUT_KEYS = frozenset({"weights", "walkaway", "limits"})
_LIMIT_BOUND_KEYS = frozenset({"min", "max"})


def _validate_private_inputs(issues: Sequence[Mapping[str, Any]], priv: Any) -> None:
    if not isinstance(priv, Mapping) or isinstance(priv, (list, tuple)):
        raise ValueError("private inputs required")
    extra_priv_key = _unknown_key_in(priv, _PRIVATE_INPUT_KEYS)
    if extra_priv_key is not None:
        raise ValueError(f"private.{extra_priv_key} is not a supported private input field")
    weights = priv.get("weights")
    walkaway = priv.get("walkaway")
    if not isinstance(weights, Mapping) or isinstance(weights, (list, tuple)) or len(weights) != len(issues):
        raise ValueError("private.weights must contain exactly the confirmed issues")
    if not isinstance(walkaway, Mapping) or isinstance(walkaway, (list, tuple)) or len(walkaway) != len(issues):
        raise ValueError("private.walkaway must contain exactly the confirmed issues")
    w_sum = 0.0
    by_id: Dict[str, Mapping[str, Any]] = {}
    for issue in issues:
        iid = str(issue["id"])
        by_id[iid] = issue
        w = weights.get(iid)
        if isinstance(w, bool) or not isinstance(w, (int, float)) or not math.isfinite(w) or float(w) < 0:
            raise ValueError(f"private.weights.{iid} invalid")
        w_sum += float(w)
        if not _is_on_grid(issue, walkaway.get(iid)):
            raise ValueError(f"private.walkaway.{iid} is not on the issue grid")
    if abs(w_sum - 1.0) > 1e-6:
        raise ValueError("private.weights must sum to 1")
    limits = priv.get("limits")
    if limits is not None:
        if not isinstance(limits, Mapping) or isinstance(limits, (list, tuple)):
            raise ValueError("private.limits must be an object")
        for lid, lim in limits.items():
            issue = by_id.get(str(lid))
            if issue is None:
                raise ValueError(f'private.limits contains unknown issue "{lid}"')
            if not isinstance(lim, Mapping) or isinstance(lim, (list, tuple)) or _unknown_key_in(lim, _LIMIT_BOUND_KEYS) is not None:
                raise ValueError(f"private.limits.{lid} bounds are invalid")
            l_min, l_max = lim.get("min"), lim.get("max")
            if (
                isinstance(l_min, bool)
                or isinstance(l_max, bool)
                or not isinstance(l_min, (int, float))
                or not isinstance(l_max, (int, float))
                or not math.isfinite(l_min)
                or not math.isfinite(l_max)
                or float(l_min) > float(l_max)
            ):
                raise ValueError(f"private.limits.{lid} bounds are invalid")
            if float(l_min) < float(issue["min"]) - _EPS or float(l_max) > float(issue["max"]) + _EPS:
                raise ValueError(f"private.limits.{lid} lies outside issue range")
            if _snap(issue, float(l_min), "ceil") > _snap(issue, float(l_max), "floor") + _EPS:
                raise ValueError(f"private.limits.{lid} contains no on-grid value")
            wv = float(walkaway[str(lid)])
            if wv < float(l_min) - _EPS or wv > float(l_max) + _EPS:
                raise ValueError(f"private.walkaway.{lid} must lie within private.limits.{lid}")


def verify_proposal_opening(opening: Mapping[str, Any]) -> Dict[str, Any]:
    try:
        if not isinstance(opening, Mapping):
            return {"ok": False, "reason": "opening must be a Mapping"}
        dispute_id = opening.get("disputeId")
        mode = opening.get("mode")
        key_or_salt = opening.get("proposalKeyOrSalt")
        if not isinstance(dispute_id, str) or len(dispute_id) == 0:
            return {"ok": False, "reason": "disputeId must be a non-empty string"}
        if mode not in ("keyed", "salted"):
            return {"ok": False, "reason": "mode must be 'keyed' or 'salted'"}
        if not isinstance(key_or_salt, str) or len(key_or_salt) == 0:
            return {"ok": False, "reason": "proposalKeyOrSalt must be a non-empty string"}
        if mode == "salted" and not _SHA256_HEX_RE.fullmatch(key_or_salt):
            return {"ok": False, "reason": "salted mode requires 64-hex derived proposalSalt (never raw audit.salt)"}

        prop_key_commit = opening.get("proposalKeyCommitment")
        if not isinstance(prop_key_commit, str) or not _SHA256_HEX_RE.fullmatch(prop_key_commit):
            return {"ok": False, "reason": "proposalKeyCommitment must be 64 lowercase hex characters"}

        issues = opening.get("issues")
        if not isinstance(issues, Sequence) or isinstance(issues, (str, bytes, bytearray)) or len(issues) == 0:
            return {"ok": False, "reason": "issues must be a non-empty sequence"}
        _validate_issues(issues)
        if "expectedIssuesHash" in opening:
            expected_issues_hash = opening["expectedIssuesHash"]
            if not isinstance(expected_issues_hash, str) or sha256_hex(canonical_json(issues)) != expected_issues_hash:
                return {"ok": False, "reason": "issues do not match expectedIssuesHash"}

        expected_key_commit = compute_proposal_key_commitment(dispute_id, key_or_salt, mode)
        if expected_key_commit != prop_key_commit:
            return {"ok": False, "reason": "proposalKeyOrSalt does not match creation-time proposalKeyCommitment"}

        declared = opening.get("declared")
        if not isinstance(declared, Mapping):
            return {"ok": False, "reason": "missing declared openings"}
        for party in ("claimant", "respondent"):
            entry = declared.get(party)
            if (
                not isinstance(entry, Mapping)
                or not isinstance(entry.get("partySalt"), str)
                or not _SHA256_HEX_RE.fullmatch(entry["partySalt"])
                or not isinstance(entry.get("commitment"), str)
                or not _SHA256_HEX_RE.fullmatch(entry["commitment"])
                or not isinstance(entry.get("private"), Mapping)
            ):
                return {"ok": False, "reason": f"invalid declared opening fields for {party}"}
            _validate_private_inputs(issues, entry["private"])
            expected_commit = compute_declared_input_commitment(dispute_id, party, entry["partySalt"], entry["private"])
            if expected_commit != entry.get("commitment"):
                return {"ok": False, "reason": f"{party} declared inputs do not match Round-1 commitment"}

        privates = {"claimant": declared["claimant"]["private"], "respondent": declared["respondent"]["private"]}
        if mode == "keyed":
            mac = hmac.new(key_or_salt.encode("utf-8"), f"agent-mediate/proposal-split/v1\n{canonical_json(privates)}".encode("utf-8"), hashlib.sha256).hexdigest()
            u = int(mac[:12], 16) / 0x1000000000000
        else:
            u = int(key_or_salt[:12], 16) / 0x1000000000000
        alpha = _SPLIT_MIN + (_SPLIT_MAX - _SPLIT_MIN) * u

        expected_proposal = _present_proposal(issues, privates, alpha)
        obs_list = opening.get("observedProposals")
        if obs_list is not None and (not isinstance(obs_list, Sequence) or isinstance(obs_list, (str, bytes, bytearray))):
            return {"ok": False, "reason": "observedProposals must be an array"}
        for obs in obs_list or ():
            if not isinstance(obs, Mapping) or isinstance(obs, (list, tuple)):
                return {"ok": False, "reason": "malformed observedProposals entry"}
            views = obs.get("views")
            if not isinstance(views, Mapping) or isinstance(views, (list, tuple)):
                return {"ok": False, "reason": "malformed observedProposals views"}
            checked = 0
            for party in ("claimant", "respondent"):
                seen = views.get(party)
                if seen is not None:
                    checked += 1
                    if canonical_json(seen) != canonical_json(expected_proposal["views"][party]):
                        return {"ok": False, "reason": f"round {obs.get('round')} proposal for {party} does not match deterministic mechanism output"}
            if checked == 0:
                return {"ok": False, "reason": "observedProposals entry must include at least one party view"}

        expected_ref = _nash_proposal(issues, privates, 0.5) or _midpoint_package(
            issues, privates["claimant"]["walkaway"], privates["respondent"]["walkaway"]
        )
        obs_ref = opening.get("observedDeterminationReference")
        if obs_ref is not None and canonical_json(obs_ref) != canonical_json(expected_ref):
            return {"ok": False, "reason": "determination reference does not match deterministic declaredReferenceTerms"}

        return {
            "ok": True,
            "alpha": alpha,
            "expectedProposal": expected_proposal,
            "expectedDeterminationReference": expected_ref,
        }
    except Exception as exc:
        return {"ok": False, "reason": str(exc) or "invalid proposal opening"}
