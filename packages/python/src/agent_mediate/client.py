"""
Agent-Mediate Python client (`AgentMediateClient`) and optional x402 EIP-3009 USDC payer.

Zero required third-party dependencies (`urllib.request` transport). Handles:
- RFC 9421 Ed25519 signing on every request
- Single `Idempotency-Key` reused across network/429/5xx retries and x402 paid retries
- Out-of-band `platform_did` pinning (mandatory on Base mainnet `eip155:8453`)
- SEC3-8 outcome verification (`disputeId`, `expectedEnvironment`, `parties` membership, Ed25519 signature)
- Compact (`?view=compact`) and full dispute views
- Webhook signature, tag, recipient, and dispute verification (`AgentMediateClient.verify_webhook`)
"""
from __future__ import annotations

import base64
import copy
import datetime
import email.utils
import hashlib
import http.client
import ipaddress
import json
import math
import os
import re
import socket
import ssl
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid
from collections import OrderedDict
from dataclasses import dataclass
from encodings import idna as _stdlib_idna
from types import MappingProxyType
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Union

from .crypto import AgentKey, is_did_key
from .jcs import canonical_json, loads_jcs_json, sha256_hex
from .protocol import (
    DEFAULT_KEY_HISTORY_TTL_MS,
    DISPUTE_INVITE_TYPE,
    HONOURS_ATTESTATION_TYPE,
    WEBHOOK_SIGNATURE_TAG,
    compute_outcome_hash,
    compute_terms_hash,
    did_key_from_ed25519_jwk,
    did_web_document_authorizes_key,
    did_web_from_url,
    encode_base_anchor_calldata,
    sign_mandate,
    sign_request,
    url_from_did_web,
    verify_agent_card_signature,
    verify_checkpoint_inclusion,
    verify_document,
    verify_document_with_key_history,
    verify_key_history,
    verify_public_audit_chain,
    verify_request,
    verify_request_proof,
)

_SHA256_HEX_RE = re.compile(r"^[0-9a-f]{64}$")
_TX_HASH_RE = re.compile(r"^0x[0-9a-fA-F]{64}$")
_EVM_ADDR_RE = re.compile(r"^0x[0-9a-fA-F]{40}$")
_UTS46_DOTS_RE = re.compile(r"[\.\u3002\uff0e\uff61]")
_UTS46_DEVIATIONS = ("\u00df", "\u03c2", "\u200c", "\u200d")
_MAX_SAFE_INT = 9007199254740991
_MAX_RETRY_AFTER_SECONDS = 30.0
_MAX_RESPONSE_BYTES = 4 * 1024 * 1024
_SETTLEMENT_METHODS = ("PROPOSAL_ACCEPTED", "OVERLAP_MIDPOINT", "FINAL_OFFER_DETERMINATION")

PRODUCTION_API_URL = "https://api.ai-agents-mediation.com"
PRODUCTION_APEX_URL = "https://ai-agents-mediation.com"
# Out-of-band pinned production platform signing DIDs by normalised API base URL (SEC3-8 / H-1 / P1-1 / T4-P2-3).
DEFAULT_PRODUCTION_PLATFORM_DIDS: Mapping[str, str] = MappingProxyType(
    {
        PRODUCTION_API_URL: "did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W",
    }
)


def normalize_base_url(raw_url: str) -> str:
    """Canonicalise an HTTP(S) API base_url (`P1-2`): lowercases scheme/host, strips default :443/:80 & trailing slashes, and rewrites bare production apex to PRODUCTION_API_URL."""
    if not isinstance(raw_url, str) or not raw_url.strip():
        raise ValueError("base_url must be a non-empty http(s) URL")
    trimmed = raw_url.strip()
    if re.search(r"[\x00-\x20\x7f\\]", trimmed):
        raise ValueError(f"base_url contains invalid characters: {raw_url}")
    parsed = urllib.parse.urlsplit(trimmed)
    scheme = parsed.scheme.lower()
    if scheme not in ("http", "https"):
        raise ValueError(f"base_url must use http:// or https://, got {parsed.scheme!r}")
    if parsed.username is not None or parsed.password is not None or parsed.query != "" or parsed.fragment != "":
        raise ValueError("base_url must not contain credentials, query parameters, or fragments")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"base_url has invalid port: {raw_url}") from exc
    raw_host = parsed.hostname
    if not raw_host:
        raise ValueError(f"base_url is missing hostname: {raw_url}")
    if ":" in raw_host:
        try:
            addr = ipaddress.ip_address(raw_host)
        except ValueError as exc:
            raise ValueError(f"base_url has invalid IPv6 host: {raw_url}") from exc
        host_str = f"[{addr.compressed}]"
    elif _is_ip_host(raw_host):
        host_str = str(ipaddress.ip_address(raw_host))
    else:
        try:
            host_str = _uts46_to_ascii(raw_host) if not raw_host.isascii() else raw_host.lower()
        except UnicodeError as exc:
            raise ValueError(f"base_url has invalid domain host: {raw_url}") from exc
    default_port = 443 if scheme == "https" else 80
    netloc = f"{host_str}:{port}" if (port is not None and port != default_port) else host_str
    clean_path = "" if parsed.path in ("", "/") else parsed.path.rstrip("/")
    normalized = f"{scheme}://{netloc}{clean_path}"
    return PRODUCTION_API_URL if normalized == PRODUCTION_APEX_URL else normalized


def _uts46_to_ascii(host: str) -> str:
    """CR-SDK-L3: UTS #46 non-transitional domain ToASCII matching Node/WHATWG URL (preserves ß, ς, ZWNJ, ZWJ)."""
    try:
        import idna  # type: ignore[import-not-found]

        return str(idna.encode(host, uts46=True).decode("ascii")).lower()
    except ImportError:
        pass
    except Exception as exc:
        raise UnicodeError(str(exc)) from exc
    if not host:
        raise UnicodeError("empty host")
    out: List[str] = []
    for raw_label in _UTS46_DOTS_RE.split(host):
        if not raw_label:
            raise UnicodeError("empty label")
        if raw_label.isascii():
            low = raw_label.lower()
            if len(low) > 63 or low.startswith("-") or low.endswith("-"):
                raise UnicodeError("invalid ASCII label")
            out.append(low)
            continue
        folded = raw_label.replace("\u1e9e", "\u00df")
        if not any(d in folded for d in _UTS46_DEVIATIONS):
            out.append(_stdlib_idna.ToASCII(folded).decode("ascii").lower())
            continue
        parts: List[str] = []
        buf: List[str] = []
        for ch in folded:
            if ch in _UTS46_DEVIATIONS:
                if buf:
                    parts.append(_stdlib_idna.nameprep("".join(buf)))
                    buf = []
                parts.append(ch)
            else:
                buf.append(ch)
        if buf:
            parts.append(_stdlib_idna.nameprep("".join(buf)))
        prepped = "".join(parts)
        if prepped.startswith("-") or prepped.endswith("-"):
            raise UnicodeError("label starts or ends with hyphen")
        ace = "xn--" + prepped.encode("punycode").decode("ascii").lower()
        if len(ace) > 63:
            raise UnicodeError("ACE label exceeds 63 bytes")
        out.append(ace)
    res = ".".join(out)
    if len(res) > 253:
        raise UnicodeError("domain exceeds 253 bytes")
    return res


def _parse_retry_after_seconds(header: Optional[str], now_ms: int) -> float:
    if not header:
        return 0.0
    trimmed = header.strip()
    if re.fullmatch(r"^\d+$", trimmed):
        return min(float(int(trimmed)), _MAX_RETRY_AFTER_SECONDS)
    try:
        dt = email.utils.parsedate_to_datetime(trimmed)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=datetime.timezone.utc)
        delta = dt.timestamp() - (now_ms / 1000.0)
        return min(max(0.0, delta), _MAX_RETRY_AFTER_SECONDS)
    except Exception:
        return 0.0

BASE_SEPOLIA = "eip155:84532"
BASE_MAINNET = "eip155:8453"

USDC_ON_BASE: Dict[str, Dict[str, Any]] = {
    BASE_SEPOLIA: {"asset": "0x036CbD53842c5426634e7929541eC2318f3dCF7e", "name": "USDC", "version": "2", "chainId": 84532},
    BASE_MAINNET: {"asset": "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", "name": "USD Coin", "version": "2", "chainId": 8453},
}


class AgentMediateError(Exception):
    def __init__(
        self,
        status: int,
        code: str,
        message: str,
        body: Any = None,
        *,
        idempotency_key: Optional[str] = None,
        payment_sent: bool = False,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.code = code
        self.body = body
        self.hint: Optional[str] = body.get("hint") if isinstance(body, Mapping) and isinstance(body.get("hint"), str) else None
        self.docs: Optional[str] = body.get("docs") if isinstance(body, Mapping) and isinstance(body.get("docs"), str) else None
        # CR-SDK-M1: retry a failed mutating call with this exact key; the server then replays/resumes the original
        # request (and the SDK resends the identical paid request) instead of charging a second fee.
        self.idempotency_key: Optional[str] = idempotency_key
        self.payment_sent: bool = payment_sent


# CR-SDK-M1: ambiguous paid failures are remembered for a byte-identical same-key retry (server idempotency window).
_PENDING_PAID_TTL_MS = 24 * 3_600_000
_PENDING_PAID_MAX = 256
_PLATFORM_INFO_CACHE_TTL_MS = 60_000
_KEY_HISTORY_CACHE_TTL_MS = 60_000
_KEY_HISTORY_REFRESH_COOLDOWN_MS = 10_000
_LOCAL_HONOURS_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_AMBIGUOUS_PAYMENT_CODES = frozenset({"PAYMENT_UNCONFIRMED", "FACILITATOR_UNAVAILABLE", "FACILITATOR_BUSY", "CONCURRENT_REQUEST"})


def _is_ip_host(host: str) -> bool:
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def _assert_not_bare_mandate_bounds(bounds: Optional[Mapping[str, Any]]) -> None:
    if isinstance(bounds, Mapping) and ("signature" in bounds or "principalId" in bounds):
        raise ValueError("pass mandate=..., not a bare Mandate dict as bounds")


def _merge_prior_determination_bounds(
    *,
    bounds: Optional[Mapping[str, Mapping[str, float]]],
    determination_consent: Optional[bool],
    determination_bounds: Optional[Mapping[str, Mapping[str, float]]],
    ctx: Optional[Mapping[str, Any]],
) -> tuple[Optional[bool], Optional[Dict[str, Dict[str, float]]]]:
    effective_consent = (
        True
        if (ctx is not None and determination_consent is None and ctx.get("prevDeterminationConsent") is True)
        else determination_consent
    )
    if determination_bounds is not None:
        return effective_consent, {k: dict(v) for k, v in determination_bounds.items()}
    prev_db_map = ctx.get("prevDeterminationBounds") if ctx is not None else None
    prev_b_map = ctx.get("prevBounds") if ctx is not None else None
    if isinstance(prev_db_map, Mapping) and bounds is not None:
        merged: Dict[str, Dict[str, float]] = {}
        for issue_id, next_b in bounds.items():
            prev_db = prev_db_map.get(issue_id)
            prev_b = prev_b_map.get(issue_id) if isinstance(prev_b_map, Mapping) else None
            if not isinstance(prev_db, Mapping):
                merged[issue_id] = {"min": next_b["min"], "max": next_b["max"]}
            elif (
                isinstance(prev_b, Mapping)
                and float(prev_db["min"]) <= float(prev_b["min"])
                and float(prev_db["max"]) >= float(prev_b["max"])
            ):
                merged[issue_id] = {
                    "min": min(prev_db["min"], next_b["min"]),
                    "max": max(prev_db["max"], next_b["max"]),
                }
            else:
                merged[issue_id] = {"min": prev_db["min"], "max": prev_db["max"]}
        return effective_consent, merged
    return effective_consent, None


class PaymentRequiredError(AgentMediateError):
    def __init__(self, payment_required: Mapping[str, Any], body: Any = None, *, idempotency_key: Optional[str] = None) -> None:
        super().__init__(
            402,
            "PAYMENT_REQUIRED",
            "a fee is due and no payer is configured",
            body,
            idempotency_key=idempotency_key,
            payment_sent=False,
        )
        self.payment_required = dict(payment_required)


class PaymentPolicyError(AgentMediateError, ValueError):
    def __init__(self, message: str) -> None:
        AgentMediateError.__init__(self, 0, "PAYMENT_POLICY_ERROR", message)


def content_hash(content: str | bytes) -> str:
    raw = content.encode("utf-8") if isinstance(content, str) else content
    return hashlib.sha256(raw).hexdigest()


@dataclass
class HttpResponse:
    status: int
    headers: Dict[str, str]
    body: str


TransportLike = Callable[[str, str, Mapping[str, str], Optional[bytes]], HttpResponse]


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> Optional[urllib.request.Request]:
        return None


def _make_default_transport(timeout_seconds: Optional[float]) -> TransportLike:
    opener = urllib.request.build_opener(_NoRedirectHandler())

    def _transport(method: str, url: str, headers: Mapping[str, str], body: Optional[bytes]) -> HttpResponse:
        req = urllib.request.Request(url, data=body, headers=dict(headers), method=method)
        try:
            with opener.open(req, timeout=timeout_seconds) as resp:
                resp_headers = {k.lower(): v for k, v in resp.headers.items()}
                raw_resp = resp.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw_resp) > _MAX_RESPONSE_BYTES:
                    raise AgentMediateError(
                        resp.status,
                        "RESPONSE_TOO_LARGE",
                        f"response body exceeds {_MAX_RESPONSE_BYTES} bytes",
                    )
                return HttpResponse(status=resp.status, headers=resp_headers, body=raw_resp.decode("utf-8"))
        except urllib.error.HTTPError as err:
            try:
                resp_headers = {k.lower(): v for k, v in err.headers.items()} if err.headers else {}
                if 300 <= err.code < 400:
                    return HttpResponse(status=err.code, headers=resp_headers, body="")
                raw_err = err.read(_MAX_RESPONSE_BYTES + 1)
                if len(raw_err) > _MAX_RESPONSE_BYTES:
                    raise AgentMediateError(
                        err.code,
                        "RESPONSE_TOO_LARGE",
                        f"response body exceeds {_MAX_RESPONSE_BYTES} bytes",
                    ) from None
                err_body = raw_err.decode("utf-8", errors="replace")
                return HttpResponse(status=err.code, headers=resp_headers, body=err_body)
            finally:
                try:
                    err.close()
                except Exception:
                    pass

    return _transport


_default_transport = _make_default_transport(30.0)


def _normalize_evm_address(raw: str, *, strict_checksum: bool = False) -> str:
    if not isinstance(raw, str) or not _EVM_ADDR_RE.fullmatch(raw):
        raise PaymentPolicyError("pay_to must be a 0x-prefixed 20-byte address")
    try:
        from eth_utils import is_checksum_address, to_checksum_address  # type: ignore[import-not-found]
    except ImportError:
        return raw
    hex_part = raw[2:]
    if strict_checksum and hex_part != hex_part.lower() and hex_part != hex_part.upper() and not is_checksum_address(raw):
        raise PaymentPolicyError("pay_to has an invalid EIP-55 address checksum")
    return str(to_checksum_address(raw.lower()))


class X402Payer:
    """
    Optional EIP-3009 USDC payer on Base (`pip install "agent-mediate[x402]"`).
    Enforces pinned `network`, `asset`, `pay_to` (required on mainnet), per-payment cap, cumulative budget,
    and short authorization validity.
    """

    def __init__(
        self,
        *,
        private_key: str,
        max_amount_atomic: int,
        budget_atomic: Optional[int] = None,
        network: str = BASE_SEPOLIA,
        pay_to: Optional[str] = None,
        asset: Optional[str] = None,
        validity_seconds: int = 120,
        now_ms: Optional[Callable[[], int]] = None,
    ) -> None:
        if network not in USDC_ON_BASE:
            raise PaymentPolicyError(f"unsupported network {network}; expected {BASE_SEPOLIA} or {BASE_MAINNET}")
        usdc = USDC_ON_BASE[network]
        if asset is not None and str(asset).lower() != str(usdc["asset"]).lower():
            raise PaymentPolicyError(f"asset {asset} is not USDC on {network} ({usdc['asset']})")
        if not isinstance(max_amount_atomic, int) or isinstance(max_amount_atomic, bool) or max_amount_atomic <= 0:
            raise PaymentPolicyError("max_amount_atomic must be a positive integer")
        resolved_budget = budget_atomic if budget_atomic is not None else max_amount_atomic * 2
        if not isinstance(resolved_budget, int) or isinstance(resolved_budget, bool) or resolved_budget <= 0:
            raise PaymentPolicyError("budget_atomic must be a positive integer")
        if not isinstance(validity_seconds, int) or isinstance(validity_seconds, bool) or validity_seconds < 10:
            raise PaymentPolicyError("validity_seconds must be an integer >= 10")
        try:
            from eth_account import Account  # type: ignore[import-not-found]
        except ImportError as exc:
            raise ImportError('install eth-account for x402 payments: pip install "agent-mediate[x402]"') from exc
        pinned_pay_to = _normalize_evm_address(pay_to, strict_checksum=True) if pay_to is not None else None
        if network == BASE_MAINNET and not pinned_pay_to:
            raise PaymentPolicyError("on Base mainnet, pay_to must be pinned out of band")

        self._account = Account.from_key(private_key)
        self.address: str = self._account.address
        self.network = network
        self._pinned_pay_to = pinned_pay_to
        self._max_amount = max_amount_atomic
        self._budget = resolved_budget
        self._spent = 0
        self._issued: Dict[str, tuple[int, int]] = {}
        self._pending_reclaims: List[tuple[int, int]] = []
        self._lock = threading.Lock()
        self._validity_seconds = validity_seconds
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))

    def _reclaim_expired_locked(self) -> None:
        if not self._pending_reclaims:
            return
        now_sec = self._now_ms() // 1000
        remaining: List[tuple[int, int]] = []
        for amt, reclaim_at in self._pending_reclaims:
            if now_sec > reclaim_at:
                self._spent = max(0, self._spent - amt)
            else:
                remaining.append((amt, reclaim_at))
        self._pending_reclaims = remaining

    @property
    def spent_atomic(self) -> int:
        with self._lock:
            self._reclaim_expired_locked()
            return self._spent

    def release_unsettled(self, payment_header: str) -> None:
        """Mark an issued PAYMENT-SIGNATURE header as definitively unsettled (`RESPONDENT_UNREACHABLE`) so its budget reclaims after `validBefore + 60s` (`CR3-SDK-M3`)."""
        with self._lock:
            entry = self._issued.pop(payment_header, None)
            if entry is not None:
                amt, valid_before = entry
                self._pending_reclaims.append((amt, valid_before + 60))
                self._reclaim_expired_locked()

    def pay(self, challenge: Mapping[str, Any], *, operation: str, expected_pay_to: Optional[str] = None) -> str:
        if operation != "file":
            raise PaymentPolicyError(f"refusing to pay for unknown operation {operation}")
        if not isinstance(challenge, Mapping) or challenge.get("x402Version") != 2 or not isinstance(challenge.get("accepts"), list):
            raise PaymentPolicyError(f"unsupported x402 version {challenge.get('x402Version') if isinstance(challenge, Mapping) else None}")

        usdc = USDC_ON_BASE[self.network]
        accepts = challenge["accepts"]
        req = next(
            (
                a
                for a in accepts
                if isinstance(a, Mapping)
                and a.get("scheme") == "exact"
                and a.get("network") == self.network
                and isinstance(a.get("asset"), str)
                and a["asset"].lower() == str(usdc["asset"]).lower()
            ),
            None,
        )
        if req is None:
            raise PaymentPolicyError(f"challenge offers no exact USDC payment on {self.network}")

        raw_target_pay_to = self._pinned_pay_to or expected_pay_to
        if not raw_target_pay_to:
            raise PaymentPolicyError("no pay_to pinned and the platform publishes none")
        target_pay_to = self._pinned_pay_to or _normalize_evm_address(raw_target_pay_to, strict_checksum=False)
        req_pay_to = req.get("payTo")
        if not isinstance(req_pay_to, str) or not _EVM_ADDR_RE.fullmatch(req_pay_to) or req_pay_to.lower() != target_pay_to.lower():
            raise PaymentPolicyError(f"payTo {req_pay_to} does not match expected {target_pay_to}")

        extra = req.get("extra")
        if extra is not None:
            if not isinstance(extra, Mapping):
                raise PaymentPolicyError("invalid extra EIP-712 domain metadata")
            if extra.get("name") is not None and extra.get("name") != usdc["name"]:
                raise PaymentPolicyError(f"unexpected EIP-712 domain name {extra.get('name')}")
            if extra.get("version") is not None and extra.get("version") != usdc["version"]:
                raise PaymentPolicyError(f"unexpected EIP-712 domain version {extra.get('version')}")

        raw_amount = req.get("amount")
        if not isinstance(raw_amount, str) or not re.fullmatch(r"^\d+$", raw_amount):
            raise PaymentPolicyError("invalid amount")
        amount = int(raw_amount)
        if amount <= 0:
            raise PaymentPolicyError("invalid amount")
        if amount > self._max_amount:
            raise PaymentPolicyError(f"fee {amount} exceeds per-payment cap {self._max_amount}")

        raw_timeout = req.get("maxTimeoutSeconds")
        if not isinstance(raw_timeout, int) or isinstance(raw_timeout, bool) or raw_timeout <= 0:
            raise PaymentPolicyError("maxTimeoutSeconds must be a positive integer")
        validity = min(raw_timeout, self._validity_seconds)

        with self._lock:
            self._reclaim_expired_locked()
            if self._spent + amount > self._budget:
                raise PaymentPolicyError(
                    f"fee {amount} would exceed remaining budget {self._budget - self._spent} of {self._budget}"
                )
            self._spent += amount

        now_sec = self._now_ms() // 1000
        valid_after = max(0, now_sec - 600)
        valid_before = now_sec + validity
        nonce_hex = "0x" + os.urandom(32).hex()

        typed_data = {
            "types": {
                "EIP712Domain": [
                    {"name": "name", "type": "string"},
                    {"name": "version", "type": "string"},
                    {"name": "chainId", "type": "uint256"},
                    {"name": "verifyingContract", "type": "address"},
                ],
                "TransferWithAuthorization": [
                    {"name": "from", "type": "address"},
                    {"name": "to", "type": "address"},
                    {"name": "value", "type": "uint256"},
                    {"name": "validAfter", "type": "uint256"},
                    {"name": "validBefore", "type": "uint256"},
                    {"name": "nonce", "type": "bytes32"},
                ],
            },
            "primaryType": "TransferWithAuthorization",
            "domain": {
                "name": usdc["name"],
                "version": usdc["version"],
                "chainId": usdc["chainId"],
                "verifyingContract": usdc["asset"],
            },
            "message": {
                "from": self.address,
                "to": target_pay_to,
                "value": amount,
                "validAfter": valid_after,
                "validBefore": valid_before,
                "nonce": bytes.fromhex(nonce_hex[2:]),
            },
        }
        try:
            signed = self._account.sign_typed_data(full_message=typed_data)
            raw_sig_hex = (
                bytes(signed.signature).hex()
                if isinstance(signed.signature, (bytes, bytearray, memoryview))
                else str(signed.signature.hex())
            )
            sig_hex = "0x" + (raw_sig_hex[2:] if raw_sig_hex.startswith(("0x", "0X")) else raw_sig_hex)
        except Exception:
            with self._lock:
                self._spent -= amount
            raise

        accepted: Dict[str, Any] = {
            "scheme": "exact",
            "network": self.network,
            "amount": raw_amount,
            "asset": req["asset"],
            "payTo": req_pay_to,
            "maxTimeoutSeconds": raw_timeout,
            "extra": {"name": usdc["name"], "version": usdc["version"]},
        }
        payload: Dict[str, Any] = {
            "x402Version": 2,
            **({"resource": challenge["resource"]} if "resource" in challenge and challenge["resource"] is not None else {}),
            "accepted": accepted,
            "payload": {
                "signature": sig_hex,
                "authorization": {
                    "from": self.address,
                    "to": target_pay_to,
                    "value": str(amount),
                    "validAfter": str(valid_after),
                    "validBefore": str(valid_before),
                    "nonce": nonce_hex,
                },
            },
        }
        encoded = base64.b64encode(json.dumps(payload).encode("utf-8")).decode("ascii")
        with self._lock:
            if encoded not in self._issued and len(self._issued) >= _PENDING_PAID_MAX:
                self._issued.pop(next(iter(self._issued)), None)
            self._issued[encoded] = (amount, valid_before)
        return encoded


def create_x402_payer(**kwargs: Any) -> X402Payer:
    return X402Payer(**kwargs)


class AgentMediateClient:
    def __init__(
        self,
        *,
        base_url: str,
        agent_key: AgentKey,
        platform_did: Optional[str] = None,
        allow_unpinned_platform_did: bool = False,
        expected_environment: Optional[str] = None,
        expected_rules_hash: Optional[str] = None,
        default_view: str = "full",
        payer: Optional[X402Payer] = None,
        transport: Optional[TransportLike] = None,
        now_ms: Optional[Callable[[], int]] = None,
        max_retries: int = 3,
        timeout_ms: int = 30_000,
    ) -> None:
        norm_base_url = normalize_base_url(base_url)
        effective_platform_did = platform_did if platform_did is not None else DEFAULT_PRODUCTION_PLATFORM_DIDS.get(norm_base_url)
        effective_expected_env = expected_environment if expected_environment is not None else (
            "production" if norm_base_url == PRODUCTION_API_URL else None
        )
        allow_unpinned = bool(allow_unpinned_platform_did)
        if effective_platform_did is not None and not is_did_key(effective_platform_did):
            raise ValueError("platform_did must be a valid Ed25519 did:key")
        if payer is not None and getattr(payer, "network", None) == BASE_MAINNET and not effective_platform_did and not allow_unpinned:
            raise ValueError("on Base mainnet, platform_did must be pinned out of band")
        if effective_expected_env == "production" and not effective_platform_did and not allow_unpinned:
            raise ValueError("in production (expected_environment='production'), platform_did must be pinned out of band")
        if default_view not in ("full", "compact"):
            raise ValueError("default_view must be 'full' or 'compact'")
        if isinstance(timeout_ms, bool) or not isinstance(timeout_ms, (int, float)) or not math.isfinite(timeout_ms) or timeout_ms < 0:
            raise ValueError("timeout_ms must be a non-negative finite number")

        self.base_url = norm_base_url
        self.agent_key = agent_key
        self.default_view = default_view
        self._pinned_platform_did = effective_platform_did
        self._allow_unpinned_platform_did = allow_unpinned
        self._expected_environment = effective_expected_env
        self._expected_rules_hash = expected_rules_hash
        self._payer = payer
        self._timeout_ms = int(timeout_ms)
        self._custom_transport = transport
        self._transport = transport or _make_default_transport((timeout_ms / 1000.0) if timeout_ms > 0 else None)
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._max_retries = max_retries
        self._platform_info: Optional[Dict[str, Any]] = None
        self._platform_info_fetched_at: int = 0
        self._verified_active_platform_did: Optional[str] = None
        self._verified_pay_to: Optional[str] = None
        self._key_history_cache: Optional[Dict[str, Any]] = None
        self._key_history_refresh_at: int = 0
        self._key_history_state: Dict[str, int] = {"min_updated_at": 0}
        self._pending_paid: Dict[str, Dict[str, Any]] = {}
        self._mandate_cache: Dict[str, Dict[str, Any]] = {}
        self._scope_cache: Dict[str, Dict[str, Any]] = {}
        self._pending_lock = threading.Lock()

    @property
    def did(self) -> str:
        return self.agent_key.did

    def with_default_view(self, default_view: str) -> "AgentMediateClient":
        if default_view == self.default_view:
            return self
        clone = AgentMediateClient(
            base_url=self.base_url,
            agent_key=self.agent_key,
            platform_did=self._pinned_platform_did,
            allow_unpinned_platform_did=self._allow_unpinned_platform_did,
            expected_environment=self._expected_environment,
            expected_rules_hash=self._expected_rules_hash,
            default_view=default_view,
            payer=self._payer,
            transport=self._custom_transport,
            now_ms=self._now_ms,
            max_retries=self._max_retries,
            timeout_ms=self._timeout_ms,
        )
        clone._platform_info = self._platform_info
        clone._platform_info_fetched_at = self._platform_info_fetched_at
        clone._verified_active_platform_did = self._verified_active_platform_did
        clone._verified_pay_to = self._verified_pay_to
        clone._key_history_cache = self._key_history_cache
        clone._key_history_refresh_at = self._key_history_refresh_at
        clone._key_history_state = self._key_history_state
        clone._pending_paid = self._pending_paid
        clone._mandate_cache = self._mandate_cache
        clone._scope_cache = self._scope_cache
        clone._pending_lock = self._pending_lock
        return clone

    def _view_path(self, path: str, view: Optional[str] = None) -> str:
        mode = view or self.default_view
        if mode != "compact":
            return path
        sep = "&" if "?" in path else "?"
        return f"{path}{sep}view=compact"

    def mandate(
        self,
        bounds: Mapping[str, Mapping[str, float]],
        *,
        expires_in_ms: int = 7 * 24 * 3_600_000,
        scope: Optional[Mapping[str, str]] = None,
        determination_consent: Optional[bool] = None,
        determination_bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        min_issued_at: Optional[int] = None,
        min_expires_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        now = self._now_ms()
        issued_at = max(now, int(min_issued_at)) if min_issued_at is not None else now
        expires_at = max(now + expires_in_ms, int(min_expires_at)) if min_expires_at is not None else now + expires_in_ms
        unsigned: Dict[str, Any] = {
            "id": f"mnd_{uuid.uuid4()}",
            "principalId": self.did,
            "agentId": self.did,
            "bounds": {k: dict(v) for k, v in bounds.items()},
            "expiresAt": expires_at,
            "issuedAt": issued_at,
        }
        if determination_consent is not None:
            unsigned["determinationConsent"] = determination_consent
        if determination_bounds is not None:
            unsigned["determinationBounds"] = {k: dict(v) for k, v in determination_bounds.items()}
        if scope is not None:
            unsigned["scope"] = {"contractHash": str(scope["contractHash"]), "counterpartyId": str(scope["counterpartyId"])}
        return sign_mandate(unsigned, self.agent_key)

    def platform(self) -> Dict[str, Any]:
        now = self._now_ms()
        with self._pending_lock:
            cached = self._platform_info
            fetched_at = self._platform_info_fetched_at
            verified_active = self._verified_active_platform_did
        if cached is None or (now - fetched_at >= _PLATFORM_INFO_CACHE_TTL_MS):
            info = self._get_public("/v1/platform", error_code="PLATFORM_UNAVAILABLE", error_detail="could not read /v1/platform")
            if self._pinned_platform_did and info.get("did") != self._pinned_platform_did and info.get("did") != verified_active:
                rotated_ok = False
                try:
                    hist = self.key_history(force=True)
                    rotated_ok = ((hist.get("document") or {}).get("activeDid")) == info.get("did")
                except Exception:
                    rotated_ok = False
                if not rotated_ok:
                    raise AgentMediateError(
                        0,
                        "PLATFORM_DID_MISMATCH",
                        f"/v1/platform reported {info.get('did')}, expected pinned {self._pinned_platform_did}",
                    )
            if self._expected_rules_hash and info.get("rulesHash") != self._expected_rules_hash:
                raise AgentMediateError(
                    0,
                    "RULES_HASH_MISMATCH",
                    f"/v1/platform reported rulesHash {info.get('rulesHash')}, expected {self._expected_rules_hash}",
                )
            with self._pending_lock:
                self._platform_info = info
                self._platform_info_fetched_at = now
                cached = info
        return dict(cached)

    def rules(self) -> Dict[str, Any]:
        info = self._get_public("/v1/rules", error_detail="could not read /v1/rules")
        if self._expected_rules_hash and info.get("rulesHash") != self._expected_rules_hash:
            raise AgentMediateError(0, "RULES_HASH_MISMATCH", f"/v1/rules reported rulesHash {info.get('rulesHash')}, expected {self._expected_rules_hash}")
        return info

    def key_history(self, force: bool = False) -> Dict[str, Any]:
        now = self._now_ms()
        expected_did = self._pinned_platform_did or self.platform()["did"]
        with self._pending_lock:
            cached = self._key_history_cache
            min_upd = self._key_history_state["min_updated_at"] or None
        if not force and cached is not None and now - cached["fetched_at"] < _KEY_HISTORY_CACHE_TTL_MS:
            if verify_key_history(
                cached["doc"],
                expected_active_did=expected_did,
                now_ms=now,
                max_age_ms=DEFAULT_KEY_HISTORY_TTL_MS,
                min_updated_at=min_upd,
            ).get("ok"):
                if self._pinned_platform_did:
                    active_did = ((cached["doc"].get("document") or {}).get("activeDid")) if isinstance(cached["doc"], Mapping) else None
                    if isinstance(active_did, str):
                        with self._pending_lock:
                            self._verified_active_platform_did = active_did
                return copy.deepcopy(cached["doc"])
            with self._pending_lock:
                self._key_history_cache = None
        doc = self._get_public("/.well-known/key-history.json", error_detail="could not read /.well-known/key-history.json")
        verdict = verify_key_history(
            doc,
            expected_active_did=expected_did,
            now_ms=now,
            max_age_ms=DEFAULT_KEY_HISTORY_TTL_MS,
            min_updated_at=min_upd,
        )
        if not verdict.get("ok"):
            raise AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", f"key-history.json failed verification: {verdict.get('reason')}")
        with self._pending_lock:
            doc_upd = ((doc.get("document") or {}).get("updatedAt")) if isinstance(doc, Mapping) else None
            if isinstance(doc_upd, int) and not isinstance(doc_upd, bool) and doc_upd > self._key_history_state["min_updated_at"]:
                self._key_history_state["min_updated_at"] = doc_upd
            if self._pinned_platform_did:
                active_did = ((doc.get("document") or {}).get("activeDid")) if isinstance(doc, Mapping) else None
                if isinstance(active_did, str):
                    self._verified_active_platform_did = active_did
            self._key_history_cache = {"doc": doc, "fetched_at": now}
        return doc

    def _verify_checkpoint_envelope(self, cp: Any, mismatch_code: str) -> None:
        if not isinstance(cp, Mapping) or not self._verify_platform_document(cp.get("signedCheckpoint") or {}):
            raise AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "transparency checkpoint signature failed verification")
        signed_cp = cp.get("signedCheckpoint") or {}
        doc = signed_cp.get("document")
        if not isinstance(doc, Mapping) or doc.get("type") != "agent-mediate/transparency-checkpoint/v1":
            raise AgentMediateError(0, mismatch_code, f"unexpected checkpoint document.type {(doc or {}).get('type') if isinstance(doc, Mapping) else None}")
        if self._expected_environment is not None and doc.get("environment") != self._expected_environment:
            raise AgentMediateError(0, mismatch_code, f"checkpoint environment {doc.get('environment')} does not match expected {self._expected_environment}")
        if self._expected_rules_hash is not None and doc.get("rulesHash") != self._expected_rules_hash:
            raise AgentMediateError(0, mismatch_code, f"checkpoint rulesHash {doc.get('rulesHash')} does not match expected {self._expected_rules_hash}")
        seq = doc.get("checkpointSeq")
        dispute_count = doc.get("disputeCount")
        merkle_root = doc.get("merkleRoot")
        prev_hash = doc.get("prevCheckpointHash")
        if (
            not isinstance(seq, int)
            or isinstance(seq, bool)
            or seq < 1
            or seq > _MAX_SAFE_INT
            or not isinstance(dispute_count, int)
            or isinstance(dispute_count, bool)
            or dispute_count < 0
            or dispute_count > _MAX_SAFE_INT
            or not isinstance(merkle_root, str)
            or not _SHA256_HEX_RE.fullmatch(merkle_root)
            or not isinstance(prev_hash, str)
            or not _SHA256_HEX_RE.fullmatch(prev_hash)
        ):
            raise AgentMediateError(0, mismatch_code, "checkpoint document fields are malformed")
        expected_calldata = encode_base_anchor_calldata(seq, merkle_root)
        calldata = doc.get("baseAnchorCalldata")
        if not isinstance(calldata, str) or calldata.lower() != expected_calldata.lower():
            raise AgentMediateError(0, mismatch_code, "checkpoint baseAnchorCalldata does not match (checkpointSeq, merkleRoot)")
        expected_hash = sha256_hex("agent-mediate/checkpoint-chain/v1\n" + canonical_json(doc))
        if cp.get("checkpointHash") != expected_hash:
            raise AgentMediateError(0, mismatch_code, "checkpointHash does not match signed checkpoint document")
        anchor = cp.get("anchor")
        if anchor is not None:
            anchored_at = anchor.get("anchoredAt") if isinstance(anchor, Mapping) else None
            if (
                not isinstance(anchor, Mapping)
                or not isinstance(anchor.get("network"), str)
                or len(anchor.get("network")) == 0
                or not isinstance(anchor.get("txHash"), str)
                or not _TX_HASH_RE.fullmatch(anchor.get("txHash"))
                or not isinstance(anchor.get("calldata"), str)
                or anchor.get("calldata").lower() != expected_calldata.lower()
                or not isinstance(anchored_at, int)
                or isinstance(anchored_at, bool)
                or anchored_at <= 0
                or anchored_at > _MAX_SAFE_INT
            ):
                raise AgentMediateError(0, mismatch_code, "checkpoint anchor metadata does not match signed checkpoint calldata")

    def transparency_checkpoint(self, seq: Optional[int] = None) -> Dict[str, Any]:
        if seq is not None and (not isinstance(seq, int) or isinstance(seq, bool) or seq < 1 or seq > _MAX_SAFE_INT):
            raise ValueError("checkpoint seq must be a positive safe integer")
        path = f"/v1/transparency/checkpoints/{seq}" if seq is not None else "/v1/transparency/checkpoint"
        cp = self._get_public(path, error_detail=f"could not read {path}")
        self._verify_checkpoint_envelope(cp, "CHECKPOINT_MISMATCH")
        if seq is not None and cp["signedCheckpoint"]["document"]["checkpointSeq"] != seq:
            raise AgentMediateError(0, "CHECKPOINT_MISMATCH", f"checkpoint seq {cp['signedCheckpoint']['document']['checkpointSeq']} does not match requested {seq}")
        return cp

    def transparency(self) -> Dict[str, Any]:
        return self._get_public("/transparency?format=json", error_detail="could not read /transparency")

    def honours_roll(self) -> Dict[str, Any]:
        return self._get_public("/v1/honours", error_detail="could not read /v1/honours")

    def check_honours(self, subject: str) -> Dict[str, Any]:
        trimmed = subject.strip()
        if not trimmed:
            raise ValueError("subject must be a non-empty domain, did:web, or did:key")
        enc = urllib.parse.quote(trimmed, safe="")
        body = self._get_public(f"/v1/honours/{enc}", error_detail=f"could not read /v1/honours/{trimmed}")
        if not body.get("listed"):
            return {**body, "verified": False}
        entry = body.get("entry")
        signed_att = body.get("signedAttestation")
        if not isinstance(entry, Mapping) or not isinstance(signed_att, Mapping):
            raise AgentMediateError(0, "HONOURS_MISMATCH", "listed Honours Roll response is missing entry or signedAttestation")
        proof = signed_att.get("proof")
        doc = signed_att.get("document")
        if not isinstance(doc, Mapping) or doc.get("type") != HONOURS_ATTESTATION_TYPE:
            raise AgentMediateError(0, "HONOURS_MISMATCH", f"unexpected Honours attestation type {(doc or {}).get('type') if isinstance(doc, Mapping) else None}")
        if doc.get("environment") == "production" and not self._pinned_platform_did and not self._allow_unpinned_platform_did:
            raise AgentMediateError(
                0,
                "UNPINNED_PLATFORM_DID",
                "refusing unpinned TOFU verification for environment=production; pin platform_did out of band",
            )
        with self._pending_lock:
            verified_active = self._verified_active_platform_did
        expected_did = verified_active or self._pinned_platform_did or self.platform()["did"]
        now = self._now_ms()
        sig_ok = verify_document(signed_att, expected_did, now_ms=now)
        vm = proof.get("verificationMethod") if isinstance(proof, Mapping) else None
        if not sig_ok and self._pinned_platform_did and isinstance(vm, str) and vm != expected_did:
            try:
                hist = self.key_history(force=True)
                hist_active = ((hist.get("document") or {}).get("activeDid")) if isinstance(hist, Mapping) else None
                if isinstance(hist_active, str) and hist_active != expected_did:
                    expected_did = hist_active
                    sig_ok = verify_document(signed_att, expected_did, now_ms=now)
            except Exception:
                sig_ok = False
        if not sig_ok:
            raise AgentMediateError(
                0,
                "INVALID_PLATFORM_SIGNATURE",
                "Honours Roll attestation signature is invalid, expired, or not signed by the active platform DID",
            )
        created = proof.get("created") if isinstance(proof, Mapping) else None
        exp = proof.get("expiresAt") if isinstance(proof, Mapping) else None
        if (
            not isinstance(created, int)
            or isinstance(created, bool)
            or not isinstance(exp, int)
            or isinstance(exp, bool)
            or created != doc.get("issuedAt")
            or created > now + 300_000
            or exp <= created
            or exp - created > 24 * 3_600_000
        ):
            raise AgentMediateError(0, "HONOURS_MISMATCH", "Honours Roll attestation proof timestamps or 24h TTL bounds are invalid")
        if self._expected_environment is not None and doc.get("environment") != self._expected_environment:
            raise AgentMediateError(0, "HONOURS_MISMATCH", f"attestation environment {doc.get('environment')} does not match expected {self._expected_environment}")
        if self._expected_rules_hash is not None and doc.get("rulesHash") != self._expected_rules_hash:
            raise AgentMediateError(0, "HONOURS_MISMATCH", f"attestation rulesHash {doc.get('rulesHash')} does not match expected {self._expected_rules_hash}")
        agent_ids = doc.get("agentIds")
        entry_agent_ids = entry.get("agentIds")
        same_agents = (
            isinstance(agent_ids, list)
            and isinstance(entry_agent_ids, list)
            and len(agent_ids) == len(entry_agent_ids)
            and all(isinstance(aid, str) and aid == entry_agent_ids[idx] for idx, aid in enumerate(agent_ids))
        )
        if (
            not same_agents
            or doc.get("domain") != entry.get("domain")
            or doc.get("didWeb") != entry.get("didWeb")
            or doc.get("memberSince") != entry.get("memberSince")
            or doc.get("verifiedAt") != entry.get("verifiedAt")
            or doc.get("qualifiedHonoredCount") != entry.get("qualifiedHonoredCount")
            or doc.get("totalHonoredObligations") != entry.get("totalHonoredObligations")
            or doc.get("confirmedByCounterpartyCount") != entry.get("confirmedByCounterpartyCount")
            or doc.get("distinctCounterparties") != entry.get("distinctCounterparties")
            or doc.get("verifiedDomainCounterparties") != entry.get("verifiedDomainCounterparties")
            or doc.get("curedLateCount") != entry.get("curedLateCount")
            or doc.get("fulfilmentRate") != 1
            or entry.get("fulfilmentRate") != 1
            or doc.get("lastHonoredAt") != entry.get("lastHonoredAt")
        ):
            raise AgentMediateError(0, "HONOURS_MISMATCH", "Honours Roll entry disagrees with signedAttestation")
        if len(trimmed) > 512:
            raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid Honours Roll subject {trimmed}")
        if trimmed.startswith("did:key:"):
            if not is_did_key(trimmed):
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid Honours Roll subject {trimmed}")
            if trimmed not in agent_ids:
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"signedAttestation does not include requested agent {trimmed}")
        elif trimmed.startswith("did:web:"):
            segments = trimmed[len("did:web:") :].split(":")
            if len(segments) != 1 or not segments[0]:
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"Honours Roll requires root-domain did:web without path segments, got {trimmed}")
            try:
                parsed = urllib.parse.urlsplit(url_from_did_web(trimmed))
                port = parsed.port
            except ValueError as exc:
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid did:web subject {trimmed}") from exc
            if parsed.path != "/.well-known/did.json" or parsed.query != "" or parsed.fragment != "":
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid did:web subject {trimmed}")
            raw_host = (parsed.hostname or "").strip("[]").lower().rstrip(".")
            if not raw_host or (_is_ip_host(raw_host) and raw_host not in _LOCAL_HONOURS_HOSTS):
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid did:web subject {trimmed}")
            try:
                host = _uts46_to_ascii(raw_host) if not _is_ip_host(raw_host) else raw_host
            except UnicodeError as exc:
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid did:web subject {trimmed}") from exc
            expected_domain = f"{host}:{port}" if (port and port != 443) else host
            if not expected_domain or doc.get("domain") != expected_domain or not isinstance(doc.get("didWeb"), str):
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"signedAttestation domain {doc.get('domain')} does not match requested {trimmed}")
        else:
            if re.search(r"[/?#@\\\s\x00-\x1f\x7f]", trimmed) or trimmed.startswith("."):
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid Honours Roll domain subject {trimmed}")
            stripped = trimmed.rstrip(".")
            if not stripped:
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid Honours Roll domain subject {trimmed}")
            try:
                parsed = urllib.parse.urlsplit(f"https://{stripped}")
                port = parsed.port
            except ValueError as exc:
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid Honours Roll domain subject {trimmed}") from exc
            if (
                not parsed.hostname
                or parsed.username is not None
                or parsed.password is not None
                or parsed.path not in ("", "/")
                or parsed.query != ""
                or parsed.fragment != ""
            ):
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid Honours Roll domain subject {trimmed}")
            raw_host = parsed.hostname.strip("[]").lower().rstrip(".")
            if not raw_host or raw_host in (".", "..") or (_is_ip_host(raw_host) and raw_host not in _LOCAL_HONOURS_HOSTS):
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid Honours Roll domain subject {trimmed}")
            try:
                host = _uts46_to_ascii(raw_host) if not _is_ip_host(raw_host) else raw_host
            except UnicodeError as exc:
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"invalid Honours Roll domain subject {trimmed}") from exc
            expected_domain = f"{host}:{port}" if (port and port != 443) else host
            if not expected_domain or doc.get("domain") != expected_domain:
                raise AgentMediateError(0, "HONOURS_MISMATCH", f"signedAttestation domain {doc.get('domain')} does not match requested {trimmed}")
        return {**body, "verified": True}

    def _verify_platform_document(self, doc: Mapping[str, Any]) -> bool:
        inner_doc = doc.get("document") if isinstance(doc, Mapping) else None
        doc_env = inner_doc.get("environment") if isinstance(inner_doc, Mapping) else None
        if doc_env == "production" and not self._pinned_platform_did and not self._allow_unpinned_platform_did:
            raise AgentMediateError(
                0,
                "UNPINNED_PLATFORM_DID",
                "refusing unpinned TOFU verification for environment=production; pin platform_did out of band",
            )
        root_expected_did = self._pinned_platform_did or self.platform()["did"]
        with self._pending_lock:
            fast_expected_did = self._verified_active_platform_did or root_expected_did
        now = self._now_ms()
        if verify_document(doc, fast_expected_did, now_ms=now):
            return True
        proof = doc.get("proof") if isinstance(doc, Mapping) else None
        vm = proof.get("verificationMethod") if isinstance(proof, Mapping) else None
        if isinstance(vm, str) and vm != fast_expected_did:
            try:
                with self._pending_lock:
                    was_cached = (
                        self._key_history_cache is not None
                        and now - self._key_history_cache["fetched_at"] < _KEY_HISTORY_CACHE_TTL_MS
                    )
                    can_refresh = now - self._key_history_refresh_at >= _KEY_HISTORY_REFRESH_COOLDOWN_MS
                hist = self.key_history()
                proof_key_id = proof.get("keyId") if isinstance(proof, Mapping) else None
                keys = ((hist.get("document") or {}).get("keys")) if isinstance(hist, Mapping) else None
                has_key = any(
                    isinstance(k, Mapping)
                    and k.get("did") == vm
                    and (proof_key_id is None or k.get("keyId") == proof_key_id)
                    for k in (keys or [])
                )
                if not has_key and was_cached and can_refresh:
                    with self._pending_lock:
                        self._key_history_refresh_at = now
                    hist = self.key_history(force=True)
                with self._pending_lock:
                    min_upd = self._key_history_state["min_updated_at"] or None
                return bool(
                    verify_document_with_key_history(
                        doc,
                        hist,
                        expected_active_did=root_expected_did,
                        now_ms=now,
                        max_age_ms=DEFAULT_KEY_HISTORY_TTL_MS,
                        min_updated_at=min_upd,
                    ).get("ok")
                )
            except Exception:
                return False
        return False

    # --- Notifications --------------------------------------------------------

    def register_notifications(
        self,
        *,
        webhook_url: Optional[str] = None,
        a2a_card_url: Optional[str] = None,
        email: Optional[str] = None,
        clear_fields: Sequence[str] = (),
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if webhook_url is not None:
            body["webhookUrl"] = webhook_url
        if a2a_card_url is not None:
            body["a2aCardUrl"] = a2a_card_url
        if email is not None:
            body["email"] = email
        for field_name in clear_fields:
            body[field_name] = None
        return self._put("/v1/agents/me/notify", body, idempotency_key=idempotency_key)

    def get_notifications(self) -> Dict[str, Any]:
        return self._get("/v1/agents/me/notify")

    def update_my_honours(
        self,
        opt_in: bool,
        *,
        did_web: Optional[str] = None,
        a2a_card_url: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {"optIn": bool(opt_in)}
        if did_web is not None:
            body["didWeb"] = did_web
        if a2a_card_url is not None:
            body["a2aCardUrl"] = a2a_card_url
        return self._put("/v1/agents/me/honours", body, idempotency_key=idempotency_key)

    def get_my_honours(self) -> Dict[str, Any]:
        return self._get("/v1/agents/me/honours")

    # --- Cold-start invites & discovery ---------------------------------------

    def create_invite(
        self,
        *,
        contract_hash: str,
        summary: str,
        respondent_id: Optional[str] = None,
        respondent_contact: Optional[Mapping[str, Any]] = None,
        webhook_url: Optional[str] = None,
        ttl_ms: Optional[int] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Send a ``$0.00`` pre-filing mediation invite (``POST /v1/invites``) and verify ``signedInvite`` against the platform DID."""
        body: Dict[str, Any] = {
            "contractHash": contract_hash,
            "summary": summary,
        }
        if respondent_id is not None:
            body["respondentId"] = respondent_id
        if respondent_contact is not None:
            body["respondentContact"] = dict(respondent_contact)
        if webhook_url is not None:
            body["webhookUrl"] = webhook_url
        if ttl_ms is not None:
            body["ttlMs"] = int(ttl_ms)
        res = self._post("/v1/invites", body, idempotency_key=idempotency_key)
        signed_invite = res.get("signedInvite")
        if not isinstance(signed_invite, Mapping):
            raise AgentMediateError(0, "INVITE_MISMATCH", "invite response is missing signedInvite")
        doc = self.verify_invite(
            signed_invite,
            invite_id=str(res.get("inviteId") or ""),
            claimant_id=self.did,
            respondent_id=respondent_id,
            contract_hash=contract_hash,
            allow_third_party=True,
        )
        if doc.get("inviteUrl") != res.get("inviteUrl"):
            raise AgentMediateError(0, "INVITE_MISMATCH", "inviteUrl does not match signedInvite.document.inviteUrl")
        return res

    def get_invite(self, invite_id: str, *, token: Optional[str] = None) -> Dict[str, Any]:
        """Read mediation invite status (``GET /v1/invites/:id``), optionally passing ``token`` for an unbound cold respondent."""
        enc = urllib.parse.quote(invite_id, safe="")
        q = f"?token={urllib.parse.quote(token, safe='')}" if token else ""
        return self._get(f"/v1/invites/{enc}{q}")

    def accept_invite(
        self,
        token: str,
        *,
        webhook_url: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Accept a ``$0.00`` mediation invite (``POST /v1/invites/:token/accept``) using your authenticated respondent ``did:key``."""
        body: Dict[str, Any] = {}
        if webhook_url is not None:
            body["webhookUrl"] = webhook_url
        enc = urllib.parse.quote(token, safe="")
        return self._post(f"/v1/invites/{enc}/accept", body, idempotency_key=idempotency_key)

    def discover_respondent(
        self,
        target: str,
        *,
        transport: Optional[TransportLike] = None,
        resolve_host: Optional[Callable[[str], Sequence[Any]]] = None,
        timeout_ms: int = 3_000,
        allow_insecure_http: bool = False,
    ) -> Dict[str, Any]:
        """Probe public metadata for a target domain, HTTPS URL, or ``did:web`` before filing a dispute."""
        with self._pending_lock:
            plat_did = self._verified_active_platform_did or self._pinned_platform_did
        return discover_respondent(
            target,
            base_url=self.base_url,
            platform_did=plat_did,
            expected_environment=self._expected_environment,
            expected_rules_hash=self._expected_rules_hash,
            transport=transport,
            api_transport=self._custom_transport,
            resolve_host=resolve_host,
            timeout_ms=timeout_ms,
            allow_insecure_http=allow_insecure_http,
            now_ms=self._now_ms,
        )

    # --- Dispute lifecycle ----------------------------------------------------

    def file_dispute(
        self,
        *,
        respondent_id: str,
        contract_hash: str,
        claim: Mapping[str, str],
        proposed_issues: Sequence[Mapping[str, Any]],
        mandate: Optional[Mapping[str, Any]] = None,
        bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        determination_consent: Optional[bool] = None,
        determination_bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        disclose_gap_on_failure: Optional[bool] = None,
        config: Optional[Mapping[str, Any]] = None,
        webhook_url: Optional[str] = None,
        respondent_contact: Optional[Mapping[str, Any]] = None,
        clause: Optional[Mapping[str, Any]] = None,
        require_delivery: Optional[bool] = None,
        invite_id: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """File a dispute. Keep ``config["feeMode"] == "FILER_PAYS"`` (the default) for cold respondents so joining costs $0.00 and zero crypto setup."""
        _assert_not_bare_mandate_bounds(bounds)
        key = idempotency_key or f"pysdk-{uuid.uuid4()}"
        scope = {"contractHash": contract_hash, "counterpartyId": respondent_id}
        fp = (
            self._mandate_fingerprint(
                bounds=bounds,
                determination_consent=determination_consent,
                determination_bounds=determination_bounds,
                scope=scope,
            )
            if (bounds is not None and mandate is None)
            else None
        )
        pending_mandate: Optional[Dict[str, Any]] = None
        if fp is not None:
            with self._pending_lock:
                pending = self._pending_paid.get(f"POST /v1/disputes {key}")
                if (
                    pending is not None
                    and self._now_ms() - pending["at"] < _PENDING_PAID_TTL_MS
                    and isinstance(pending.get("mandate"), Mapping)
                    and pending.get("mandateFingerprint") == fp
                ):
                    pending_mandate = dict(pending["mandate"])
        resolved_mandate = (
            pending_mandate
            if pending_mandate is not None
            else self._resolve_mandate(
                mandate=mandate,
                bounds=bounds,
                determination_consent=determination_consent,
                determination_bounds=determination_bounds,
                scope=scope,
                idempotency_key=f"file::{key}",
            )
        )
        body: Dict[str, Any] = {
            "respondentId": respondent_id,
            "contractHash": contract_hash,
            "claim": dict(claim),
            "mandate": resolved_mandate,
            "proposedIssues": [dict(i) for i in proposed_issues],
        }
        if disclose_gap_on_failure is not None:
            body["discloseGapOnFailure"] = disclose_gap_on_failure
        if config is not None:
            body["config"] = dict(config)
        if webhook_url is not None:
            body["webhookUrl"] = webhook_url
        if respondent_contact is not None:
            body["respondentContact"] = dict(respondent_contact)
        if clause is not None:
            body["clause"] = dict(clause)
        if require_delivery is not None:
            body["requireDelivery"] = bool(require_delivery)
        if invite_id is not None:
            body["inviteId"] = invite_id
        res = self._post(
            self._view_path("/v1/disputes"),
            body,
            idempotency_key=key,
            paid_operation="file",
            mandate_meta={"mandate": resolved_mandate, "fingerprint": fp} if fp is not None else None,
        )
        notice = res.get("notice") if isinstance(res, Mapping) else None
        if notice is not None:
            if not isinstance(notice, Mapping) or notice.get("signedNotice") is None:
                raise AgentMediateError(0, "NOTICE_MISMATCH", "filing response included notice metadata without signedNotice")
            self._verify_filing_notice(
                notice.get("signedNotice"),
                dispute_id=str(res.get("disputeId") or ""),
                respondent_id=respondent_id,
                contract_hash=contract_hash,
                notice_url=notice.get("noticeUrl") if "noticeUrl" in notice else None,
            )
        return res

    def list_disputes(
        self,
        *,
        status: Optional[str] = None,
        role: Optional[str] = None,
        limit: Optional[int] = None,
        cursor: Optional[str] = None,
    ) -> Dict[str, Any]:
        params: Dict[str, str] = {}
        if status is not None:
            params["status"] = status
        if role is not None:
            params["role"] = role
        if limit is not None:
            params["limit"] = str(limit)
        if cursor is not None:
            params["cursor"] = cursor
        qs = urllib.parse.urlencode(params)
        return self._get(f"/v1/disputes?{qs}" if qs else "/v1/disputes")

    def get_dispute(self, dispute_id: str, *, view: Optional[str] = None) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._get(self._view_path(f"/v1/disputes/{enc}", view=view))

    def events(self, dispute_id: str, *, after: int = 0) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._get(f"/v1/disputes/{enc}/events?after={after}")

    def audit(
        self,
        dispute_id: str,
        *,
        require_checkpoint: bool = False,
        require_anchor: bool = False,
        expected_outcome: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        res = self._get(f"/v1/disputes/{enc}/audit")
        entries = res.get("entries")
        if not isinstance(entries, list):
            raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit response entries must be a list")
        verified = verify_public_audit_chain(entries)
        if not verified.get("ok"):
            raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", f"audit chain broken at seq {verified.get('atSeq')}: {verified.get('reason')}")
        if verified.get("head") != res.get("head"):
            raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit chain does not end at the reported head")
        cp = res.get("checkpoint")
        if (require_checkpoint or require_anchor) and cp is None:
            raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit response does not include a required transparency checkpoint")
        if require_anchor and (not isinstance(cp, Mapping) or cp.get("anchor") is None):
            raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit transparency checkpoint does not include a required Base L2 anchor")
        if cp is not None:
            self._verify_checkpoint_envelope(cp, "INVALID_AUDIT_CHAIN")
            leaf = cp.get("leaf")
            inc = cp.get("inclusionProof")
            cp_doc = cp["signedCheckpoint"]["document"]
            merkle_root = str(cp_doc["merkleRoot"])
            if not isinstance(leaf, Mapping) or not isinstance(inc, Mapping):
                raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit checkpoint Merkle inclusion proof failed verification")
            # Checkpoints are daily: the checkpointed head may be older than `head`, but it must be a point of this
            # same verified chain (a forked head is rejected).
            at_checkpoint = next((e for e in entries if isinstance(e, Mapping) and e.get("seq") == leaf.get("auditSeq")), None)
            if (
                leaf.get("disputeId") != dispute_id
                or at_checkpoint is None
                or at_checkpoint.get("hash") != leaf.get("auditHead")
                or not verify_checkpoint_inclusion(leaf, inc, merkle_root, expected_total_leaves=cp_doc["disputeCount"])
            ):
                raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit checkpoint Merkle inclusion proof failed verification")
        if expected_outcome is not None:
            out_doc = expected_outcome.get("document") if isinstance(expected_outcome, Mapping) else None
            if (
                not isinstance(out_doc, Mapping)
                or out_doc.get("disputeId") != dispute_id
                or not isinstance(out_doc.get("auditRoot"), str)
                or not isinstance(out_doc.get("outcomeHash"), str)
            ):
                raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "expected_outcome does not match disputeId or lacks auditRoot/outcomeHash")
            expected_status = (
                out_doc.get("executionStatus")
                if out_doc.get("type") == "agent-mediate/settlement-instruction/v1"
                else ("UNRESOLVED" if out_doc.get("type") == "agent-mediate/unresolved-certificate/v1" else None)
            )
            if not isinstance(expected_status, str):
                raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", f"expected_outcome carries unsupported type {out_doc.get('type')}")
            out_entry = next((e for e in entries if e.get("hash") == out_doc.get("auditRoot")), None)
            if out_entry is None:
                raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "expected_outcome auditRoot is not present in the verified audit chain")
            if cp is not None:
                leaf = cp["leaf"]
                is_terminal = expected_status in ("HONORED", "BREACH_REPORTED", "UNRESOLVED")
                if leaf["auditSeq"] > out_entry["seq"] and is_terminal:
                    raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "checkpoint leaf advances beyond a terminal signed outcome")
                if leaf["auditSeq"] == out_entry["seq"] and (
                    leaf["outcomeHash"] != out_doc["outcomeHash"] or leaf["status"] != expected_status
                ):
                    raise AgentMediateError(0, "INVALID_AUDIT_CHAIN", "checkpoint leaf outcomeHash/status disagrees with expected_outcome")
        out: Dict[str, Any] = {"head": res["head"], "entries": res["entries"], "redacted": verified["redacted"]}
        if cp is not None:
            out["checkpoint"] = cp
        return out

    def signatures(
        self,
        dispute_id: str,
        *,
        strict: bool = True,
        expected_parties: Optional[Mapping[str, str]] = None,
    ) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        res = self._get(f"/v1/disputes/{enc}/signatures")
        raw_sigs = res.get("signatures") if isinstance(res, Mapping) else None
        if not isinstance(res, Mapping) or res.get("disputeId") != dispute_id or not isinstance(raw_sigs, list):
            raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"signatures response disputeId {(res or {}).get('disputeId') if isinstance(res, Mapping) else None} does not match requested {dispute_id}")
        party_agents: Dict[str, str] = {}
        seen_file_dispute = False
        checked: List[Dict[str, Any]] = []

        for entry in raw_sigs:
            if not isinstance(entry, Mapping):
                raise AgentMediateError(0, "INVALID_REQUEST_PROOF", "malformed signature entry")
            party = entry.get("party")
            agent_id = entry.get("agentId")
            action = entry.get("action")
            seq_range = entry.get("seqRange")
            if entry.get("redacted") is True and action == "confidential_action":
                proof_hash = entry.get("proofHash")
                valid_confidential_seq_range = seq_range is None or (
                    isinstance(seq_range, list)
                    and len(seq_range) == 2
                    and all(isinstance(x, int) and not isinstance(x, bool) and 0 < x <= _MAX_SAFE_INT for x in seq_range)
                    and seq_range[0] > 1
                    and seq_range[1] >= seq_range[0]
                )
                if (
                    party is not None
                    or agent_id is not None
                    or not seen_file_dispute
                    or not valid_confidential_seq_range
                    or not isinstance(proof_hash, str)
                    or not _SHA256_HEX_RE.fullmatch(proof_hash)
                ):
                    raise AgentMediateError(
                        0,
                        "INVALID_REQUEST_PROOF",
                        f"signature #{entry.get('id')} (confidential_action) has invalid redacted metadata",
                    )
                checked.append(dict(entry))
                continue

            if party not in ("claimant", "respondent") or not is_did_key(agent_id) or not isinstance(action, str):
                raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"signature #{entry.get('id')} has invalid party, agentId, or action")
            if action == "file_dispute":
                if party != "claimant" or seen_file_dispute or not isinstance(seq_range, list) or len(seq_range) != 2 or seq_range[0] != 1:
                    raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"signature #{entry.get('id')} (file_dispute) has invalid party or sequence binding")
                seen_file_dispute = True
            elif action == "join_dispute" and party != "respondent":
                raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"signature #{entry.get('id')} (join_dispute) must belong to respondent")

            if party in party_agents and party_agents[party] != agent_id:
                raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"party {party} changed agentId across signatures")
            party_agents[party] = agent_id
            if "claimant" in party_agents and "respondent" in party_agents and party_agents["claimant"] == party_agents["respondent"]:
                raise AgentMediateError(0, "INVALID_REQUEST_PROOF", "claimant and respondent cannot share the same agentId")
            if expected_parties is not None and expected_parties.get(party) is not None and agent_id != expected_parties.get(party):
                raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"party {party} agentId {agent_id} does not match expected {expected_parties.get(party)}")
            if agent_id == self.did and entry.get("redacted") is True:
                raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"own signature #{entry.get('id')} must not be redacted")

            item = dict(entry)
            if not entry.get("redacted"):
                try:
                    verdict = verify_request_proof(
                        entry.get("proof") or {},
                        expected_agent_id=agent_id,
                        expected_proof_hash=entry.get("proofHash"),
                        expected_base_url=self.base_url,
                        expected_dispute_id=dispute_id,
                        expected_action=action,
                    )
                except Exception as exc:
                    verdict = {"ok": False, "reason": f"malformed proof: {exc}"}
                ok = bool(verdict.get("ok"))
                if not ok and strict:
                    raise AgentMediateError(
                        0,
                        "INVALID_REQUEST_PROOF",
                        f"signature #{entry.get('id')} ({action}) failed verification: {verdict.get('reason')}",
                    )
                item["verified"] = ok
                if not ok:
                    item["verifyReason"] = verdict.get("reason")
            else:
                proof_hash = entry.get("proofHash")
                if action != "file_dispute" or not isinstance(proof_hash, str) or not _SHA256_HEX_RE.fullmatch(proof_hash):
                    raise AgentMediateError(
                        0,
                        "INVALID_REQUEST_PROOF",
                        f"signature #{entry.get('id')} ({action}) has an invalid redacted entry or non-confidential action",
                    )
            checked.append(item)

        if len(raw_sigs) > 0 and not seen_file_dispute:
            raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"signatures for {dispute_id} are missing the claimant file_dispute entry")
        if (
            ("claimant" in party_agents and "respondent" in party_agents and self.did not in (party_agents["claimant"], party_agents["respondent"]))
            or (
                "claimant" in party_agents
                and self.did != party_agents["claimant"]
                and "respondent" not in party_agents
                and any(s.get("action") == "confidential_action" for s in checked)
            )
        ):
            raise AgentMediateError(0, "INVALID_REQUEST_PROOF", f"signatures for {dispute_id} do not name this agent ({self.did}) as a party")
        if expected_parties is not None and (
            (expected_parties.get("claimant") is not None and "claimant" not in party_agents)
            or (expected_parties.get("respondent") is not None and "respondent" not in party_agents)
        ):
            compact_view = self.get_dispute(dispute_id, view="compact")["view"]
            actual_parties = (
                {"claimant": self.did, "respondent": str(compact_view["counterpartId"])}
                if compact_view.get("you") == "claimant"
                else {"claimant": str(compact_view["counterpartId"]), "respondent": self.did}
            )
            for p_name in ("claimant", "respondent"):
                if expected_parties.get(p_name) is not None and actual_parties[p_name] != expected_parties.get(p_name):
                    raise AgentMediateError(
                        0,
                        "INVALID_REQUEST_PROOF",
                        f"party {p_name} agentId {actual_parties[p_name]} does not match expected {expected_parties.get(p_name)}",
                    )
        return {"disputeId": dispute_id, "signatures": checked}

    def join(
        self,
        dispute_id: str,
        *,
        mandate: Optional[Mapping[str, Any]] = None,
        bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        determination_consent: Optional[bool] = None,
        determination_bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        disclose_gap_on_failure: Optional[bool] = None,
        webhook_url: Optional[str] = None,
        windows: Optional[Mapping[str, int]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        _assert_not_bare_mandate_bounds(bounds)
        key = idempotency_key or f"pysdk-{uuid.uuid4()}"
        scope = self._scope_of(dispute_id, idempotency_key=f"join:{key}") if (bounds is not None and mandate is None) else None
        resolved_mandate = self._resolve_mandate(
            mandate=mandate,
            bounds=bounds,
            determination_consent=determination_consent,
            determination_bounds=determination_bounds,
            scope=scope,
            idempotency_key=f"join:{dispute_id}:{key}",
        )
        body: Dict[str, Any] = {"mandate": resolved_mandate}
        if disclose_gap_on_failure is not None:
            body["discloseGapOnFailure"] = disclose_gap_on_failure
        if webhook_url is not None:
            body["webhookUrl"] = webhook_url
        if windows is not None:
            body["windows"] = dict(windows)
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/join"), body, idempotency_key=key)

    def submit_evidence(
        self,
        dispute_id: str,
        items: Sequence[Mapping[str, Any]],
        *,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        payload: List[Dict[str, Any]] = []
        for raw_item in items:
            item = dict(raw_item)
            content = item.pop("content", None)
            sha = item.get("sha256")
            if not sha and content is None:
                raise ValueError(f"evidence {item.get('id')}: provide sha256 or content")
            item["sha256"] = sha or content_hash(content)
            payload.append(item)
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/evidence"), {"items": payload}, idempotency_key=idempotency_key)

    def close_evidence(self, dispute_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/evidence/close"), {}, idempotency_key=idempotency_key)

    def confirm_issues(
        self,
        dispute_id: str,
        issues_hash: str,
        *,
        mandate: Optional[Mapping[str, Any]] = None,
        bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        determination_consent: Optional[bool] = None,
        determination_bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        key = idempotency_key or f"pysdk-{uuid.uuid4()}"
        body: Dict[str, Any] = {"issuesHash": issues_hash}
        if mandate is not None or bounds is not None:
            _assert_not_bare_mandate_bounds(bounds)
            ctx = self._mandate_context_of(dispute_id, idempotency_key=f"confirm:{key}") if (bounds is not None and mandate is None) else None
            effective_consent, effective_det_bounds = _merge_prior_determination_bounds(
                bounds=bounds,
                determination_consent=determination_consent,
                determination_bounds=determination_bounds,
                ctx=ctx,
            )
            body["mandate"] = self._resolve_mandate(
                mandate=mandate,
                bounds=bounds,
                determination_consent=effective_consent,
                determination_bounds=effective_det_bounds,
                scope={"contractHash": ctx["contractHash"], "counterpartyId": ctx["counterpartyId"]} if ctx is not None else None,
                idempotency_key=f"confirm:{dispute_id}:{key}",
                min_issued_at=(int(ctx["prevIssuedAt"]) + 1) if (ctx is not None and ctx.get("prevIssuedAt") is not None) else None,
                min_expires_at=int(ctx["prevExpiresAt"]) if (ctx is not None and ctx.get("prevExpiresAt") is not None) else None,
            )
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/issues/confirm"), body, idempotency_key=key)

    def reject_issues(
        self,
        dispute_id: str,
        issues_hash: str,
        *,
        adopt_suggested_ids: Optional[Sequence[str]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        if not isinstance(issues_hash, str) or len(issues_hash) == 0:
            raise ValueError("reject_issues requires issues_hash")
        body: Dict[str, Any] = {"issuesHash": issues_hash}
        if adopt_suggested_ids is not None:
            body["adoptSuggestedIds"] = [str(s) for s in adopt_suggested_ids]
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/issues/reject"), body, idempotency_key=idempotency_key)

    def update_mandate(
        self,
        dispute_id: str,
        *,
        mandate: Optional[Mapping[str, Any]] = None,
        bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        determination_consent: Optional[bool] = None,
        determination_bounds: Optional[Mapping[str, Mapping[str, float]]] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Monotonically widen your principal-signed mandate during BARGAINING or DETERMINATION (v1.2.0/v1.3.0)."""
        _assert_not_bare_mandate_bounds(bounds)
        key = idempotency_key or f"pysdk-{uuid.uuid4()}"
        ctx = self._mandate_context_of(dispute_id, idempotency_key=f"update:{key}") if (bounds is not None and mandate is None) else None
        effective_consent, effective_det_bounds = _merge_prior_determination_bounds(
            bounds=bounds,
            determination_consent=determination_consent,
            determination_bounds=determination_bounds,
            ctx=ctx,
        )
        resolved = self._resolve_mandate(
            mandate=mandate,
            bounds=bounds,
            determination_consent=effective_consent,
            determination_bounds=effective_det_bounds,
            scope={"contractHash": ctx["contractHash"], "counterpartyId": ctx["counterpartyId"]} if ctx is not None else None,
            idempotency_key=f"update:{dispute_id}:{key}",
            min_issued_at=(int(ctx["prevIssuedAt"]) + 1) if (ctx is not None and ctx.get("prevIssuedAt") is not None) else None,
            min_expires_at=int(ctx["prevExpiresAt"]) if (ctx is not None and ctx.get("prevExpiresAt") is not None) else None,
        )
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/mandate"), {"mandate": resolved}, idempotency_key=key)

    def submit_offer(
        self,
        dispute_id: str,
        round_num: int,
        *,
        offer: Mapping[str, float],
        private: Optional[Mapping[str, Any]] = None,
        weights: Optional[Mapping[str, float]] = None,
        walkaway: Optional[Mapping[str, float]] = None,
        limits: Optional[Mapping[str, Mapping[str, float]]] = None,
        proposal_response: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        if private is not None and (weights is not None or walkaway is not None or limits is not None):
            raise ValueError("pass either private=... or weights/walkaway/limits, not both")
        if (weights is None) != (walkaway is None):
            raise ValueError("weights and walkaway must both be provided together on your first offer")
        if limits is not None and private is None and weights is None:
            raise ValueError("limits requires weights and walkaway (or private=...)")
        body: Dict[str, Any] = {"offer": dict(offer)}
        if private is not None or (weights is not None and walkaway is not None):
            priv_dict: Dict[str, Any] = dict(private) if private is not None else {
                "weights": dict(weights or {}),
                "walkaway": dict(walkaway or {}),
            }
            if limits is not None:
                priv_dict["limits"] = {k: dict(v) for k, v in limits.items()}
            body["private"] = priv_dict
        if proposal_response is not None:
            body["proposalResponse"] = proposal_response
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/rounds/{round_num}/offer"), body, idempotency_key=idempotency_key)

    def submit_final_offer(
        self,
        dispute_id: str,
        offer: Mapping[str, float],
        *,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(
            self._view_path(f"/v1/disputes/{enc}/determination/final-offer"),
            {"offer": dict(offer)},
            idempotency_key=idempotency_key,
        )

    def respond_improvement(
        self,
        dispute_id: str,
        response: str,
        *,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(
            self._view_path(f"/v1/disputes/{enc}/execution/improvement"),
            {"response": response},
            idempotency_key=idempotency_key,
        )

    def submit_execution_proof(
        self,
        dispute_id: str,
        reference: str,
        *,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(
            self._view_path(f"/v1/disputes/{enc}/execution/proof"),
            {"reference": reference},
            idempotency_key=idempotency_key,
        )

    def confirm_execution(self, dispute_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/execution/confirm"), {}, idempotency_key=idempotency_key)

    def contest_execution(
        self,
        dispute_id: str,
        reason: str,
        *,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(
            self._view_path(f"/v1/disputes/{enc}/execution/contest"),
            {"reason": reason},
            idempotency_key=idempotency_key,
        )

    def acknowledge_cure(
        self,
        dispute_id: str,
        *,
        reference: Optional[str] = None,
        note: Optional[str] = None,
        idempotency_key: Optional[str] = None,
    ) -> Dict[str, Any]:
        body: Dict[str, Any] = {}
        if reference is not None:
            body["reference"] = reference
        if note is not None:
            body["note"] = note
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(f"/v1/disputes/{enc}/cure", body, idempotency_key=idempotency_key)

    def withdraw(self, dispute_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        return self._post(self._view_path(f"/v1/disputes/{enc}/withdraw"), {}, idempotency_key=idempotency_key)

    def verify_notice(
        self,
        signed_notice: Mapping[str, Any],
        *,
        dispute_id: Optional[str] = None,
        claimant_id: Optional[str] = None,
        respondent_id: Optional[str] = None,
        contract_hash: Optional[str] = None,
        rules_version: Optional[str] = None,
        allow_third_party: bool = False,
    ) -> Dict[str, Any]:
        """Verify a platform-signed Notice of Dispute (`agent-mediate/dispute-notice/v1`) received via `/n/:token`, webhook, A2A card, or email (`PR-L10`, `CR3-SDK-L1`)."""
        doc = signed_notice.get("document") if isinstance(signed_notice, Mapping) else None
        if not isinstance(doc, Mapping) or doc.get("type") != "agent-mediate/dispute-notice/v1":
            raise AgentMediateError(
                0,
                "NOTICE_MISMATCH",
                f"unexpected notice document.type {(doc or {}).get('type') if isinstance(doc, Mapping) else None}",
            )
        if (
            not isinstance(doc.get("disputeId"), str)
            or len(doc["disputeId"]) == 0
            or not is_did_key(doc.get("claimantId"))
            or not is_did_key(doc.get("respondentId"))
            or not isinstance(doc.get("contractHash"), str)
            or not _SHA256_HEX_RE.fullmatch(doc["contractHash"])
        ):
            raise AgentMediateError(0, "NOTICE_MISMATCH", "dispute notice document fields are malformed")
        base_prefix = f"{self.base_url}/"
        for url_field in ("noticeUrl", "joinEndpoint", "disputeEndpoint", "llmsTxtUrl"):
            val = doc.get(url_field)
            if val is not None and (not isinstance(val, str) or not val.startswith(base_prefix)):
                raise AgentMediateError(0, "NOTICE_MISMATCH", f"notice {url_field} does not start with base_url {base_prefix}")
        if doc.get("rulesVersion") is not None and (not isinstance(doc.get("rulesVersion"), str) or len(doc["rulesVersion"]) == 0):
            raise AgentMediateError(0, "NOTICE_MISMATCH", "notice rulesVersion is malformed")
        if rules_version is not None and doc.get("rulesVersion") != rules_version:
            raise AgentMediateError(0, "NOTICE_MISMATCH", f"notice rulesVersion {doc.get('rulesVersion')} does not match expected {rules_version}")
        if dispute_id is not None and doc.get("disputeId") != dispute_id:
            raise AgentMediateError(0, "NOTICE_MISMATCH", f"notice disputeId {doc.get('disputeId')} does not match expected {dispute_id}")
        if claimant_id is not None and doc.get("claimantId") != claimant_id:
            raise AgentMediateError(0, "NOTICE_MISMATCH", f"notice claimantId {doc.get('claimantId')} does not match expected {claimant_id}")
        expected_respondent = respondent_id if respondent_id is not None else (None if allow_third_party else self.did)
        if expected_respondent is not None and doc.get("respondentId") != expected_respondent:
            raise AgentMediateError(0, "NOTICE_MISMATCH", f"notice respondentId {doc.get('respondentId')} does not match expected {expected_respondent}")
        if contract_hash is not None and doc.get("contractHash") != contract_hash:
            raise AgentMediateError(0, "NOTICE_MISMATCH", f"notice contractHash {doc.get('contractHash')} does not match expected {contract_hash}")
        if self._expected_environment is not None and doc.get("environment") != self._expected_environment:
            raise AgentMediateError(
                0,
                "NOTICE_MISMATCH",
                f"notice environment {doc.get('environment')} does not match expected {self._expected_environment}",
            )
        if not self._verify_platform_document(signed_notice):
            raise AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "dispute notice signature failed verification")
        return dict(doc)

    def verify_invite(
        self,
        signed_invite: Mapping[str, Any],
        *,
        invite_id: Optional[str] = None,
        claimant_id: Optional[str] = None,
        respondent_id: Optional[str] = None,
        contract_hash: Optional[str] = None,
        rules_version: Optional[str] = None,
        allow_third_party: bool = False,
    ) -> Dict[str, Any]:
        """Verify a platform-signed Pre-Filing Mediation Invite (`agent-mediate/dispute-invite/v1`) received via `/i/:token`, webhook, A2A card, or email (`CR3-SDK-L1`)."""
        doc = signed_invite.get("document") if isinstance(signed_invite, Mapping) else None
        if not isinstance(doc, Mapping) or doc.get("type") != DISPUTE_INVITE_TYPE:
            raise AgentMediateError(
                0,
                "INVITE_MISMATCH",
                f"unexpected invite document.type {(doc or {}).get('type') if isinstance(doc, Mapping) else None}",
            )
        resp_val = doc.get("respondentId")
        if (
            not isinstance(doc.get("inviteId"), str)
            or len(doc["inviteId"]) == 0
            or not is_did_key(doc.get("claimantId"))
            or (resp_val is not None and not is_did_key(resp_val))
            or not isinstance(doc.get("contractHash"), str)
            or not _SHA256_HEX_RE.fullmatch(doc["contractHash"])
            or not isinstance(doc.get("rulesVersion"), str)
            or len(doc["rulesVersion"]) == 0
        ):
            raise AgentMediateError(0, "INVITE_MISMATCH", "dispute invite document fields are malformed")
        base_prefix = f"{self.base_url}/"
        for url_field in ("inviteUrl", "acceptEndpoint", "inviteEndpoint"):
            val = doc.get(url_field)
            if not isinstance(val, str) or not val.startswith(base_prefix):
                raise AgentMediateError(0, "INVITE_MISMATCH", f"invite {url_field} does not start with base_url {base_prefix}")
        if doc.get("llmsTxtUrl") is not None and (
            not isinstance(doc.get("llmsTxtUrl"), str) or not str(doc["llmsTxtUrl"]).startswith(base_prefix)
        ):
            raise AgentMediateError(0, "INVITE_MISMATCH", f"invite llmsTxtUrl does not start with base_url {base_prefix}")
        if rules_version is not None and doc.get("rulesVersion") != rules_version:
            raise AgentMediateError(0, "INVITE_MISMATCH", f"invite rulesVersion {doc.get('rulesVersion')} does not match expected {rules_version}")
        if invite_id is not None and doc.get("inviteId") != invite_id:
            raise AgentMediateError(0, "INVITE_MISMATCH", f"invite inviteId {doc.get('inviteId')} does not match expected {invite_id}")
        if claimant_id is not None and doc.get("claimantId") != claimant_id:
            raise AgentMediateError(0, "INVITE_MISMATCH", f"invite claimantId {doc.get('claimantId')} does not match expected {claimant_id}")
        if respondent_id is not None:
            if resp_val != respondent_id:
                raise AgentMediateError(0, "INVITE_MISMATCH", f"invite respondentId {resp_val} does not match expected {respondent_id}")
        elif not allow_third_party and resp_val is not None and resp_val != self.did:
            raise AgentMediateError(0, "INVITE_MISMATCH", f"invite respondentId {resp_val} does not match this agent ({self.did})")
        if contract_hash is not None and doc.get("contractHash") != contract_hash:
            raise AgentMediateError(0, "INVITE_MISMATCH", f"invite contractHash {doc.get('contractHash')} does not match expected {contract_hash}")
        if self._expected_environment is not None and doc.get("environment") != self._expected_environment:
            raise AgentMediateError(
                0,
                "INVITE_MISMATCH",
                f"invite environment {doc.get('environment')} does not match expected {self._expected_environment}",
            )
        if not self._verify_platform_document(signed_invite):
            raise AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "dispute invite signature failed verification")
        return dict(doc)

    def _verify_filing_notice(
        self,
        signed_notice: Any,
        *,
        dispute_id: str,
        respondent_id: str,
        contract_hash: str,
        notice_url: Optional[Any] = None,
    ) -> None:
        doc = signed_notice.get("document") if isinstance(signed_notice, Mapping) else None
        if not isinstance(doc, Mapping) or doc.get("type") != "agent-mediate/dispute-notice/v1":
            raise AgentMediateError(
                0,
                "NOTICE_MISMATCH",
                f"unexpected notice document.type {(doc or {}).get('type') if isinstance(doc, Mapping) else None}",
            )
        if (
            doc.get("disputeId") != dispute_id
            or doc.get("claimantId") != self.did
            or doc.get("respondentId") != respondent_id
            or doc.get("contractHash") != contract_hash
        ):
            raise AgentMediateError(0, "NOTICE_MISMATCH", "filing notice document fields do not match the filed dispute")
        if (notice_url is not None or doc.get("noticeUrl") is not None) and doc.get("noticeUrl") != notice_url:
            raise AgentMediateError(0, "NOTICE_MISMATCH", "filing noticeUrl does not match signedNotice.document.noticeUrl")
        base_prefix = f"{self.base_url}/"
        for url_field in ("noticeUrl", "joinEndpoint", "disputeEndpoint", "llmsTxtUrl"):
            val = doc.get(url_field)
            if val is not None and (not isinstance(val, str) or not val.startswith(base_prefix)):
                raise AgentMediateError(0, "NOTICE_MISMATCH", f"filing notice {url_field} does not start with base_url {base_prefix}")
        if self._expected_environment is not None and doc.get("environment") != self._expected_environment:
            raise AgentMediateError(
                0,
                "NOTICE_MISMATCH",
                f"filing notice environment {doc.get('environment')} does not match expected {self._expected_environment}",
            )
        if not self._verify_platform_document(signed_notice):
            raise AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "filing notice signature failed verification")

    def outcome(self, dispute_id: str) -> Dict[str, Any]:
        enc = urllib.parse.quote(dispute_id, safe="")
        doc = self._get(f"/v1/disputes/{enc}/outcome")
        if not self._verify_platform_document(doc):
            raise AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "outcome signature does not verify against the platform did")
        payload = doc.get("document") or {}
        doc_type = payload.get("type")
        if doc_type not in ("agent-mediate/settlement-instruction/v1", "agent-mediate/unresolved-certificate/v1"):
            raise AgentMediateError(0, "OUTCOME_MISMATCH", f"unexpected outcome document.type {doc_type}")
        if payload.get("disputeId") != dispute_id:
            raise AgentMediateError(0, "OUTCOME_MISMATCH", f"outcome disputeId {payload.get('disputeId')} does not match requested {dispute_id}")
        if self._expected_environment is not None and payload.get("environment") != self._expected_environment:
            raise AgentMediateError(
                0,
                "OUTCOME_MISMATCH",
                f"outcome environment {payload.get('environment')} does not match expected {self._expected_environment}",
            )
        if self._expected_rules_hash is not None and payload.get("rulesHash") != self._expected_rules_hash:
            raise AgentMediateError(
                0,
                "OUTCOME_MISMATCH",
                f"outcome rulesHash {payload.get('rulesHash')} does not match expected {self._expected_rules_hash}",
            )
        parties = payload.get("parties") or {}
        claimant_agent = (parties.get("claimant") or {}).get("agentId")
        respondent_agent = (parties.get("respondent") or {}).get("agentId")
        if self.did not in (claimant_agent, respondent_agent):
            raise AgentMediateError(0, "OUTCOME_MISMATCH", f"outcome for {dispute_id} does not name this agent ({self.did}) as a party")
        outcome_hash = payload.get("outcomeHash")
        audit_root = payload.get("auditRoot")
        if not isinstance(outcome_hash, str) or not _SHA256_HEX_RE.fullmatch(outcome_hash):
            raise AgentMediateError(0, "OUTCOME_MISMATCH", "outcome document is missing a valid 64-hex outcomeHash")
        if not isinstance(audit_root, str) or not _SHA256_HEX_RE.fullmatch(audit_root):
            raise AgentMediateError(0, "OUTCOME_MISMATCH", "outcome document is missing a valid 64-hex auditRoot")
        if doc_type == "agent-mediate/settlement-instruction/v1":
            terms = payload.get("terms")
            method = payload.get("method")
            settled_at = payload.get("settledAt")
            rounds_completed = payload.get("roundsCompleted")
            exec_status = payload.get("executionStatus")
            if (
                payload.get("status") != "SETTLED"
                or exec_status not in ("EXECUTION_PENDING", "HONORED", "BREACH_REPORTED")
                or not isinstance(method, str)
                or method not in _SETTLEMENT_METHODS
                or not isinstance(settled_at, int)
                or isinstance(settled_at, bool)
                or abs(settled_at) > _MAX_SAFE_INT
                or not isinstance(rounds_completed, int)
                or isinstance(rounds_completed, bool)
                or rounds_completed < 0
                or rounds_completed > _MAX_SAFE_INT
                or not isinstance(terms, Mapping)
                or isinstance(terms, (list, tuple))
                or compute_terms_hash(terms) != payload.get("termsHash")
                or compute_outcome_hash(
                    {
                        "kind": "SETTLED",
                        "method": method,
                        "terms": terms,
                        "at": settled_at,
                        "roundsCompleted": rounds_completed,
                    },
                    exec_status,
                )
                != outcome_hash
            ):
                raise AgentMediateError(0, "OUTCOME_MISMATCH", "settlement instruction outcomeHash, termsHash, or status is inconsistent")
        else:
            issued_at = payload.get("issuedAt")
            rounds_completed = payload.get("roundsCompleted")
            if (
                payload.get("status") != "UNRESOLVED"
                or not isinstance(payload.get("reason"), str)
                or not isinstance(issued_at, int)
                or isinstance(issued_at, bool)
                or abs(issued_at) > _MAX_SAFE_INT
                or not isinstance(rounds_completed, int)
                or isinstance(rounds_completed, bool)
                or rounds_completed < 0
                or rounds_completed > _MAX_SAFE_INT
                or compute_outcome_hash(
                    {
                        "kind": "UNRESOLVED",
                        "reason": payload.get("reason"),
                        "at": issued_at,
                        "roundsCompleted": rounds_completed,
                    },
                    "UNRESOLVED",
                )
                != outcome_hash
            ):
                raise AgentMediateError(0, "OUTCOME_MISMATCH", "unresolved certificate outcomeHash or status is inconsistent")
        return doc

    def wait_for(
        self,
        dispute_id: str,
        predicate: Callable[[Mapping[str, Any]], bool],
        *,
        timeout_ms: int = 60_000,
        interval_ms: int = 1000,
        view: Optional[str] = None,
    ) -> Dict[str, Any]:
        deadline = self._now_ms() + timeout_ms
        while True:
            res = self.get_dispute(dispute_id, view=view)
            if predicate(res["view"]) or self._now_ms() >= deadline:
                return res
            time.sleep(interval_ms / 1000.0)

    def wait_for_turn(
        self,
        dispute_id: str,
        *,
        timeout_ms: int = 60_000,
        interval_ms: int = 1000,
        view: Optional[str] = None,
    ) -> Dict[str, Any]:
        """Poll until it is your turn to act (`view['nextActions'][0] != 'wait_for_change'`) or the timeout passes."""
        return self.wait_for(
            dispute_id,
            lambda v: bool(v.get("nextActions")) and v["nextActions"][0] != "wait_for_change",
            timeout_ms=timeout_ms,
            interval_ms=interval_ms,
            view=view,
        )

    @staticmethod
    def verify_webhook(
        *,
        url: str,
        headers: Mapping[str, str],
        body: str,
        platform_did: str,
        now_ms: Optional[int] = None,
        agent_id: Optional[str] = None,
        allow_unbound_invite: bool = False,
        dispute_id: Optional[str] = None,
        invite_id: Optional[str] = None,
        key_history: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        resolved_now_ms = now_ms if now_ms is not None else int(time.time() * 1000)
        verified = verify_request(
            method="POST",
            target_uri=url,
            headers=headers,
            body=body,
            now_ms=resolved_now_ms,
            expect_tag=WEBHOOK_SIGNATURE_TAG,
        )
        if not verified.get("ok"):
            return {"ok": False, "reason": verified.get("reason")}
        if verified.get("keyid") != platform_did:
            if key_history is None:
                return {"ok": False, "reason": "signed by an unexpected key"}
            kh = verify_key_history(
                key_history,
                expected_active_did=platform_did,
                now_ms=resolved_now_ms,
                max_age_ms=DEFAULT_KEY_HISTORY_TTL_MS,
            )
            if not kh.get("ok"):
                return {"ok": False, "reason": f"key_history invalid: {kh.get('reason')}"}
            hist_doc = (key_history.get("document") or {}) if isinstance(key_history, Mapping) else {}
            keys = hist_doc.get("keys")
            hist = next((k for k in (keys or []) if isinstance(k, Mapping) and k.get("did") == verified.get("keyid")), None)
            allowed_status = (
                hist is not None
                and (
                    hist.get("status") == "retired"
                    or (hist.get("status") == "active" and verified.get("keyid") == hist_doc.get("activeDid"))
                )
            )
            created_sec = int(verified["created"])
            if (
                hist is None
                or not allowed_status
                or hist.get("compromisedAfter") is not None
                or hist.get("revokedAt") is not None
                or (int(hist["validFrom"]) // 1000) > created_sec
                or (hist.get("validUntil") is not None and created_sec > (int(hist["validUntil"]) // 1000))
            ):
                return {"ok": False, "reason": "signed by an unexpected key"}
        try:
            event = loads_jcs_json(body)
        except Exception:
            return {"ok": False, "reason": "body is not JSON"}
        if not isinstance(event, Mapping):
            return {"ok": False, "reason": "body is not a JSON object"}
        if dispute_id is not None and event.get("disputeId") != dispute_id:
            return {"ok": False, "reason": "event is for another dispute"}
        if invite_id is not None and event.get("inviteId") != invite_id:
            return {"ok": False, "reason": "event is for another invite"}
        recipient = event.get("recipient")
        recipient_agent = recipient.get("agentId") if isinstance(recipient, Mapping) else None
        if agent_id is not None and recipient_agent != agent_id:
            is_unbound_invite = (
                allow_unbound_invite is True
                and event.get("type") == "DISPUTE_INVITE"
                and recipient_agent is None
            )
            if not is_unbound_invite:
                return {"ok": False, "reason": "event is addressed to another agent"}
        return {"ok": True, "event": event, "nonce": verified["nonce"], "created": verified["created"]}

    # --- Internal transport ---------------------------------------------------

    def _backoff(self, attempt: int, res: Optional[HttpResponse] = None) -> bool:
        if attempt >= self._max_retries:
            return False
        wait_sec = _parse_retry_after_seconds(res.headers.get("retry-after"), self._now_ms()) if res is not None else 0.0
        time.sleep(wait_sec if wait_sec > 0 else 0.25 * (2**attempt))
        return True

    def _get_public(
        self,
        path: str,
        *,
        error_code: str = "HTTP_ERROR",
        error_detail: Optional[str] = None,
    ) -> Dict[str, Any]:
        attempt = 0
        while True:
            try:
                res = self._transport("GET", f"{self.base_url}{path}", {}, None)
            except AgentMediateError:
                raise
            except Exception as err:
                if self._backoff(attempt):
                    attempt += 1
                    continue
                raise AgentMediateError(0, "NETWORK_ERROR", str(err)) from err

            if 300 <= res.status < 400:
                raise AgentMediateError(res.status, "UNEXPECTED_REDIRECT", f"refusing HTTP {res.status} redirect from {path}")

            if (res.status == 429 or res.status >= 500) and self._backoff(attempt, res):
                attempt += 1
                continue

            if len(res.body.encode("utf-8")) > _MAX_RESPONSE_BYTES:
                raise AgentMediateError(res.status, "RESPONSE_TOO_LARGE", f"response body exceeds {_MAX_RESPONSE_BYTES} bytes")

            try:
                parsed_any: Any = loads_jcs_json(res.body) if res.body else {}
            except Exception:
                parsed_any = None

            if res.status < 200 or res.status >= 300:
                parsed_err = parsed_any if isinstance(parsed_any, Mapping) else {}
                code = (
                    str(parsed_err["code"])
                    if error_code == "HTTP_ERROR" and isinstance(parsed_err.get("code"), str)
                    else error_code
                )
                detail = (
                    str(parsed_err["detail"])
                    if isinstance(parsed_err.get("detail"), str)
                    else (error_detail or f"could not read {path}")
                )
                raise AgentMediateError(res.status, code, detail, parsed_any)
            if not isinstance(parsed_any, dict):
                raise AgentMediateError(res.status, error_code, error_detail or f"expected JSON object from {path}", parsed_any)
            return parsed_any

    def _mandate_fingerprint(
        self,
        *,
        bounds: Optional[Mapping[str, Mapping[str, float]]],
        determination_consent: Optional[bool],
        determination_bounds: Optional[Mapping[str, Mapping[str, float]]],
        scope: Optional[Mapping[str, str]],
    ) -> str:
        return canonical_json(
            {
                "baseUrl": self.base_url,
                "agentId": self.did,
                "bounds": {k: dict(v) for k, v in bounds.items()} if bounds is not None else None,
                "determinationConsent": determination_consent,
                "determinationBounds": {k: dict(v) for k, v in determination_bounds.items()} if determination_bounds is not None else None,
                "scope": dict(scope) if scope is not None else None,
            }
        )

    def _resolve_mandate(
        self,
        *,
        mandate: Optional[Mapping[str, Any]],
        bounds: Optional[Mapping[str, Mapping[str, float]]],
        determination_consent: Optional[bool],
        determination_bounds: Optional[Mapping[str, Mapping[str, float]]],
        scope: Optional[Mapping[str, str]],
        idempotency_key: Optional[str] = None,
        min_issued_at: Optional[int] = None,
        min_expires_at: Optional[int] = None,
    ) -> Dict[str, Any]:
        if mandate is not None:
            if determination_consent is not None and bool(mandate.get("determinationConsent") is True) != determination_consent:
                raise ValueError("determination_consent must be signed inside mandate.determinationConsent when providing a pre-signed mandate")
            if determination_bounds is not None:
                raise ValueError("determination_bounds must be signed inside mandate.determinationBounds when providing a pre-signed mandate")
            return dict(mandate)
        if bounds is not None:
            if isinstance(bounds, Mapping) and ("signature" in bounds or "principalId" in bounds):
                raise ValueError("pass mandate=..., not a bare Mandate dict as bounds")
            now = self._now_ms()
            fingerprint = self._mandate_fingerprint(
                bounds=bounds,
                determination_consent=determination_consent,
                determination_bounds=determination_bounds,
                scope=scope,
            )
            if idempotency_key:
                with self._pending_lock:
                    cached = self._mandate_cache.get(idempotency_key)
                    if (
                        cached is not None
                        and cached["fingerprint"] == fingerprint
                        and now - cached["at"] < _PENDING_PAID_TTL_MS
                        and int(cached["mandate"]["expiresAt"]) > now + 60_000
                        and (min_issued_at is None or int(cached["mandate"]["issuedAt"]) >= int(min_issued_at))
                        and (min_expires_at is None or int(cached["mandate"]["expiresAt"]) >= int(min_expires_at))
                    ):
                        return dict(cached["mandate"])
            created = self.mandate(
                bounds,
                scope=scope,
                determination_consent=determination_consent,
                determination_bounds=determination_bounds,
                min_issued_at=min_issued_at,
                min_expires_at=min_expires_at,
            )
            if idempotency_key:
                with self._pending_lock:
                    if idempotency_key not in self._mandate_cache and len(self._mandate_cache) >= _PENDING_PAID_MAX:
                        self._mandate_cache.pop(next(iter(self._mandate_cache)), None)
                    self._mandate_cache[idempotency_key] = {"fingerprint": fingerprint, "mandate": created, "at": now}
            return created
        raise ValueError("provide mandate or bounds")

    def _mandate_context_of(self, dispute_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        cache_key = f"{dispute_id}:{idempotency_key}" if idempotency_key else None
        if cache_key is not None:
            with self._pending_lock:
                cached = self._scope_cache.get(cache_key)
                if cached is not None and self._now_ms() - cached["at"] < _PENDING_PAID_TTL_MS:
                    return {k: v for k, v in cached.items() if k != "at"}
        view = self.get_dispute(dispute_id, view="compact")["view"]
        ym = view.get("yourMandate")
        ctx: Dict[str, Any] = {
            "contractHash": str(view["contractHash"]),
            "counterpartyId": str(view["counterpartId"]),
        }
        if isinstance(ym, Mapping):
            if isinstance(ym.get("issuedAt"), int) and not isinstance(ym.get("issuedAt"), bool):
                ctx["prevIssuedAt"] = int(ym["issuedAt"])
            if isinstance(ym.get("expiresAt"), int) and not isinstance(ym.get("expiresAt"), bool):
                ctx["prevExpiresAt"] = int(ym["expiresAt"])
            if isinstance(ym.get("determinationConsent"), bool):
                ctx["prevDeterminationConsent"] = bool(ym["determinationConsent"])
            if isinstance(ym.get("bounds"), Mapping):
                ctx["prevBounds"] = {str(k): dict(v) for k, v in ym["bounds"].items() if isinstance(v, Mapping)}
            if isinstance(ym.get("determinationBounds"), Mapping):
                ctx["prevDeterminationBounds"] = {str(k): dict(v) for k, v in ym["determinationBounds"].items() if isinstance(v, Mapping)}
        if cache_key is not None:
            with self._pending_lock:
                if cache_key not in self._scope_cache and len(self._scope_cache) >= _PENDING_PAID_MAX:
                    self._scope_cache.pop(next(iter(self._scope_cache)), None)
                self._scope_cache[cache_key] = {**ctx, "at": self._now_ms()}
        return ctx

    def _scope_of(self, dispute_id: str, *, idempotency_key: Optional[str] = None) -> Dict[str, str]:
        ctx = self._mandate_context_of(dispute_id, idempotency_key=idempotency_key)
        return {"contractHash": str(ctx["contractHash"]), "counterpartyId": str(ctx["counterpartyId"])}

    def _verified_platform_pay_to(self, info: Mapping[str, Any]) -> Optional[str]:
        fees = info.get("fees") if isinstance(info.get("fees"), Mapping) else None
        raw_pay_to = fees.get("payTo") if isinstance(fees, Mapping) and isinstance(fees.get("payTo"), str) else None
        if not raw_pay_to:
            return None
        with self._pending_lock:
            cached_pay_to = self._verified_pay_to
            verified_active = self._verified_active_platform_did
        if cached_pay_to is not None and cached_pay_to.lower() == raw_pay_to.lower():
            return cached_pay_to
        expected_did = verified_active or self._pinned_platform_did or str(info.get("did") or "")
        try:
            card = self._get_public("/.well-known/agent-card.json", error_detail="could not read /.well-known/agent-card.json")
        except AgentMediateError as err:
            raise PaymentPolicyError(f"could not verify /.well-known/agent-card.json for payTo: {err}") from err
        sig_ok = verify_agent_card_signature(card, expected_did)
        if not sig_ok and self._pinned_platform_did:
            try:
                hist = self.key_history(force=True)
                hist_active = ((hist.get("document") or {}).get("activeDid")) if isinstance(hist, Mapping) else None
                if isinstance(hist_active, str) and hist_active != expected_did:
                    expected_did = hist_active
                    sig_ok = verify_agent_card_signature(card, expected_did)
            except Exception:
                sig_ok = False
        if not sig_ok:
            raise PaymentPolicyError("/.well-known/agent-card.json failed platform signature verification")
        norm_base = self.base_url.rstrip("/")

        def _check_origin(candidate: Any, label: str) -> None:
            if isinstance(candidate, str) and candidate.rstrip("/") != norm_base:
                raise PaymentPolicyError(
                    f"/.well-known/agent-card.json {label} ({candidate}) does not match base_url ({norm_base})"
                )

        _check_origin(card.get("url") if isinstance(card, Mapping) else None, "url")
        provider = card.get("provider") if isinstance(card, Mapping) else None
        _check_origin(provider.get("url") if isinstance(provider, Mapping) else None, "provider.url")
        caps = card.get("capabilities") if isinstance(card, Mapping) else None
        exts = caps.get("extensions") if isinstance(caps, Mapping) and isinstance(caps.get("extensions"), list) else []
        rest_ext = next((ext for ext in exts if isinstance(ext, Mapping) and ext.get("uri") == "urn:agent-mediate:ext:rest-api:v1"), None)
        rest_params = rest_ext.get("params") if isinstance(rest_ext, Mapping) and isinstance(rest_ext.get("params"), Mapping) else None
        _check_origin(rest_params.get("baseUrl") if isinstance(rest_params, Mapping) else None, "rest-api baseUrl")
        try:
            expected_did_web: Optional[str] = did_web_from_url(norm_base)
        except Exception:
            expected_did_web = None
        sigs = card.get("signatures") if isinstance(card, Mapping) else None
        if expected_did_web is not None and isinstance(sigs, list):
            for sig_entry in sigs:
                prot = sig_entry.get("protected") if isinstance(sig_entry, Mapping) else None
                if not isinstance(prot, str):
                    continue
                try:
                    pad = "=" * ((4 - (len(prot) % 4)) % 4)
                    hdr = loads_jcs_json(base64.urlsafe_b64decode(prot + pad).decode("utf-8"))
                    kid = hdr.get("kid") if isinstance(hdr, Mapping) else None
                    if isinstance(kid, str) and kid.startswith("did:web:") and kid.split("#", 1)[0] != expected_did_web:
                        raise PaymentPolicyError(
                            f"/.well-known/agent-card.json JWS kid ({kid}) does not match expected {expected_did_web}"
                        )
                except PaymentPolicyError:
                    raise
                except Exception:
                    pass
        fee_ext = next((ext for ext in exts if isinstance(ext, Mapping) and ext.get("uri") == "urn:agent-mediate:ext:x402-fees:v1"), None)
        params = fee_ext.get("params") if isinstance(fee_ext, Mapping) and isinstance(fee_ext.get("params"), Mapping) else None
        signed_pay_to = params.get("payTo") if isinstance(params, Mapping) and isinstance(params.get("payTo"), str) else None
        if not signed_pay_to or signed_pay_to.lower() != raw_pay_to.lower():
            raise PaymentPolicyError(
                f"/v1/platform fees.payTo ({raw_pay_to}) does not match signed /.well-known/agent-card.json payTo ({signed_pay_to})"
            )
        with self._pending_lock:
            self._verified_pay_to = signed_pay_to
        return signed_pay_to

    def _get(self, path: str) -> Dict[str, Any]:
        return self._request("GET", path)

    def _post(
        self,
        path: str,
        body: Mapping[str, Any],
        *,
        idempotency_key: Optional[str] = None,
        paid_operation: Optional[str] = None,
        mandate_meta: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        return self._request(
            "POST",
            path,
            body=body,
            idempotency_key=idempotency_key or f"pysdk-{uuid.uuid4()}",
            paid_operation=paid_operation,
            mandate_meta=mandate_meta,
        )

    def _put(self, path: str, body: Mapping[str, Any], *, idempotency_key: Optional[str] = None) -> Dict[str, Any]:
        return self._request("PUT", path, body=body, idempotency_key=idempotency_key or f"pysdk-{uuid.uuid4()}")

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: Optional[Mapping[str, Any]] = None,
        idempotency_key: Optional[str] = None,
        paid_operation: Optional[str] = None,
        mandate_meta: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        raw_str = "" if body is None else json.dumps(body, separators=(",", ":"))
        payment_sig: Optional[str] = None
        attempt = 0
        # CR-SDK-M1: a retry of a paid call that failed ambiguously after paying resends the identical request + payment.
        pending_key = f"{method} {path.split('?')[0]} {idempotency_key}" if idempotency_key and paid_operation else None
        if pending_key is not None:
            with self._pending_lock:
                prior = self._pending_paid.get(pending_key)
                if prior is not None and self._now_ms() - prior["at"] < _PENDING_PAID_TTL_MS:
                    if body is not None and canonical_json(body) != canonical_json(loads_jcs_json(prior["raw"])):
                        raise AgentMediateError(
                            422,
                            "IDEMPOTENCY_CONFLICT",
                            "Idempotency-Key has a pending payment for a different request body",
                            idempotency_key=idempotency_key,
                            payment_sent=True,
                        )
                    path, raw_str, payment_sig = prior["path"], prior["raw"], prior["payment"]
                elif prior is not None:
                    self._pending_paid.pop(pending_key, None)
        raw_bytes = raw_str.encode("utf-8") if raw_str else None

        def fail(status: int, code: str, message: str, err_body: Any = None) -> AgentMediateError:
            # H-05: Only ambiguous transport/facilitator failures may have settled a payment in flight.
            # Definitive rejections (402 invalid payment, 400/404/409/410/422, redirects) never settled ($0.00 charged):
            # report payment_sent=False, clear _pending_paid, and release the unsettled EIP-3009 authorization.
            retain_pending = (
                payment_sig is not None
                and code != "RESPONDENT_UNREACHABLE"
                and (status == 0 or status == 429 or status >= 500 or code in _AMBIGUOUS_PAYMENT_CODES)
            )
            paid = retain_pending
            if payment_sig is not None and not retain_pending and self._payer is not None:
                release_fn = getattr(self._payer, "release_unsettled", None)
                if callable(release_fn):
                    release_fn(payment_sig)
            if pending_key is not None:
                with self._pending_lock:
                    if retain_pending:
                        if pending_key not in self._pending_paid and len(self._pending_paid) >= _PENDING_PAID_MAX:
                            self._pending_paid.pop(next(iter(self._pending_paid)), None)
                        existing = self._pending_paid.get(pending_key)
                        entry_data: Dict[str, Any] = {"path": path, "raw": raw_str, "payment": payment_sig, "at": self._now_ms()}
                        if mandate_meta is not None:
                            entry_data["mandate"] = dict(mandate_meta["mandate"])
                            entry_data["mandateFingerprint"] = str(mandate_meta["fingerprint"])
                        elif isinstance(existing, Mapping) and "mandate" in existing and "mandateFingerprint" in existing:
                            entry_data["mandate"] = existing["mandate"]
                            entry_data["mandateFingerprint"] = existing["mandateFingerprint"]
                        self._pending_paid[pending_key] = entry_data
                    else:
                        self._pending_paid.pop(pending_key, None)
            suffix = (
                f' (a payment authorisation was already sent: retry with idempotency_key "{idempotency_key}" to avoid a second charge)'
                if idempotency_key and paid
                else ""
            )
            return AgentMediateError(status, code, message + suffix, err_body, idempotency_key=idempotency_key, payment_sent=paid)

        while True:
            headers: Dict[str, str] = {}
            if raw_str:
                headers["content-type"] = "application/json"
            if idempotency_key:
                headers["idempotency-key"] = idempotency_key
            sig_headers = sign_request(
                method=method,
                target_uri=self.base_url + path,
                headers=headers,
                body=raw_str if raw_str else None,
                key=self.agent_key,
                created=self._now_ms() // 1000,
                nonce=str(uuid.uuid4()),
            )
            headers.update(sig_headers)
            if payment_sig:
                headers["payment-signature"] = payment_sig

            try:
                res = self._transport(method, self.base_url + path, headers, raw_bytes)
            except AgentMediateError as err:
                raise fail(err.status, err.code, str(err), err.body) from err
            except Exception as err:
                if self._backoff(attempt):
                    attempt += 1
                    continue
                raise fail(0, "NETWORK_ERROR", str(err)) from err

            if 300 <= res.status < 400:
                raise fail(res.status, "UNEXPECTED_REDIRECT", f"refusing HTTP {res.status} redirect from {path}")

            if len(res.body.encode("utf-8")) > _MAX_RESPONSE_BYTES:
                raise fail(res.status, "RESPONSE_TOO_LARGE", f"response body exceeds {_MAX_RESPONSE_BYTES} bytes")

            try:
                parsed_any: Any = loads_jcs_json(res.body) if res.body else {}
            except Exception:
                parsed_any = None
            parsed: Dict[str, Any] = parsed_any if isinstance(parsed_any, dict) else {}

            if res.status == 402 and parsed.get("code") == "PAYMENT_REQUIRED" and not payment_sig:
                pr_hdr = res.headers.get("payment-required")
                try:
                    challenge = json.loads(base64.b64decode(pr_hdr).decode("utf-8")) if pr_hdr else (parsed.get("paymentRequired") or {})
                except Exception:
                    raise fail(402, "MALFORMED_PAYMENT_REQUIRED", "the payment-required header is not valid base64 JSON", parsed) from None
                if not isinstance(challenge, Mapping):
                    raise fail(402, "MALFORMED_PAYMENT_REQUIRED", "the 402 response carries no payment challenge", parsed)
                if not paid_operation:
                    raise fail(402, "UNEXPECTED_PAYMENT_REQUEST", f"{method} {path} is not a paid operation; refusing to pay", parsed)
                if self._payer is None:
                    raise PaymentRequiredError(challenge, parsed, idempotency_key=idempotency_key)
                info = self.platform()
                fees = info.get("fees") if isinstance(info.get("fees"), Mapping) else {}
                accepts = challenge.get("accepts")
                # CR-SDK-L6: enforce out-of-band platform_did pinning on Base mainnet even when a custom payer omits .network.
                is_mainnet = (
                    getattr(self._payer, "network", None) == BASE_MAINNET
                    or fees.get("network") == BASE_MAINNET
                    or (isinstance(accepts, Sequence) and any(isinstance(a, Mapping) and a.get("network") == BASE_MAINNET for a in accepts))
                )
                if is_mainnet and not self._pinned_platform_did:
                    raise PaymentPolicyError("on Base mainnet, platform_did must be pinned out of band")
                expected_pay_to = self._verified_platform_pay_to(info)
                payment_sig = self._payer.pay(challenge, operation=paid_operation, expected_pay_to=expected_pay_to)
                continue

            if (res.status == 429 or res.status >= 500) and self._backoff(attempt, res):
                attempt += 1
                continue

            if res.status < 200 or res.status >= 300:
                raise fail(
                    res.status,
                    str(parsed.get("code") or "HTTP_ERROR"),
                    str(parsed.get("detail") or f"HTTP {res.status}"),
                    parsed_any,
                )
            if not isinstance(parsed_any, dict):
                raise fail(res.status, "HTTP_ERROR", f"expected JSON object from {path}", parsed_any)
            if pending_key is not None:
                with self._pending_lock:
                    self._pending_paid.pop(pending_key, None)
            return parsed_any


# --- Out-of-band respondent discovery (`CR3-SDK-H1`, `CR3-MCP-H1`, `CR3-SDK-M1`, `CR3-PY-M1`) ---

_MAX_DISCOVERY_BYTES = 128 * 1024
_SIMPLE_EMAIL_RE = re.compile(r"^[^\s@<>,\"';:\\]+@[^\s@<>,\"';:\\]+\.[^\s@<>,\"';:\\]+$")
_DISCOVERY_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet", ".corp", ".private")
_DISCOVERY_BLOCKED_NAMES = frozenset({"localhost", "metadata.google.internal", "metadata", "instance-data"})
_DISCOVERY_V4_BLOCKED = tuple(
    ipaddress.ip_network(cidr)
    for cidr in (
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.0.0.0/24",
        "192.0.2.0/24",
        "192.88.99.0/24",
        "192.168.0.0/16",
        "198.18.0.0/15",
        "198.51.100.0/24",
        "203.0.113.0/24",
        "224.0.0.0/4",
        "240.0.0.0/4",
    )
)


def is_public_ip_address(ip: str) -> bool:
    """Return True iff ``ip`` is a publicly routable global-unicast IPv4 or IPv6 address."""
    if not isinstance(ip, str) or not ip:
        return False
    cleaned = ip.split("%", 1)[0] if ":" in ip else ip
    try:
        addr = ipaddress.ip_address(cleaned)
    except ValueError:
        return False
    if isinstance(addr, ipaddress.IPv4Address):
        return not any(addr in net for net in _DISCOVERY_V4_BLOCKED)
    val = int(addr)
    h0 = (val >> 112) & 0xFFFF
    h1 = (val >> 96) & 0xFFFF
    if (h0 & 0xE000) != 0x2000:
        return False
    if h0 == 0x2001 and h1 < 0x0200:
        return False
    if h0 == 0x2001 and h1 == 0x0DB8:
        return False
    if h0 == 0x2002:
        return False
    if h0 == 0x3FFF and h1 < 0x1000:
        return False
    return True


def _is_loopback_discovery_host(hostname: str) -> bool:
    h = hostname.strip("[]").lower()
    return h in ("localhost", "127.0.0.1", "::1")


def _is_internal_or_ip_discovery_host(hostname: str) -> bool:
    h = hostname.strip("[]").lower().rstrip(".")
    if not h or ":" in h:
        return True
    if _is_ip_host(h) or re.fullmatch(r"^\d{1,3}(?:\.\d{1,3}){3}$", h) or re.fullmatch(r"^[0-9.]+$", h) or h.startswith("0x"):
        return True
    if "." not in h:
        return True
    if h in _DISCOVERY_BLOCKED_NAMES or any(h.endswith(s) for s in _DISCOVERY_BLOCKED_SUFFIXES):
        return True
    return False


def _origin_of_url(raw: str) -> Optional[str]:
    try:
        u = urllib.parse.urlsplit(raw)
        port = u.port
    except ValueError:
        return None
    scheme = u.scheme.lower()
    if scheme not in ("http", "https") or not u.hostname or u.username is not None or u.password is not None:
        return None
    raw_host = u.hostname.strip("[]").lower().rstrip(".")
    if not raw_host:
        return None
    if ":" in raw_host:
        host_fmt = f"[{raw_host}]"
    elif _is_ip_host(raw_host):
        host_fmt = raw_host
    else:
        try:
            host_fmt = _uts46_to_ascii(raw_host)
        except UnicodeError:
            return None
    default_port = 443 if scheme == "https" else 80
    port_suffix = f":{port}" if (port is not None and port != default_port) else ""
    return f"{scheme}://{host_fmt}{port_suffix}"


def _normalize_discovery_target(
    target: str,
    allow_insecure_http: bool,
) -> tuple[str, str, bool, Optional[str], str]:
    trimmed = target.strip()
    if not trimmed:
        raise ValueError("target must be a non-empty domain, URL, or did:web")
    if trimmed.startswith("did:web:"):
        raw_doc_url = url_from_did_web(trimmed)
        parsed = urllib.parse.urlsplit(raw_doc_url)
        raw_host = (parsed.hostname or "").strip("[]").lower().rstrip(".")
        loopback = _is_loopback_discovery_host(raw_host)
        if loopback:
            if not allow_insecure_http:
                raise ValueError("target must be a public domain name")
        else:
            if parsed.scheme.lower() != "https":
                raise ValueError("target URL must use https://")
            if parsed.port is not None and parsed.port != 443:
                raise ValueError("target URL must use default https port 443")
            if _is_internal_or_ip_discovery_host(raw_host):
                raise ValueError("target must be a public domain name")
        clean_host = raw_host if (_is_ip_host(raw_host) or loopback) else _uts46_to_ascii(raw_host)
        origin = _origin_of_url(raw_doc_url)
        if not origin:
            raise ValueError("invalid did:web target")
        did_doc_url = f"{origin}{parsed.path or '/.well-known/did.json'}"
        return origin, clean_host, loopback, trimmed, did_doc_url

    with_scheme = trimmed if re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", trimmed) else f"https://{trimmed}"
    parsed = urllib.parse.urlsplit(with_scheme)
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("target URL must not contain credentials")
    if not parsed.hostname:
        raise ValueError("target must be a valid domain or URL")
    raw_host = parsed.hostname.strip("[]").lower().rstrip(".")
    loopback = _is_loopback_discovery_host(raw_host)
    scheme = parsed.scheme.lower()
    if loopback:
        if not allow_insecure_http:
            raise ValueError("target must be a public domain name")
        if scheme not in ("http", "https"):
            raise ValueError(f"unsupported target protocol {scheme}:")
    else:
        if scheme != "https":
            raise ValueError("target URL must use https://")
        if parsed.port is not None and parsed.port != 443:
            raise ValueError("target URL must use default https port 443")
        if _is_internal_or_ip_discovery_host(raw_host):
            raise ValueError("target must be a public domain name")
    clean_host = raw_host if (_is_ip_host(raw_host) or loopback) else _uts46_to_ascii(raw_host)
    origin = _origin_of_url(with_scheme)
    if not origin:
        raise ValueError("invalid target URL")
    return origin, clean_host, loopback, None, f"{origin}/.well-known/did.json"


def _default_resolve_discovery_host(hostname: str) -> List[tuple[str, int]]:
    infos = socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
    seen: List[tuple[str, int]] = []
    for family, _socktype, _proto, _canon, sockaddr in infos:
        addr = str(sockaddr[0])
        fam = 6 if family == socket.AF_INET6 else 4
        if (addr, fam) not in seen:
            seen.append((addr, fam))
    return seen


def _transport_get_bounded(
    transport: TransportLike,
    url: str,
    accept: str,
) -> Optional[HttpResponse]:
    try:
        res = transport("GET", url, {"accept": accept}, None)
    except Exception:
        return None
    if res.status < 200 or res.status >= 300:
        return None
    try:
        declared = int(res.headers.get("content-length") or "0")
        if declared > _MAX_DISCOVERY_BYTES:
            return None
    except ValueError:
        pass
    if len(res.body.encode("utf-8")) > _MAX_DISCOVERY_BYTES:
        return None
    return res


def _pinned_socket_get_bounded(
    url: str,
    accept: str,
    timeout_sec: float,
    pins: Optional[Sequence[tuple[str, int]]],
) -> Optional[HttpResponse]:
    u = urllib.parse.urlsplit(url)
    scheme = u.scheme.lower()
    if scheme not in ("http", "https") or not u.hostname:
        return None
    hostname = u.hostname.strip("[]")
    clean_sni = hostname.rstrip(".")
    try:
        sni_host = _uts46_to_ascii(clean_sni) if (clean_sni and not _is_ip_host(clean_sni)) else clean_sni
    except UnicodeError:
        sni_host = clean_sni
    port = u.port or (443 if scheme == "https" else 80)
    target_path = (u.path or "/") + (f"?{u.query}" if u.query else "")
    host_header = f"[{hostname}]" if ":" in hostname else (sni_host or hostname)
    if u.port is not None and u.port != (443 if scheme == "https" else 80):
        host_header = f"{host_header}:{u.port}"

    candidates: Sequence[Optional[tuple[str, int]]] = list(pins[:2]) if pins else [None]
    for idx, pin in enumerate(candidates):
        conn: Optional[http.client.HTTPConnection] = None
        sock: Optional[socket.socket] = None
        raw_sock: Optional[socket.socket] = None
        received_headers = False
        try:
            if pin is not None:
                pin_addr, pin_family = pin
                af = socket.AF_INET6 if pin_family == 6 else socket.AF_INET
                raw_sock = socket.socket(af, socket.SOCK_STREAM)
                raw_sock.settimeout(timeout_sec)
                raw_sock.connect((pin_addr, port))
                if scheme == "https":
                    ctx = ssl.create_default_context()
                    sock = ctx.wrap_socket(raw_sock, server_hostname=sni_host or hostname)
                else:
                    sock = raw_sock
                conn = http.client.HTTPConnection(hostname, port=port, timeout=timeout_sec)
                conn.sock = sock
            else:
                if scheme == "https":
                    conn = http.client.HTTPSConnection(hostname, port=port, timeout=timeout_sec)
                else:
                    conn = http.client.HTTPConnection(hostname, port=port, timeout=timeout_sec)
            conn.request("GET", target_path, headers={"Host": host_header, "Accept": accept, "Connection": "close"})
            resp = conn.getresponse()
            received_headers = True
            if resp.status < 200 or resp.status >= 300:
                return None
            headers = {k.lower(): v for k, v in resp.getheaders()}
            try:
                if int(headers.get("content-length") or "0") > _MAX_DISCOVERY_BYTES:
                    return None
            except ValueError:
                pass
            raw_bytes = resp.read(_MAX_DISCOVERY_BYTES + 1)
            if len(raw_bytes) > _MAX_DISCOVERY_BYTES:
                return None
            return HttpResponse(status=resp.status, headers=headers, body=raw_bytes.decode("utf-8"))
        except Exception:
            if idx + 1 < len(candidates) and not received_headers:
                continue
            return None
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass
            elif sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
            elif raw_sock is not None:
                try:
                    raw_sock.close()
                except Exception:
                    pass
    return None


def _parse_link_header_agent_card(link_header: Optional[str], expected_origin: str) -> Optional[str]:
    if not link_header or len(link_header) > 4096:
        return None
    for part in link_header.split(","):
        url_match = re.search(r"<([^>\s]{1,1024})>", part)
        rel_match = re.search(r';\s*rel\s*=\s*(?:"([^"]*)"|([^\s;]+))', part, re.IGNORECASE)
        if not url_match or not rel_match:
            continue
        rel_tokens = [t for t in (rel_match.group(1) or rel_match.group(2) or "").lower().split() if t]
        if "agent-card" not in rel_tokens and "https://a2a-protocol.org/rel/agent-card" not in rel_tokens:
            continue
        resolved = urllib.parse.urljoin(f"{expected_origin}/", url_match.group(1))
        if _origin_of_url(resolved) == expected_origin:
            return resolved
    return None


def _extract_did_methods_from_did_doc(
    doc: Mapping[str, Any],
    expected_did_web: Optional[str],
) -> tuple[List[str], Dict[str, str]]:
    candidates: List[str] = []
    method_by_id: Dict[str, str] = {}
    aka = doc.get("alsoKnownAs")
    if isinstance(aka, list):
        for item in aka:
            if isinstance(item, str) and is_did_key(item) and item not in candidates:
                candidates.append(item)
    vms = doc.get("verificationMethod")
    if isinstance(vms, list):
        for vm in vms:
            if not isinstance(vm, Mapping):
                continue
            resolved_did: Optional[str] = None
            jwk = vm.get("publicKeyJwk")
            if isinstance(jwk, Mapping):
                try:
                    derived = did_key_from_ed25519_jwk(jwk)
                    if derived and is_did_key(derived):
                        resolved_did = derived
                except Exception:
                    pass
            if resolved_did is None and isinstance(vm.get("publicKeyMultibase"), str):
                maybe_did = f"did:key:{vm['publicKeyMultibase']}"
                if is_did_key(maybe_did):
                    resolved_did = maybe_did
            if resolved_did:
                if resolved_did not in candidates:
                    candidates.append(resolved_did)
                vm_id = vm.get("id")
                if isinstance(vm_id, str) and vm_id:
                    norm_id = f"{expected_did_web}{vm_id}" if (vm_id.startswith("#") and expected_did_web) else vm_id
                    method_by_id[norm_id] = resolved_did
    return candidates, method_by_id


def _extract_did_candidates_from_card(
    card: Mapping[str, Any],
    did_doc_methods: Optional[Mapping[str, str]],
    expected_did_web: Optional[str],
) -> List[str]:
    candidates: List[str] = []
    caps = card.get("capabilities")
    exts = caps.get("extensions") if isinstance(caps, Mapping) else None
    if isinstance(exts, list):
        for ext in exts:
            params = ext.get("params") if isinstance(ext, Mapping) else None
            if not isinstance(params, Mapping):
                continue
            for key_name in ("agentId", "did", "didKey", "respondentId"):
                val = params.get(key_name)
                if isinstance(val, str) and is_did_key(val) and val not in candidates:
                    candidates.append(val)
    sigs = card.get("signatures")
    if isinstance(sigs, list):
        for sig in sigs:
            prot = sig.get("protected") if isinstance(sig, Mapping) else None
            if not isinstance(prot, str):
                continue
            try:
                pad = "=" * ((4 - (len(prot) % 4)) % 4)
                hdr = json.loads(base64.urlsafe_b64decode(prot + pad).decode("utf-8"))
                if not isinstance(hdr, Mapping):
                    continue
                kid = hdr.get("kid")
                if isinstance(kid, str):
                    if is_did_key(kid) and kid not in candidates:
                        candidates.append(kid)
                    elif did_doc_methods:
                        norm_kid = f"{expected_did_web}{kid}" if (kid.startswith("#") and expected_did_web) else kid
                        mapped = did_doc_methods.get(norm_kid)
                        if mapped and is_did_key(mapped) and mapped not in candidates:
                            candidates.append(mapped)
                jwk = hdr.get("jwk")
                if isinstance(jwk, Mapping):
                    derived = did_key_from_ed25519_jwk(jwk)
                    if derived and is_did_key(derived) and derived not in candidates:
                        candidates.append(derived)
            except Exception:
                pass
    return candidates


def _inspect_agent_card_origin_claims(
    card: Mapping[str, Any],
    expected_origin: str,
    allowed_did_webs: set[str],
    has_custom_same_origin_webhook: bool,
) -> tuple[bool, bool]:
    has_positive_claim = has_custom_same_origin_webhook

    def same_origin_url(raw: Any) -> bool:
        return isinstance(raw, str) and _origin_of_url(raw) == expected_origin

    if "url" in card and card.get("url") is not None:
        if not same_origin_url(card.get("url")):
            return True, False
        has_positive_claim = True
    if "supportedInterfaces" in card and card.get("supportedInterfaces") is not None:
        ifaces = card.get("supportedInterfaces")
        if not isinstance(ifaces, list):
            return True, False
        for iface in ifaces:
            if not isinstance(iface, Mapping):
                return True, False
            if "url" in iface and iface.get("url") is not None:
                if not same_origin_url(iface.get("url")):
                    return True, False
                has_positive_claim = True
    provider = card.get("provider")
    if isinstance(provider, Mapping) and "url" in provider and provider.get("url") is not None:
        if not same_origin_url(provider.get("url")):
            return True, False
        has_positive_claim = True
    sigs = card.get("signatures")
    if isinstance(sigs, list):
        for sig in sigs:
            prot = sig.get("protected") if isinstance(sig, Mapping) else None
            if not isinstance(prot, str):
                continue
            try:
                pad = "=" * ((4 - (len(prot) % 4)) % 4)
                hdr = json.loads(base64.urlsafe_b64decode(prot + pad).decode("utf-8"))
                if not isinstance(hdr, Mapping):
                    return True, False
                if "jku" in hdr and hdr.get("jku") is not None:
                    if not same_origin_url(hdr.get("jku")):
                        return True, False
                    has_positive_claim = True
                kid = hdr.get("kid")
                if isinstance(kid, str) and kid.startswith("did:web:"):
                    kid_did_web = kid.split("#", 1)[0]
                    if kid_did_web not in allowed_did_webs:
                        return True, False
                    has_positive_claim = True
            except Exception:
                return True, False
    return False, has_positive_claim


def _agent_card_matches_origin(
    card: Mapping[str, Any],
    expected_origin: str,
    allowed_did_webs: set[str],
    has_custom_same_origin_webhook: bool,
) -> bool:
    has_foreign, has_positive = _inspect_agent_card_origin_claims(
        card, expected_origin, allowed_did_webs, has_custom_same_origin_webhook
    )
    return (not has_foreign) and has_positive


_STANDARD_A2A_JSONRPC_BINDINGS = frozenset({"JSONRPC", "JSON-RPC", "HTTP+JSONRPC"})


def _extract_standard_a2a_rpc_url(card: Mapping[str, Any], expected_origin: str) -> Optional[str]:
    ifaces = card.get("supportedInterfaces")
    if isinstance(ifaces, list):
        for iface in ifaces:
            if not isinstance(iface, Mapping) or not isinstance(iface.get("url"), str):
                continue
            binding = str(iface.get("protocolBinding") or "JSONRPC").strip().upper()
            if binding not in _STANDARD_A2A_JSONRPC_BINDINGS:
                continue
            if _origin_of_url(iface["url"]) == expected_origin:
                return iface["url"]
    if isinstance(card.get("url"), str):
        transport = str(card.get("preferredTransport") or "JSONRPC").strip().upper()
        if transport in _STANDARD_A2A_JSONRPC_BINDINGS and _origin_of_url(card["url"]) == expected_origin:
            return card["url"]
    return None


def _parse_security_txt_email(text: str) -> Optional[str]:
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        m = re.match(r"^contact\s*:\s*(.+)$", line, re.IGNORECASE)
        if not m:
            continue
        raw_val = m.group(1).strip()
        email_addr = raw_val[7:].split("?", 1)[0].strip() if raw_val.lower().startswith("mailto:") else raw_val
        if len(email_addr) <= 254 and _SIMPLE_EMAIL_RE.fullmatch(email_addr):
            return email_addr
    return None


def discover_respondent(
    target: str,
    *,
    base_url: Optional[str] = None,
    platform_did: Optional[str] = None,
    expected_environment: Optional[str] = None,
    expected_rules_hash: Optional[str] = None,
    transport: Optional[TransportLike] = None,
    api_transport: Optional[TransportLike] = None,
    resolve_host: Optional[Callable[[str], Sequence[Any]]] = None,
    timeout_ms: int = 3_000,
    allow_insecure_http: bool = False,
    now_ms: Optional[Callable[[], int]] = None,
) -> Dict[str, Any]:
    """
    Out-of-band respondent discovery helper matching TypeScript ``discoverRespondent`` (``CR3-SDK-H1``, ``CR3-MCP-H1``, ``CR3-SDK-M1``, ``CR3-PY-M1``, ``M-2``).
    """
    timeout_sec = max(0.1, float(timeout_ms) / 1000.0)
    clock = now_ms or (lambda: int(time.time() * 1000))
    origin, domain, is_loopback, initial_did_web, did_doc_url = _normalize_discovery_target(target, allow_insecure_http)

    vetted_pins: Optional[List[tuple[str, int]]] = None
    if not is_loopback and (transport is None or resolve_host is not None):
        try:
            raw_resolved = resolve_host(domain) if resolve_host is not None else _default_resolve_discovery_host(domain)
        except Exception as exc:
            raise ValueError("target host could not be resolved") from exc
        if not raw_resolved:
            raise ValueError("target host could not be resolved")
        parsed_pins: List[tuple[str, int]] = []
        for item in raw_resolved:
            if isinstance(item, str):
                addr_str = item
            elif isinstance(item, Mapping) and isinstance(item.get("address"), str):
                addr_str = str(item["address"])
            elif isinstance(item, (tuple, list)) and len(item) >= 1 and isinstance(item[0], str):
                addr_str = str(item[0])
            else:
                raise ValueError("target must resolve exclusively to public IP addresses")
            if not is_public_ip_address(addr_str):
                raise ValueError("target must resolve exclusively to public IP addresses")
            fam = 6 if ":" in addr_str else 4
            if (addr_str, fam) not in parsed_pins:
                parsed_pins.append((addr_str, fam))
        vetted_pins = parsed_pins

    def get_from_target(url: str, accept: str) -> Optional[HttpResponse]:
        if transport is not None:
            return _transport_get_bounded(transport, url, accept)
        return _pinned_socket_get_bounded(url, accept, timeout_sec, vetted_pins)

    honours_transport = api_transport or transport or _make_default_transport(timeout_sec)

    sources: List[str] = []

    def add_source(src: str) -> None:
        if src not in sources:
            sources.append(src)

    respondent_id: Optional[str] = None
    verified_standing = False
    standing: Dict[str, Any] = {
        "listed": False,
        "strength": "none",
        "qualifiedHonoredCount": 0,
        "distinctCounterparties": 0,
        "verifiedDomainCounterparties": 0,
    }
    has_verified_notice_channel = False
    contact: Dict[str, str] = {}
    if initial_did_web:
        contact["didWeb"] = initial_did_web

    # 1. Settlement Honours Roll lookup (trusted ONLY with verified active platform signedAttestation, P1-2)
    clean_base = normalize_base_url(base_url) if base_url else None
    effective_platform_did = platform_did if platform_did is not None else (
        DEFAULT_PRODUCTION_PLATFORM_DIDS.get(clean_base) if clean_base else None
    )
    effective_expected_env = expected_environment if expected_environment is not None else (
        "production" if clean_base == PRODUCTION_API_URL else None
    )
    if clean_base and effective_platform_did and is_did_key(effective_platform_did):
        honours_res = _transport_get_bounded(
            honours_transport,
            f"{clean_base}/v1/honours/{urllib.parse.quote(domain, safe='')}",
            "application/json",
        )
        if honours_res is not None:
            try:
                body = json.loads(honours_res.body)
                now_ts = clock()
                att = body.get("signedAttestation") if isinstance(body, Mapping) else None
                doc = att.get("document") if isinstance(att, Mapping) else None
                proof = att.get("proof") if isinstance(att, Mapping) else None
                created = proof.get("created") if isinstance(proof, Mapping) else None
                exp = proof.get("expiresAt") if isinstance(proof, Mapping) else None
                agent_ids = doc.get("agentIds") if isinstance(doc, Mapping) else None
                if (
                    isinstance(body, Mapping)
                    and body.get("listed") is True
                    and body.get("inGoodStanding") is not False
                    and isinstance(att, Mapping)
                    and isinstance(doc, Mapping)
                    and doc.get("type") == HONOURS_ATTESTATION_TYPE
                    and doc.get("domain") == domain
                    and (effective_expected_env is None or doc.get("environment") == effective_expected_env)
                    and (expected_rules_hash is None or doc.get("rulesHash") == expected_rules_hash)
                    and doc.get("fulfilmentRate") == 1
                    and isinstance(agent_ids, list)
                    and len(agent_ids) > 0
                    and isinstance(created, int)
                    and not isinstance(created, bool)
                    and isinstance(exp, int)
                    and not isinstance(exp, bool)
                    and created == doc.get("issuedAt")
                    and created <= now_ts + 300_000
                    and exp > created
                    and exp - created <= 24 * 3_600_000
                ):
                    att_sig_ok = verify_document(att, effective_platform_did, now_ms=now_ts)
                    if (
                        not att_sig_ok
                        and isinstance(proof, Mapping)
                        and proof.get("verificationMethod") != effective_platform_did
                    ):
                        kh_res = _transport_get_bounded(
                            honours_transport,
                            f"{clean_base}/.well-known/key-history.json",
                            "application/json",
                        )
                        if kh_res is not None:
                            kh = json.loads(kh_res.body)
                            if (
                                isinstance(kh, Mapping)
                                and verify_key_history(
                                    kh,
                                    expected_active_did=effective_platform_did,
                                    now_ms=now_ts,
                                    max_age_ms=DEFAULT_KEY_HISTORY_TTL_MS,
                                ).get("ok")
                            ):
                                kh_active = kh.get("document", {}).get("activeDid")
                                if isinstance(kh_active, str) and kh_active != effective_platform_did:
                                    att_sig_ok = verify_document(att, kh_active, now_ms=now_ts)
                    if att_sig_ok:
                        entry = body.get("entry")
                        entry_matches = entry is None or (
                            isinstance(entry, Mapping)
                            and entry.get("domain") == doc.get("domain")
                            and entry.get("didWeb") == doc.get("didWeb")
                            and isinstance(entry.get("agentIds"), list)
                            and entry.get("agentIds") == agent_ids
                        )
                        if entry_matches:
                            first_did = next((aid for aid in agent_ids if isinstance(aid, str) and is_did_key(aid)), None)
                            if first_did:
                                respondent_id = first_did
                                verified_standing = True
                                q_count = doc.get("qualifiedHonoredCount")
                                qualified_honored = (
                                    q_count
                                    if (isinstance(q_count, int) and not isinstance(q_count, bool) and q_count >= 0)
                                    else 0
                                )
                                d_cp = doc.get("distinctCounterparties")
                                distinct_cp = (
                                    d_cp
                                    if (isinstance(d_cp, int) and not isinstance(d_cp, bool) and d_cp >= 0)
                                    else 0
                                )
                                vd_cp = doc.get("verifiedDomainCounterparties")
                                verified_domain_cp = (
                                    vd_cp
                                    if (isinstance(vd_cp, int) and not isinstance(vd_cp, bool) and vd_cp >= 0)
                                    else 0
                                )
                                strength = (
                                    "domain-corroborated"
                                    if (doc.get("standingStrength") == "domain-corroborated" or verified_domain_cp >= 1)
                                    else "basic"
                                )
                                standing = {
                                    "listed": True,
                                    "strength": strength,
                                    "qualifiedHonoredCount": qualified_honored,
                                    "distinctCounterparties": distinct_cp,
                                    "verifiedDomainCounterparties": verified_domain_cp,
                                }
                                if isinstance(doc.get("didWeb"), str) and str(doc["didWeb"]).startswith("did:web:"):
                                    contact["didWeb"] = str(doc["didWeb"])
                                add_source("honours")
            except Exception:
                pass

    try:
        root_did_web: Optional[str] = did_web_from_url(origin)
    except Exception:
        root_did_web = None
    expected_did_web = initial_did_web or root_did_web
    allowed_did_webs: set[str] = set()
    if root_did_web:
        allowed_did_webs.add(root_did_web)
    if initial_did_web:
        allowed_did_webs.add(initial_did_web)

    # 2. A2A Agent Card (/.well-known/agent-card.json -> /.well-known/agent.json -> Link header on /)
    card_url: Optional[str] = f"{origin}/.well-known/agent-card.json"
    card_from_link_header = False
    card_res = get_from_target(card_url, "application/json")
    if card_res is None:
        card_url = f"{origin}/.well-known/agent.json"
        card_res = get_from_target(card_url, "application/json")
    if card_res is None:
        root_res = get_from_target(f"{origin}/", "text/html, application/json;q=0.9, */*;q=0.5")
        linked = _parse_link_header_agent_card(root_res.headers.get("link") if root_res else None, origin)
        if linked:
            card_res = get_from_target(linked, "application/json")
            if card_res is not None:
                card_url = linked
                card_from_link_header = True

    parsed_card: Optional[Dict[str, Any]] = None
    if card_res is not None and card_url is not None:
        try:
            c = json.loads(card_res.body)
            if isinstance(c, dict) and not _inspect_agent_card_origin_claims(c, origin, allowed_did_webs, False)[0]:
                parsed_card = c
                if card_from_link_header:
                    add_source("link_header")
                contact["a2aCardUrl"] = card_url
                add_source("a2a_card")
        except Exception:
            pass

    # 3. W3C did:web (/.well-known/did.json or path-scoped did_doc_url)

    did_doc_authorized_keys: List[str] = []
    did_doc_method_by_id: Dict[str, str] = {}
    did_res = get_from_target(did_doc_url, "application/did+ld+json, application/json")
    if did_res is not None:
        try:
            did_doc = json.loads(did_res.body)
            if isinstance(did_doc, dict):
                if expected_did_web:
                    contact["didWeb"] = expected_did_web
                add_source("did_web")
                extracted_candidates, did_doc_method_by_id = _extract_did_methods_from_did_doc(did_doc, expected_did_web)
                raw_candidates = ([respondent_id] if respondent_id else []) + extracted_candidates
                if expected_did_web:
                    for cand in raw_candidates:
                        if cand not in did_doc_authorized_keys and did_web_document_authorizes_key(did_doc, expected_did_web, cand):
                            did_doc_authorized_keys.append(cand)
                did_webhook_url: Optional[str] = None
                if isinstance(did_doc.get("service"), list):
                    for svc in did_doc["service"]:
                        if (
                            isinstance(svc, Mapping)
                            and svc.get("type") == "AgentMediateNotice"
                            and isinstance(svc.get("serviceEndpoint"), str)
                            and _origin_of_url(svc["serviceEndpoint"]) == origin
                        ):
                            did_webhook_url = svc["serviceEndpoint"]
                            break
                for cand in did_doc_authorized_keys:
                    if verify_agent_card_signature(did_doc, cand):
                        if respondent_id is None:
                            respondent_id = cand
                        if cand == respondent_id and did_webhook_url is not None:
                            if "webhookUrl" not in contact:
                                contact["webhookUrl"] = did_webhook_url
                            has_verified_notice_channel = True
                        break
                if parsed_card is None and isinstance(did_doc.get("service"), list):
                    for svc in did_doc["service"]:
                        if (
                            isinstance(svc, Mapping)
                            and svc.get("type") in ("A2AAgentCard", "AgentCard")
                            and isinstance(svc.get("serviceEndpoint"), str)
                        ):
                            ep = svc["serviceEndpoint"]
                            if _origin_of_url(ep) == origin:
                                linked_card = get_from_target(ep, "application/json")
                                if linked_card is not None:
                                    try:
                                        c = json.loads(linked_card.body)
                                        if isinstance(c, dict) and not _inspect_agent_card_origin_claims(c, origin, allowed_did_webs, False)[0]:
                                            parsed_card = c
                                            contact["a2aCardUrl"] = ep
                                            add_source("a2a_card")
                                    except Exception:
                                        pass
                                break
        except Exception:
            pass

    # Evaluate Agent Card cryptographic binding & channels
    if parsed_card is not None:
        caps = parsed_card.get("capabilities")
        exts = caps.get("extensions") if isinstance(caps, Mapping) else None
        custom_webhook: Optional[str] = None
        if isinstance(exts, list):
            for ext in exts:
                if isinstance(ext, Mapping) and ext.get("uri") in (
                    "urn:agent-mediate:ext:dispute-notice:v1",
                    "urn:agent-mediate:ext:dispute-clause:v1",
                    "urn:agent-mediate:ext:notifications:v1",
                    "urn:agent-mediate:ext:notice:v1",
                ):
                    params = ext.get("params")
                    wh = (params.get("noticeWebhookUrl") or params.get("webhookUrl")) if isinstance(params, Mapping) else None
                    if isinstance(wh, str) and _origin_of_url(wh) == origin:
                        custom_webhook = wh
        standard_rpc_url = _extract_standard_a2a_rpc_url(parsed_card, origin)
        if _agent_card_matches_origin(parsed_card, origin, allowed_did_webs, custom_webhook is not None):
            raw_card_candidates = (
                ([respondent_id] if respondent_id else [])
                + _extract_did_candidates_from_card(parsed_card, did_doc_method_by_id, expected_did_web)
                + did_doc_authorized_keys
            )
            unique_candidates: List[str] = []
            for cand in raw_card_candidates:
                if cand not in unique_candidates:
                    unique_candidates.append(cand)
            for cand in unique_candidates:
                if verify_agent_card_signature(parsed_card, cand):
                    if respondent_id is None:
                        respondent_id = cand
                    if cand == respondent_id and (custom_webhook is not None or standard_rpc_url is not None):
                        has_verified_notice_channel = True
                    break
        provider = parsed_card.get("provider")
        prov_email = provider.get("email") if isinstance(provider, Mapping) else None
        if isinstance(prov_email, str) and _SIMPLE_EMAIL_RE.fullmatch(prov_email.strip()):
            contact["email"] = prov_email.strip()

    # 4. RFC 9116 security.txt fallback
    if "email" not in contact:
        sec_res = get_from_target(f"{origin}/.well-known/security.txt", "text/plain")
        if sec_res is None:
            sec_res = get_from_target(f"{origin}/security.txt", "text/plain")
        if sec_res is not None:
            sec_email = _parse_security_txt_email(sec_res.body)
            if sec_email:
                contact["email"] = sec_email
                add_source("security_txt")

    recommended_action = (
        "file_dispute"
        if (respondent_id is not None and has_verified_notice_channel)
        else "send_invite"
    )
    return {
        "domain": domain,
        "origin": origin,
        "respondentId": respondent_id,
        "respondentContact": contact,
        "verifiedStanding": verified_standing,
        "standing": standing,
        "hasVerifiedNoticeChannel": has_verified_notice_channel,
        "recommendedAction": recommended_action,
        "sources": sources,
    }


class WebhookReplayGuard:
    """
    Bounded, thread-safe in-memory RFC 9421 webhook nonce replay guard (`IT6-P2-1`).
    Pair with ``AgentMediateClient.verify_webhook`` (or call ``guard.verify(...)`` directly) so
    captured platform webhook deliveries cannot be replayed within the 5-minute clock-skew window.
    """

    def __init__(
        self,
        *,
        ttl_ms: int = 600_000,
        max_entries: int = 10_000,
        now_ms: Optional[Callable[[], int]] = None,
    ) -> None:
        if isinstance(ttl_ms, bool) or not isinstance(ttl_ms, (int, float)) or not math.isfinite(ttl_ms) or ttl_ms <= 0:
            raise ValueError("WebhookReplayGuard ttl_ms must be a positive number")
        if isinstance(max_entries, bool) or not isinstance(max_entries, int) or max_entries < 1:
            raise ValueError("WebhookReplayGuard max_entries must be a positive integer")
        self._ttl_ms = int(ttl_ms)
        self._max_entries = max_entries
        self._now_ms = now_ms or (lambda: int(time.time() * 1000))
        self._seen: "OrderedDict[str, int]" = OrderedDict()
        self._lock = threading.Lock()

    def _prune_locked(self, now_ts: int) -> None:
        while self._seen:
            first_key = next(iter(self._seen))
            if self._seen[first_key] <= now_ts:
                self._seen.popitem(last=False)
            else:
                break

    def check(
        self,
        nonce_or_verified: Union[str, Mapping[str, Any]],
        *,
        now_ms: Optional[int] = None,
    ) -> bool:
        nonce = (
            nonce_or_verified
            if isinstance(nonce_or_verified, str)
            else (nonce_or_verified.get("nonce") if isinstance(nonce_or_verified, Mapping) else None)
        )
        if not isinstance(nonce, str) or not nonce:
            return False
        t = now_ms if now_ms is not None else self._now_ms()
        with self._lock:
            self._prune_locked(t)
            existing = self._seen.get(nonce)
            if existing is not None and existing > t:
                return False
            if existing is not None:
                del self._seen[nonce]
            while len(self._seen) >= self._max_entries:
                self._seen.popitem(last=False)
            self._seen[nonce] = t + self._ttl_ms
            return True

    def verify(
        self,
        *,
        url: str,
        headers: Mapping[str, str],
        body: str,
        platform_did: str,
        now_ms: Optional[int] = None,
        agent_id: Optional[str] = None,
        allow_unbound_invite: bool = False,
        dispute_id: Optional[str] = None,
        invite_id: Optional[str] = None,
        key_history: Optional[Mapping[str, Any]] = None,
    ) -> Dict[str, Any]:
        resolved_now_ms = now_ms if now_ms is not None else self._now_ms()
        verified = AgentMediateClient.verify_webhook(
            url=url,
            headers=headers,
            body=body,
            platform_did=platform_did,
            now_ms=resolved_now_ms,
            agent_id=agent_id,
            allow_unbound_invite=allow_unbound_invite,
            dispute_id=dispute_id,
            invite_id=invite_id,
            key_history=key_history,
        )
        if not verified.get("ok"):
            return verified
        if not self.check(verified, now_ms=resolved_now_ms):
            return {"ok": False, "reason": "replayed webhook nonce"}
        return verified

    def size(self) -> int:
        with self._lock:
            self._prune_locked(self._now_ms())
            return len(self._seen)

    def clear(self) -> None:
        with self._lock:
            self._seen.clear()


def create_webhook_replay_guard(
    *,
    ttl_ms: int = 600_000,
    max_entries: int = 10_000,
    now_ms: Optional[Callable[[], int]] = None,
) -> WebhookReplayGuard:
    """Create a bounded in-memory RFC 9421 webhook nonce replay guard (`IT6-P2-1`)."""
    return WebhookReplayGuard(ttl_ms=ttl_ms, max_entries=max_entries, now_ms=now_ms)
