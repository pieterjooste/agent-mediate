"""
RFC 8785 JSON Canonicalization Scheme (JCS) and SHA-256 `contract_hash`.

Produces byte-for-byte identical canonical JSON to `canonicalJson` in `@agent-mediate/core`:
- Object keys sorted by UTF-16 code units (RFC 8785 §3.2.3)
- IEEE-754 numbers serialized per ECMAScript `Number.prototype.toString()` with `-0.0` normalized to `0`
- Non-finite floats (`NaN`, `Infinity`, `-Infinity`) rejected
- No insignificant whitespace
"""
from __future__ import annotations

import hashlib
import json
import math
from decimal import Decimal
from types import MappingProxyType
from typing import Any, Mapping, Sequence

RULES_VERSION = "1.3.0"


def _parse_jcs_int(token: str) -> int | float:
    iv = int(token)
    if -9007199254740991 <= iv <= 9007199254740991:
        return iv
    fv = float(token)
    if not math.isfinite(fv):
        raise ValueError("JSON number exceeds IEEE-754 double range")
    return fv


def _reject_jcs_constant(token: str) -> Any:
    raise ValueError(f"Non-standard JSON constant {token!r} is rejected by RFC 8785 / RFC 8259")


def loads_jcs_json(raw: str | bytes) -> Any:
    """Parse JSON per RFC 8785 §3.1 / ECMAScript JSON.parse (mapping integers outside safe-int range to IEEE-754 float)."""
    text = raw.decode("utf-8") if isinstance(raw, bytes) else raw
    return json.loads(text, parse_int=_parse_jcs_int, parse_constant=_reject_jcs_constant)

_ESCAPE_MAP = {
    0x08: "\\b",
    0x09: "\\t",
    0x0A: "\\n",
    0x0C: "\\f",
    0x0D: "\\r",
    0x22: '\\"',
    0x5C: "\\\\",
}


def sha256_hex(data: str | bytes) -> str:
    raw = data.encode("utf-8", errors="surrogatepass") if isinstance(data, str) else data
    return hashlib.sha256(raw).hexdigest()


def _escape_jcs_string(s: str) -> str:
    out = ['"']
    for ch in s:
        cp = ord(ch)
        if cp in _ESCAPE_MAP:
            out.append(_ESCAPE_MAP[cp])
        elif cp < 0x20 or (0xD800 <= cp <= 0xDFFF):
            out.append(f"\\u{cp:04x}")
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _format_jcs_number(val: int | float) -> str:
    # Python bool is a subclass of int; callers check isinstance(val, bool) before calling this.
    if isinstance(val, int):
        if -9007199254740991 <= val <= 9007199254740991:
            return str(val)
        raise ValueError("integer exceeds IEEE-754 safe integer range in canonical_json")

    if not math.isfinite(val):
        raise ValueError("non-finite number in canonical_json")
    if val == 0.0:
        return "0"

    sign = "-" if val < 0 else ""
    abs_val = -val if val < 0 else val

    # Python's repr(float) uses David Gay's shortest round-trip dtoa (same shortest significand as ES6)!
    d = Decimal(repr(abs_val))
    tup = d.as_tuple()
    digits = "".join(str(x) for x in tup.digits).rstrip("0") or "0"
    # Value is 0.<digits> * 10**n where n = len(tup.digits) + tup.exponent
    k = len(digits)
    n = len(tup.digits) + int(tup.exponent)

    # ECMAScript 7.1.12.1 Number::toString formatting rules (RFC 8785 §3.2.2.3):
    if k <= n <= 21:
        return sign + digits + ("0" * (n - k))
    if 0 < n <= 21:
        return sign + digits[:n] + "." + digits[n:]
    if -6 < n <= 0:
        return sign + "0." + ("0" * (-n)) + digits
    exp = n - 1
    exp_str = f"e+{exp}" if exp >= 0 else f"e{exp}"
    if k == 1:
        return sign + digits + exp_str
    return sign + digits[0] + "." + digits[1:] + exp_str


def canonical_json(value: Any) -> str:
    if value is None:
        return "null"
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return _format_jcs_number(value)
    if isinstance(value, str):
        return _escape_jcs_string(value)
    if isinstance(value, Sequence) and not isinstance(value, (bytes, bytearray)):
        return "[" + ",".join(canonical_json(item) for item in value) + "]"
    if isinstance(value, Mapping):
        # Sort keys by UTF-16 code units (big-endian 16-bit code units compare identically to JS UTF-16 code units)
        items = sorted(((str(k), v) for k, v in value.items()), key=lambda kv: kv[0].encode("utf-16-be", errors="surrogatepass"))
        return "{" + ",".join(f"{_escape_jcs_string(k)}:{canonical_json(v)}" for k, v in items) + "}"
    raise TypeError(f"unsupported type in canonical_json: {type(value).__name__}")


def contract_hash(contract: Any) -> str:
    return sha256_hex(canonical_json(contract))


_MINUTE = 60_000
_HOUR = 60 * _MINUTE
_DAY = 24 * _HOUR


def _deep_freeze(obj: Any) -> Any:
    """CR-SDK-L9: recursively freeze dicts/lists via MappingProxyType/tuple (matches TS deepFreeze)."""
    if isinstance(obj, Mapping):
        return MappingProxyType({k: _deep_freeze(v) for k, v in obj.items()})
    if isinstance(obj, Sequence) and not isinstance(obj, (str, bytes, bytearray)):
        return tuple(_deep_freeze(x) for x in obj)
    return obj


MECHANISM_SPEC: Mapping[str, Any] = _deep_freeze({
    "schema": "agent-mediate/mechanism-spec/v1",
    "rulesVersion": RULES_VERSION,
    "canonicalization": "RFC 8785 (JCS) + SHA-256",
    "grid": {
        "maxIssues": 5,
        "stepAlignment": "exact_integer_step_grid",
        "monotonicity": "per_issue_no_retraction",
    },
    "crossingSettlement": {
        "method": "OVERLAP_MIDPOINT",
        "clamping": "mandate_box_minimal_utility_compensation_MECH_6",
    },
    "platformProposal": {
        "fromRoundDefault": 2,
        "alwaysPresented": True,
        "splitRange": [0.3, 0.7],
        "splitKeyDomain": "agent-mediate/proposal-key/v1",
        "splitHmacDomain": "agent-mediate/proposal-split/v1",
        "keyCommitDomain": "agent-mediate/proposal-key-commit/v1",
        "declaredCommitDomain": "agent-mediate/declared-input-commit/v1",
        "objective": "asymmetric_nash_product_within_declared_limits_MECH_7",
        "noZoneBehavior": "non_settling_reflected_stand_in_within_viewer_limits_D75",
    },
    "postSettlementImprovement": {
        "enabled": True,
        "split": 0.5,
        "baseline": "settled_terms_never_walkaways_MECH_10",
        "acceptance": "unanimous_within_mandates_before_execution_proof",
    },
    "stallDetection": {
        "metric": "relative_fraction_of_previous_gap_MECH_3",
        "defaultThreshold": 0.05,
        "defaultWindow": 2,
    },
    "finalOfferDetermination": {
        "contractualNotArbitration": True,
        "consentSource": "principal_signed_mandate_determinationConsent_MECH_1",
        "reference": "round1_declared_symmetric_nash_or_walkaway_midpoint_MECH_8",
        "distance": "mean_declared_weight_normalised_L1_MECH_8",
        "tieBreakDomain": "arbitration-tiebreak",
    },
    "issueNegotiation": {
        "adoptSuggestedOnReject": True,
        "rejectRequiresIssuesHash": True,
        "maxProposals": 3,
    },
    "mandateEscalation": {
        "allowedStatuses": ["BARGAINING", "DETERMINATION"],
        "maxUpdatesPerParty": 3,
        "monotonicWideningOnly": True,
        "freezesDeterminationConsentAtBargainingStart": True,
        "preservesFrozenRound1Private": True,
    },
    "execution": {
        "zeroObligationImmediateHonored": True,
        "uncontestedProofAtDeadline": "HONORED_MECH_2",
        "contestedOrMissingProofAtDeadline": "BREACH_REPORTED",
    },
    "defaults": {
        "maxRounds": 6,
        "maxIssueProposals": 3,
        "feeMode": "FILER_PAYS",
        "windowsMs": {
            "joinTimeoutMs": 24 * 60 * _MINUTE,
            "stageTimeoutMs": 30 * _MINUTE,
            "roundTimeoutMs": 2 * _MINUTE,
            "bargainingWallClockMs": 15 * _MINUTE,
            "determinationTimeoutMs": 10 * _MINUTE,
            "executionTimeoutMs": 7 * 24 * 60 * _MINUTE,
        },
    },
    "windowLimitsMs": {
        "roundTimeoutMs": {"min": 2 * _MINUTE, "max": _HOUR},
        "bargainingWallClockMs": {"min": 10 * _MINUTE, "max": _HOUR},
        "joinTimeoutMs": {"min": _DAY, "max": 30 * _DAY},
        "stageTimeoutMs": {"min": 10 * _MINUTE, "max": 7 * _DAY},
        "determinationTimeoutMs": {"min": 5 * _MINUTE, "max": _DAY},
        "executionTimeoutMs": {"min": _DAY, "max": 90 * _DAY},
    },
})

RULES_HASH: str = sha256_hex(canonical_json(MECHANISM_SPEC))
