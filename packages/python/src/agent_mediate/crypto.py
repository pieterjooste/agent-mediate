"""
Pure-Python RFC 8032 Ed25519, PKCS#8 PEM import/export, and W3C Ed25519 `did:key` (`did:key:z6Mk...`).

Zero third-party or C dependencies (Python 3.9+ stdlib only). Includes full canonical encoding and
8-torsion small-order public key rejection matching `@agent-mediate/protocol`.
"""
from __future__ import annotations

import base64
import hashlib
import os
from dataclasses import dataclass, field
from typing import Optional, Tuple

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey as _FastEd25519PrivateKey  # type: ignore[import-not-found]
except Exception:
    _FastEd25519PrivateKey = None

ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
ALPHABET_INDEX = {ch: i for i, ch in enumerate(ALPHABET)}
ED25519_MULTICODEC = b"\xed\x01"
DID_KEY_PREFIX = "did:key:z"

# RFC 8410 PKCS#8 v0 DER prefix for Ed25519 (OID 1.3.101.112 = 06 03 2b 65 70) + OCTET STRING(OCTET STRING(32))
PKCS8_ED25519_PREFIX = bytes.fromhex("302e020100300506032b657004220420")
ED25519_OID_DER = bytes.fromhex("06032b6570")

# Edwards25519 curve constants (RFC 8032 §5.1)
P = (1 << 255) - 19
L = (1 << 252) + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
D2 = (2 * D) % P
SQRT_M1 = pow(2, (P - 1) // 4, P)

_GY = (4 * pow(5, P - 2, P)) % P
_GU = (_GY * _GY - 1) % P
_GV = (D * _GY * _GY + 1) % P
_GX = (_GU * pow(_GV, 3, P) * pow(_GU * pow(_GV, 7, P) % P, (P - 5) // 8, P)) % P
if (_GV * _GX * _GX) % P != _GU:
    _GX = (_GX * SQRT_M1) % P
if _GX & 1:
    _GX = P - _GX
# Extended twisted Edwards coordinates (X, Y, Z, T) where x = X/Z, y = Y/Z, x*y = T/Z
ExtendedPoint = Tuple[int, int, int, int]
BASE_POINT: ExtendedPoint = (_GX, _GY, 1, (_GX * _GY) % P)
IDENTITY_POINT: ExtendedPoint = (0, 1, 1, 0)


def _point_add(p1: ExtendedPoint, p2: ExtendedPoint) -> ExtendedPoint:
    x1, y1, z1, t1 = p1
    x2, y2, z2, t2 = p2
    a = ((y1 - x1) * (y2 - x2)) % P
    b = ((y1 + x1) * (y2 + x2)) % P
    c = (t1 * D2 * t2) % P
    d = (2 * z1 * z2) % P
    e = (b - a) % P
    f = (d - c) % P
    g = (d + c) % P
    h = (b + a) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _point_double(pt: ExtendedPoint) -> ExtendedPoint:
    x1, y1, z1, _ = pt
    a = (x1 * x1) % P
    b = (y1 * y1) % P
    c = (2 * z1 * z1) % P
    h = (a + b) % P
    xy = (x1 + y1) % P
    e = (h - xy * xy) % P
    g = (a - b) % P
    f = (c + g) % P
    return ((e * f) % P, (g * h) % P, (f * g) % P, (e * h) % P)


def _scalar_mult(k: int, pt: ExtendedPoint = BASE_POINT) -> ExtendedPoint:
    res = IDENTITY_POINT
    addend = pt
    n = k
    while n > 0:
        if n & 1:
            res = _point_add(res, addend)
        addend = _point_double(addend)
        n >>= 1
    return res


def _encode_point(pt: ExtendedPoint) -> bytes:
    x, y, z, _ = pt
    zi = pow(z, P - 2, P)
    xp = (x * zi) % P
    yp = (y * zi) % P
    raw = bytearray(yp.to_bytes(32, "little"))
    raw[31] |= (xp & 1) << 7
    return bytes(raw)


def _decode_point(raw: bytes) -> Optional[ExtendedPoint]:
    if len(raw) != 32:
        return None
    y_bytes = bytearray(raw)
    sign = (y_bytes[31] >> 7) & 1
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")
    if y >= P:
        return None
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow((u * pow(v, 7, P)) % P, (P - 5) // 8, P)) % P
    vx2 = (v * x * x) % P
    if vx2 == (-u) % P:
        x = (x * SQRT_M1) % P
    elif vx2 != u:
        return None
    if x == 0 and sign == 1:
        return None
    if (x & 1) != sign:
        x = P - x
    return (x, y, 1, (x * y) % P)


def _decode_valid_public_key(raw: bytes) -> Tuple[Optional[ExtendedPoint], Optional[str]]:
    if len(raw) != 32:
        return None, "public key must be 32 bytes"
    y_bytes = bytearray(raw)
    sign = (y_bytes[31] >> 7) & 1
    y_bytes[31] &= 0x7F
    y = int.from_bytes(y_bytes, "little")
    if y >= P:
        return None, "non-canonical encoding"
    u = (y * y - 1) % P
    v = (D * y * y + 1) % P
    x = (u * pow(v, 3, P) * pow((u * pow(v, 7, P)) % P, (P - 5) // 8, P)) % P
    vx2 = (v * x * x) % P
    if vx2 == (-u) % P:
        x = (x * SQRT_M1) % P
    elif vx2 != u:
        return None, "not a curve point"
    if x == 0 and sign == 1:
        return None, "non-canonical encoding"
    if (x & 1) != sign:
        x = P - x
    pt: ExtendedPoint = (x, y, 1, (x * y) % P)
    p8 = _point_double(_point_double(_point_double(pt)))
    if p8[0] == 0 and p8[1] == p8[2]:
        return None, "small-order point"
    return pt, None


def weak_point_reason(raw: bytes) -> Optional[str]:
    return _decode_valid_public_key(raw)[1]


def _clamp_seed(seed: bytes) -> Tuple[int, bytes, bytes]:
    if len(seed) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    h = bytearray(hashlib.sha512(seed).digest())
    h[0] &= 248
    h[31] &= 127
    h[31] |= 64
    a = int.from_bytes(h[:32], "little")
    prefix = bytes(h[32:])
    pub = _encode_point(_scalar_mult(a))
    return a, prefix, pub


def ed25519_public_from_seed(seed: bytes) -> bytes:
    _, _, pub = _clamp_seed(seed)
    return pub


def ed25519_sign(seed: bytes, message: bytes) -> bytes:
    if len(seed) != 32:
        raise ValueError("Ed25519 private seed must be 32 bytes")
    if _FastEd25519PrivateKey is not None:
        return _FastEd25519PrivateKey.from_private_bytes(seed).sign(message)
    a, prefix, pub = _clamp_seed(seed)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), "little") % L
    r_bytes = _encode_point(_scalar_mult(r))
    k = int.from_bytes(hashlib.sha512(r_bytes + pub + message).digest(), "little") % L
    s = (r + k * a) % L
    return r_bytes + s.to_bytes(32, "little")


def ed25519_verify(public_key: bytes, message: bytes, signature: bytes) -> bool:
    if len(signature) != 64:
        return False
    a_pt, reason = _decode_valid_public_key(public_key)
    if reason is not None or a_pt is None:
        return False
    r_pt = _decode_point(signature[:32])
    if r_pt is None:
        return False
    s = int.from_bytes(signature[32:], "little")
    if s >= L:
        return False
    k = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), "little") % L
    # Compute rhs_zero = [S]B - R - [k]A after canonical point (y < P), S < L, and non-small-order A checks,
    # enforcing strict cofactorless verification ([S]B == R + [k]A) to match Node.js/OpenSSL ED25519_verify
    # and prevent small-order torsion-R signature split attacks across runtimes.
    lhs = _scalar_mult(s)
    neg_a = ((-a_pt[0]) % P, a_pt[1], a_pt[2], (-a_pt[3]) % P)
    rhs_zero = _point_add(lhs, _point_add(((-r_pt[0]) % P, r_pt[1], r_pt[2], (-r_pt[3]) % P), _scalar_mult(k, neg_a)))
    return rhs_zero[0] == 0 and rhs_zero[1] == rhs_zero[2]


def base58btc_encode(data: bytes) -> str:
    zeros = 0
    while zeros < len(data) and data[zeros] == 0:
        zeros += 1
    n = int.from_bytes(data, "big")
    chars = []
    while n > 0:
        n, rem = divmod(n, 58)
        chars.append(ALPHABET[rem])
    return ("1" * zeros) + "".join(reversed(chars))


def base58btc_decode(text: str) -> bytes:
    if not isinstance(text, str) or len(text) > 128:
        raise ValueError("base58btc input exceeds maximum length")
    n = 0
    for ch in text:
        idx = ALPHABET_INDEX.get(ch)
        if idx is None:
            raise ValueError("invalid base58btc character")
        n = n * 58 + idx
    out = bytearray()
    while n > 0:
        n, rem = divmod(n, 256)
        out.append(rem)
    out.reverse()
    zeros = 0
    while zeros < len(text) and text[zeros] == "1":
        zeros += 1
    return (b"\x00" * zeros) + bytes(out)


def did_key_from_raw_public_key(raw: bytes) -> str:
    if len(raw) != 32:
        raise ValueError("Ed25519 public key must be 32 bytes")
    return DID_KEY_PREFIX + base58btc_encode(ED25519_MULTICODEC + raw)


def raw_public_key_from_did_key(did: str) -> bytes:
    if not isinstance(did, str) or not did.startswith(DID_KEY_PREFIX) or len(did) > 64:
        raise ValueError("not an Ed25519 did:key")
    decoded = base58btc_decode(did[len(DID_KEY_PREFIX) :])
    if len(decoded) != 34 or decoded[:2] != ED25519_MULTICODEC:
        raise ValueError("not an Ed25519 did:key")
    raw = decoded[2:]
    reason = weak_point_reason(raw)
    if reason is not None:
        raise ValueError(f"not an acceptable Ed25519 did:key ({reason})")
    if DID_KEY_PREFIX + base58btc_encode(decoded) != did:
        raise ValueError("not an Ed25519 did:key (non-canonical encoding)")
    return raw


def is_did_key(did: object) -> bool:
    if not isinstance(did, str):
        return False
    try:
        raw_public_key_from_did_key(did)
        return True
    except Exception:
        return False


@dataclass(frozen=True)
class AgentKey:
    did: str
    # CR-SDK-M2: the Ed25519 private seed must never appear in repr()/logs/tracebacks/error-tracker locals.
    seed: bytes = field(repr=False)
    public_key: bytes = field(repr=False)

    def __repr__(self) -> str:
        return f"AgentKey(did={self.did!r})"

    def sign_bytes(self, data: bytes) -> bytes:
        return ed25519_sign(self.seed, data)

    def sign_text(self, text: str) -> str:
        return base64.b64encode(self.sign_bytes(text.encode("utf-8"))).decode("ascii")

    def to_pem(self) -> str:
        der = PKCS8_ED25519_PREFIX + self.seed
        b64 = base64.b64encode(der).decode("ascii")
        lines = [b64[i : i + 64] for i in range(0, len(b64), 64)]
        return "-----BEGIN PRIVATE KEY-----\n" + "\n".join(lines) + "\n-----END PRIVATE KEY-----\n"


def generate_agent_key() -> AgentKey:
    seed = os.urandom(32)
    pub = ed25519_public_from_seed(seed)
    return AgentKey(did=did_key_from_raw_public_key(pub), seed=seed, public_key=pub)


def agent_key_from_seed(seed: bytes) -> AgentKey:
    if len(seed) != 32:
        raise ValueError("Ed25519 seed must be 32 bytes")
    pub = ed25519_public_from_seed(seed)
    return AgentKey(did=did_key_from_raw_public_key(pub), seed=bytes(seed), public_key=pub)


def _read_der_tlv(buf: bytes, offset: int) -> Tuple[int, bytes, int]:
    if offset + 2 > len(buf):
        raise ValueError("truncated ASN.1 DER element")
    tag = buf[offset]
    first_len = buf[offset + 1]
    if first_len < 0x80:
        length = first_len
        val_start = offset + 2
    else:
        num_bytes = first_len & 0x7F
        if num_bytes == 0 or num_bytes > 4 or offset + 2 + num_bytes > len(buf):
            raise ValueError("invalid ASN.1 DER length encoding")
        if buf[offset + 2] == 0:
            raise ValueError("non-minimal ASN.1 DER length encoding")
        length = int.from_bytes(buf[offset + 2 : offset + 2 + num_bytes], "big")
        if length < 0x80:
            raise ValueError("non-minimal ASN.1 DER short length encoded in long form")
        val_start = offset + 2 + num_bytes
    val_end = val_start + length
    if val_end > len(buf):
        raise ValueError("ASN.1 DER element exceeds buffer")
    return tag, buf[val_start:val_end], val_end


def agent_key_from_pem(pem: str) -> AgentKey:
    if not isinstance(pem, str) or len(pem) > 16_384:
        raise ValueError("PEM must be a string")
    raw_lines = [ln.strip() for ln in pem.strip().splitlines() if ln.strip()]
    if len(raw_lines) < 3 or raw_lines[0] != "-----BEGIN PRIVATE KEY-----" or raw_lines[-1] != "-----END PRIVATE KEY-----":
        raise ValueError("PEM must be a PKCS#8 PRIVATE KEY block")
    body = "".join(raw_lines[1:-1])
    if any(ln.startswith("-----") for ln in raw_lines[1:-1]):
        raise ValueError("PEM contains unexpected armor line")
    try:
        der = base64.b64decode(body, validate=True)
    except Exception as exc:
        raise ValueError("PEM contains invalid base64") from exc
    if der.startswith(PKCS8_ED25519_PREFIX) and len(der) == 48:
        return agent_key_from_seed(der[16:48])
    try:
        outer_tag, seq_body, outer_end = _read_der_tlv(der, 0)
        if outer_tag != 0x30 or outer_end != len(der):
            raise ValueError("outer PKCS#8 wrapper must be a single DER SEQUENCE")
        ver_tag, ver_val, pos = _read_der_tlv(seq_body, 0)
        if ver_tag != 0x02 or ver_val not in (b"\x00", b"\x01"):
            raise ValueError("unsupported PKCS#8 version")
        version = ver_val[0]
        alg_tag, alg_val, pos = _read_der_tlv(seq_body, pos)
        if alg_tag != 0x30 or alg_val != ED25519_OID_DER:
            raise ValueError("PKCS#8 AlgorithmIdentifier must be Ed25519 (OID 1.3.101.112 with absent parameters)")
        priv_tag, priv_val, pos = _read_der_tlv(seq_body, pos)
        if priv_tag != 0x04:
            raise ValueError("PKCS#8 privateKey must be an OCTET STRING")
        seed_tag, seed_bytes, seed_end = _read_der_tlv(priv_val, 0)
        if seed_tag != 0x04 or len(seed_bytes) != 32 or seed_end != len(priv_val):
            raise ValueError("Ed25519 CurvePrivateKey must be a 32-byte OCTET STRING")
        embedded_pub: Optional[bytes] = None
        seen_attrs = False
        while pos < len(seq_body):
            opt_tag, opt_val, pos = _read_der_tlv(seq_body, pos)
            if opt_tag == 0xA0 and not seen_attrs and embedded_pub is None:
                attr_pos = 0
                while attr_pos < len(opt_val):
                    _, _, attr_pos = _read_der_tlv(opt_val, attr_pos)
                seen_attrs = True
            elif opt_tag == 0x81 and version == 1 and embedded_pub is None:
                if len(opt_val) != 33 or opt_val[0] != 0x00:
                    raise ValueError("OneAsymmetricKey [1] publicKey BIT STRING must be 32 bytes with 0 unused bits")
                embedded_pub = opt_val[1:]
            elif opt_tag == 0xA1 and version == 1 and embedded_pub is None:
                bs_tag, bs_val, bs_end = _read_der_tlv(opt_val, 0)
                if bs_tag != 0x03 or bs_end != len(opt_val) or len(bs_val) != 33 or bs_val[0] != 0x00:
                    raise ValueError("OneAsymmetricKey [1] publicKey BIT STRING is malformed")
                embedded_pub = bs_val[1:]
            else:
                raise ValueError("unexpected trailing field in PKCS#8 PRIVATE KEY")
    except ValueError as exc:
        raise ValueError("PEM is not a valid Ed25519 PKCS#8 PRIVATE KEY") from exc
    key = agent_key_from_seed(seed_bytes)
    if embedded_pub is not None and embedded_pub != key.public_key:
        raise ValueError("PEM is not a valid Ed25519 PKCS#8 PRIVATE KEY (embedded publicKey mismatches private seed)")
    return key


def verify_text(did: str, text: str, signature_b64: str) -> bool:
    try:
        if not isinstance(signature_b64, str):
            return False
        pub = raw_public_key_from_did_key(did)
        sig = base64.b64decode(signature_b64, validate=True)
        if len(sig) != 64 or base64.b64encode(sig).decode("ascii") != signature_b64:
            return False
        return ed25519_verify(pub, text.encode("utf-8"), sig)
    except Exception:
        return False
