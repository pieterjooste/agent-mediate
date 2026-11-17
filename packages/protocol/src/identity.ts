/**
 * Agent identity: self-certifying `did:key` identifiers for Ed25519 keys.
 *
 * An agent's id *is* its public key (multicodec 0xed01 + 32 raw bytes,
 * base58btc-encoded), so request signatures can be verified without a key
 * registry. Optional domain binding via W3C `did:web` and signed A2A Agent Cards
 * is implemented in `./did-web.ts`.
 */
import {
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  sign,
  verify,
  type KeyObject,
} from "node:crypto";

const ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
const ED25519_MULTICODEC = [0xed, 0x01];
const DID_KEY_PREFIX = "did:key:z";

export interface AgentKey {
  did: string;
  privateKey: KeyObject;
}

export function base58btcEncode(bytes: Uint8Array): string {
  let zeros = 0;
  while (zeros < bytes.length && bytes[zeros] === 0) zeros++;
  let n = 0n;
  for (const b of bytes) n = n * 256n + BigInt(b);
  let out = "";
  while (n > 0n) {
    out = ALPHABET[Number(n % 58n)] + out;
    n /= 58n;
  }
  return "1".repeat(zeros) + out;
}

export function base58btcDecode(s: string): Uint8Array {
  if (typeof s !== "string" || s.length > 256) throw new Error("base58btc string too long");
  let n = 0n;
  for (const ch of s) {
    const i = ALPHABET.indexOf(ch);
    if (i < 0) throw new Error("invalid base58btc character");
    n = n * 58n + BigInt(i);
  }
  const bytes: number[] = [];
  while (n > 0n) {
    bytes.unshift(Number(n % 256n));
    n /= 256n;
  }
  let zeros = 0;
  while (zeros < s.length && s[zeros] === "1") zeros++;
  return Uint8Array.from([...new Array<number>(zeros).fill(0), ...bytes]);
}

export function didKeyFromRawPublicKey(raw: Uint8Array): string {
  if (raw.length !== 32) throw new Error("Ed25519 public key must be 32 bytes");
  return DID_KEY_PREFIX + base58btcEncode(Uint8Array.from([...ED25519_MULTICODEC, ...raw]));
}

export function didKeyFromPublicKey(publicKey: KeyObject): string {
  const x = publicKey.export({ format: "jwk" }).x;
  if (!x) throw new Error("not an Ed25519 public key");
  return didKeyFromRawPublicKey(Buffer.from(x, "base64url"));
}

/** Throws on anything that is not a well-formed Ed25519 did:key. */
export function publicKeyFromDidKey(did: string): KeyObject {
  if (typeof did !== "string" || !did.startsWith(DID_KEY_PREFIX) || did.length > 64) {
    throw new Error("not an Ed25519 did:key");
  }
  const bytes = base58btcDecode(did.slice(DID_KEY_PREFIX.length));
  if (bytes.length !== 34 || bytes[0] !== ED25519_MULTICODEC[0] || bytes[1] !== ED25519_MULTICODEC[1]) {
    throw new Error("not an Ed25519 did:key");
  }
  const raw = bytes.subarray(2);
  // Security review L2: a small-order point (e.g. the identity) is a "public key" under which anyone can produce
  // valid signatures, and non-canonical encodings give one key several ids.
  const problem = weakPointReason(raw);
  if (problem) throw new Error(`not an acceptable Ed25519 did:key (${problem})`);
  // Canonical base58 too: one key, one id.
  if (DID_KEY_PREFIX + base58btcEncode(bytes) !== did) throw new Error("not an Ed25519 did:key (non-canonical encoding)");
  return createPublicKey({
    key: { kty: "OKP", crv: "Ed25519", x: Buffer.from(raw).toString("base64url") },
    format: "jwk",
  });
}

// --- Ed25519 point checks (RFC 8032 §5.1.3 decoding; edwards25519, a = -1) ---------------------------------

const P = 2n ** 255n - 19n;
const D = mod(-121665n * modInverse(121666n));
const SQRT_M1 = modPow(2n, (P - 1n) / 4n);

function mod(a: bigint): bigint {
  const r = a % P;
  return r >= 0n ? r : r + P;
}
function modPow(base: bigint, exp: bigint): bigint {
  let result = 1n;
  let b = mod(base);
  let e = exp;
  while (e > 0n) {
    if (e & 1n) result = (result * b) % P;
    b = (b * b) % P;
    e >>= 1n;
  }
  return result;
}
function modInverse(a: bigint): bigint {
  return modPow(a, P - 2n);
}

/**
 * Why a 32-byte Ed25519 public key encoding is unacceptable, or null if it is fine:
 * - y ≥ p, or x = 0 with the sign bit set: non-canonical encodings;
 * - no point on the curve with that y;
 * - small order: [8]P is the identity (the eight torsion points, including the identity itself).
 */
export function weakPointReason(raw: Uint8Array): string | null {
  if (raw.length !== 32) return "public key must be 32 bytes";
  let y = 0n;
  for (let i = 31; i >= 0; i--) y = (y << 8n) | BigInt(i === 31 ? raw[i]! & 0x7f : raw[i]!);
  const sign = (raw[31]! >> 7) & 1;
  if (y >= P) return "non-canonical encoding";
  // x² = (y² − 1) / (d·y² + 1)
  const u = mod(y * y - 1n);
  const v = mod(D * y * y + 1n);
  let x = mod(u * modPow(v, 3n) * modPow(u * modPow(v, 7n), (P - 5n) / 8n));
  const vx2 = mod(v * x * x);
  if (vx2 === mod(-u)) x = mod(x * SQRT_M1);
  else if (vx2 !== u) return "not a curve point";
  if (x === 0n && sign === 1) return "non-canonical encoding";
  if (Number(x & 1n) !== sign) x = mod(-x);
  // Small-order check: double three times in extended coordinates (RFC 8032 §5.1.4).
  let X = x;
  let Y = y;
  let Z = 1n;
  for (let i = 0; i < 3; i++) {
    const A = mod(X * X);
    const B = mod(Y * Y);
    const C = mod(2n * Z * Z);
    const H = mod(A + B);
    const E = mod(H - mod((X + Y) * (X + Y)));
    const G = mod(A - B);
    const F = mod(C + G);
    X = mod(E * F);
    Y = mod(G * H);
    Z = mod(F * G);
  }
  if (X === 0n && Y === Z) return "small-order point";
  return null;
}

export function isDidKey(did: string): boolean {
  try {
    publicKeyFromDidKey(did);
    return true;
  } catch {
    return false;
  }
}

export function generateAgentKey(): AgentKey {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return { did: didKeyFromPublicKey(publicKey), privateKey };
}

/** Load a PKCS#8 PEM Ed25519 private key (e.g. the platform signing key from a secret). */
export function agentKeyFromPem(pem: string): AgentKey {
  const privateKey = createPrivateKey(pem);
  if (privateKey.asymmetricKeyType !== "ed25519") throw new Error("platform key must be Ed25519");
  return { did: didKeyFromPublicKey(createPublicKey(privateKey)), privateKey };
}

export function signText(key: AgentKey, text: string): string {
  return sign(null, Buffer.from(text, "utf8"), key.privateKey).toString("base64");
}

/** False on any malformed input rather than throwing. */
export function verifyText(did: string, text: string, signatureB64: string): boolean {
  try {
    if (typeof signatureB64 !== "string") return false;
    const raw = Buffer.from(signatureB64, "base64");
    if (raw.length !== 64 || raw.toString("base64") !== signatureB64) return false;
    return verify(null, Buffer.from(text, "utf8"), publicKeyFromDidKey(did), raw);
  } catch {
    return false;
  }
}
