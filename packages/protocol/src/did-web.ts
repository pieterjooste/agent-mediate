/**
 * Domain-anchored identity and A2A v1.0 Agent Card signing (DISC-4).
 *
 * - `did:web` W3C DID Document (`/.well-known/did.json`) linking the HTTPS domain to the platform's Ed25519 `did:key`
 *   via `JsonWebKey2020`, `Multikey`, and `alsoKnownAs`.
 * - RFC 7517 JWKS (`/.well-known/jwks.json`) for standard JOSE verifiers following `jku`.
 * - A2A v1.0 `AgentCardSignature`: RFC 7515 detached-payload JWS (`alg: "EdDSA"`, `typ: "JOSE"`) over the
 *   RFC 8785 (JCS) canonical JSON of the Agent Card with `signatures` omitted.
 */
import { sign, verify } from "node:crypto";
import { isIP } from "node:net";
import { canonicalJson } from "@agent-mediate/core";
import { didKeyFromRawPublicKey, isDidKey, publicKeyFromDidKey, type AgentKey } from "./identity.ts";

export interface Ed25519PublicJwk {
  kty: "OKP";
  crv: "Ed25519";
  x: string;
}

export interface DidWebService {
  id: string;
  type: string;
  serviceEndpoint: string;
}

export interface AgentCardSignature {
  protected: string;
  signature: string;
  header?: Record<string, unknown>;
}

const ALLOWED_DID_VM_TYPES: ReadonlySet<string> = new Set([
  "JsonWebKey2020",
  "Multikey",
  "Ed25519VerificationKey2020",
]);

function isValidAsciiDnsOrIpv4Host(host: string): boolean {
  if (!host || /[^\x21-\x7e]/.test(host)) return false;
  const labels = host.split(".");
  if (labels.some((l) => !l)) return false;
  const allNumericOrHex = labels.every((l) => /^(?:0x[0-9a-f]+|\d+)$/i.test(l));
  if (allNumericOrHex) {
    return isIP(host) === 4 && /^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(host);
  }
  return labels.every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l)) && /[a-z]/.test(labels.at(-1)!);
}

/** Derive a W3C `did:web` identifier from an HTTP(S) base URL (ports percent-encoded as `%3A`). */
export function didWebFromUrl(baseUrl: string): string {
  if (typeof baseUrl !== "string" || /[^\x21-\x7e]/.test(baseUrl)) {
    throw new Error("baseUrl must be an ASCII HTTP(S) URL");
  }
  const rawAuthMatch = /^https?:\/\/([^/?#]+)/i.exec(baseUrl);
  if (!rawAuthMatch) {
    throw new Error("baseUrl must be an HTTP(S) URL");
  }
  const rawAuthHost = rawAuthMatch[1]!.split(":")[0]!.toLowerCase();
  const u = new URL(baseUrl);
  if ((u.protocol !== "http:" && u.protocol !== "https:") || u.username !== "" || u.password !== "" || u.search !== "" || u.hash !== "") {
    throw new Error("baseUrl must be an HTTP(S) URL without credentials, query or fragment");
  }
  const rawHost = u.hostname.toLowerCase();
  if (
    !rawHost ||
    rawHost !== rawAuthHost ||
    rawHost === "." ||
    rawHost.includes("..") ||
    rawHost.startsWith(".") ||
    rawHost.endsWith(".") ||
    rawHost.startsWith("[") ||
    !isValidAsciiDnsOrIpv4Host(rawHost)
  ) {
    throw new Error("baseUrl must use a valid DNS hostname or IPv4 address");
  }
  const host = u.port ? `${rawHost}%3A${u.port}` : rawHost;
  const segments = u.pathname
    .split("/")
    .filter(Boolean)
    .map((s) => encodeURIComponent(decodeURIComponent(s)));
  return segments.length > 0 ? `did:web:${host}:${segments.join(":")}` : `did:web:${host}`;
}

/**
 * Resolve a `did:web` identifier to its HTTPS DID document URL per the W3C `did:web` specification.
 * Throws on non-`did:web:` inputs, backslashes/control characters (`%5C` RFC 8615 bypass), dot-segments,
 * or invalid host/port segments.
 */
export function urlFromDidWeb(didWeb: string): string {
  if (typeof didWeb !== "string" || !didWeb.startsWith("did:web:")) {
    throw new Error("not a did:web identifier");
  }
  const rest = didWeb.slice("did:web:".length);
  if (!rest) throw new Error("empty did:web identifier");
  const parts = rest.split(":");
  if (parts.some((p) => p.length === 0)) throw new Error("invalid did:web segment");
  if (/[A-Z]/.test(parts[0]!.replace(/%[0-9A-Fa-f]{2}/g, ""))) {
    throw new Error("invalid did:web host");
  }
  const host = decodeURIComponent(parts[0]!);
  if (!host || host.includes("..") || /[A-Z/?#@\\\s\x00-\x1f\x7f[\]]/.test(host) || host.startsWith(".") || host.endsWith(".")) {
    throw new Error("invalid did:web host");
  }
  if (host.includes(":")) {
    const colonParts = host.split(":");
    if (colonParts.length !== 2 || !colonParts[0] || colonParts[0].endsWith(".")) {
      throw new Error("invalid did:web host");
    }
    const portStr = colonParts[1]!;
    if (!/^[1-9][0-9]{0,4}$/.test(portStr) || Number(portStr) > 65535) {
      throw new Error("invalid did:web host");
    }
  }
  const hostOnly = host.includes(":") ? host.split(":")[0]! : host;
  if (!isValidAsciiDnsOrIpv4Host(hostOnly)) {
    throw new Error("invalid did:web host");
  }
  let parsedOrigin: URL;
  try {
    parsedOrigin = new URL(`https://${host}`);
  } catch {
    throw new Error("invalid did:web host");
  }
  if (
    !parsedOrigin.hostname ||
    parsedOrigin.hostname === "." ||
    parsedOrigin.hostname === ".." ||
    parsedOrigin.username !== "" ||
    parsedOrigin.password !== "" ||
    parsedOrigin.pathname !== "/" ||
    parsedOrigin.search !== "" ||
    parsedOrigin.hash !== ""
  ) {
    throw new Error("invalid did:web host");
  }
  const pathSegments = parts.slice(1).map((p) => {
    const decoded = decodeURIComponent(p);
    if (!decoded || decoded === "." || decoded === ".." || /[/?#\\\x00-\x1f\x7f]/.test(decoded)) {
      throw new Error("invalid did:web path segment");
    }
    return encodeURIComponent(decoded);
  });
  const path = pathSegments.length > 0 ? `/${pathSegments.join("/")}/did.json` : "/.well-known/did.json";
  return `https://${host}${path}`;
}

/** Export a validated Ed25519 `did:key` as an RFC 8037 OKP public JWK (`x` is 43-char unpadded base64url). */
export function ed25519PublicJwkFromDidKey(did: string): Ed25519PublicJwk {
  const pub = publicKeyFromDidKey(did);
  const jwk = pub.export({ format: "jwk" });
  if (jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("not an Ed25519 public key");
  }
  return { kty: "OKP", crv: "Ed25519", x: jwk.x };
}

/** Convert an RFC 8037 Ed25519 public JWK to its canonical `did:key` (rejecting non-canonical or small-order keys). */
export function didKeyFromEd25519Jwk(jwk: { kty?: unknown; crv?: unknown; x?: unknown }): string {
  if (!jwk || jwk.kty !== "OKP" || jwk.crv !== "Ed25519" || typeof jwk.x !== "string") {
    throw new Error("not an Ed25519 OKP JWK");
  }
  if (!/^[A-Za-z0-9_-]{43}$/.test(jwk.x)) {
    throw new Error("invalid Ed25519 JWK x coordinate");
  }
  const raw = Buffer.from(jwk.x, "base64url");
  if (raw.length !== 32 || raw.toString("base64url") !== jwk.x) {
    throw new Error("non-canonical Ed25519 JWK x coordinate");
  }
  const did = didKeyFromRawPublicKey(raw);
  // Run full point + canonical base58 check via publicKeyFromDidKey.
  publicKeyFromDidKey(did);
  return did;
}

/**
 * Build a W3C `did:web` DID Document exposing both `JsonWebKey2020` and `Multikey` verification methods.
 * Retired keys (`status === "retired"`) remain in `alsoKnownAs`, `verificationMethod`, and `assertionMethod`
 * (never `authentication`) so historical outcomes remain verifiable; `revoked` keys are excluded (`KEY-1`).
 */
export function buildDidWebDocument(opts: {
  baseUrl: string;
  platformDid: string;
  services?: DidWebService[];
  historicalKeys?: Array<{ did: string; status: "retired" | "revoked"; revokedAt?: number; compromisedAfter?: number }>;
}) {
  const didWeb = didWebFromUrl(opts.baseUrl);
  const jwk = ed25519PublicJwkFromDidKey(opts.platformDid);
  const multibase = opts.platformDid.slice("did:key:".length);
  const keyJwkId = `${didWeb}#key-1`;
  const keyMultiId = `${didWeb}#key-1-multikey`;
  // CR3-PROTO-M1: exclude any historical key carrying a revocation or compromise marker even if configured as "retired".
  const retired = (opts.historicalKeys ?? []).filter(
    (h) => h.status === "retired" && h.revokedAt === undefined && h.compromisedAfter === undefined && h.did !== opts.platformDid,
  );

  const verificationMethod: Array<Record<string, unknown>> = [
    {
      id: keyJwkId,
      type: "JsonWebKey2020",
      controller: didWeb,
      publicKeyJwk: jwk,
    },
    {
      id: keyMultiId,
      type: "Multikey",
      controller: didWeb,
      publicKeyMultibase: multibase,
    },
  ];
  const assertionMethod: string[] = [keyJwkId, keyMultiId];
  retired.forEach((h, idx) => {
    const rJwkId = `${didWeb}#retired-${idx + 1}`;
    const rMultiId = `${didWeb}#retired-${idx + 1}-multikey`;
    verificationMethod.push(
      {
        id: rJwkId,
        type: "JsonWebKey2020",
        controller: didWeb,
        publicKeyJwk: ed25519PublicJwkFromDidKey(h.did),
      },
      {
        id: rMultiId,
        type: "Multikey",
        controller: didWeb,
        publicKeyMultibase: h.did.slice("did:key:".length),
      },
    );
    assertionMethod.push(rJwkId, rMultiId);
  });

  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://w3id.org/security/suites/jws-2020/v1",
      "https://w3id.org/security/multikey/v1",
    ],
    id: didWeb,
    alsoKnownAs: [opts.platformDid, ...retired.map((r) => r.did)],
    verificationMethod,
    authentication: [keyJwkId, keyMultiId],
    assertionMethod,
    ...(opts.services && opts.services.length > 0 ? { service: opts.services } : {}),
  };
}

/**
 * Verify that a W3C `did:web` DID Document (`/.well-known/did.json`) belongs to `expectedDidWeb`
 * and cryptographically authorises `expectedDidKey` in `authentication` (`MECH-15`, review H4).
 *
 * Strictly requires a non-empty `authentication` relationship (never falling back to `assertionMethod` or
 * bare `verificationMethod`) so retired `assertionMethod`-only keys cannot authenticate, rejects duplicate
 * `verificationMethod[].id` entries per W3C DID Core, and requires `controller === expectedDidWeb`.
 */
export function didWebDocumentAuthorizesKey(
  doc: Record<string, unknown>,
  expectedDidWeb: string,
  expectedDidKey: string,
): boolean {
  try {
    if (!doc || typeof doc !== "object" || Array.isArray(doc)) return false;
    if (typeof expectedDidWeb !== "string" || !expectedDidWeb.startsWith("did:web:")) return false;
    urlFromDidWeb(expectedDidWeb);
    // Validate canonical Ed25519 did:key and small-order rejection.
    publicKeyFromDidKey(expectedDidKey);
    if (doc.id !== expectedDidWeb) return false;
    if (!Array.isArray(doc.authentication) || doc.authentication.length === 0) return false;
    if (doc.verificationMethod !== undefined && !Array.isArray(doc.verificationMethod)) return false;

    const expectedMultibase = expectedDidKey.slice("did:key:".length);
    const normalizeMethodId = (id: string): string => (id.startsWith("#") ? `${expectedDidWeb}${id}` : id);

    const methodMatchesKey = (vm: unknown): boolean => {
      if (!vm || typeof vm !== "object" || Array.isArray(vm)) return false;
      const obj = vm as Record<string, unknown>;
      if (obj.controller !== expectedDidWeb) return false;
      if (typeof obj.type !== "string" || !ALLOWED_DID_VM_TYPES.has(obj.type)) return false;
      const hasJwk = obj.publicKeyJwk !== undefined;
      const hasMultibase = obj.publicKeyMultibase !== undefined;
      if (!hasJwk && !hasMultibase) return false;
      if (obj.type === "JsonWebKey2020" && !hasJwk) return false;
      if (obj.type === "Multikey" && !hasMultibase) return false;
      if (hasJwk) {
        if (!obj.publicKeyJwk || typeof obj.publicKeyJwk !== "object" || Array.isArray(obj.publicKeyJwk)) {
          return false;
        }
        try {
          if (didKeyFromEd25519Jwk(obj.publicKeyJwk as { kty?: unknown; crv?: unknown; x?: unknown }) !== expectedDidKey) {
            return false;
          }
        } catch {
          return false;
        }
      }
      if (hasMultibase) {
        if (typeof obj.publicKeyMultibase !== "string" || obj.publicKeyMultibase !== expectedMultibase) {
          return false;
        }
      }
      return true;
    };

    const methodsById = new Map<string, Record<string, unknown>>();
    if (Array.isArray(doc.verificationMethod)) {
      for (const vm of doc.verificationMethod) {
        if (!vm || typeof vm !== "object" || Array.isArray(vm)) return false;
        const obj = vm as Record<string, unknown>;
        if (typeof obj.id !== "string" || obj.id.length === 0) return false;
        const normId = normalizeMethodId(obj.id);
        if (methodsById.has(normId)) return false;
        methodsById.set(normId, obj);
      }
    }

    const inlineIds = new Set<string>();
    let matchedAuth = false;
    for (const entry of doc.authentication) {
      if (typeof entry === "string" && entry.length > 0) {
        const resolved = methodsById.get(normalizeMethodId(entry));
        if (resolved && methodMatchesKey(resolved)) matchedAuth = true;
      } else if (entry && typeof entry === "object" && !Array.isArray(entry)) {
        const obj = entry as Record<string, unknown>;
        if (typeof obj.id !== "string" || obj.id.length === 0) return false;
        const normId = normalizeMethodId(obj.id);
        if (methodsById.has(normId) || inlineIds.has(normId)) return false;
        inlineIds.add(normId);
        if (methodMatchesKey(obj)) matchedAuth = true;
      } else {
        return false;
      }
    }
    return matchedAuth;
  } catch {
    return false;
  }
}

/**
 * Build an RFC 7517 JSON Web Key Set (`/.well-known/jwks.json`) for the platform signing key.
 * Retired keys (`status === "retired"`) remain in `keys` after the active key; `revoked` keys are excluded (`KEY-1`).
 */
export function buildJwks(opts: {
  baseUrl: string;
  platformDid: string;
  historicalKeys?: Array<{ did: string; status: "retired" | "revoked"; revokedAt?: number; compromisedAfter?: number }>;
}) {
  const didWeb = didWebFromUrl(opts.baseUrl);
  const jwk = ed25519PublicJwkFromDidKey(opts.platformDid);
  // CR3-PROTO-M1: exclude any historical key carrying a revocation or compromise marker even if configured as "retired".
  const retired = (opts.historicalKeys ?? []).filter(
    (h) => h.status === "retired" && h.revokedAt === undefined && h.compromisedAfter === undefined && h.did !== opts.platformDid,
  );
  return {
    keys: [
      {
        ...jwk,
        alg: "EdDSA",
        use: "sig",
        kid: `${didWeb}#key-1`,
      },
      ...retired.map((h, idx) => ({
        ...ed25519PublicJwkFromDidKey(h.did),
        alg: "EdDSA",
        use: "sig",
        kid: `${didWeb}#retired-${idx + 1}`,
      })),
    ],
  };
}

function stripSignatures<T extends Record<string, unknown>>(card: T): Omit<T, "signatures"> {
  const { signatures: _ignored, ...rest } = card;
  return rest;
}

/**
 * Sign an A2A v1.0 Agent Card using RFC 7515 detached-payload JWS (`alg: "EdDSA"`) over the RFC 8785 (JCS)
 * canonical representation of the card with `signatures` omitted.
 */
export function signAgentCard<T extends Record<string, unknown>>(
  card: T,
  key: AgentKey,
  opts: { kid: string; jku?: string },
): Omit<T, "signatures"> & { signatures: AgentCardSignature[] } {
  const unsigned = stripSignatures(card);
  const protectedHeader: Record<string, string> = {
    alg: "EdDSA",
    kid: opts.kid,
    typ: "JOSE",
    ...(opts.jku ? { jku: opts.jku } : {}),
  };
  const protectedB64 = Buffer.from(canonicalJson(protectedHeader), "utf8").toString("base64url");
  const payloadB64 = Buffer.from(canonicalJson(unsigned), "utf8").toString("base64url");
  const signingInput = `${protectedB64}.${payloadB64}`;
  const sigB64 = sign(null, Buffer.from(signingInput, "ascii"), key.privateKey).toString("base64url");
  return {
    ...unsigned,
    signatures: [{ protected: protectedB64, signature: sigB64 }],
  };
}

/**
 * Verify an A2A v1.0 Agent Card's `signatures` array against `expectedDidKey` (RFC 7515 EdDSA JWS over JCS card).
 * Returns false on any malformed input rather than throwing.
 */
export function verifyAgentCardSignature(card: Record<string, unknown>, expectedDidKey: string): boolean {
  try {
    if (!card || typeof card !== "object" || !Array.isArray(card.signatures) || card.signatures.length === 0 || card.signatures.length > 16) {
      return false;
    }
    const pubKey = publicKeyFromDidKey(expectedDidKey);
    const unsigned = stripSignatures(card);
    const payloadB64 = Buffer.from(canonicalJson(unsigned), "utf8").toString("base64url");
    for (const entry of card.signatures as unknown[]) {
      if (!entry || typeof entry !== "object" || Array.isArray(entry)) continue;
      const { protected: prot, signature: sig } = entry as { protected?: unknown; signature?: unknown };
      if (typeof prot !== "string" || typeof sig !== "string") continue;
      if (!/^[A-Za-z0-9_-]+$/.test(prot) || !/^[A-Za-z0-9_-]+$/.test(sig)) continue;
      let header: unknown;
      try {
        header = JSON.parse(Buffer.from(prot, "base64url").toString("utf8"));
      } catch {
        continue;
      }
      if (!header || typeof header !== "object" || Array.isArray(header)) continue;
      if ((header as Record<string, unknown>).alg !== "EdDSA" || "crit" in (header as Record<string, unknown>)) continue;
      const sigBytes = Buffer.from(sig, "base64url");
      if (sigBytes.length !== 64 || sigBytes.toString("base64url") !== sig) continue;
      if (verify(null, Buffer.from(`${prot}.${payloadB64}`, "ascii"), pubKey, sigBytes)) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

const LOCAL_HONOURS_HOSTS = new Set(["localhost", "127.0.0.1", "::1"]);

/** Normalize a DNS domain (including uppercase, trailing dot, IDN punycode, and default `:443` port), rejecting IPs/paths. */
export function normalizeHonoursDomainSubject(raw: string): string | null {
  if (!raw || /[/?#@\\\s\x00-\x1f\x7f]/.test(raw) || raw.startsWith(".")) return null;
  const stripped = raw.replace(/\.+$/, "");
  if (!stripped) return null;
  let u: URL;
  try {
    u = new URL(`https://${stripped}`);
  } catch {
    return null;
  }
  if (u.username !== "" || u.password !== "" || u.pathname !== "/" || u.search !== "" || u.hash !== "") {
    return null;
  }
  const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.+$/, "");
  if (!host || host === "." || host.includes("..")) return null;
  if (isIP(host) !== 0 && !LOCAL_HONOURS_HOSTS.has(host)) return null;
  return u.port && u.port !== "443" ? `${host}:${u.port}` : host;
}

/**
 * Parse a Settlement Honours Roll lookup `:subject` into either `{ kind: "agent", agentId }`,
 * `{ kind: "did_web", domain }`, `{ kind: "domain", domain }`, or `null`.
 */
export function parseHonoursSubject(
  rawSubject: string,
): { kind: "agent"; agentId: string } | { kind: "did_web"; domain: string } | { kind: "domain"; domain: string } | null {
  if (typeof rawSubject !== "string") return null;
  const trimmed = rawSubject.trim();
  if (!trimmed || trimmed.length > 512) return null;
  if (trimmed.startsWith("did:key:")) {
    return isDidKey(trimmed) ? { kind: "agent", agentId: trimmed } : null;
  }
  if (trimmed.startsWith("did:web:")) {
    try {
      const segments = trimmed.slice("did:web:".length).split(":");
      if (segments.length !== 1 || !segments[0]) return null;
      const u = new URL(urlFromDidWeb(trimmed));
      if (u.pathname !== "/.well-known/did.json" || u.search !== "" || u.hash !== "") return null;
      const host = u.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.+$/, "");
      if (!host || (isIP(host) !== 0 && !LOCAL_HONOURS_HOSTS.has(host))) return null;
      const domain = u.port && u.port !== "443" ? `${host}:${u.port}` : host;
      return { kind: "did_web", domain };
    } catch {
      return null;
    }
  }
  const domain = normalizeHonoursDomainSubject(trimmed);
  return domain ? { kind: "domain", domain } : null;
}

