/**
 * Out-of-band respondent discovery helper (`discoverRespondent`).
 *
 * Probes public metadata for a target domain, HTTPS URL, or `did:web` before filing a dispute:
 * 1. Agent-Mediate Settlement Honours Roll (`GET /v1/honours/:domain`, when `baseUrl` and `platformDid` are supplied)
 * 2. A2A Agent Card (`/.well-known/agent-card.json`, fallback `/.well-known/agent.json`, or same-origin HTTP `Link` header)
 * 3. W3C `did:web` document (`/.well-known/did.json` or path-scoped `/.../did.json`)
 * 4. RFC 9116 `/.well-known/security.txt` (`Contact: mailto:...` operator fallback)
 *
 * Security invariants (`CR3-SDK-H1`, `CR3-MCP-H1`, `CR3-SDK-M1`):
 * - Non-loopback targets must use `https://` on port 443, pass DNS resolution against global-unicast IPv4/IPv6 checks,
 *   and connect via an IP-pinned Node socket when using the default network transport (preventing host-network SSRF and DNS rebinding).
 * - Agent Cards must bind positively to the target origin before their EdDSA JWS signatures can bind `respondentId`.
 * - Honours Roll entries are trusted only when `platformDid` verifies the active 24h `signedAttestation` document.
 * - `did:web` documents must both authorize `candidate` in `authentication` (`didWebDocumentAuthorizesKey(didDoc, expectedDidWeb, candidate)`)
 *   and carry cryptographic proof-of-possession (a JWS signature on `did.json` or an origin-bound Agent Card).
 */
import { lookup as dnsLookup } from "node:dns/promises";
import http from "node:http";
import https from "node:https";
import { isIP, type LookupFunction } from "node:net";
import {
  DEFAULT_PRODUCTION_PLATFORM_DIDS,
  normalizeBaseUrl,
  PRODUCTION_API_URL,
} from "@agent-mediate/core";
import {
  DEFAULT_KEY_HISTORY_TTL_MS,
  didKeyFromEd25519Jwk,
  didWebDocumentAuthorizesKey,
  didWebFromUrl,
  HONOURS_ATTESTATION_TYPE,
  isDidKey,
  urlFromDidWeb,
  verifyAgentCardSignature,
  verifyDocument,
  verifyKeyHistory,
  type Ed25519PublicJwk,
  type HonoursAttestationDocument,
  type KeyHistoryDocument,
  type PartyContact,
  type SignedDocument,
} from "@agent-mediate/protocol";

export type DiscoverySource = "honours" | "a2a_card" | "did_web" | "link_header" | "security_txt";

export interface DiscoveryResolvedAddress {
  address: string;
  family: 4 | 6;
}

export type DiscoveryHostResolver = (hostname: string) => Promise<DiscoveryResolvedAddress[]>;

export interface DiscoverRespondentOptions {
  /** Optional Agent-Mediate API base URL (e.g. `https://api.ai-agents-mediation.com`) to check `/v1/honours/:domain`. */
  baseUrl?: string;
  /** Pinned platform `did:key` used to verify `/v1/honours/:domain` attestations when `baseUrl` is supplied. */
  platformDid?: string;
  /** Optional expected deployment environment (e.g. `"production"`) checked on Honours attestations. */
  expectedEnvironment?: string;
  /** Optional expected mechanism `rulesHash` checked on Honours attestations. */
  expectedRulesHash?: string;
  /** Custom `fetch` implementation for target probes (for unit tests; when omitted, target probes use DNS-vetted IP-pinned sockets). */
  fetch?: (url: string, init?: RequestInit) => Promise<Response>;
  /** Custom `fetch` implementation exclusively for the trusted Agent-Mediate `baseUrl` Honours lookup. */
  apiFetch?: (url: string, init?: RequestInit) => Promise<Response>;
  /** Optional DNS resolver override for SSRF target vetting. */
  resolveHost?: DiscoveryHostResolver;
  /** Per-probe timeout in milliseconds (default `3_000`). */
  timeoutMs?: number;
  /** Allow `http://` (and arbitrary ports) strictly on `localhost` / `127.0.0.1` / `[::1]` for local tests (default `false`). */
  allowInsecureHttp?: boolean;
  /** Clock override for attestation TTL checks. */
  now?: () => number;
}

export interface DiscoveredRespondent {
  domain: string;
  origin: string;
  respondentId: string | null;
  respondentContact: PartyContact;
  verifiedStanding: boolean;
  hasVerifiedNoticeChannel: boolean;
  recommendedAction: "file_dispute" | "send_invite";
  sources: DiscoverySource[];
}

const MAX_DISCOVERY_BYTES = 128 * 1024;
const SIMPLE_EMAIL_RE = /^[^\s@<>,"';:\\]+@[^\s@<>,"';:\\]+\.[^\s@<>,"';:\\]+$/;
const BLOCKED_SUFFIXES = [".localhost", ".local", ".internal", ".home.arpa", ".lan", ".intranet", ".corp", ".private"];
const BLOCKED_NAMES = new Set(["localhost", "metadata.google.internal", "metadata", "instance-data"]);

const defaultResolveHost: DiscoveryHostResolver = async (hostname) =>
  (await dnsLookup(hostname, { all: true, verbatim: true })).map((a) => ({
    address: a.address,
    family: a.family === 6 ? 6 : 4,
  }));

function isLoopbackHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase();
  return h === "localhost" || h === "127.0.0.1" || h === "::1";
}

function isInternalOrIpHost(hostname: string): boolean {
  const h = hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.+$/, "");
  if (!h || h.includes(":")) return true;
  if (isIP(h) !== 0 || /^\d{1,3}(?:\.\d{1,3}){3}$/.test(h) || /^[0-9.]+$/.test(h) || /^0x/i.test(h)) return true;
  if (!h.includes(".")) return true;
  if (BLOCKED_NAMES.has(h) || BLOCKED_SUFFIXES.some((s) => h.endsWith(s))) {
    return true;
  }
  return false;
}

const V4_BLOCKED: Array<[string, number]> = [
  ["0.0.0.0", 8],
  ["10.0.0.0", 8],
  ["100.64.0.0", 10],
  ["127.0.0.0", 8],
  ["169.254.0.0", 16],
  ["172.16.0.0", 12],
  ["192.0.0.0", 24],
  ["192.0.2.0", 24],
  ["192.88.99.0", 24],
  ["192.168.0.0", 16],
  ["198.18.0.0", 15],
  ["198.51.100.0", 24],
  ["203.0.113.0", 24],
  ["224.0.0.0", 4],
  ["240.0.0.0", 4],
];

function v4ToInt(ip: string): number {
  return ip.split(".").reduce((acc, o) => acc * 256 + Number(o), 0);
}

function v4Global(ip: string): boolean {
  const n = v4ToInt(ip);
  return !V4_BLOCKED.some(([base, bits]) => {
    const size = 2 ** (32 - bits);
    const start = v4ToInt(base);
    return n >= start && n < start + size;
  });
}

function v6Hextets(ip: string): number[] | null {
  let s = ip.toLowerCase().replace(/%.*$/, "");
  const v4 = /(\d+\.\d+\.\d+\.\d+)$/.exec(s);
  if (v4) {
    if (isIP(v4[1]!) !== 4) return null;
    const n = v4ToInt(v4[1]!);
    s = s.slice(0, -v4[1]!.length) + `${(n >>> 16).toString(16)}:${(n & 0xffff).toString(16)}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const parse = (part: string) => (part === "" ? [] : part.split(":").map((h) => parseInt(h, 16)));
  const head = parse(halves[0]!);
  const tail = halves.length === 2 ? parse(halves[1]!) : [];
  const fill = 8 - head.length - tail.length;
  if (fill < 0 || (halves.length === 1 && fill !== 0)) return null;
  const all = [...head, ...new Array<number>(halves.length === 2 ? fill : 0).fill(0), ...tail];
  return all.length === 8 && all.every((h) => Number.isInteger(h) && h >= 0 && h <= 0xffff) ? all : null;
}

function v6Global(ip: string): boolean {
  const h = v6Hextets(ip);
  if (!h) return false;
  if ((h[0]! & 0xe000) !== 0x2000) return false;
  if (h[0] === 0x2001 && h[1]! < 0x0200) return false;
  if (h[0] === 0x2001 && h[1] === 0x0db8) return false;
  if (h[0] === 0x2002) return false;
  if (h[0] === 0x3fff && h[1]! < 0x1000) return false;
  return true;
}

export function isPublicIpAddress(ip: string): boolean {
  const family = isIP(ip);
  if (family === 4) return v4Global(ip);
  if (family === 6) return v6Global(ip);
  return false;
}

function normalizeTargetOrigin(
  target: string,
  allowInsecureHttp: boolean,
): { origin: string; domain: string; isLoopback: boolean; initialDidWeb?: string; didDocUrl: string } {
  const trimmed = target.trim();
  if (!trimmed) throw new Error("target must be a non-empty domain, URL, or did:web");
  if (trimmed.startsWith("did:web:")) {
    const docUrl = new URL(urlFromDidWeb(trimmed));
    const loopback = isLoopbackHost(docUrl.hostname);
    if (loopback) {
      if (!allowInsecureHttp) {
        throw new Error("target must be a public domain name");
      }
    } else {
      if (docUrl.protocol !== "https:") {
        throw new Error("target URL must use https://");
      }
      if (docUrl.port !== "" && docUrl.port !== "443") {
        throw new Error("target URL must use default https port 443");
      }
      if (isInternalOrIpHost(docUrl.hostname)) {
        throw new Error("target must be a public domain name");
      }
    }
    const cleanHost = docUrl.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.+$/, "");
    return {
      origin: docUrl.origin,
      domain: cleanHost,
      isLoopback: loopback,
      initialDidWeb: trimmed,
      didDocUrl: docUrl.toString(),
    };
  }
  const withScheme = /^[a-zA-Z][a-zA-Z0-9+.-]*:\/\//.test(trimmed) ? trimmed : `https://${trimmed}`;
  const parsed = new URL(withScheme);
  if (parsed.username || parsed.password) {
    throw new Error("target URL must not contain credentials");
  }
  const loopback = isLoopbackHost(parsed.hostname);
  if (loopback) {
    if (!allowInsecureHttp) {
      throw new Error("target must be a public domain name");
    }
    if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
      throw new Error(`unsupported target protocol ${parsed.protocol}`);
    }
  } else {
    if (parsed.protocol !== "https:") {
      throw new Error("target URL must use https://");
    }
    if (parsed.port !== "" && parsed.port !== "443") {
      throw new Error("target URL must use default https port 443");
    }
    if (isInternalOrIpHost(parsed.hostname)) {
      throw new Error("target must be a public domain name");
    }
  }
  const cleanHost = parsed.hostname.replace(/^\[|\]$/g, "").toLowerCase().replace(/\.+$/, "");
  return {
    origin: parsed.origin,
    domain: cleanHost,
    isLoopback: loopback,
    didDocUrl: `${parsed.origin}/.well-known/did.json`,
  };
}

type TextResponse = { status: number; headers: Headers; text: string };
type BoundedGetter = (url: string, accept: string) => Promise<TextResponse | null>;

async function fetchTextBounded(
  fetchImpl: (url: string, init?: RequestInit) => Promise<Response>,
  url: string,
  accept: string,
  timeoutMs: number,
): Promise<TextResponse | null> {
  let res: Response;
  try {
    res = await fetchImpl(url, {
      method: "GET",
      headers: { accept },
      redirect: "error",
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    return null;
  }
  if (!res.ok) {
    await res.body?.cancel().catch(() => {});
    return null;
  }
  const declared = Number(res.headers.get("content-length") ?? 0);
  if (Number.isFinite(declared) && declared > MAX_DISCOVERY_BYTES) {
    await res.body?.cancel().catch(() => {});
    return null;
  }
  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    const chunks: string[] = [];
    let total = 0;
    try {
      for (;;) {
        const { done, value } = await reader.read();
        if (done) break;
        if (value) {
          total += value.byteLength;
          if (total > MAX_DISCOVERY_BYTES) {
            await reader.cancel().catch(() => {});
            return null;
          }
          chunks.push(decoder.decode(value, { stream: true }));
        }
      }
      chunks.push(decoder.decode());
      return { status: res.status, headers: res.headers, text: chunks.join("") };
    } catch {
      return null;
    }
  }
  try {
    const text = await res.text();
    if (Buffer.byteLength(text, "utf8") > MAX_DISCOVERY_BYTES) return null;
    return { status: res.status, headers: res.headers, text };
  } catch {
    return null;
  }
}

async function pinnedNodeGetBounded(
  url: string,
  accept: string,
  timeoutMs: number,
  pins: DiscoveryResolvedAddress[] | null,
): Promise<TextResponse | null> {
  const u = new URL(url);
  const mod = u.protocol === "https:" ? https : http;
  const candidates: Array<DiscoveryResolvedAddress | null> = pins && pins.length > 0 ? pins.slice(0, 2) : [null];
  const signal = AbortSignal.timeout(timeoutMs);

  const attempt = (pin: DiscoveryResolvedAddress | null) =>
    new Promise<TextResponse | null>((resolve, reject) => {
      let receivedHeaders = false;
      const lookup = pin
        ? (((_host: string, options: { all?: boolean }, cb: (err: Error | null, address: unknown, family?: number) => void) => {
            if (options?.all) cb(null, [{ address: pin.address, family: pin.family }]);
            else cb(null, pin.address, pin.family);
          }) as unknown as LookupFunction)
        : undefined;
      const req = mod.request(
        u,
        {
          method: "GET",
          headers: { accept },
          signal,
          ...(lookup ? { lookup } : {}),
          agent: false,
        },
        (res) => {
          receivedHeaders = true;
          const status = res.statusCode ?? 0;
          if (status < 200 || status >= 300) {
            res.destroy();
            resolve(null);
            return;
          }
          const declared = Number(res.headers["content-length"] ?? 0);
          if (Number.isFinite(declared) && declared > MAX_DISCOVERY_BYTES) {
            res.destroy();
            resolve(null);
            return;
          }
          const headers = new Headers();
          for (const [k, v] of Object.entries(res.headers)) {
            if (typeof v === "string") headers.set(k, v);
            else if (Array.isArray(v)) headers.set(k, v.join(", "));
          }
          const chunks: Buffer[] = [];
          let total = 0;
          let settled = false;
          res.on("data", (chunk: Buffer) => {
            const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
            total += buf.byteLength;
            if (total > MAX_DISCOVERY_BYTES) {
              settled = true;
              res.destroy();
              resolve(null);
              return;
            }
            chunks.push(buf);
          });
          res.on("end", () => {
            if (settled) return;
            settled = true;
            resolve({ status, headers, text: Buffer.concat(chunks, total).toString("utf8") });
          });
          res.on("error", () => {
            if (settled) return;
            settled = true;
            resolve(null);
          });
        },
      );
      req.on("error", (err) => {
        Object.assign(err as object, { _receivedHeaders: receivedHeaders });
        reject(err);
      });
      req.end();
    });

  try {
    return await attempt(candidates[0]!);
  } catch (err) {
    const hadHeaders = Boolean((err as { _receivedHeaders?: boolean })?._receivedHeaders);
    if (candidates.length > 1 && !hadHeaders && !signal.aborted) {
      try {
        return await attempt(candidates[1]!);
      } catch {
        return null;
      }
    }
    return null;
  }
}

function parseLinkHeaderAgentCard(linkHeader: string | null, expectedOrigin: string): string | null {
  if (!linkHeader || linkHeader.length > 4096) return null;
  for (const part of linkHeader.split(",")) {
    const urlMatch = /<([^>\s]{1,1024})>/.exec(part);
    const relMatch = /;\s*rel\s*=\s*(?:"([^"]*)"|([^\s;]+))/i.exec(part);
    if (!urlMatch || !relMatch) continue;
    const relTokens = (relMatch[1] ?? relMatch[2] ?? "")
      .toLowerCase()
      .split(/\s+/)
      .filter(Boolean);
    if (!relTokens.includes("agent-card") && !relTokens.includes("https://a2a-protocol.org/rel/agent-card")) {
      continue;
    }
    try {
      const resolved = new URL(urlMatch[1]!, expectedOrigin);
      if (resolved.origin === expectedOrigin) return resolved.toString();
    } catch {
      // Ignore malformed Link URI.
    }
  }
  return null;
}

function extractDidCandidatesFromCard(
  card: Record<string, unknown>,
  didDocMethods?: Map<string, string>,
  expectedDidWeb?: string | null,
): string[] {
  const candidates = new Set<string>();
  const caps = card.capabilities as { extensions?: Array<{ uri?: unknown; params?: Record<string, unknown> }> } | undefined;
  if (Array.isArray(caps?.extensions)) {
    for (const ext of caps.extensions) {
      const p = ext?.params;
      if (!p || typeof p !== "object") continue;
      for (const k of ["agentId", "did", "didKey", "respondentId"]) {
        const v = p[k];
        if (typeof v === "string" && isDidKey(v)) candidates.add(v);
      }
    }
  }
  if (Array.isArray(card.signatures)) {
    for (const sig of card.signatures as Array<{ protected?: unknown }>) {
      if (typeof sig?.protected !== "string") continue;
      try {
        const hdr = JSON.parse(Buffer.from(sig.protected, "base64url").toString("utf8")) as {
          kid?: unknown;
          jwk?: Ed25519PublicJwk;
        };
        if (typeof hdr.kid === "string") {
          if (isDidKey(hdr.kid)) {
            candidates.add(hdr.kid);
          } else if (didDocMethods) {
            const normKid =
              hdr.kid.startsWith("#") && expectedDidWeb ? `${expectedDidWeb}${hdr.kid}` : hdr.kid;
            const mapped = didDocMethods.get(normKid);
            if (mapped && isDidKey(mapped)) candidates.add(mapped);
          }
        }
        if (hdr.jwk && typeof hdr.jwk === "object") {
          const derived = didKeyFromEd25519Jwk(hdr.jwk);
          if (derived && isDidKey(derived)) candidates.add(derived);
        }
      } catch {
        // Ignore malformed JWS header.
      }
    }
  }
  return [...candidates];
}

function extractDidMethodsAndCandidatesFromDidDoc(
  doc: Record<string, unknown>,
  expectedDidWeb: string | null,
): { candidates: string[]; methodById: Map<string, string> } {
  const candidates = new Set<string>();
  const methodById = new Map<string, string>();
  if (Array.isArray(doc.alsoKnownAs)) {
    for (const aka of doc.alsoKnownAs) {
      if (typeof aka === "string" && isDidKey(aka)) candidates.add(aka);
    }
  }
  if (Array.isArray(doc.verificationMethod)) {
    for (const vm of doc.verificationMethod as Array<Record<string, unknown>>) {
      if (!vm || typeof vm !== "object") continue;
      let resolvedDid: string | null = null;
      if (vm.publicKeyJwk && typeof vm.publicKeyJwk === "object") {
        try {
          const derived = didKeyFromEd25519Jwk(vm.publicKeyJwk as Ed25519PublicJwk);
          if (derived && isDidKey(derived)) resolvedDid = derived;
        } catch {
          // Ignore non-Ed25519 JWK.
        }
      }
      if (!resolvedDid && typeof vm.publicKeyMultibase === "string") {
        const maybeDid = `did:key:${vm.publicKeyMultibase}`;
        if (isDidKey(maybeDid)) resolvedDid = maybeDid;
      }
      if (resolvedDid) {
        candidates.add(resolvedDid);
        if (typeof vm.id === "string" && vm.id.length > 0) {
          const normId = vm.id.startsWith("#") && expectedDidWeb ? `${expectedDidWeb}${vm.id}` : vm.id;
          methodById.set(normId, resolvedDid);
        }
      }
    }
  }
  return { candidates: [...candidates], methodById };
}

function agentCardMatchesOrigin(
  card: Record<string, unknown>,
  expectedOrigin: string,
  allowedDidWebs: Set<string>,
  hasCustomSameOriginWebhook: boolean,
): boolean {
  let hasPositiveOriginClaim = hasCustomSameOriginWebhook;
  const sameOriginUrl = (raw: unknown): boolean => {
    try {
      return typeof raw === "string" && new URL(raw).origin === expectedOrigin;
    } catch {
      return false;
    }
  };

  if (card.url !== undefined) {
    if (!sameOriginUrl(card.url)) return false;
    hasPositiveOriginClaim = true;
  }
  if (card.supportedInterfaces !== undefined) {
    if (!Array.isArray(card.supportedInterfaces)) return false;
    for (const iface of card.supportedInterfaces as Array<Record<string, unknown>>) {
      if (!iface || typeof iface !== "object") return false;
      if (iface.url !== undefined) {
        if (!sameOriginUrl(iface.url)) return false;
        hasPositiveOriginClaim = true;
      }
    }
  }
  const provider = card.provider as Record<string, unknown> | undefined;
  if (provider && typeof provider === "object" && provider.url !== undefined) {
    if (!sameOriginUrl(provider.url)) return false;
    hasPositiveOriginClaim = true;
  }
  if (Array.isArray(card.signatures)) {
    for (const sig of card.signatures as Array<{ protected?: unknown }>) {
      if (typeof sig?.protected !== "string") continue;
      try {
        const hdr = JSON.parse(Buffer.from(sig.protected, "base64url").toString("utf8")) as {
          kid?: unknown;
          jku?: unknown;
        };
        if (hdr.jku !== undefined) {
          if (!sameOriginUrl(hdr.jku)) return false;
          hasPositiveOriginClaim = true;
        }
        if (typeof hdr.kid === "string" && hdr.kid.startsWith("did:web:")) {
          const kidDidWeb = hdr.kid.split("#")[0]!;
          if (!allowedDidWebs.has(kidDidWeb)) return false;
          hasPositiveOriginClaim = true;
        }
      } catch {
        return false;
      }
    }
  }
  return hasPositiveOriginClaim;
}

function extractStandardA2aRpcUrl(card: Record<string, unknown>, expectedOrigin: string): string | null {
  if (Array.isArray(card.supportedInterfaces)) {
    for (const iface of card.supportedInterfaces as Array<Record<string, unknown>>) {
      if (!iface || typeof iface !== "object" || typeof iface.url !== "string") continue;
      const binding = typeof iface.protocolBinding === "string" ? iface.protocolBinding.trim().toUpperCase() : "JSONRPC";
      if (binding !== "JSONRPC" && binding !== "HTTP+JSONRPC") continue;
      try {
        const parsed = new URL(iface.url);
        if (parsed.origin === expectedOrigin) return parsed.toString();
      } catch {
        // Ignore malformed interface URL.
      }
    }
  }
  if (typeof card.url === "string") {
    const transport = typeof card.preferredTransport === "string" ? card.preferredTransport.trim().toUpperCase() : "JSONRPC";
    if (transport === "JSONRPC" || transport === "HTTP+JSONRPC") {
      try {
        const parsed = new URL(card.url);
        if (parsed.origin === expectedOrigin) return parsed.toString();
      } catch {
        // Ignore malformed card.url.
      }
    }
  }
  return null;
}

function parseSecurityTxtEmail(text: string): string | null {
  for (const rawLine of text.split(/\r?\n/)) {
    const line = rawLine.trim();
    if (!line || line.startsWith("#")) continue;
    const m = /^contact\s*:\s*(.+)$/i.exec(line);
    if (!m) continue;
    const rawVal = m[1]!.trim();
    const email = rawVal.toLowerCase().startsWith("mailto:") ? rawVal.slice(7).split("?")[0]!.trim() : rawVal;
    if (email.length <= 254 && SIMPLE_EMAIL_RE.test(email)) {
      return email;
    }
  }
  return null;
}

export async function discoverRespondent(
  target: string,
  opts: DiscoverRespondentOptions = {},
): Promise<DiscoveredRespondent> {
  const timeoutMs = opts.timeoutMs ?? 3_000;
  const now = opts.now ?? Date.now;
  const { origin, domain, isLoopback, initialDidWeb, didDocUrl } = normalizeTargetOrigin(target, opts.allowInsecureHttp ?? false);

  // CR3-MCP-H1: resolve target DNS and reject any private/loopback/CGNAT/link-local/ULA/reserved IPs before probing.
  let vettedPins: DiscoveryResolvedAddress[] | null = null;
  if (!isLoopback && (!opts.fetch || opts.resolveHost)) {
    const resolver = opts.resolveHost ?? defaultResolveHost;
    let resolved: DiscoveryResolvedAddress[];
    try {
      resolved = await resolver(domain);
    } catch {
      throw new Error("target host could not be resolved");
    }
    if (!Array.isArray(resolved) || resolved.length === 0) {
      throw new Error("target host could not be resolved");
    }
    for (const addr of resolved) {
      if (!addr || typeof addr.address !== "string" || !isPublicIpAddress(addr.address)) {
        throw new Error("target must resolve exclusively to public IP addresses");
      }
    }
    vettedPins = resolved;
  }

  const getFromTarget: BoundedGetter = opts.fetch
    ? (url, accept) => fetchTextBounded(opts.fetch!, url, accept, timeoutMs)
    : (url, accept) => pinnedNodeGetBounded(url, accept, timeoutMs, vettedPins);
  const apiFetch = opts.apiFetch ?? opts.fetch ?? globalThis.fetch;

  const sources: DiscoverySource[] = [];
  const addSource = (s: DiscoverySource) => {
    if (!sources.includes(s)) sources.push(s);
  };

  let respondentId: string | null = null;
  let verifiedStanding = false;
  let hasVerifiedNoticeChannel = false;
  const contact: PartyContact = {};
  if (initialDidWeb) contact.didWeb = initialDidWeb;

  // 1. Agent-Mediate Honours Roll lookup (trusted ONLY when signedAttestation verifies against pinned platformDid, CR3-SDK-H1 & P1-2)
  const cleanBase = opts.baseUrl ? normalizeBaseUrl(opts.baseUrl) : undefined;
  const effectivePlatformDid = opts.platformDid ?? (cleanBase ? DEFAULT_PRODUCTION_PLATFORM_DIDS[cleanBase] : undefined);
  const effectiveExpectedEnv =
    opts.expectedEnvironment ?? (cleanBase === PRODUCTION_API_URL ? "production" : undefined);
  if (cleanBase && effectivePlatformDid && isDidKey(effectivePlatformDid)) {
    const honoursRes = await fetchTextBounded(
      apiFetch,
      `${cleanBase}/v1/honours/${encodeURIComponent(domain)}`,
      "application/json",
      timeoutMs,
    );
    if (honoursRes) {
      try {
        const body = JSON.parse(honoursRes.text) as {
          listed?: boolean;
          inGoodStanding?: boolean;
          entry?: { domain?: string; didWeb?: string | null; agentIds?: string[]; fulfilmentRate?: number } | null;
          signedAttestation?: SignedDocument<HonoursAttestationDocument> | null;
        };
        const nowTs = now();
        const att = body?.signedAttestation;
        const doc = att?.document;
        const proof = att?.proof;
        if (
          body?.listed === true &&
          body.inGoodStanding !== false &&
          att &&
          doc &&
          proof &&
          doc.type === HONOURS_ATTESTATION_TYPE &&
          doc.domain === domain &&
          (effectiveExpectedEnv === undefined || doc.environment === effectiveExpectedEnv) &&
          (opts.expectedRulesHash === undefined || doc.rulesHash === opts.expectedRulesHash) &&
          doc.fulfilmentRate === 1 &&
          Array.isArray(doc.agentIds) &&
          doc.agentIds.length > 0 &&
          Number.isSafeInteger(proof.created) &&
          typeof proof.expiresAt === "number" &&
          Number.isSafeInteger(proof.expiresAt) &&
          proof.created === doc.issuedAt &&
          proof.created <= nowTs + 300_000 &&
          proof.expiresAt > proof.created &&
          proof.expiresAt - proof.created <= 24 * 3_600_000
        ) {
          let attSigOk = verifyDocument(att, effectivePlatformDid, { now: nowTs });
          if (!attSigOk && proof.verificationMethod !== effectivePlatformDid) {
            const khRes = await fetchTextBounded(
              apiFetch,
              `${cleanBase}/.well-known/key-history.json`,
              "application/json",
              timeoutMs,
            );
            if (khRes) {
              const kh = JSON.parse(khRes.text) as SignedDocument<KeyHistoryDocument>;
              if (
                verifyKeyHistory(kh, {
                  expectedActiveDid: effectivePlatformDid,
                  now: nowTs,
                  maxAgeMs: DEFAULT_KEY_HISTORY_TTL_MS,
                }).ok &&
                kh.document.activeDid !== effectivePlatformDid
              ) {
                attSigOk = verifyDocument(att, kh.document.activeDid, { now: nowTs });
              }
            }
          }
          if (attSigOk) {
            const entryMatches =
              !body.entry ||
              (body.entry.domain === doc.domain &&
                body.entry.didWeb === doc.didWeb &&
                Array.isArray(body.entry.agentIds) &&
                body.entry.agentIds.length === doc.agentIds.length &&
                body.entry.agentIds.every((id, idx) => id === doc.agentIds[idx]));
            if (entryMatches) {
              const firstDid = doc.agentIds.find((id) => typeof id === "string" && isDidKey(id));
              if (firstDid) {
                respondentId = firstDid;
                verifiedStanding = true;
                if (typeof doc.didWeb === "string" && doc.didWeb.startsWith("did:web:")) {
                  contact.didWeb = doc.didWeb;
                }
                addSource("honours");
              }
            }
          }
        }
      } catch {
        // Ignore malformed Honours JSON and continue probing target origin.
      }
    }
  }

  // 2. A2A Agent Card (/.well-known/agent-card.json -> /.well-known/agent.json -> Link header on /)
  let cardUrl: string | null = `${origin}/.well-known/agent-card.json`;
  let cardRes = await getFromTarget(cardUrl, "application/json");
  if (!cardRes) {
    cardUrl = `${origin}/.well-known/agent.json`;
    cardRes = await getFromTarget(cardUrl, "application/json");
  }
  if (!cardRes) {
    const rootRes = await getFromTarget(`${origin}/`, "text/html, application/json;q=0.9, */*;q=0.5");
    const linked = rootRes ? parseLinkHeaderAgentCard(rootRes.headers.get("link"), origin) : null;
    if (linked) {
      cardRes = await getFromTarget(linked, "application/json");
      if (cardRes) {
        cardUrl = linked;
        addSource("link_header");
      }
    }
  }

  let parsedCard: Record<string, unknown> | null = null;
  let parsedCardUrl: string | null = null;
  if (cardRes && cardUrl) {
    try {
      const c = JSON.parse(cardRes.text) as Record<string, unknown>;
      if (c && typeof c === "object" && !Array.isArray(c)) {
        parsedCard = c;
        parsedCardUrl = cardUrl;
        contact.a2aCardUrl = cardUrl;
        addSource("a2a_card");
      }
    } catch {
      // Ignore invalid Agent Card JSON.
    }
  }

  // 3. W3C did:web (/.well-known/did.json or path-scoped didDocUrl, CR3-SDK-M1 & CR3-SDK-H1)
  let rootDidWeb: string | null = null;
  try {
    rootDidWeb = didWebFromUrl(origin);
  } catch {
    rootDidWeb = null;
  }
  const expectedDidWeb = initialDidWeb ?? rootDidWeb;
  const allowedDidWebs = new Set<string>();
  if (rootDidWeb) allowedDidWebs.add(rootDidWeb);
  if (initialDidWeb) allowedDidWebs.add(initialDidWeb);

  let didDocAuthorizedKeys: string[] = [];
  let didDocMethodById = new Map<string, string>();
  const didRes = await getFromTarget(didDocUrl, "application/did+ld+json, application/json");
  if (didRes) {
    try {
      const didDoc = JSON.parse(didRes.text) as Record<string, unknown>;
      if (didDoc && typeof didDoc === "object" && !Array.isArray(didDoc)) {
        if (expectedDidWeb) {
          contact.didWeb = expectedDidWeb;
        }
        addSource("did_web");

        const extracted = extractDidMethodsAndCandidatesFromDidDoc(didDoc, expectedDidWeb);
        didDocMethodById = extracted.methodById;
        const rawCandidates = respondentId ? [respondentId, ...extracted.candidates] : extracted.candidates;
        if (expectedDidWeb) {
          didDocAuthorizedKeys = rawCandidates.filter((c, i) => rawCandidates.indexOf(c) === i && didWebDocumentAuthorizesKey(didDoc, expectedDidWeb, c));
        }

        let didWebhookUrl: string | null = null;
        if (Array.isArray(didDoc.service)) {
          for (const svc of didDoc.service as Array<{ type?: unknown; serviceEndpoint?: unknown }>) {
            if (svc?.type === "AgentMediateNotice" && typeof svc.serviceEndpoint === "string") {
              try {
                const ep = new URL(svc.serviceEndpoint);
                if (ep.origin === origin) {
                  didWebhookUrl = ep.toString();
                  break;
                }
              } catch {
                // Ignore malformed serviceEndpoint.
              }
            }
          }
        }

        for (const candidate of didDocAuthorizedKeys) {
          // CR3-SDK-H1(3) & P1-3: require cryptographic proof-of-possession on did.json before binding respondentId,
          // and mark hasVerifiedNoticeChannel only when did.json actually publishes a same-origin AgentMediateNotice webhook.
          if (verifyAgentCardSignature(didDoc, candidate)) {
            if (!respondentId) respondentId = candidate;
            if (candidate === respondentId && didWebhookUrl !== null) {
              if (!contact.webhookUrl) contact.webhookUrl = didWebhookUrl;
              hasVerifiedNoticeChannel = true;
            }
            break;
          }
        }

        // If did.json links to a same-origin A2AAgentCard service we haven't inspected yet, fetch it.
        if (!parsedCard && Array.isArray(didDoc.service)) {
          for (const svc of didDoc.service as Array<{ type?: unknown; serviceEndpoint?: unknown }>) {
            if (
              (svc?.type === "A2AAgentCard" || svc?.type === "AgentCard") &&
              typeof svc.serviceEndpoint === "string"
            ) {
              try {
                const ep = new URL(svc.serviceEndpoint);
                if (ep.origin === origin) {
                  const linkedCard = await getFromTarget(ep.toString(), "application/json");
                  if (linkedCard) {
                    const c = JSON.parse(linkedCard.text) as Record<string, unknown>;
                    if (c && typeof c === "object" && !Array.isArray(c)) {
                      parsedCard = c;
                      parsedCardUrl = ep.toString();
                      contact.a2aCardUrl = parsedCardUrl;
                      addSource("a2a_card");
                    }
                  }
                  break;
                }
              } catch {
                // Ignore malformed serviceEndpoint or card JSON.
              }
            }
          }
        }
      }
    } catch {
      // Ignore malformed did.json.
    }
  }

  // Evaluate Agent Card cryptographic binding & channels (using both card candidates and did:web-authorized keys, CR3-SDK-H1 & CR3-SDK-M1)
  if (parsedCard) {
    const caps = parsedCard.capabilities as { extensions?: Array<{ uri?: unknown; params?: Record<string, unknown> }> } | undefined;
    let customWebhook: string | null = null;
    if (Array.isArray(caps?.extensions)) {
      for (const ext of caps.extensions) {
        if (
          ext?.uri === "urn:agent-mediate:ext:dispute-notice:v1" ||
          ext?.uri === "urn:agent-mediate:ext:dispute-clause:v1" ||
          ext?.uri === "urn:agent-mediate:ext:notifications:v1" ||
          ext?.uri === "urn:agent-mediate:ext:notice:v1"
        ) {
          const wh = ext.params?.noticeWebhookUrl ?? ext.params?.webhookUrl;
          if (typeof wh === "string") {
            try {
              const parsedWh = new URL(wh);
              if (parsedWh.origin === origin) customWebhook = parsedWh.toString();
            } catch {
              // Ignore invalid webhook URL.
            }
          }
        }
      }
    }
    const standardRpcUrl = extractStandardA2aRpcUrl(parsedCard, origin);
    if (agentCardMatchesOrigin(parsedCard, origin, allowedDidWebs, customWebhook !== null)) {
      const rawCandidates = [
        ...(respondentId ? [respondentId] : []),
        ...extractDidCandidatesFromCard(parsedCard, didDocMethodById, expectedDidWeb),
        ...didDocAuthorizedKeys,
      ];
      const uniqueCandidates = rawCandidates.filter((c, idx) => rawCandidates.indexOf(c) === idx);
      for (const candidate of uniqueCandidates) {
        if (verifyAgentCardSignature(parsedCard, candidate)) {
          if (!respondentId) respondentId = candidate;
          if (candidate === respondentId && (customWebhook !== null || standardRpcUrl !== null)) {
            hasVerifiedNoticeChannel = true;
          }
          break;
        }
      }
    }

    const provider = parsedCard.provider as { email?: unknown } | undefined;
    if (typeof provider?.email === "string" && SIMPLE_EMAIL_RE.test(provider.email.trim())) {
      contact.email = provider.email.trim();
    }
  }

  // 4. RFC 9116 security.txt fallback for operator email
  if (!contact.email) {
    let secRes = await getFromTarget(`${origin}/.well-known/security.txt`, "text/plain");
    if (!secRes) {
      secRes = await getFromTarget(`${origin}/security.txt`, "text/plain");
    }
    if (secRes) {
      const email = parseSecurityTxtEmail(secRes.text);
      if (email) {
        contact.email = email;
        addSource("security_txt");
      }
    }
  }

  const recommendedAction: "file_dispute" | "send_invite" =
    respondentId !== null && hasVerifiedNoticeChannel ? "file_dispute" : "send_invite";

  return {
    domain,
    origin,
    respondentId,
    respondentContact: contact,
    verifiedStanding,
    hasVerifiedNoticeChannel,
    recommendedAction,
    sources,
  };
}
