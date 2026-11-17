/**
 * HTTP Message Signatures (RFC 9421) with Content-Digest (RFC 9530), Ed25519.
 *
 * A deliberately strict subset: one signature labelled `sig1`, covered
 * components limited to `@method`, `@target-uri` and header fields, and
 * parameters `created`, `keyid`, `alg`, `nonce` and optionally `tag`. Anything else is rejected.
 *
 * Requirements enforced on verify:
 * - `@method` and `@target-uri` always covered
 * - `content-digest` covered and correct whenever there is a body
 * - `idempotency-key` covered whenever the header is present
 * - `created` within ±5 minutes; `nonce` present (single-use is enforced by the caller)
 * - `keyid` is an Ed25519 did:key, which is also the authenticated agent id
 * - `tag` (RFC 9421 §2.3) is absent unless the verifier expects exactly that tag. The platform signs webhooks
 *   with `tag="agent-mediate-webhook-v1"` (WEBHOOK_SIGNATURE_TAG); the tag is covered by the signature, so a webhook delivery can't be
 *   replayed as an API request, and an API request can't pass as a webhook (security review L3).
 */
import { createHash, sign, verify } from "node:crypto";
import { canonicalJson, sha256Hex } from "@agent-mediate/core";
import { publicKeyFromDidKey, type AgentKey } from "./identity.ts";

export const MAX_CLOCK_SKEW_SECONDS = 300;
/** Application tag on platform webhook signatures (security review L3). */
export const WEBHOOK_SIGNATURE_TAG = "agent-mediate-webhook-v1";
const TAG = /^[A-Za-z0-9_.:-]{1,64}$/;
const LABEL = "sig1";
const DERIVED = new Set(["@method", "@target-uri"]);
const ALLOWED_COMPONENTS = new Set(["@method", "@target-uri", "content-digest", "idempotency-key"]);
const NONCE = /^[A-Za-z0-9_\-.:]{16,128}$/;
const SIGNATURE_INPUT = /^sig1=\(((?:"[^"\s]+"(?: "[^"\s]+")*)?)\)((?:;[a-z]+=(?:"[^"\\]*"|\d+))*)$/;
const SIGNATURE = /^sig1=:([A-Za-z0-9+/]+={0,2}):$/;

export function contentDigest(body: string | Uint8Array): string {
  return `sha-256=:${createHash("sha256").update(body).digest("base64")}:`;
}

export interface SignRequestInput {
  method: string;
  targetUri: string;
  /** Lower-case header names. `idempotency-key` is covered automatically if present. */
  headers?: Record<string, string>;
  body?: string;
  key: AgentKey;
  /** Unix seconds. */
  created: number;
  nonce: string;
  /** RFC 9421 `tag` parameter (e.g. WEBHOOK_SIGNATURE_TAG). */
  tag?: string;
}

/** Returns the headers to add: `content-digest` (if body), `signature-input`, `signature`. */
export function signRequest(input: SignRequestInput): Record<string, string> {
  if (!Number.isSafeInteger(input.created) || input.created < 0) {
    throw new Error("created must be a non-negative integer timestamp");
  }
  if (typeof input.nonce !== "string" || !NONCE.test(input.nonce)) {
    throw new Error("nonce must be 16-128 URL-safe characters");
  }
  const headers: Record<string, string> = {};
  for (const [k, v] of Object.entries(input.headers ?? {})) headers[k.toLowerCase()] = v;
  const components = ["@method", "@target-uri"];
  if (input.body !== undefined && input.body.length > 0) {
    headers["content-digest"] = contentDigest(input.body);
    components.push("content-digest");
  }
  if (headers["idempotency-key"] !== undefined) {
    if (headers["idempotency-key"].trim().length === 0) {
      throw new Error("idempotency-key must be non-empty");
    }
    components.push("idempotency-key");
  }

  if (input.tag !== undefined && !TAG.test(input.tag)) throw new Error("invalid signature tag");
  const params = `;created=${input.created};keyid="${input.key.did}";alg="ed25519";nonce="${input.nonce}"${input.tag !== undefined ? `;tag="${input.tag}"` : ""}`;
  const signatureParams = `(${components.map((c) => `"${c}"`).join(" ")})${params}`;
  const lookup = (name: string) => headers[name] ?? null;
  const base = signatureBase(components, input.method, input.targetUri, lookup, signatureParams);
  const signature = sign(null, Buffer.from(base, "utf8"), input.key.privateKey).toString("base64");

  const out: Record<string, string> = {
    "signature-input": `${LABEL}=${signatureParams}`,
    signature: `${LABEL}=:${signature}:`,
  };
  if (headers["content-digest"]) out["content-digest"] = headers["content-digest"];
  return out;
}

export interface VerifyRequestInput {
  method: string;
  /** Reconstructed from the configured public base URL, not from proxy-supplied Host headers. */
  targetUri: string;
  header: (name: string) => string | null;
  body: string;
  /** Unix milliseconds. */
  now: number;
  /** The only acceptable `tag`. Unset: a signature carrying any tag is rejected (API requests carry none). */
  expectTag?: string;
}

export interface RequestSignatureProof {
  method: string;
  targetUri: string;
  contentDigest: string | null;
  idempotencyKey: string | null;
  signatureInput: string;
  signature: string;
  created: number;
  nonce: string;
  keyid: string;
}

export const REQUEST_PROOF_HASH_DOMAIN = "agent-mediate/request-proof/v1\n";

export function computeRequestProofHash(proof: RequestSignatureProof): string {
  return sha256Hex(REQUEST_PROOF_HASH_DOMAIN + canonicalJson(proof));
}

export type VerifyResult =
  | {
      ok: true;
      keyid: string;
      nonce: string;
      created: number;
      tag: string | null;
      proof: RequestSignatureProof;
    }
  | { ok: false; reason: string };

export function verifyRequest(input: VerifyRequestInput): VerifyResult {
  const sigInput = input.header("signature-input");
  const sigHeader = input.header("signature");
  if (!sigInput || !sigHeader) return { ok: false, reason: "missing Signature-Input or Signature header" };

  const parsed = SIGNATURE_INPUT.exec(sigInput.trim());
  if (!parsed) return { ok: false, reason: "malformed Signature-Input (expected a single sig1 entry)" };
  const components = parsed[1] ? parsed[1].split(" ").map((c) => c.slice(1, -1)) : [];
  const params = new Map<string, string>();
  for (const m of parsed[2]!.matchAll(/;([a-z]+)=("[^"\\]*"|\d+)/g)) {
    if (params.has(m[1]!)) return { ok: false, reason: `duplicate parameter ${m[1]}` };
    params.set(m[1]!, m[2]!.startsWith('"') ? m[2]!.slice(1, -1) : m[2]!);
  }
  for (const key of params.keys()) {
    if (!["created", "keyid", "alg", "nonce", "tag"].includes(key)) return { ok: false, reason: `unsupported parameter ${key}` };
  }
  const tag = params.get("tag") ?? null;
  if (tag !== (input.expectTag ?? null)) {
    return { ok: false, reason: input.expectTag ? `signature tag must be "${input.expectTag}"` : `unexpected signature tag "${String(tag).slice(0, 64)}" (webhook signatures are not API credentials)` };
  }

  if (new Set(components).size !== components.length) return { ok: false, reason: "duplicate covered component" };
  // Review M1: restrict covered components at auth time to the exact set preserved in RequestSignatureProof,
  // so neither a counterparty covering x-junk nor a client covering content-type can record an unverifiable proof.
  for (const c of components) {
    if (!ALLOWED_COMPONENTS.has(c)) return { ok: false, reason: `unsupported component ${c}` };
  }
  for (const required of ["@method", "@target-uri"]) {
    if (!components.includes(required)) return { ok: false, reason: `${required} must be covered` };
  }
  if (input.body.length > 0 && !components.includes("content-digest")) {
    return { ok: false, reason: "content-digest must be covered for requests with a body" };
  }
  if (input.header("content-digest") !== null && !components.includes("content-digest")) {
    return { ok: false, reason: "content-digest must be covered when present" };
  }
  if (components.includes("content-digest")) {
    if (input.header("content-digest")?.trim() !== contentDigest(input.body)) {
      return { ok: false, reason: "content-digest does not match body" };
    }
  }
  if (input.header("idempotency-key") !== null && !components.includes("idempotency-key")) {
    return { ok: false, reason: "idempotency-key must be covered when present" };
  }
  if (components.includes("idempotency-key")) {
    const idem = input.header("idempotency-key");
    if (idem === null || idem.trim().length === 0) {
      return { ok: false, reason: "covered idempotency-key must be non-empty" };
    }
  }

  if (params.get("alg") !== "ed25519") return { ok: false, reason: 'alg must be "ed25519"' };
  if (!Number.isFinite(input.now) || input.now <= 0) {
    return { ok: false, reason: "now must be a positive finite timestamp" };
  }
  const created = Number(params.get("created"));
  if (!Number.isSafeInteger(created)) return { ok: false, reason: "created is required" };
  if (Math.abs(input.now / 1000 - created) > MAX_CLOCK_SKEW_SECONDS) return { ok: false, reason: "created is outside the allowed clock skew" };
  const nonce = params.get("nonce") ?? "";
  if (!NONCE.test(nonce)) return { ok: false, reason: "nonce is required (16-128 URL-safe characters)" };

  const keyid = params.get("keyid") ?? "";
  let publicKey;
  try {
    publicKey = publicKeyFromDidKey(keyid);
  } catch {
    return { ok: false, reason: "keyid must be an Ed25519 did:key" };
  }

  const sig = SIGNATURE.exec(sigHeader.trim());
  if (!sig) return { ok: false, reason: "malformed Signature header" };
  const signatureParams = sigInput.trim().slice(`${LABEL}=`.length);
  let base: string;
  try {
    base = signatureBase(components, input.method, input.targetUri, input.header, signatureParams);
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
  const sigBytes = Buffer.from(sig[1]!, "base64");
  if (sigBytes.length !== 64 || sigBytes.toString("base64") !== sig[1]!) {
    return { ok: false, reason: "malformed Signature header" };
  }
  const valid = verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes);
  if (!valid) return { ok: false, reason: "signature verification failed" };
  const proof: RequestSignatureProof = {
    method: input.method.toUpperCase(),
    targetUri: input.targetUri,
    contentDigest: components.includes("content-digest") ? input.header("content-digest")!.trim() : null,
    idempotencyKey: components.includes("idempotency-key") ? input.header("idempotency-key")!.trim() : null,
    signatureInput: sigInput.trim(),
    signature: sigHeader.trim(),
    created,
    nonce,
    keyid,
  };
  return { ok: true, keyid, nonce, created, tag, proof };
}

export interface VerifyDisputeActionTargetInput {
  expectedDisputeId: string;
  expectedAction: string;
  expectedBaseUrl?: string;
}

function normalizeExpectedBaseUrl(raw: string): string | null {
  if (typeof raw !== "string") return null;
  const trimmed = raw.replace(/\/+$/, "");
  if (!trimmed) return null;
  try {
    const u = new URL(trimmed);
    if (
      (u.protocol !== "http:" && u.protocol !== "https:") ||
      u.username !== "" ||
      u.password !== "" ||
      u.search !== "" ||
      u.hash !== ""
    ) {
      return null;
    }
    return trimmed;
  } catch {
    return null;
  }
}

/**
 * Bind a `RequestSignatureProof`'s signed `@method` and `@target-uri` to the specific dispute and action
 * claimed in `/v1/disputes/:id/signatures` so a genuine proof from one dispute or action cannot be replayed
 * as another (review M6).
 */
export function verifyDisputeActionTarget(
  proof: Pick<RequestSignatureProof, "method" | "targetUri">,
  opts: VerifyDisputeActionTargetInput,
): { ok: true } | { ok: false; reason: string } {
  if (!proof || typeof proof.method !== "string" || typeof proof.targetUri !== "string") {
    return { ok: false, reason: "invalid proof method or targetUri" };
  }
  if (!opts || typeof opts.expectedDisputeId !== "string" || opts.expectedDisputeId.length === 0) {
    return { ok: false, reason: "expectedDisputeId must be a non-empty string" };
  }
  if (proof.method.toUpperCase() !== "POST") {
    return { ok: false, reason: `dispute action proof method must be POST, got ${proof.method}` };
  }
  let rest: string;
  if (opts.expectedBaseUrl !== undefined) {
    const base = normalizeExpectedBaseUrl(opts.expectedBaseUrl);
    if (!base) {
      return { ok: false, reason: "expectedBaseUrl is not a valid HTTP(S) base URL" };
    }
    if (!proof.targetUri.startsWith(`${base}/`)) {
      return { ok: false, reason: "proof targetUri does not match expected baseUrl" };
    }
    rest = proof.targetUri.slice(base.length);
  } else {
    const rawMatch = /^https?:\/\/[^/?#]+(\/[^?#]*)?(\?[^#]*)?(#.*)?$/i.exec(proof.targetUri);
    if (!rawMatch) {
      return { ok: false, reason: "proof targetUri is not a valid URL" };
    }
    const rawPath = rawMatch[1] ?? "/";
    if (rawPath.split("/").some((seg) => seg === "." || seg === "..")) {
      return { ok: false, reason: "proof targetUri must not contain dot-segments" };
    }
    try {
      const parsed = new URL(proof.targetUri);
      if (parsed.protocol !== "http:" && parsed.protocol !== "https:") {
        return { ok: false, reason: "proof targetUri must use http or https" };
      }
      rest = `${rawPath}${rawMatch[2] ?? ""}${rawMatch[3] ?? ""}`;
    } catch {
      return { ok: false, reason: "proof targetUri is not a valid URL" };
    }
  }
  if (rest.includes("#")) {
    return { ok: false, reason: "proof targetUri must not contain a fragment" };
  }
  const qIdx = rest.indexOf("?");
  const pathPart = qIdx === -1 ? rest : rest.slice(0, qIdx);
  const queryPart = qIdx === -1 ? undefined : rest.slice(qIdx + 1);
  if (queryPart !== undefined && queryPart !== "view=full" && queryPart !== "view=compact") {
    return { ok: false, reason: "proof targetUri carries unexpected query parameters" };
  }

  const encId = encodeURIComponent(opts.expectedDisputeId);
  const prefix = `/v1/disputes/${encId}`;
  switch (opts.expectedAction) {
    case "file_dispute":
      return pathPart === "/v1/disputes" ? { ok: true } : { ok: false, reason: "file_dispute targetUri mismatch" };
    case "join_dispute":
      return pathPart === `${prefix}/join` ? { ok: true } : { ok: false, reason: "join_dispute targetUri mismatch" };
    case "submit_evidence":
      return pathPart === `${prefix}/evidence` ? { ok: true } : { ok: false, reason: "submit_evidence targetUri mismatch" };
    case "close_evidence":
      return pathPart === `${prefix}/evidence/close` ? { ok: true } : { ok: false, reason: "close_evidence targetUri mismatch" };
    case "confirm_issues":
      return pathPart === `${prefix}/issues/confirm` ? { ok: true } : { ok: false, reason: "confirm_issues targetUri mismatch" };
    case "reject_issues":
      return pathPart === `${prefix}/issues/reject` ? { ok: true } : { ok: false, reason: "reject_issues targetUri mismatch" };
    case "update_mandate":
      return pathPart === `${prefix}/mandate` ? { ok: true } : { ok: false, reason: "update_mandate targetUri mismatch" };
    case "submit_offer": {
      if (!pathPart.startsWith(`${prefix}/rounds/`) || !pathPart.endsWith("/offer")) {
        return { ok: false, reason: "submit_offer targetUri mismatch" };
      }
      const roundSeg = pathPart.slice(`${prefix}/rounds/`.length, -"/offer".length);
      return /^[1-9][0-9]*$/.test(roundSeg) ? { ok: true } : { ok: false, reason: "submit_offer round segment invalid" };
    }
    case "submit_final_offer":
      return pathPart === `${prefix}/determination/final-offer`
        ? { ok: true }
        : { ok: false, reason: "submit_final_offer targetUri mismatch" };
    case "respond_improvement":
      return pathPart === `${prefix}/execution/improvement`
        ? { ok: true }
        : { ok: false, reason: "respond_improvement targetUri mismatch" };
    case "submit_execution_proof":
      return pathPart === `${prefix}/execution/proof`
        ? { ok: true }
        : { ok: false, reason: "submit_execution_proof targetUri mismatch" };
    case "confirm_execution":
      return pathPart === `${prefix}/execution/confirm`
        ? { ok: true }
        : { ok: false, reason: "confirm_execution targetUri mismatch" };
    case "contest_execution":
      return pathPart === `${prefix}/execution/contest`
        ? { ok: true }
        : { ok: false, reason: "contest_execution targetUri mismatch" };
    case "acknowledge_cure":
      return pathPart === `${prefix}/cure`
        ? { ok: true }
        : { ok: false, reason: "acknowledge_cure targetUri mismatch" };
    case "withdraw":
      return pathPart === `${prefix}/withdraw` ? { ok: true } : { ok: false, reason: "withdraw targetUri mismatch" };
    default:
      return { ok: false, reason: `unknown dispute action ${opts.expectedAction}` };
  }
}

export const BODY_REQUIRED_DISPUTE_ACTIONS: ReadonlySet<string> = new Set([
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
]);

export interface VerifyRequestProofOptions {
  expectedAgentId?: string;
  expectedProofHash?: string;
  expectedBaseUrl?: string;
  expectedDisputeId?: string;
  expectedAction?: string;
  expectTag?: string;
  expectedContentDigest?: string;
  expectedIdempotencyKey?: string;
}

/**
 * Re-verify a stored RFC 9421 Ed25519 `RequestSignatureProof` offline (`SEC3-5`),
 * without the live 5-minute clock-skew check so historical dispute actions remain
 * verifiable arbitrarily long after execution.
 */
export function verifyRequestProof(
  proof: RequestSignatureProof,
  opts?: VerifyRequestProofOptions,
): { ok: true; proofHash: string } | { ok: false; reason: string } {
  if (!proof || typeof proof !== "object") return { ok: false, reason: "invalid proof object" };
  if (typeof proof.method !== "string" || typeof proof.targetUri !== "string") {
    return { ok: false, reason: "invalid method or targetUri" };
  }
  // CR-CORE-L2: a verifier must answer {ok:false}, never throw, on malformed stored proofs.
  if (typeof proof.signatureInput !== "string" || typeof proof.signature !== "string" || typeof proof.keyid !== "string") {
    return { ok: false, reason: "invalid signatureInput, signature or keyid" };
  }
  for (const f of ["contentDigest", "idempotencyKey"] as const) {
    if (proof[f] !== undefined && proof[f] !== null && typeof proof[f] !== "string") return { ok: false, reason: `invalid ${f}` };
  }
  if (opts?.expectedAgentId !== undefined && proof.keyid !== opts.expectedAgentId) {
    return { ok: false, reason: "proof keyid does not match expected agentId" };
  }
  if (opts?.expectedDisputeId !== undefined || opts?.expectedAction !== undefined) {
    if (!opts.expectedDisputeId || !opts.expectedAction) {
      return { ok: false, reason: "both expectedDisputeId and expectedAction are required for target binding" };
    }
    const targetOk = verifyDisputeActionTarget(proof, {
      expectedDisputeId: opts.expectedDisputeId,
      expectedAction: opts.expectedAction,
      ...(opts.expectedBaseUrl !== undefined ? { expectedBaseUrl: opts.expectedBaseUrl } : {}),
    });
    if (!targetOk.ok) return targetOk;
    if (BODY_REQUIRED_DISPUTE_ACTIONS.has(opts.expectedAction) && (proof.contentDigest === null || proof.contentDigest === undefined)) {
      return { ok: false, reason: `${opts.expectedAction} proof must cover content-digest` };
    }
  } else if (opts?.expectedBaseUrl !== undefined) {
    const base = normalizeExpectedBaseUrl(opts.expectedBaseUrl);
    if (!base) {
      return { ok: false, reason: "expectedBaseUrl is not a valid HTTP(S) base URL" };
    }
    if (!proof.targetUri.startsWith(`${base}/`)) {
      return { ok: false, reason: "proof targetUri does not match expected baseUrl" };
    }
  }
  if (opts?.expectedContentDigest !== undefined && (proof.contentDigest ?? null)?.trim() !== opts.expectedContentDigest.trim()) {
    return { ok: false, reason: "proof contentDigest does not match expectedContentDigest" };
  }
  if (opts?.expectedIdempotencyKey !== undefined && (proof.idempotencyKey ?? null)?.trim() !== opts.expectedIdempotencyKey.trim()) {
    return { ok: false, reason: "proof idempotencyKey does not match expectedIdempotencyKey" };
  }
  const parsed = SIGNATURE_INPUT.exec((proof.signatureInput ?? "").trim());
  if (!parsed) return { ok: false, reason: "malformed Signature-Input" };
  const components = parsed[1] ? parsed[1].split(" ").map((c) => c.slice(1, -1)) : [];
  const params = new Map<string, string>();
  for (const m of parsed[2]!.matchAll(/;([a-z]+)=("[^"\\]*"|\d+)/g)) {
    if (params.has(m[1]!)) return { ok: false, reason: `duplicate parameter ${m[1]}` };
    params.set(m[1]!, m[2]!.startsWith('"') ? m[2]!.slice(1, -1) : m[2]!);
  }
  for (const key of params.keys()) {
    if (!["created", "keyid", "alg", "nonce", "tag"].includes(key)) return { ok: false, reason: `unsupported parameter ${key}` };
  }
  const tag = params.get("tag") ?? null;
  if (tag !== (opts?.expectTag ?? null)) {
    return {
      ok: false,
      reason: opts?.expectTag ? `signature tag must be "${opts.expectTag}"` : `unexpected signature tag "${String(tag).slice(0, 64)}"`,
    };
  }
  if (new Set(components).size !== components.length) return { ok: false, reason: "duplicate covered component" };
  const allowedComponents = new Set(["@method", "@target-uri", "content-digest", "idempotency-key"]);
  for (const c of components) {
    if (!allowedComponents.has(c)) return { ok: false, reason: `unsupported component ${c}` };
  }
  for (const required of ["@method", "@target-uri"]) {
    if (!components.includes(required)) return { ok: false, reason: `${required} must be covered` };
  }
  if (components.includes("content-digest")) {
    if (typeof proof.contentDigest !== "string" || !/^sha-256=:[A-Za-z0-9+/]+={0,2}:$/.test(proof.contentDigest.trim())) {
      return { ok: false, reason: "invalid covered content-digest" };
    }
  } else if (proof.contentDigest !== null) {
    return { ok: false, reason: "contentDigest must be null when not covered" };
  }
  if (components.includes("idempotency-key")) {
    if (typeof proof.idempotencyKey !== "string" || proof.idempotencyKey.trim().length === 0) {
      return { ok: false, reason: "invalid covered idempotency-key" };
    }
  } else if (proof.idempotencyKey !== null) {
    return { ok: false, reason: "idempotencyKey must be null when not covered" };
  }
  if (params.get("alg") !== "ed25519") return { ok: false, reason: 'alg must be "ed25519"' };
  const created = Number(params.get("created"));
  if (!Number.isSafeInteger(created) || created !== proof.created) return { ok: false, reason: "created mismatch" };
  const nonce = params.get("nonce") ?? "";
  if (!NONCE.test(nonce) || nonce !== proof.nonce) return { ok: false, reason: "nonce mismatch" };
  const keyid = params.get("keyid") ?? "";
  if (keyid !== proof.keyid) return { ok: false, reason: "keyid mismatch" };

  let publicKey;
  try {
    publicKey = publicKeyFromDidKey(keyid);
  } catch {
    return { ok: false, reason: "keyid must be an Ed25519 did:key" };
  }
  const sig = SIGNATURE.exec((proof.signature ?? "").trim());
  if (!sig) return { ok: false, reason: "malformed Signature" };
  const signatureParams = proof.signatureInput.trim().slice(`${LABEL}=`.length);
  const header = (name: string) =>
    name === "content-digest" ? proof.contentDigest : name === "idempotency-key" ? proof.idempotencyKey : null;
  let base: string;
  try {
    base = signatureBase(components, proof.method, proof.targetUri, header, signatureParams);
  } catch (e) {
    return { ok: false, reason: (e as Error).message };
  }
  const sigBytes = Buffer.from(sig[1]!, "base64");
  if (sigBytes.length !== 64 || sigBytes.toString("base64") !== sig[1]!) {
    return { ok: false, reason: "malformed Signature header" };
  }
  const valid = verify(null, Buffer.from(base, "utf8"), publicKey, sigBytes);
  if (!valid) return { ok: false, reason: "signature verification failed" };
  const normalized: RequestSignatureProof = {
    method: proof.method.toUpperCase(),
    targetUri: proof.targetUri,
    contentDigest: proof.contentDigest !== null ? proof.contentDigest.trim() : null,
    idempotencyKey: proof.idempotencyKey !== null ? proof.idempotencyKey.trim() : null,
    signatureInput: proof.signatureInput.trim(),
    signature: proof.signature.trim(),
    created: proof.created,
    nonce: proof.nonce,
    keyid: proof.keyid,
  };
  const proofHash = computeRequestProofHash(normalized);
  if (opts?.expectedProofHash !== undefined && proofHash !== opts.expectedProofHash) {
    return { ok: false, reason: "proofHash mismatch" };
  }
  return { ok: true, proofHash };
}

function signatureBase(
  components: string[],
  method: string,
  targetUri: string,
  header: (name: string) => string | null,
  signatureParams: string,
): string {
  const lines = components.map((c) => {
    let value: string | null;
    if (c === "@method") value = method.toUpperCase();
    else if (c === "@target-uri") value = targetUri;
    else value = header(c);
    if (value === null) throw new Error(`covered header ${c} is missing`);
    if (/[\r\n]/.test(value)) throw new Error(`covered header ${c} contains a newline`);
    return `"${c}": ${value.trim()}`;
  });
  lines.push(`"@signature-params": ${signatureParams}`);
  return lines.join("\n");
}
