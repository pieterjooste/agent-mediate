/**
 * Machine-readable pre-dispute mediation clause (`agent-mediate/clause/v1`, DISC-3)
 * and platform-signed Notice of Dispute (`agent-mediate/dispute-notice/v1`, DISC-2).
 *
 * Two agents agree on a `DisputeClause` at contract time — pinning the contract's RFC 8785 (JCS)
 * `contractHash`, the platform `did:key`, pre-agreed fee mode and window floors, and each party's
 * verified notification endpoints — and co-sign `"agent-mediate/clause/v1\n" + canonicalJson(unsigned)`.
 */
import { isIP } from "node:net";
import {
  canonicalJson,
  CONFIG_LIMITS,
  contractHash,
  isOnGrid,
  RULES_HASH,
  RULES_VERSION,
  validateIssues,
  type DisputeConfig,
  type FeeMode,
  type Issue,
  type NoticeMethod,
} from "@agent-mediate/core";
import { isDidKey, signText, verifyText, type AgentKey } from "./identity.ts";
import { urlFromDidWeb } from "./did-web.ts";
import { verifyKeyHistory, type KeyHistoryDocument, type SignedDocument } from "./signed-documents.ts";

export const CLAUSE_TYPE = "agent-mediate/clause/v1" as const;
const CLAUSE_DOMAIN = "agent-mediate/clause/v1\n";

export const DISPUTE_NOTICE_TYPE = "agent-mediate/dispute-notice/v1" as const;
export const DISPUTE_INVITE_TYPE = "agent-mediate/dispute-invite/v1" as const;

export interface PartyContact {
  webhookUrl?: string;
  a2aCardUrl?: string;
  didWeb?: string;
  email?: string;
}

export interface ClauseParty {
  /** Agent's Ed25519 did:key. */
  agentId: string;
  /** Optional principal Ed25519 did:key (defaults to agentId when self-representing). */
  principalId?: string;
  /** Pre-agreed notification endpoints for this party (treated as verifiedEndpoint: true). */
  notice?: PartyContact;
}

export type ClauseWindowKey = keyof typeof CONFIG_LIMITS;

export interface ClauseTerms {
  feeMode?: FeeMode;
  /** Minimum window floors agreed by both parties (filings may lengthen within platform limits, never shorten). */
  windows?: Partial<Pick<DisputeConfig, ClauseWindowKey>>;
  /** Pre-agreed opt-in to contractual final-offer determination (must also be present in principal-signed mandates). */
  determinationConsent?: boolean;
  discloseGapOnFailure?: boolean;
  /** Optional pre-agreed issue templates for disputes under this contract. */
  issueTemplates?: Issue[];
}

export interface UnsignedDisputeClause {
  type: typeof CLAUSE_TYPE;
  /** 64-char lowercase hex SHA-256 of the RFC 8785 (JCS) canonical JSON contract. */
  contractHash: string;
  platform: {
    did: string;
    baseUrl?: string;
    rulesVersion: string;
    /** Optional 64-char lowercase hex SHA-256 of canonical `MECHANISM_SPEC` (`DISC-11`). */
    rulesHash?: string;
  };
  parties: [ClauseParty, ClauseParty];
  terms?: ClauseTerms;
  issuedAt: number;
  expiresAt?: number;
}

export interface ClauseSignature {
  partyAgentId: string;
  signerId: string;
  signature: string;
}

export interface DisputeClause extends UnsignedDisputeClause {
  signatures: ClauseSignature[];
}

export interface DisputeNoticeDocument {
  type: typeof DISPUTE_NOTICE_TYPE;
  rulesVersion: string;
  environment: string;
  disputeId: string;
  claimantId: string;
  respondentId: string;
  contractHash: string;
  feeMode: FeeMode;
  respondentFeeDue: boolean;
  joinDeadline: number;
  issuedAt: number;
  noticeUrl: string;
  joinEndpoint: string;
  disputeEndpoint: string;
  llmsTxtUrl: string;
  mcpPackage: string;
}

export interface DisputeInviteDocument {
  type: typeof DISPUTE_INVITE_TYPE;
  rulesVersion: string;
  environment: string;
  inviteId: string;
  claimantId: string;
  /** Expected respondent Ed25519 did:key if already known; null on cold-target invites until accepted. */
  respondentId: string | null;
  contractHash: string;
  feeMode: FeeMode;
  respondentFeeDue: false;
  expiresAt: number;
  issuedAt: number;
  inviteUrl: string;
  acceptEndpoint: string;
  inviteEndpoint: string;
  llmsTxtUrl: string;
  mcpPackage: string;
}

export interface RecordedNoticeInfo {
  token: string;
  noticeUrl: string;
  method: NoticeMethod;
  delivered: boolean;
  verifiedEndpoint: boolean;
  attempted: NoticeMethod[];
}

export interface BuildClauseInput {
  /** Structured JSON contract (hashed via RFC 8785 JCS `contractHash(contract)`). Provide `contract` or `contractHash`. */
  contract?: unknown;
  /** Pre-computed 64-char lowercase hex SHA-256 contract hash. */
  contractHash?: string;
  platformDid: string;
  platformBaseUrl?: string;
  rulesVersion?: string;
  rulesHash?: string;
  parties: [ClauseParty, ClauseParty];
  terms?: ClauseTerms;
  issuedAt?: number;
  expiresAt?: number;
}

const SHA256_HEX = /^[a-f0-9]{64}$/;
const EMAIL_PATTERN = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
const CLAUSE_KEYS: ReadonlySet<string> = new Set([
  "type",
  "contractHash",
  "platform",
  "parties",
  "terms",
  "issuedAt",
  "expiresAt",
  "signatures",
]);
const CLAUSE_PLATFORM_KEYS: ReadonlySet<string> = new Set(["did", "baseUrl", "rulesVersion", "rulesHash"]);
const CLAUSE_PARTY_KEYS: ReadonlySet<string> = new Set(["agentId", "principalId", "notice"]);
const PARTY_CONTACT_KEYS: ReadonlySet<string> = new Set(["webhookUrl", "a2aCardUrl", "didWeb", "email"]);
const CLAUSE_TERMS_KEYS: ReadonlySet<string> = new Set([
  "feeMode",
  "windows",
  "determinationConsent",
  "discloseGapOnFailure",
  "issueTemplates",
]);
const CLAUSE_SIGNATURE_KEYS: ReadonlySet<string> = new Set(["partyAgentId", "signerId", "signature"]);

function isPlainRecord(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === null || proto === Object.prototype;
}

function unknownKeyIn(obj: Record<string, unknown>, allowed: ReadonlySet<string>): string | null {
  for (const k of Object.keys(obj)) {
    if (!allowed.has(k)) return k;
  }
  return null;
}

function isValidHttpUrl(raw: string): boolean {
  if (typeof raw !== "string" || raw.length === 0 || /[\x00-\x20\x7f\\]/.test(raw)) return false;
  const authMatch = /^https?:\/\/([^/?#]+)/i.exec(raw);
  if (!authMatch) return false;
  const authority = authMatch[1]!;
  if (authority.includes("@")) return false;
  let hostPart: string;
  let portPart: string | undefined;
  if (authority.startsWith("[")) {
    const closeIdx = authority.indexOf("]");
    if (closeIdx <= 1) return false;
    const ipv6 = authority.slice(1, closeIdx);
    if (isIP(ipv6) !== 6) return false;
    const rest = authority.slice(closeIdx + 1);
    if (rest.length > 0) {
      if (!rest.startsWith(":")) return false;
      portPart = rest.slice(1);
    }
    hostPart = authority.slice(0, closeIdx + 1);
  } else {
    const colonIdx = authority.indexOf(":");
    if (colonIdx !== -1) {
      if (authority.indexOf(":", colonIdx + 1) !== -1) return false;
      hostPart = authority.slice(0, colonIdx);
      portPart = authority.slice(colonIdx + 1);
    } else {
      hostPart = authority;
    }
    const lowerHost = hostPart.toLowerCase();
    if (!lowerHost || lowerHost.startsWith(".") || lowerHost.endsWith(".") || lowerHost.includes("..")) return false;
    if (!/^[a-z0-9.-]+$/.test(lowerHost)) return false;
    const labels = lowerHost.split(".");
    const allNumericOrHex = labels.every((l) => /^(?:0x[0-9a-f]+|\d+)$/i.test(l));
    if (allNumericOrHex) {
      if (isIP(lowerHost) !== 4 || !/^(?:0|[1-9]\d{0,2})(?:\.(?:0|[1-9]\d{0,2})){3}$/.test(lowerHost)) return false;
    } else if (!labels.every((l) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(l))) {
      return false;
    }
  }
  if (portPart !== undefined && portPart.length > 0) {
    if (!/^[1-9][0-9]{0,4}$/.test(portPart) || Number(portPart) > 65535) return false;
  }
  try {
    const u = new URL(raw);
    return (u.protocol === "http:" || u.protocol === "https:") && u.username === "" && u.password === "" && Boolean(hostPart);
  } catch {
    return false;
  }
}

export function partyContactProblem(contact: unknown, label: string): string | null {
  if (!isPlainRecord(contact)) {
    return `${label} must be an object`;
  }
  const extra = unknownKeyIn(contact, PARTY_CONTACT_KEYS);
  if (extra) return `${label}.${extra} is not a supported contact field`;
  for (const [k, v] of Object.entries(contact)) {
    if (v === undefined) continue;
    const maxLen = k === "webhookUrl" || k === "a2aCardUrl" ? 2048 : k === "email" ? 320 : 512;
    if (typeof v !== "string" || v.trim().length === 0 || v.length > maxLen) {
      return `${label}.${k} must be a non-empty string (<= ${maxLen} chars)`;
    }
    if ((k === "webhookUrl" || k === "a2aCardUrl") && !isValidHttpUrl(v)) {
      return `${label}.${k} must be a valid HTTP(S) URL`;
    }
    if (k === "email" && !EMAIL_PATTERN.test(v)) {
      return `${label}.email must be a valid email address`;
    }
    if (k === "didWeb") {
      try {
        urlFromDidWeb(v);
      } catch {
        return `${label}.didWeb must be a valid did:web identifier`;
      }
    }
  }
  return null;
}

export function buildClause(input: BuildClauseInput): DisputeClause {
  const hash =
    input.contractHash !== undefined
      ? input.contractHash
      : input.contract !== undefined
        ? contractHash(input.contract)
        : "";
  if (!SHA256_HEX.test(hash)) throw new Error("provide contract or a 64-char lowercase hex contractHash");
  if (!isDidKey(input.platformDid)) throw new Error("platformDid must be a valid Ed25519 did:key");
  if (input.platformBaseUrl !== undefined) {
    if (typeof input.platformBaseUrl !== "string" || !isValidHttpUrl(input.platformBaseUrl.replace(/\/+$/, ""))) {
      throw new Error("platformBaseUrl must be a valid HTTP(S) URL");
    }
  }
  const [a, b] = input.parties;
  if (!isPlainRecord(a) || !isPlainRecord(b) || !isDidKey(a.agentId) || !isDidKey(b.agentId)) {
    throw new Error("both clause parties must have valid Ed25519 did:key agentIds");
  }
  for (const [idx, p] of [a, b].entries()) {
    const extraPartyKey = unknownKeyIn(p, CLAUSE_PARTY_KEYS);
    if (extraPartyKey) throw new Error(`party[${idx}].${extraPartyKey} is not a supported party field`);
  }
  if (a.agentId === b.agentId) throw new Error("clause parties must have distinct agentIds");
  if (a.principalId !== undefined && !isDidKey(a.principalId)) throw new Error("party[0].principalId must be a valid Ed25519 did:key");
  if (b.principalId !== undefined && !isDidKey(b.principalId)) throw new Error("party[1].principalId must be a valid Ed25519 did:key");
  for (const [idx, p] of [a, b].entries()) {
    if (p.notice !== undefined) {
      const problem = partyContactProblem(p.notice, `party[${idx}].notice`);
      if (problem) throw new Error(problem);
    }
  }
  const issuedAt = input.issuedAt ?? Date.now();
  if (!Number.isSafeInteger(issuedAt) || issuedAt <= 0) throw new Error("issuedAt must be a positive integer timestamp");
  if (input.expiresAt !== undefined && (!Number.isSafeInteger(input.expiresAt) || input.expiresAt <= issuedAt)) {
    throw new Error("expiresAt must be an integer timestamp after issuedAt");
  }
  if (input.terms !== undefined) {
    if (!isPlainRecord(input.terms)) {
      throw new Error("terms must be an object");
    }
    const extraTermsKey = unknownKeyIn(input.terms, CLAUSE_TERMS_KEYS);
    if (extraTermsKey) throw new Error(`terms.${extraTermsKey} is not a supported terms field`);
    if (input.terms.feeMode !== undefined && input.terms.feeMode !== "FILER_PAYS") {
      throw new Error("terms.feeMode must be FILER_PAYS");
    }
    if (input.terms.determinationConsent !== undefined && typeof input.terms.determinationConsent !== "boolean") {
      throw new Error("terms.determinationConsent must be a boolean");
    }
    if (input.terms.discloseGapOnFailure !== undefined && typeof input.terms.discloseGapOnFailure !== "boolean") {
      throw new Error("terms.discloseGapOnFailure must be a boolean");
    }
    if (input.terms.windows !== undefined) {
      if (!isPlainRecord(input.terms.windows)) {
        throw new Error("terms.windows must be an object");
      }
      for (const [k, v] of Object.entries(input.terms.windows) as Array<[ClauseWindowKey, number | undefined]>) {
        // Own keys only (CR-CORE-L1): CONFIG_LIMITS["constructor"] would otherwise pass every bound check.
        const lim = Object.prototype.hasOwnProperty.call(CONFIG_LIMITS, k) ? CONFIG_LIMITS[k] : undefined;
        if (!lim) {
          throw new Error(`terms.windows.${k} is not a supported window field`);
        }
        if (v === undefined) continue;
        if (!Number.isSafeInteger(v) || v < lim.min || v > lim.max) {
          throw new Error(`terms.windows.${k} must lie within platform limits`);
        }
      }
      if (
        typeof input.terms.windows.bargainingWallClockMs === "number" &&
        typeof input.terms.windows.roundTimeoutMs === "number" &&
        input.terms.windows.bargainingWallClockMs < input.terms.windows.roundTimeoutMs
      ) {
        throw new Error("terms.windows.bargainingWallClockMs must be at least roundTimeoutMs");
      }
    }
    if (input.terms.issueTemplates !== undefined) {
      if (!Array.isArray(input.terms.issueTemplates)) {
        throw new Error("terms.issueTemplates must be an array");
      }
      if (input.terms.issueTemplates.length > 0) {
        validateIssues(input.terms.issueTemplates);
      }
    }
  }
  const rulesVersion = input.rulesVersion ?? RULES_VERSION;
  if (typeof rulesVersion !== "string" || rulesVersion.trim().length === 0 || rulesVersion.length > 64) {
    throw new Error("rulesVersion must be a non-empty string");
  }
  const rulesHash = input.rulesHash ?? (rulesVersion === RULES_VERSION ? RULES_HASH : undefined);
  if (rulesHash !== undefined && !SHA256_HEX.test(rulesHash)) {
    throw new Error("rulesHash must be 64 lowercase hex characters");
  }
  return {
    type: CLAUSE_TYPE,
    contractHash: hash,
    platform: {
      did: input.platformDid,
      ...(input.platformBaseUrl ? { baseUrl: input.platformBaseUrl.replace(/\/+$/, "") } : {}),
      rulesVersion,
      ...(rulesHash !== undefined ? { rulesHash } : {}),
    },
    parties: [structuredClone(a), structuredClone(b)],
    ...(input.terms ? { terms: structuredClone(input.terms) } : {}),
    issuedAt,
    ...(input.expiresAt !== undefined ? { expiresAt: input.expiresAt } : {}),
    signatures: [],
  };
}

export function clauseSigningPayload(clause: UnsignedDisputeClause | DisputeClause): string {
  const { signatures: _ignored, ...unsigned } = clause as DisputeClause;
  return CLAUSE_DOMAIN + canonicalJson(unsigned);
}

/**
 * Add (or replace) one party's signature on a `DisputeClause`.
 * Sign with `party.principalId` when set, otherwise with `party.agentId`.
 * Pass `partyAgentId` when the same principal key represents multiple agents.
 */
export function signClause(clause: UnsignedDisputeClause | DisputeClause, signer: AgentKey, partyAgentId?: string): DisputeClause {
  const matching = clause.parties.filter((p) =>
    partyAgentId ? p.agentId === partyAgentId && (p.principalId ?? p.agentId) === signer.did : (p.principalId ?? p.agentId) === signer.did,
  );
  if (matching.length === 0) {
    throw new Error(`signer ${signer.did} does not match any party's principalId/agentId in this clause`);
  }
  if (matching.length > 1) {
    throw new Error("same principal represents both parties; specify partyAgentId explicitly");
  }
  const target = matching[0]!;
  const payload = clauseSigningPayload(clause);
  const existing = "signatures" in clause && Array.isArray(clause.signatures) ? clause.signatures.filter((s) => s.partyAgentId !== target.agentId) : [];
  const { signatures: _ignored, ...unsigned } = clause as DisputeClause;
  return {
    ...structuredClone(unsigned),
    signatures: [
      ...existing,
      {
        partyAgentId: target.agentId,
        signerId: signer.did,
        signature: signText(signer, payload),
      },
    ],
  };
}

export interface VerifyClauseOptions {
  expectedPlatformDid?: string;
  expectedPlatformBaseUrl?: string;
  keyHistory?: SignedDocument<KeyHistoryDocument>;
  expectedContractHash?: string;
  expectedRulesHash?: string;
  /** Optional list of additional accepted rules hashes (e.g. legacy `HISTORICAL_RULES_HASHES` during upgrades). */
  acceptedRulesHashes?: readonly string[];
  claimantId?: string;
  respondentId?: string;
  now?: number;
}

export type VerifiedClause =
  | { ok: true; parties: [ClauseParty, ClauseParty]; claimantParty?: ClauseParty; respondentParty?: ClauseParty }
  | { ok: false; reason: string };

/**
 * Verify that `issues` is a non-empty subset of `templates` (`SEC-2`), matching each template's
 * `id`, `claimantPrefers`, `obligor`, `unit`, and `step`, with on-grid `min >= template.min` and `max <= template.max`.
 */
export function validateIssuesAgainstClauseTemplates(
  issues: Issue[],
  templates: Issue[],
): { ok: true } | { ok: false; reason: string } {
  if (!Array.isArray(templates) || templates.length === 0) return { ok: true };
  if (!Array.isArray(issues) || issues.length === 0) {
    return { ok: false, reason: "proposedIssues must be a non-empty subset of clause.terms.issueTemplates" };
  }
  const byId = new Map<string, Issue>();
  for (const t of templates) byId.set(t.id, t);
  const seen = new Set<string>();
  for (const issue of issues) {
    if (!issue || typeof issue.id !== "string") {
      return { ok: false, reason: "proposed issue is missing id" };
    }
    if (seen.has(issue.id)) {
      return { ok: false, reason: `duplicate proposed issue id "${issue.id}"` };
    }
    seen.add(issue.id);
    const tmpl = byId.get(issue.id);
    if (!tmpl) {
      return { ok: false, reason: `issue "${issue.id}" is not permitted by clause.terms.issueTemplates` };
    }
    if (
      issue.claimantPrefers !== tmpl.claimantPrefers ||
      issue.obligor !== tmpl.obligor ||
      issue.unit !== tmpl.unit ||
      issue.step !== tmpl.step ||
      Number.isInteger(issue.min) !== Number.isInteger(tmpl.min)
    ) {
      return {
        ok: false,
        reason: `issue "${issue.id}" must match clause template unit, step, claimantPrefers, and obligor`,
      };
    }
    if (
      issue.min < tmpl.min - 1e-9 ||
      issue.max > tmpl.max + 1e-9 ||
      !(issue.max > issue.min) ||
      !isOnGrid(tmpl, issue.min) ||
      !isOnGrid(tmpl, issue.max)
    ) {
      return {
        ok: false,
        reason: `issue "${issue.id}" range [${issue.min}, ${issue.max}] must lie on-grid within clause template [${tmpl.min}, ${tmpl.max}]`,
      };
    }
  }
  return { ok: true };
}

/**
 * Verify a co-signed `DisputeClause`: structure, expiry, platform/contract/party bindings, and both Ed25519 signatures.
 */
export function verifyClause(clause: DisputeClause, opts: VerifyClauseOptions = {}): VerifiedClause {
  if (!isPlainRecord(clause) || clause.type !== CLAUSE_TYPE) {
    return { ok: false, reason: `clause.type must be ${CLAUSE_TYPE}` };
  }
  const extraClauseKey = unknownKeyIn(clause, CLAUSE_KEYS);
  if (extraClauseKey) {
    return { ok: false, reason: `clause.${extraClauseKey} is not a supported clause field` };
  }
  if (typeof clause.contractHash !== "string" || !SHA256_HEX.test(clause.contractHash)) {
    return { ok: false, reason: "clause.contractHash must be 64 lowercase hex characters" };
  }
  if (opts.expectedContractHash !== undefined && clause.contractHash !== opts.expectedContractHash) {
    return { ok: false, reason: "clause.contractHash does not match filing contractHash" };
  }
  if (opts.now !== undefined && (!Number.isFinite(opts.now) || opts.now <= 0)) {
    return { ok: false, reason: "now must be a positive finite timestamp" };
  }
  if (!isPlainRecord(clause.platform) || typeof clause.platform.did !== "string" || !isDidKey(clause.platform.did)) {
    return { ok: false, reason: "clause.platform.did must be a valid Ed25519 did:key" };
  }
  const extraPlatformKey = unknownKeyIn(clause.platform, CLAUSE_PLATFORM_KEYS);
  if (extraPlatformKey) {
    return { ok: false, reason: `clause.platform.${extraPlatformKey} is not a supported platform field` };
  }
  if (typeof clause.platform.rulesVersion !== "string" || clause.platform.rulesVersion.trim().length === 0 || clause.platform.rulesVersion.length > 64) {
    return { ok: false, reason: "clause.platform.rulesVersion must be a non-empty string" };
  }
  if (clause.platform.baseUrl !== undefined) {
    if (typeof clause.platform.baseUrl !== "string" || clause.platform.baseUrl.length > 2048 || !isValidHttpUrl(clause.platform.baseUrl)) {
      return { ok: false, reason: "clause.platform.baseUrl must be a valid HTTP(S) URL" };
    }
    if (opts.expectedPlatformBaseUrl !== undefined) {
      const normClauseUrl = clause.platform.baseUrl.replace(/\/+$/, "");
      const normExpectedUrl = opts.expectedPlatformBaseUrl.replace(/\/+$/, "");
      if (normClauseUrl !== normExpectedUrl) {
        return { ok: false, reason: "clause.platform.baseUrl does not match this platform" };
      }
    }
  }
  if (!Number.isSafeInteger(clause.issuedAt) || clause.issuedAt <= 0) {
    return { ok: false, reason: "clause.issuedAt must be a positive integer" };
  }
  if (opts.keyHistory !== undefined) {
    const vh = verifyKeyHistory(opts.keyHistory, {
      ...(opts.expectedPlatformDid !== undefined ? { expectedActiveDid: opts.expectedPlatformDid } : {}),
      ...(opts.now !== undefined ? { now: opts.now } : {}),
    });
    if (!vh.ok) {
      return { ok: false, reason: `clause.platform.did key history invalid: ${vh.reason}` };
    }
    const histKey = opts.keyHistory.document.keys.find((k) => k.did === clause.platform.did);
    if (
      !histKey ||
      (histKey.status !== "active" && histKey.status !== "retired") ||
      histKey.revokedAt !== undefined ||
      histKey.compromisedAfter !== undefined ||
      clause.issuedAt < histKey.validFrom ||
      (histKey.validUntil !== undefined && clause.issuedAt > histKey.validUntil)
    ) {
      return { ok: false, reason: "clause.platform.did does not match this platform" };
    }
  } else if (opts.expectedPlatformDid !== undefined && clause.platform.did !== opts.expectedPlatformDid) {
    return { ok: false, reason: "clause.platform.did does not match this platform" };
  }
  const allowedRulesHashes =
    opts.expectedRulesHash !== undefined || (opts.acceptedRulesHashes && opts.acceptedRulesHashes.length > 0)
      ? new Set([
          ...(opts.expectedRulesHash !== undefined ? [opts.expectedRulesHash] : []),
          ...(opts.acceptedRulesHashes ?? []),
        ])
      : null;
  if (clause.platform.rulesHash !== undefined) {
    if (typeof clause.platform.rulesHash !== "string" || !SHA256_HEX.test(clause.platform.rulesHash)) {
      return { ok: false, reason: "clause.platform.rulesHash must be 64 lowercase hex characters" };
    }
    if (allowedRulesHashes !== null && !allowedRulesHashes.has(clause.platform.rulesHash)) {
      return { ok: false, reason: "clause.platform.rulesHash does not match platform rulesHash" };
    }
  } else if (allowedRulesHashes !== null) {
    return { ok: false, reason: "clause.platform.rulesHash is missing" };
  }
  if (clause.expiresAt !== undefined) {
    if (!Number.isSafeInteger(clause.expiresAt) || clause.expiresAt <= clause.issuedAt) {
      return { ok: false, reason: "clause.expiresAt must be after issuedAt" };
    }
    if (opts.now !== undefined && opts.now >= clause.expiresAt) {
      return { ok: false, reason: "clause has expired" };
    }
  }
  if (!Array.isArray(clause.parties) || clause.parties.length !== 2) {
    return { ok: false, reason: "clause.parties must contain exactly two parties" };
  }
  const [p0, p1] = clause.parties;
  if (!isPlainRecord(p0) || !isPlainRecord(p1) || !isDidKey(p0.agentId) || !isDidKey(p1.agentId) || p0.agentId === p1.agentId) {
    return { ok: false, reason: "clause.parties must have two distinct valid Ed25519 did:key agentIds" };
  }
  for (const [idx, p] of [p0, p1].entries()) {
    const extraPartyKey = unknownKeyIn(p, CLAUSE_PARTY_KEYS);
    if (extraPartyKey) {
      return { ok: false, reason: `clause.parties[${idx}].${extraPartyKey} is not a supported party field` };
    }
  }
  if ((p0.principalId !== undefined && !isDidKey(p0.principalId)) || (p1.principalId !== undefined && !isDidKey(p1.principalId))) {
    return { ok: false, reason: "clause party principalId must be a valid Ed25519 did:key" };
  }
  for (const [idx, p] of [p0, p1].entries()) {
    if (p.notice !== undefined) {
      const problem = partyContactProblem(p.notice, `clause.parties[${idx}].notice`);
      if (problem) return { ok: false, reason: problem };
    }
  }
  if (clause.terms !== undefined) {
    if (!isPlainRecord(clause.terms)) {
      return { ok: false, reason: "clause.terms must be an object" };
    }
    const extraTermsKey = unknownKeyIn(clause.terms, CLAUSE_TERMS_KEYS);
    if (extraTermsKey) {
      return { ok: false, reason: `clause.terms.${extraTermsKey} is not a supported terms field` };
    }
    if (clause.terms.feeMode !== undefined && clause.terms.feeMode !== "FILER_PAYS") {
      return { ok: false, reason: "clause.terms.feeMode must be FILER_PAYS" };
    }
    if (clause.terms.determinationConsent !== undefined && typeof clause.terms.determinationConsent !== "boolean") {
      return { ok: false, reason: "clause.terms.determinationConsent must be a boolean" };
    }
    if (clause.terms.discloseGapOnFailure !== undefined && typeof clause.terms.discloseGapOnFailure !== "boolean") {
      return { ok: false, reason: "clause.terms.discloseGapOnFailure must be a boolean" };
    }
    if (clause.terms.windows !== undefined) {
      if (!isPlainRecord(clause.terms.windows)) {
        return { ok: false, reason: "clause.terms.windows must be an object" };
      }
      for (const [k, v] of Object.entries(clause.terms.windows) as Array<[ClauseWindowKey, unknown]>) {
        // Own keys only (CR-CORE-L1): CONFIG_LIMITS["constructor"] would otherwise pass every bound check.
        const lim = Object.prototype.hasOwnProperty.call(CONFIG_LIMITS, k) ? CONFIG_LIMITS[k] : undefined;
        if (!lim) {
          return { ok: false, reason: `clause.terms.windows.${k} is not a supported window field` };
        }
        if (v === undefined) continue;
        if (typeof v !== "number" || !Number.isSafeInteger(v) || v < lim.min || v > lim.max) {
          return { ok: false, reason: `clause.terms.windows.${k} is outside platform limits` };
        }
      }
      if (
        typeof clause.terms.windows.bargainingWallClockMs === "number" &&
        typeof clause.terms.windows.roundTimeoutMs === "number" &&
        clause.terms.windows.bargainingWallClockMs < clause.terms.windows.roundTimeoutMs
      ) {
        return { ok: false, reason: "clause.terms.windows.bargainingWallClockMs must be at least roundTimeoutMs" };
      }
    }
    if (clause.terms.issueTemplates !== undefined) {
      if (!Array.isArray(clause.terms.issueTemplates) || clause.terms.issueTemplates.length > 5) {
        return { ok: false, reason: "clause.terms.issueTemplates must be an array of at most 5 issues" };
      }
      if (clause.terms.issueTemplates.length > 0) {
        try {
          validateIssues(clause.terms.issueTemplates);
        } catch (e) {
          return { ok: false, reason: `clause.terms.issueTemplates invalid: ${(e as Error).message}` };
        }
      }
    }
  }
  if (!Array.isArray(clause.signatures) || clause.signatures.length !== 2) {
    return { ok: false, reason: "clause must carry signatures from both parties" };
  }
  for (const [idx, s] of clause.signatures.entries()) {
    if (!isPlainRecord(s)) {
      return { ok: false, reason: `clause.signatures[${idx}] must be an object` };
    }
    const extraSigKey = unknownKeyIn(s, CLAUSE_SIGNATURE_KEYS);
    if (extraSigKey) {
      return { ok: false, reason: `clause.signatures[${idx}].${extraSigKey} is not a supported signature field` };
    }
  }
  let payload: string;
  try {
    payload = clauseSigningPayload(clause);
  } catch (e) {
    return { ok: false, reason: `clause payload invalid: ${(e as Error).message}` };
  }
  for (const party of [p0, p1]) {
    const expectedSigner = party.principalId ?? party.agentId;
    const sig = clause.signatures.find((s) => s && s.partyAgentId === party.agentId);
    if (!sig) return { ok: false, reason: `missing signature for party ${party.agentId}` };
    if (sig.signerId !== expectedSigner) {
      return { ok: false, reason: `party ${party.agentId} must be signed by ${expectedSigner}` };
    }
    if (typeof sig.signature !== "string" || !verifyText(expectedSigner, payload, sig.signature)) {
      return { ok: false, reason: `invalid signature for party ${party.agentId}` };
    }
  }

  let claimantParty: ClauseParty | undefined;
  let respondentParty: ClauseParty | undefined;
  if (opts.claimantId !== undefined) {
    claimantParty = [p0, p1].find((p) => p.agentId === opts.claimantId);
    if (!claimantParty) return { ok: false, reason: "claimant is not a party to this clause" };
  }
  if (opts.respondentId !== undefined) {
    respondentParty = [p0, p1].find((p) => p.agentId === opts.respondentId);
    if (!respondentParty) return { ok: false, reason: "respondent is not a party to this clause" };
  }
  return {
    ok: true,
    parties: [p0, p1],
    ...(claimantParty ? { claimantParty } : {}),
    ...(respondentParty ? { respondentParty } : {}),
  };
}
