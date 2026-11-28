/**
 * Agent-Mediate client. Handles RFC 9421 signing, idempotency keys (reused
 * across retries, including the paid retry after a 402), x402 payment,
 * platform-signature verification of outcomes, and webhook verification.
 */
import { createHash, randomUUID } from "node:crypto";
import {
  canonicalJson,
  computeOutcomeHash,
  computeTermsHash,
  DEFAULT_PRODUCTION_PLATFORM_DIDS,
  encodeBaseAnchorCalldata,
  normalizeBaseUrl,
  PRODUCTION_API_URL,
  SETTLEMENT_METHODS,
  sha256Hex,
  verifyCheckpointInclusion,
  verifyPublicAuditChain,
  type CheckpointLeafInput,
  type CompactPartyView,
  type DisputeConfig,
  type ImprovementResponse,
  type Issue,
  type IssueLimits,
  type Mandate,
  type MerkleInclusionProof,
  type NoticeDelivery,
  type Package,
  type PartyView,
  type ProposalResponse,
  type PublicAuditEntry,
  type ReasonCode,
  type SettlementMethod,
} from "@agent-mediate/core";
import {
  DEFAULT_KEY_HISTORY_TTL_MS,
  didWebFromUrl,
  DISPUTE_INVITE_TYPE,
  HONOURS_ATTESTATION_TYPE,
  isDidKey,
  parseHonoursSubject,
  signMandate,
  signRequest,
  verifyAgentCardSignature,
  verifyDocument,
  verifyDocumentWithKeyHistory,
  verifyKeyHistory,
  verifyRequest,
  verifyRequestProof,
  WEBHOOK_SIGNATURE_TAG,
  type AgentKey,
  type DisputeClause,
  type DisputeInviteDocument,
  type DisputeNoticeDocument,
  type HonoursAttestationDocument,
  type KeyHistoryDocument,
  type PartyContact,
  type RequestSignatureProof,
  type SignedDocument,
} from "@agent-mediate/protocol";
import { AgentMediateError } from "./errors.ts";
import { discoverRespondent, type DiscoveredRespondent, type DiscoverRespondentOptions } from "./discover.ts";
import { BASE_MAINNET, PaymentPolicyError, type PaidOperation, type Payer, type PaymentRequired } from "./payer.ts";

export { AgentMediateError } from "./errors.ts";

export type FetchLike = (
  url: string,
  init: { method: string; headers: Record<string, string>; body?: string; signal?: AbortSignal; redirect?: RequestRedirect },
) => Promise<Response>;
export type Bounds = Mandate["bounds"];
export type ViewOption = "full" | "compact";
export type DefaultViewOf<V extends ViewOption> = V extends "compact" ? CompactPartyView : PartyView;

/** Thrown when a fee is due and no payer is configured. `paymentRequired` is the x402 challenge. */
export class PaymentRequiredError extends AgentMediateError {
  readonly paymentRequired: PaymentRequired;
  constructor(paymentRequired: PaymentRequired, body: unknown, idempotencyKey?: string) {
    super(402, "PAYMENT_REQUIRED", "a fee is due and no payer is configured", body, idempotencyKey ? { idempotencyKey } : undefined);
    this.name = "PaymentRequiredError";
    this.paymentRequired = paymentRequired;
  }
}

export interface PlatformInfo {
  did: string;
  didWeb?: string;
  didDocument?: string;
  keyHistory?: string;
  rulesVersion?: string;
  rulesHash?: string;
  rulesUrl?: string;
  mechanismDoc?: string;
  transparency?: string;
  transparencyCheckpoint?: string;
  honoursRoll?: string;
  honoursApi?: string;
  requestSignatures?: string;
  documentProof?: string;
  fees: { payTo: string; network: string; fullFeeAtomic: string } | { waived: true };
  practiceBot?: {
    did: string;
    role: string;
    active?: boolean;
    feeFree?: boolean;
    nonBinding?: boolean;
    honoursEligible?: boolean;
    description?: string;
    claimantSteps?: string[];
  };
  termsOfService?: string;
  privacyPolicy?: string;
}

export interface RulesInfo {
  rulesVersion: string;
  rulesHash: string;
  mechanismDocUrl: string;
  spec: Record<string, unknown>;
}

export interface CheckpointAnchorInfo {
  network: string;
  txHash: string;
  calldata: string;
  anchoredAt: number;
}

export interface TransparencyCheckpointDocument {
  type: "agent-mediate/transparency-checkpoint/v1";
  rulesVersion: string;
  rulesHash: string;
  environment: string;
  checkpointSeq: number;
  merkleRoot: string;
  disputeCount: number;
  prevCheckpointHash: string;
  baseAnchorCalldata: string;
  issuedAt: number;
}

export interface TransparencyCheckpointInfo {
  signedCheckpoint: SignedDocument<TransparencyCheckpointDocument>;
  checkpointHash: string;
  anchor: CheckpointAnchorInfo | null;
}

export interface AuditCheckpointInclusion {
  signedCheckpoint: SignedDocument<TransparencyCheckpointDocument>;
  checkpointHash: string;
  leaf: CheckpointLeafInput;
  inclusionProof: MerkleInclusionProof;
  anchor: CheckpointAnchorInfo | null;
}

export type DisputeSignatureEntry =
  | {
      id: number;
      party: "claimant" | "respondent";
      agentId: string;
      action: string;
      seqRange: [number, number];
      proofHash: string;
      redacted: false;
      proof: RequestSignatureProof;
      verified?: boolean;
      verifyReason?: string;
    }
  | {
      id: number;
      party: "claimant";
      agentId: string;
      action: "file_dispute";
      seqRange: [number, number];
      proofHash: string;
      redacted: true;
    }
  | {
      id: number;
      party: null;
      agentId: null;
      action: "confidential_action";
      seqRange: [number, number] | null;
      proofHash: string;
      redacted: true;
    };

export interface AuditOptions {
  /** Reject when the audit response carries no transparency checkpoint (`M5`). */
  requireCheckpoint?: boolean;
  /** Reject when the audit response carries no Base L2 anchor (`M5`). */
  requireAnchor?: boolean;
  /** Cross-check the verified audit chain and checkpoint leaf against a signed outcome (`M5`). */
  expectedOutcome?: SignedDocument<Record<string, unknown>>;
}

export interface SignaturesOptions {
  /** Throw `INVALID_REQUEST_PROOF` on the first failing unredacted entry (`true` default); set `false` to annotate per-entry `verified` / `verifyReason` (`M1`). */
  strict?: boolean;
  /** Optional expected party DIDs to pin against the returned signature log (`M6`). */
  expectedParties?: { claimant?: string; respondent?: string };
}

export interface Advisory {
  status: "ok" | "unavailable";
  notice: string;
  /** The advisory is AI-generated from both parties' free text: untrusted (security review M12). */
  provenance: { authoredBy: "ai-from-party-text"; untrusted: true; notice: string };
  evidenceSummary: string | null;
  /** Each cites evidence ids from both parties (security review M12). */
  candidateAgreedFacts: Array<{ statement: string; evidenceIds: string[] }>;
  candidateDisputedFacts: string[];
  suggestedIssues: Array<{ issue: Issue; rationale: string }>;
}

export interface DisputeResponse<V = PartyView> {
  view: V;
  advisory?: Advisory | null;
  payment?: { status: string; transaction: string; amount: string; network: string };
}

export interface ClientOptions<DefaultView extends ViewOption = "full"> {
  baseUrl: string;
  agentKey: AgentKey;
  /**
   * Platform `did:key` pinned out of band (DISC-4, SEC3-8, H-1). Required when `expectedEnvironment === "production"`
   * or `payer` is configured for Base mainnet (`eip155:8453`), unless `DEFAULT_PRODUCTION_PLATFORM_DIDS[baseUrl]`
   * provides a built-in pin or `allowUnpinnedPlatformDid: true` is set explicitly for staging/smoke tests.
   */
  platformDid?: string;
  /**
   * Explicit opt-out for staging/smoke tests that target an `environment: "production"` deployment without pinning
   * `platformDid` out of band (`H-1`). Never enable for untrusted production traffic.
   */
  allowUnpinnedPlatformDid?: boolean;
  /**
   * Optional expected deployment environment (e.g. `"production"`). When set, `outcome()` refuses signed documents
   * from any other environment (SEC3-8).
   */
  expectedEnvironment?: string;
  /**
   * Optional expected deterministic `rulesHash` (`DISC-11`). When set, `/v1/platform` and `outcome()` refuse
   * responses reporting a different mechanism `rulesHash`.
   */
  expectedRulesHash?: string;
  /**
   * Default view projection for dispute reads and mutations (`"full"` default, `"compact"` for LLM/MCP context budgets, DISC-8).
   */
  defaultView?: DefaultView;
  /**
   * Pays fees automatically, for fileDispute only (security review M10): a 402 on any
   * other call is refused with UNEXPECTED_PAYMENT_REQUEST. Without a payer, paid calls throw PaymentRequiredError.
   */
  payer?: Payer;
  fetch?: FetchLike;
  now?: () => number;
  /** Retries for network errors, 429 and 5xx (same Idempotency-Key). Default 3. */
  maxRetries?: number;
  /** Per-request HTTP timeout in milliseconds (`CR-SDK-L5`). Default 30_000 (pass 0 to disable). */
  timeoutMs?: number;
}

export interface MandateInput {
  /** A ready, principal-signed mandate… */
  mandate?: Mandate;
  /** …or bounds, signed here with your agent key as your own principal. */
  bounds?: Bounds;
  /** Opt in to binding final-offer determination (signed into the mandate when `bounds` is used). */
  determinationConsent?: boolean;
  /** Optional per-issue bounds for binding final-offer determination (may be tighter OR wider than `bounds`; signed into the mandate when `bounds` is used). */
  determinationBounds?: Bounds;
  /** Guard against accidentally passing a bare `Mandate` object instead of `{ mandate }` (`M-09`). */
  signature?: never;
  principalId?: never;
}

export interface RejectIssuesInput {
  /** Hash of the current issue proposal (`view.issueNegotiation.proposedHash`, `v1.3.0` `BUG-3`). */
  issuesHash: string;
  /** Optional 1-2 issue IDs from `advisory.suggestedIssues` to append in the next issue proposal (`v1.2.0`). */
  adoptSuggestedIds?: string[];
}

export interface FilingNotice {
  token: string;
  noticeUrl: string;
  signedNotice: SignedDocument<DisputeNoticeDocument>;
  delivery: NoticeDelivery;
}

export interface NotificationSettings {
  agentId: string;
  webhookUrl: string | null;
  a2aCardUrl: string | null;
  email: string | null;
  updatedAt: number | null;
}

export interface RegisterNotificationsInput {
  webhookUrl?: string | null;
  a2aCardUrl?: string | null;
  email?: string | null;
}

export interface UpdateHonoursInput {
  optIn: boolean;
  didWeb?: string;
  a2aCardUrl?: string;
}

export interface HonoursRollEntry {
  domain: string;
  didWeb: string | null;
  agentIds: string[];
  verificationMethods: Array<"did_web" | "a2a_card">;
  memberSince: number;
  verifiedAt: number;
  qualifiedHonoredCount: number;
  totalHonoredObligations: number;
  confirmedByCounterpartyCount: number;
  distinctCounterparties: number;
  verifiedDomainCounterparties: number;
  distinctHonoredWeeks?: number;
  standingStrength?: "basic" | "domain-corroborated";
  curedLateCount: number;
  fulfilmentRate: 1;
  lastHonoredAt: number;
  lookupUrl: string;
}

export interface HonoursDirectory {
  environment: string;
  generatedAt: number;
  platform: {
    did: string;
    didWeb: string;
    activeKeyId: string;
    rulesVersion: string;
    rulesHash: string;
    honoursPageUrl: string;
  };
  policy: {
    optInOnly: true;
    domainVerificationRequired: true;
    permanentKeyDomainBinding: true;
    pairDeduplicationWindowDays: 30;
    minDistinctCounterparties?: number;
    minDistinctWeeks?: number;
    excludesPracticeBot?: true;
    excludesZeroObligationSettlements: true;
    requiresZeroBreachesAndZeroVerifiedNoShows: true;
    cureCooldownDays: 30;
    noShowRehabilitationDays: 180;
    maxCuredIncidentsPerYear: 1;
    attestationTtlHours: 24;
  };
  totalListedDomains: number;
  entries: HonoursRollEntry[];
}

export interface HonoursLookupResult {
  subject: string;
  listed: boolean;
  verified: boolean;
  checkedAt: number;
  entry: HonoursRollEntry | null;
  signedAttestation: SignedDocument<HonoursAttestationDocument> | null;
}

export interface MyHonoursSettings {
  agentId: string;
  optedIn: boolean;
  domain: string | null;
  didWeb: string | null;
  verificationMethod: "did_web" | "a2a_card" | null;
  verificationUrl: string | null;
  optedInAt: number | null;
  verifiedAt: number | null;
  updatedAt: number | null;
  standing: {
    listed: boolean;
    inGoodStanding: boolean;
    standingStrength?: "basic" | "domain-corroborated" | null;
    disqualifiers: string[];
    qualifiedHonoredCount: number;
    totalHonoredObligations: number;
    confirmedByCounterpartyCount: number;
    distinctCounterparties: number;
    verifiedDomainCounterparties: number;
    distinctHonoredWeeks?: number;
    defaultedBreachCount: number;
    uncuredBreachCount: number;
    curedLateCount: number;
    verifiedNoShowCount: number;
    uncuredNoShowCount: number;
    curedNoShowCount: number;
    probationEndsAt: number | null;
    lastHonoredAt: number | null;
  };
  honoursPageUrl: string;
  lookupUrl: string | null;
}

export interface AcknowledgeCureInput {
  reference?: string;
  note?: string;
}

export interface CureAcknowledgement {
  disputeId: string;
  curedParty: "claimant" | "respondent";
  curedAgentId: string;
  acknowledgedByParty: "claimant" | "respondent";
  acknowledgedByAgentId: string;
  cureKind: "breach_cured" | "no_show_waived";
  reference: string | null;
  note: string | null;
  proofHash: string | null;
  curedAt: number;
  probationCooldownDays: number;
}

export interface FileDisputeInput extends MandateInput {
  respondentId: string;
  contractHash: string;
  claim: { summary: string; requestedRemedy: string };
  proposedIssues: Issue[];
  discloseGapOnFailure?: boolean;
  config?: Partial<DisputeConfig>;
  webhookUrl?: string;
  respondentContact?: PartyContact;
  clause?: DisputeClause;
  /** Verify outbound respondent delivery before settling the $2.00 x402 fee; aborts with 422 RESPONDENT_UNREACHABLE ($0.00 charged) if unreachable. */
  requireDelivery?: boolean;
  /** Accepted $0.00 pre-filing handshake invite ID from POST /v1/invites. */
  inviteId?: string;
}

export interface CreateInviteInput {
  contractHash: string;
  summary: string;
  respondentId?: string;
  respondentContact?: PartyContact;
  webhookUrl?: string;
  ttlMs?: number;
}

export interface InviteCreated {
  inviteId: string;
  token: string;
  inviteUrl: string;
  status: "PENDING" | "ACCEPTED" | "FILED" | "EXPIRED";
  claimantId: string;
  respondentId: string | null;
  contractHash: string;
  createdAt: number;
  expiresAt: number;
  signedInvite: SignedDocument<DisputeInviteDocument>;
  delivery: NoticeDelivery;
}

export type InviteRespondentIdentity = "bound" | "domain_verified" | "unverified";

export interface InviteStatus {
  inviteId: string;
  role: "claimant" | "respondent";
  status: "PENDING" | "ACCEPTED" | "FILED" | "EXPIRED";
  claimantId: string;
  respondentId: string | null;
  respondentIdentity?: InviteRespondentIdentity | null;
  contractHash: string;
  summary: string;
  createdAt: number;
  expiresAt: number;
  acceptedAt: number | null;
  filedAt: number | null;
  disputeId: string | null;
  inviteUrl?: string;
  delivery?: NoticeDelivery;
  respondentWebhookRegistered?: boolean;
  webhookRegistered?: boolean;
  untrusted?: Array<{ path: string; authoredBy: string }>;
}

export interface AcceptInviteInput {
  webhookUrl?: string;
}

export interface InviteAccepted {
  inviteId: string;
  status: "ACCEPTED";
  claimantId: string;
  respondentId: string;
  respondentIdentity?: InviteRespondentIdentity;
  contractHash: string;
  summary: string;
  acceptedAt: number;
  expiresAt: number;
  webhookRegistered: boolean;
  untrusted: Array<{ path: string; authoredBy: string }>;
}

export interface VerifyInviteOptions {
  inviteId?: string;
  claimantId?: string;
  /** Expected respondent DID; when omitted and `allowThirdParty` is false, enforces `doc.respondentId === this.did` only if `doc.respondentId !== null`. */
  respondentId?: string;
  contractHash?: string;
  rulesVersion?: string;
  allowThirdParty?: boolean;
}

export interface JoinInput extends MandateInput {
  discloseGapOnFailure?: boolean;
  webhookUrl?: string;
  windows?: Partial<Record<"roundTimeoutMs" | "bargainingWallClockMs" | "stageTimeoutMs" | "determinationTimeoutMs" | "executionTimeoutMs", number>>;
}

export interface OfferInput {
  offer: Package;
  /** Required with your first offer. Never disclosed. */
  private?: { weights: Record<string, number>; walkaway: Package; limits?: IssueLimits };
  proposalResponse?: ProposalResponse;
}

export interface ListDisputesParams {
  status?: string;
  role?: "claimant" | "respondent";
  /** 1-100, default 50. */
  limit?: number;
  /** `nextCursor` from the previous page. */
  cursor?: string;
}

export interface DisputeSummary {
  disputeId: string;
  role: "claimant" | "respondent";
  status: string;
  createdAt: number;
  counterpartId: string;
  claimSummary: string;
  untrusted?: Array<{ path: string; authoredBy: string }>;
}

/** A verified webhook event. `recipient` names the party and (once bound) agent it was sent to (security review L3, `CR3-SDK-M2`, `L-08`). */
export interface WebhookEvent {
  disputeId?: string;
  inviteId?: string;
  seq?: number;
  type: string;
  at: number;
  data?: unknown;
  recipient: { party: "claimant" | "respondent"; agentId?: string };
  /** True on pre-commit `DISPUTE_NOTICE` probe under `requireDelivery: true` before DB commit (`DISPUTE_FILED` follows after commit). */
  preCommit?: boolean;
  followUpEvent?: string;
  noticeUrl?: string;
  signedNotice?: SignedDocument<DisputeNoticeDocument>;
  inviteUrl?: string;
  signedInvite?: SignedDocument<DisputeInviteDocument>;
}

export interface VerifyNoticeOptions {
  disputeId?: string;
  claimantId?: string;
  /** Expected respondent DID; defaults to `this.did` unless `allowThirdParty` is true. */
  respondentId?: string;
  contractHash?: string;
  rulesVersion?: string;
  /** Set true to verify a notice addressed to another agent rather than `this.did`. */
  allowThirdParty?: boolean;
}

export interface VerifyWebhookOptions {
  now?: number;
  /** Refuse an event addressed to another agent (compare with your did). Recommended. */
  agentId?: string;
  /** Allow cold-start `DISPUTE_INVITE` webhooks whose `recipient.agentId` is omitted until `acceptInvite` binds a `did:key` (`CR3-SDK-M2`). */
  allowUnboundInvite?: boolean;
  /** Refuse an event for another dispute. */
  disputeId?: string;
  /** Refuse an invite webhook event for another invite. */
  inviteId?: string;
  /** Optional signed `/.well-known/key-history.json` so in-flight webhooks signed just before key rotation verify cleanly (`SEC-9`). */
  keyHistory?: SignedDocument<KeyHistoryDocument>;
}

export type VerifiedWebhook =
  | { ok: true; event: WebhookEvent; nonce: string; created: number }
  | { ok: false; reason: string };

const sleep = (ms: number, signal?: AbortSignal) =>
  new Promise<void>((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error("Aborted"));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", onAbort);
      resolve();
    }, ms);
    const onAbort = () => {
      clearTimeout(timer);
      reject(signal?.reason ?? new Error("Aborted"));
    };
    signal?.addEventListener("abort", onAbort, { once: true });
  });
const MAX_RETRY_AFTER_MS = 30_000;

function parseRetryAfterMs(header: string | null, nowMs: number): number {
  if (!header) return 0;
  const trimmed = header.trim();
  if (/^\d+$/.test(trimmed)) {
    return Math.min(Number(trimmed) * 1000, MAX_RETRY_AFTER_MS);
  }
  const parsedDate = Date.parse(trimmed);
  if (Number.isFinite(parsedDate)) {
    return Math.min(Math.max(0, parsedDate - nowMs), MAX_RETRY_AFTER_MS);
  }
  return 0;
}

/** How long an ambiguous paid request is remembered for a byte-identical retry (the server's idempotency window). */
const PENDING_PAID_TTL_MS = 24 * 3_600_000;
const PENDING_PAID_MAX = 256;
const PLATFORM_INFO_CACHE_TTL_MS = 60_000;
const KEY_HISTORY_CACHE_TTL_MS = 60_000;
const KEY_HISTORY_REFRESH_COOLDOWN_MS = 10_000;
const MAX_RESPONSE_BYTES = 4 * 1024 * 1024;
/** Server codes meaning "a payment may be in flight; retry the same request later" (never a definitive refusal). */
const AMBIGUOUS_PAYMENT_CODES = new Set(["PAYMENT_UNCONFIRMED", "FACILITATOR_UNAVAILABLE", "FACILITATOR_BUSY", "CONCURRENT_REQUEST"]);

async function readJsonBounded(res: Response, maxBytes = MAX_RESPONSE_BYTES): Promise<Record<string, unknown>> {
  const contentLength = res.headers?.get?.("content-length");
  if (contentLength !== null && contentLength !== undefined) {
    const declared = Number(contentLength);
    if (Number.isFinite(declared) && declared > maxBytes) {
      await res.body?.cancel().catch(() => {});
      throw new AgentMediateError(res.status, "RESPONSE_TOO_LARGE", `response body exceeds ${maxBytes} bytes`);
    }
  }
  let rawText = "";
  if (res.body && typeof res.body.getReader === "function") {
    const reader = res.body.getReader();
    const decoder = new TextDecoder("utf-8");
    const parts: string[] = [];
    let total = 0;
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel().catch(() => {});
          throw new AgentMediateError(res.status, "RESPONSE_TOO_LARGE", `response body exceeds ${maxBytes} bytes`);
        }
        parts.push(decoder.decode(value, { stream: true }));
      }
    }
    parts.push(decoder.decode());
    rawText = parts.join("");
  } else if (typeof res.text === "function") {
    rawText = await res.text().catch(() => "");
    if (Buffer.byteLength(rawText, "utf8") > maxBytes) {
      throw new AgentMediateError(res.status, "RESPONSE_TOO_LARGE", `response body exceeds ${maxBytes} bytes`);
    }
  } else {
    const parsed = await res.json().catch(() => ({}));
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  }
  if (!rawText) return {};
  try {
    const parsed = JSON.parse(rawText);
    return parsed && typeof parsed === "object" && !Array.isArray(parsed) ? (parsed as Record<string, unknown>) : {};
  } catch {
    return {};
  }
}

interface MandateContext {
  contractHash: string;
  counterpartyId: string;
  prevIssuedAt?: number;
  prevExpiresAt?: number;
  prevDeterminationConsent?: boolean;
  prevBounds?: Bounds;
  prevDeterminationBounds?: Bounds;
}

function mergePriorDeterminationBounds(input: MandateInput, ctx?: MandateContext): MandateInput {
  let out = input;
  if (ctx && out.determinationConsent === undefined && ctx.prevDeterminationConsent === true) {
    out = { ...out, determinationConsent: true };
  }
  if (ctx?.prevDeterminationBounds && out.bounds && out.determinationBounds === undefined) {
    const merged: Bounds = {};
    for (const [issueId, nextB] of Object.entries(out.bounds)) {
      const prevDb = ctx.prevDeterminationBounds[issueId];
      const prevB = ctx.prevBounds?.[issueId];
      if (!prevDb) {
        merged[issueId] = { min: nextB.min, max: nextB.max };
      } else if (prevB && prevDb.min <= prevB.min && prevDb.max >= prevB.max) {
        // Previous determinationBounds was at least as wide as voluntary bounds: preserve it and expand if new bounds went wider.
        merged[issueId] = { min: Math.min(prevDb.min, nextB.min), max: Math.max(prevDb.max, nextB.max) };
      } else {
        // Previous determinationBounds had a tighter contingency cap on one or both sides: preserve it verbatim unless explicitly overridden.
        merged[issueId] = { min: prevDb.min, max: prevDb.max };
      }
    }
    out = { ...out, determinationBounds: merged };
  }
  return out;
}

function assertNotBareMandate(input: unknown): void {
  if (
    input !== null &&
    typeof input === "object" &&
    !(input as { mandate?: unknown }).mandate &&
    ("signature" in input || "principalId" in input)
  ) {
    throw new Error("pass { mandate }, not a bare Mandate object");
  }
}

function isRedirectFetchError(err: unknown): boolean {
  if (!err || typeof err !== "object") return false;
  const msg = typeof (err as { message?: unknown }).message === "string" ? (err as { message: string }).message : "";
  const cause = (err as { cause?: unknown }).cause;
  const causeMsg =
    cause && typeof cause === "object" && typeof (cause as { message?: unknown }).message === "string"
      ? (cause as { message: string }).message
      : "";
  return /redirect/i.test(msg) || /redirect/i.test(causeMsg);
}

export class AgentMediateClient<DefaultView extends ViewOption = "full"> {
  readonly baseUrl: string;
  readonly agentKey: AgentKey;
  readonly defaultView: DefaultView;
  private readonly pinnedPlatformDid: string | undefined;
  private readonly allowUnpinnedPlatformDid: boolean;
  private readonly expectedEnvironment: string | undefined;
  private readonly expectedRulesHash: string | undefined;
  private readonly payer: Payer | undefined;
  private readonly customFetch: FetchLike | undefined;
  private readonly fetchImpl: FetchLike;
  private readonly now: () => number;
  private readonly maxRetries: number;
  private readonly timeoutMs: number;
  private platformInfo: PlatformInfo | null = null;
  private platformInfoFetchedAt = 0;
  private verifiedActivePlatformDid: string | undefined;
  private verifiedPayTo: string | null = null;
  private keyHistoryCache: { doc: SignedDocument<KeyHistoryDocument>; fetchedAt: number } | null = null;
  private keyHistoryRefreshAt = 0;
  private keyHistoryState = { minUpdatedAt: 0 };
  /**
   * CR-SDK-M1: paid requests that failed ambiguously AFTER a payment authorisation was attached, keyed by
   * Idempotency-Key. Retrying with the same key resends the byte-identical request (same target, body and
   * payment-signature), so the server replays or resumes it against the payment it already holds instead of
   * rejecting a re-signed body (IDEMPOTENCY_CONFLICT) or charging a second fee. Shared across withDefaultView().
   */
  private pendingPaid = new Map<
    string,
    { method: string; path: string; raw: string; payment: string; at: number; mandate?: Mandate; mandateFingerprint?: string }
  >();
  /**
   * SA-SDK-M1: self-signed mandates cached by Idempotency-Key so retrying `fileDispute`, `join`, or `confirmIssues`
   * with `bounds` reuses the exact signed `Mandate` (`mnd_<UUID>`, `issuedAt`, `signature`) instead of minting a new
   * UUID and failing the server's `IDEMPOTENCY_CONFLICT` body hash check.
   */
  private mandateCache = new Map<string, { fingerprint: string; mandate: Mandate; at: number }>();
  private scopeCache = new Map<string, MandateContext & { at: number }>();

  constructor(opts: ClientOptions<DefaultView>) {
    this.baseUrl = normalizeBaseUrl(opts.baseUrl);
    this.agentKey = opts.agentKey;
    const effectivePlatformDid = opts.platformDid ?? DEFAULT_PRODUCTION_PLATFORM_DIDS[this.baseUrl];
    const effectiveExpectedEnvironment =
      opts.expectedEnvironment ?? (this.baseUrl === PRODUCTION_API_URL ? "production" : undefined);
    const allowUnpinned = opts.allowUnpinnedPlatformDid === true;
    if (effectivePlatformDid !== undefined && !isDidKey(effectivePlatformDid)) {
      throw new Error("platformDid must be a valid Ed25519 did:key");
    }
    if (opts.payer?.network === BASE_MAINNET && !effectivePlatformDid && !allowUnpinned) {
      throw new Error("on Base mainnet, platformDid must be pinned out of band (constructor option)");
    }
    if (effectiveExpectedEnvironment === "production" && !effectivePlatformDid && !allowUnpinned) {
      throw new Error("in production (expectedEnvironment=\"production\"), platformDid must be pinned out of band");
    }
    if (opts.timeoutMs !== undefined && (!Number.isFinite(opts.timeoutMs) || opts.timeoutMs < 0)) {
      throw new Error("timeoutMs must be a non-negative finite number");
    }
    this.pinnedPlatformDid = effectivePlatformDid;
    this.allowUnpinnedPlatformDid = allowUnpinned;
    this.expectedEnvironment = effectiveExpectedEnvironment;
    this.expectedRulesHash = opts.expectedRulesHash;
    this.defaultView = (opts.defaultView ?? "full") as DefaultView;
    this.payer = opts.payer;
    this.customFetch = opts.fetch;
    this.fetchImpl = opts.fetch ?? ((url, init) => fetch(url, init));
    this.now = opts.now ?? Date.now;
    this.maxRetries = opts.maxRetries ?? 3;
    this.timeoutMs = opts.timeoutMs ?? 30_000;
  }

  /** Return a client sharing keys, payer and transport, using `defaultView` for dispute reads and mutations (DISC-8). */
  withDefaultView<V extends ViewOption>(defaultView: V): AgentMediateClient<V> {
    if ((this.defaultView as ViewOption) === defaultView) return this as unknown as AgentMediateClient<V>;
    const next = new AgentMediateClient<V>({
      baseUrl: this.baseUrl,
      agentKey: this.agentKey,
      ...(this.pinnedPlatformDid ? { platformDid: this.pinnedPlatformDid } : {}),
      ...(this.allowUnpinnedPlatformDid ? { allowUnpinnedPlatformDid: true } : {}),
      ...(this.expectedEnvironment ? { expectedEnvironment: this.expectedEnvironment } : {}),
      ...(this.expectedRulesHash ? { expectedRulesHash: this.expectedRulesHash } : {}),
      defaultView,
      ...(this.payer ? { payer: this.payer } : {}),
      ...(this.customFetch ? { fetch: this.customFetch } : {}),
      now: this.now,
      maxRetries: this.maxRetries,
      timeoutMs: this.timeoutMs,
    });
    next.platformInfo = this.platformInfo;
    next.platformInfoFetchedAt = this.platformInfoFetchedAt;
    next.verifiedActivePlatformDid = this.verifiedActivePlatformDid;
    next.verifiedPayTo = this.verifiedPayTo;
    next.keyHistoryCache = this.keyHistoryCache;
    next.keyHistoryRefreshAt = this.keyHistoryRefreshAt;
    next.keyHistoryState = this.keyHistoryState;
    next.pendingPaid = this.pendingPaid;
    next.mandateCache = this.mandateCache;
    next.scopeCache = this.scopeCache;
    return next;
  }

  private viewPath(path: string, view?: ViewOption): string {
    const mode = view ?? this.defaultView;
    if (mode !== "compact") return path;
    return `${path}${path.includes("?") ? "&" : "?"}view=compact`;
  }

  get did(): string {
    return this.agentKey.did;
  }

  /** Current clock reading in Unix milliseconds (uses the injected `now` clock when configured). */
  nowMs(): number {
    return this.now();
  }

  /**
   * Self-signed mandate (your agent acts as its own principal). Carries `issuedAt` (a replacement must be newer,
   * CR2-11) and, when given, a signed scope so it can't be reused in another dispute. The dispute methods below
   * always pass the scope {contractHash, counterpartyId}.
   */
  mandate(
    bounds: Bounds,
    expiresInMs = 7 * 24 * 3_600_000,
    scope?: { contractHash: string; counterpartyId: string },
    extra?: { determinationConsent?: boolean; determinationBounds?: Bounds; minIssuedAt?: number; minExpiresAt?: number },
  ): Mandate {
    const now = this.now();
    const issuedAt = extra?.minIssuedAt !== undefined ? Math.max(now, extra.minIssuedAt) : now;
    const expiresAt = extra?.minExpiresAt !== undefined ? Math.max(now + expiresInMs, extra.minExpiresAt) : now + expiresInMs;
    return signMandate(
      {
        id: `mnd_${randomUUID()}`,
        principalId: this.did,
        agentId: this.did,
        bounds,
        ...(extra?.determinationConsent !== undefined ? { determinationConsent: extra.determinationConsent } : {}),
        ...(extra?.determinationBounds ? { determinationBounds: extra.determinationBounds } : {}),
        expiresAt,
        issuedAt,
        ...(scope ? { scope: { contractHash: scope.contractHash, counterpartyId: scope.counterpartyId } } : {}),
      },
      this.agentKey,
    );
  }

  async platform(): Promise<PlatformInfo> {
    const now = this.now();
    if (!this.platformInfo || now - this.platformInfoFetchedAt >= PLATFORM_INFO_CACHE_TTL_MS) {
      const info = await this.getPublic<PlatformInfo>("/v1/platform", "PLATFORM_UNAVAILABLE", "could not read /v1/platform");
      if (this.pinnedPlatformDid && info.did !== this.pinnedPlatformDid && info.did !== this.verifiedActivePlatformDid) {
        let rotatedOk = false;
        try {
          const hist = await this.keyHistory(true);
          rotatedOk = hist.document.activeDid === info.did;
        } catch {
          rotatedOk = false;
        }
        if (!rotatedOk) {
          throw new AgentMediateError(0, "PLATFORM_DID_MISMATCH", `/v1/platform reported ${info.did}, expected pinned ${this.pinnedPlatformDid}`);
        }
      }
      if (this.expectedRulesHash && info.rulesHash !== this.expectedRulesHash) {
        throw new AgentMediateError(0, "RULES_HASH_MISMATCH", `/v1/platform reported rulesHash ${String(info.rulesHash)}, expected ${this.expectedRulesHash}`);
      }
      this.platformInfo = info;
      this.platformInfoFetchedAt = now;
    }
    return this.platformInfo;
  }

  /** Fetch `/v1/rules` (`MECHANISM_SPEC` + deterministic `rulesHash`, `DISC-11`). */
  async rules(): Promise<RulesInfo> {
    const info = await this.getPublic<RulesInfo>("/v1/rules", "HTTP_ERROR", "could not read /v1/rules");
    if (this.expectedRulesHash && info.rulesHash !== this.expectedRulesHash) {
      throw new AgentMediateError(0, "RULES_HASH_MISMATCH", `/v1/rules reported rulesHash ${info.rulesHash}, expected ${this.expectedRulesHash}`);
    }
    return info;
  }

  /** Fetch and verify `/.well-known/key-history.json` (`KEY-1`, `FS-M13`, `PERF-5`, `CR3-PROTO-M2`, `P1-1`). */
  async keyHistory(force = false): Promise<SignedDocument<KeyHistoryDocument>> {
    const now = this.now();
    const expectedDid = this.pinnedPlatformDid ?? (await this.platform()).did;
    const minUpdatedAt = this.keyHistoryState.minUpdatedAt > 0 ? this.keyHistoryState.minUpdatedAt : undefined;
    if (!force && this.keyHistoryCache && now - this.keyHistoryCache.fetchedAt < KEY_HISTORY_CACHE_TTL_MS) {
      if (
        verifyKeyHistory(this.keyHistoryCache.doc, {
          expectedActiveDid: expectedDid,
          now,
          maxAgeMs: DEFAULT_KEY_HISTORY_TTL_MS,
          ...(minUpdatedAt !== undefined ? { minUpdatedAt } : {}),
        }).ok
      ) {
        if (this.pinnedPlatformDid) {
          this.verifiedActivePlatformDid = this.keyHistoryCache.doc.document.activeDid;
        }
        return this.keyHistoryCache.doc;
      }
      this.keyHistoryCache = null;
    }
    const doc = await this.getPublic<SignedDocument<KeyHistoryDocument>>(
      "/.well-known/key-history.json",
      "HTTP_ERROR",
      "could not read /.well-known/key-history.json",
    );
    const verified = verifyKeyHistory(doc, {
      expectedActiveDid: expectedDid,
      now,
      maxAgeMs: DEFAULT_KEY_HISTORY_TTL_MS,
      ...(minUpdatedAt !== undefined ? { minUpdatedAt } : {}),
    });
    if (!verified.ok) {
      throw new AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", `key-history.json failed verification: ${verified.reason}`);
    }
    if (doc.document.updatedAt > this.keyHistoryState.minUpdatedAt) {
      this.keyHistoryState.minUpdatedAt = doc.document.updatedAt;
    }
    if (this.pinnedPlatformDid) {
      this.verifiedActivePlatformDid = doc.document.activeDid;
    }
    this.keyHistoryCache = { doc, fetchedAt: now };
    return doc;
  }

  private async verifyCheckpointEnvelope(
    cp: { signedCheckpoint: SignedDocument<TransparencyCheckpointDocument>; checkpointHash: string; anchor: CheckpointAnchorInfo | null },
    mismatchCode: "CHECKPOINT_MISMATCH" | "INVALID_AUDIT_CHAIN",
  ): Promise<void> {
    if (!cp || typeof cp !== "object" || !(await this.verifyPlatformDocument(cp.signedCheckpoint))) {
      throw new AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "transparency checkpoint signature failed verification");
    }
    const doc = cp.signedCheckpoint.document;
    if (!doc || doc.type !== "agent-mediate/transparency-checkpoint/v1") {
      throw new AgentMediateError(0, mismatchCode, `unexpected checkpoint document.type ${String((doc as { type?: unknown })?.type)}`);
    }
    if (this.expectedEnvironment !== undefined && doc.environment !== this.expectedEnvironment) {
      throw new AgentMediateError(0, mismatchCode, `checkpoint environment ${String(doc.environment)} does not match expected ${this.expectedEnvironment}`);
    }
    if (this.expectedRulesHash !== undefined && doc.rulesHash !== this.expectedRulesHash) {
      throw new AgentMediateError(0, mismatchCode, `checkpoint rulesHash ${String(doc.rulesHash)} does not match expected ${this.expectedRulesHash}`);
    }
    if (
      !Number.isSafeInteger(doc.checkpointSeq) ||
      doc.checkpointSeq < 1 ||
      !Number.isSafeInteger(doc.disputeCount) ||
      doc.disputeCount < 0 ||
      typeof doc.merkleRoot !== "string" ||
      !/^[a-f0-9]{64}$/.test(doc.merkleRoot) ||
      typeof doc.prevCheckpointHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(doc.prevCheckpointHash)
    ) {
      throw new AgentMediateError(0, mismatchCode, "checkpoint document fields are malformed");
    }
    const expectedCalldata = encodeBaseAnchorCalldata(doc.checkpointSeq, doc.merkleRoot);
    if (typeof doc.baseAnchorCalldata !== "string" || doc.baseAnchorCalldata.toLowerCase() !== expectedCalldata.toLowerCase()) {
      throw new AgentMediateError(0, mismatchCode, "checkpoint baseAnchorCalldata does not match (checkpointSeq, merkleRoot)");
    }
    const expectedHash = sha256Hex("agent-mediate/checkpoint-chain/v1\n" + canonicalJson(doc));
    if (cp.checkpointHash !== expectedHash) {
      throw new AgentMediateError(0, mismatchCode, "checkpointHash does not match signed checkpoint document");
    }
    if (cp.anchor !== null && cp.anchor !== undefined) {
      if (
        typeof cp.anchor !== "object" ||
        typeof cp.anchor.network !== "string" ||
        cp.anchor.network.length === 0 ||
        typeof cp.anchor.txHash !== "string" ||
        !/^0x[a-fA-F0-9]{64}$/.test(cp.anchor.txHash) ||
        typeof cp.anchor.calldata !== "string" ||
        cp.anchor.calldata.toLowerCase() !== expectedCalldata.toLowerCase() ||
        !Number.isSafeInteger(cp.anchor.anchoredAt) ||
        cp.anchor.anchoredAt <= 0
      ) {
        throw new AgentMediateError(0, mismatchCode, "checkpoint anchor metadata does not match signed checkpoint calldata");
      }
    }
  }

  /** Fetch and verify `/v1/transparency/checkpoint` (or `/v1/transparency/checkpoints/:seq` when `seq` is given) (`SEC3-5`, `DISC-12`, `M5`). */
  async transparencyCheckpoint(seq?: number): Promise<TransparencyCheckpointInfo> {
    if (seq !== undefined && (!Number.isSafeInteger(seq) || seq < 1)) {
      throw new Error("checkpoint seq must be a positive safe integer");
    }
    const path = seq !== undefined ? `/v1/transparency/checkpoints/${seq}` : "/v1/transparency/checkpoint";
    const cp = await this.getPublic<TransparencyCheckpointInfo>(path, "HTTP_ERROR", `could not read ${path}`);
    await this.verifyCheckpointEnvelope(cp, "CHECKPOINT_MISMATCH");
    if (seq !== undefined && cp.signedCheckpoint.document.checkpointSeq !== seq) {
      throw new AgentMediateError(0, "CHECKPOINT_MISMATCH", `checkpoint seq ${cp.signedCheckpoint.document.checkpointSeq} does not match requested ${seq}`);
    }
    return cp;
  }

  /** Fetch `/transparency?format=json` aggregate transparency report (`DISC-12`). */
  async transparency(): Promise<Record<string, unknown>> {
    return this.getPublic<Record<string, unknown>>("/transparency?format=json", "HTTP_ERROR", "could not read /transparency");
  }

  /** Fetch `/v1/honours` public Settlement Honours Roll directory (`MECH-15`). */
  async honoursRoll(): Promise<HonoursDirectory> {
    return this.getPublic<HonoursDirectory>("/v1/honours", "HTTP_ERROR", "could not read /v1/honours");
  }

  /**
   * Check a counterparty's domain, `did:web`, or `did:key` on the Settlement Honours Roll (`MECH-15`, review M1).
   * When `listed === true`, verifies the active platform DID's 24-hour `Ed25519Signature2026` v2 signature
   * (never accepting retired historical keys), TTL bounds, environment, `rulesHash`, full `entry` equality,
   * and normalized subject binding on `signedAttestation`.
   */
  async checkHonours(subject: string): Promise<HonoursLookupResult> {
    const trimmed = subject.trim();
    if (!trimmed) throw new Error("subject must be a non-empty domain, did:web, or did:key");
    const body = await this.getPublic<Omit<HonoursLookupResult, "verified">>(
      `/v1/honours/${encodeURIComponent(trimmed)}`,
      "HTTP_ERROR",
      `could not read /v1/honours/${trimmed}`,
    );
    if (!body.listed) {
      return { ...body, verified: false };
    }
    if (!body.entry || !body.signedAttestation) {
      throw new AgentMediateError(0, "HONOURS_MISMATCH", "listed Honours Roll response is missing entry or signedAttestation");
    }
    const proof = body.signedAttestation.proof;
    const doc = body.signedAttestation.document;
    if (!doc || doc.type !== HONOURS_ATTESTATION_TYPE) {
      throw new AgentMediateError(0, "HONOURS_MISMATCH", `unexpected Honours attestation type ${String((doc as { type?: unknown })?.type)}`);
    }
    if (doc.environment === "production" && !this.pinnedPlatformDid && !this.allowUnpinnedPlatformDid) {
      throw new AgentMediateError(
        0,
        "UNPINNED_PLATFORM_DID",
        "refusing unpinned TOFU verification for environment=production; pin platformDid out of band",
      );
    }
    let expectedDid = this.verifiedActivePlatformDid ?? this.pinnedPlatformDid ?? (await this.platform()).did;
    const now = this.now();
    let sigOk = verifyDocument(body.signedAttestation, expectedDid, { now });
    if (!sigOk && this.pinnedPlatformDid && proof?.verificationMethod && proof.verificationMethod !== expectedDid) {
      try {
        const hist = await this.keyHistory(true);
        if (hist.document.activeDid !== expectedDid) {
          expectedDid = hist.document.activeDid;
          sigOk = verifyDocument(body.signedAttestation, expectedDid, { now });
        }
      } catch {
        sigOk = false;
      }
    }
    if (!sigOk) {
      throw new AgentMediateError(
        0,
        "INVALID_PLATFORM_SIGNATURE",
        "Honours Roll attestation signature is invalid, expired, or not signed by the active platform DID",
      );
    }
    if (
      !Number.isSafeInteger(proof.created) ||
      typeof proof.expiresAt !== "number" ||
      !Number.isSafeInteger(proof.expiresAt) ||
      proof.created !== doc.issuedAt ||
      proof.created > now + 300_000 ||
      proof.expiresAt <= proof.created ||
      proof.expiresAt - proof.created > 24 * 3_600_000
    ) {
      throw new AgentMediateError(0, "HONOURS_MISMATCH", "Honours Roll attestation proof timestamps or 24h TTL bounds are invalid");
    }
    if (this.expectedEnvironment !== undefined && doc.environment !== this.expectedEnvironment) {
      throw new AgentMediateError(0, "HONOURS_MISMATCH", `attestation environment ${doc.environment} does not match expected ${this.expectedEnvironment}`);
    }
    if (this.expectedRulesHash !== undefined && doc.rulesHash !== this.expectedRulesHash) {
      throw new AgentMediateError(0, "HONOURS_MISMATCH", `attestation rulesHash ${doc.rulesHash} does not match expected ${this.expectedRulesHash}`);
    }
    const entry = body.entry;
    const sameAgentIds =
      Array.isArray(doc.agentIds) &&
      Array.isArray(entry.agentIds) &&
      doc.agentIds.length === entry.agentIds.length &&
      doc.agentIds.every((id, idx) => typeof id === "string" && id === entry.agentIds[idx]);
    if (
      !sameAgentIds ||
      doc.domain !== entry.domain ||
      doc.didWeb !== entry.didWeb ||
      doc.memberSince !== entry.memberSince ||
      doc.verifiedAt !== entry.verifiedAt ||
      doc.qualifiedHonoredCount !== entry.qualifiedHonoredCount ||
      doc.totalHonoredObligations !== entry.totalHonoredObligations ||
      doc.confirmedByCounterpartyCount !== entry.confirmedByCounterpartyCount ||
      doc.distinctCounterparties !== entry.distinctCounterparties ||
      doc.verifiedDomainCounterparties !== entry.verifiedDomainCounterparties ||
      doc.curedLateCount !== entry.curedLateCount ||
      doc.fulfilmentRate !== 1 ||
      entry.fulfilmentRate !== 1 ||
      doc.lastHonoredAt !== entry.lastHonoredAt
    ) {
      throw new AgentMediateError(0, "HONOURS_MISMATCH", "Honours Roll entry disagrees with signedAttestation");
    }
    const parsed = parseHonoursSubject(trimmed);
    if (!parsed) {
      throw new AgentMediateError(0, "HONOURS_MISMATCH", `invalid Honours Roll subject ${trimmed}`);
    }
    if (parsed.kind === "agent") {
      if (!doc.agentIds.includes(parsed.agentId)) {
        throw new AgentMediateError(0, "HONOURS_MISMATCH", `signedAttestation does not include requested agent ${trimmed}`);
      }
    } else if (doc.domain !== parsed.domain || (parsed.kind === "did_web" && typeof doc.didWeb !== "string")) {
      throw new AgentMediateError(0, "HONOURS_MISMATCH", `signedAttestation domain ${doc.domain} does not match requested ${trimmed}`);
    }
    return { ...body, verified: true };
  }

  // --- Dispute operations ---------------------------------------------------

  registerNotifications(input: RegisterNotificationsInput, idempotencyKey?: string): Promise<NotificationSettings> {
    return this.put("/v1/agents/me/notify", input, idempotencyKey);
  }

  getNotifications(): Promise<NotificationSettings> {
    return this.get("/v1/agents/me/notify");
  }

  updateMyHonours(input: UpdateHonoursInput, idempotencyKey?: string): Promise<MyHonoursSettings> {
    return this.put("/v1/agents/me/honours", input, idempotencyKey);
  }

  getMyHonours(): Promise<MyHonoursSettings> {
    return this.get("/v1/agents/me/honours");
  }

  /**
   * Send a `$0.00` pre-filing mediation invite (`POST /v1/invites`) to verify respondent reachability and bind
   * a cold respondent's `did:key` before paying the `$2.00` filing fee. Verifies `signedInvite` against the platform DID.
   */
  async createInvite(input: CreateInviteInput, idempotencyKey?: string): Promise<InviteCreated> {
    const res = await this.post<InviteCreated>("/v1/invites", input, idempotencyKey);
    await this.verifyInvite(res.signedInvite, {
      inviteId: res.inviteId,
      claimantId: this.did,
      ...(input.respondentId !== undefined ? { respondentId: input.respondentId } : {}),
      contractHash: input.contractHash,
      allowThirdParty: true,
    });
    if (res.signedInvite.document.inviteUrl !== res.inviteUrl) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", "inviteUrl does not match signedInvite.document.inviteUrl");
    }
    return res;
  }

  /** Read mediation invite status (`GET /v1/invites/:id`), optionally passing `?token=` for an unbound cold respondent. */
  getInvite(id: string, opts?: { token?: string }): Promise<InviteStatus> {
    const q = opts?.token ? `?token=${encodeURIComponent(opts.token)}` : "";
    return this.get(`/v1/invites/${encodeURIComponent(id)}${q}`);
  }

  /** Accept a `$0.00` mediation invite (`POST /v1/invites/:token/accept`) using your authenticated respondent `did:key`. */
  acceptInvite(token: string, input: AcceptInviteInput = {}, idempotencyKey?: string): Promise<InviteAccepted> {
    return this.post(`/v1/invites/${encodeURIComponent(token)}/accept`, input, idempotencyKey);
  }

  /**
   * Probe public metadata for a target domain, HTTPS URL, or `did:web` before filing a dispute (`L-08`),
   * automatically binding this client's `baseUrl`, verified/pinned `platformDid`, `expectedEnvironment`, `expectedRulesHash`, and `now` clock.
   */
  discoverRespondent(target: string, opts: DiscoverRespondentOptions = {}): Promise<DiscoveredRespondent> {
    const platDid = this.verifiedActivePlatformDid ?? this.pinnedPlatformDid;
    return discoverRespondent(target, {
      baseUrl: this.baseUrl,
      ...(platDid !== undefined ? { platformDid: platDid } : {}),
      ...(this.expectedEnvironment !== undefined ? { expectedEnvironment: this.expectedEnvironment } : {}),
      ...(this.expectedRulesHash !== undefined ? { expectedRulesHash: this.expectedRulesHash } : {}),
      ...(this.customFetch && !opts.apiFetch ? { apiFetch: this.customFetch as (url: string, init?: RequestInit) => Promise<Response> } : {}),
      now: this.now,
      ...opts,
    });
  }

  /**
   * File a dispute. Leave `config.feeMode` as `"FILER_PAYS"` (default) whenever inviting a cold or unregistered
   * respondent so joining costs them `$0.00` and requires zero crypto/x402 wallet setup.
   */
  async fileDispute(
    input: FileDisputeInput,
    idempotencyKey?: string,
  ): Promise<DisputeResponse<DefaultViewOf<DefaultView>> & { disputeId: string; notice?: FilingNotice }> {
    assertNotBareMandate(input);
    const key = idempotencyKey ?? `sdk-${randomUUID()}`;
    const { bounds, mandate, determinationConsent, determinationBounds, ...rest } = input;
    const scope = { contractHash: input.contractHash, counterpartyId: input.respondentId };
    const mandateInput: MandateInput = { bounds, mandate, determinationConsent, determinationBounds };
    const fp = bounds && !mandate ? this.mandateFingerprint(mandateInput, scope) : undefined;
    const pending = this.pendingPaid.get(`POST /v1/disputes ${key}`);
    const resolvedMandate =
      pending && this.now() - pending.at < PENDING_PAID_TTL_MS && fp && pending.mandate && pending.mandateFingerprint === fp
        ? pending.mandate
        : this.resolveMandate(mandateInput, scope, `file::${key}`);
    const res = await this.post<DisputeResponse<DefaultViewOf<DefaultView>> & { disputeId: string; notice?: FilingNotice }>(
      this.viewPath("/v1/disputes"),
      { ...rest, mandate: resolvedMandate },
      key,
      "file",
      fp ? { mandate: resolvedMandate, fingerprint: fp } : undefined,
    );
    if (res.notice !== undefined && res.notice !== null) {
      if (!res.notice.signedNotice) {
        throw new AgentMediateError(0, "NOTICE_MISMATCH", "filing response included notice metadata without signedNotice");
      }
      await this.verifyFilingNotice(res.notice.signedNotice, {
        disputeId: res.disputeId,
        respondentId: input.respondentId,
        contractHash: input.contractHash,
        noticeUrl: res.notice.noticeUrl,
      });
    }
    return res;
  }

  /**
   * Disputes you are a party to, newest first, one page at a time (security review L5). Respondents use this to
   * find disputes filed against them, e.g. `{ role: "respondent", status: "AWAITING_RESPONDENT" }`. Pass
   * `nextCursor` back as `cursor` until it is null.
   */
  listDisputes(params: ListDisputesParams = {}): Promise<{ disputes: DisputeSummary[]; nextCursor: string | null }> {
    const q = new URLSearchParams();
    if (params.status !== undefined) q.set("status", params.status);
    if (params.role !== undefined) q.set("role", params.role);
    if (params.limit !== undefined) q.set("limit", String(params.limit));
    if (params.cursor !== undefined) q.set("cursor", params.cursor);
    const qs = q.toString();
    return this.get(`/v1/disputes${qs ? `?${qs}` : ""}`);
  }

  /**
   * The public audit chain, verified: every link and every entry you can see is checked, entries you can't see are
   * opaque links (security review L1). Also verifies the RFC 6962 Merkle inclusion proof against the signed
   * transparency checkpoint when present (`SEC3-5`): checkpoints are daily, so the checkpointed head may be older
   * than `head`, but it must be a point of this same verified chain (a forked head is rejected). Compare `head`
   * with the signed outcome's `auditRoot`.
   */
  async audit(
    id: string,
    opts?: AuditOptions,
  ): Promise<{ head: string; entries: PublicAuditEntry[]; redacted: number; checkpoint?: AuditCheckpointInclusion }> {
    const res = await this.get<{ head: string; entries: PublicAuditEntry[]; checkpoint?: AuditCheckpointInclusion }>(
      `/v1/disputes/${encodeURIComponent(id)}/audit`,
    );
    const v = verifyPublicAuditChain(res.entries);
    if (!v.ok) throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", `audit chain broken at seq ${v.atSeq}: ${v.reason}`);
    if (v.head !== res.head) throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit chain does not end at the reported head");
    if ((opts?.requireCheckpoint || opts?.requireAnchor) && !res.checkpoint) {
      throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit response does not include a required transparency checkpoint");
    }
    if (opts?.requireAnchor && !res.checkpoint?.anchor) {
      throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit transparency checkpoint does not include a required Base L2 anchor");
    }
    if (res.checkpoint) {
      await this.verifyCheckpointEnvelope(res.checkpoint, "INVALID_AUDIT_CHAIN");
      const leaf = res.checkpoint.leaf;
      const cpDoc = res.checkpoint.signedCheckpoint.document;
      const atCheckpoint = res.entries.find((e) => e.seq === leaf.auditSeq);
      if (
        leaf.disputeId !== id ||
        !atCheckpoint ||
        atCheckpoint.hash !== leaf.auditHead ||
        !verifyCheckpointInclusion(
          leaf,
          res.checkpoint.inclusionProof,
          cpDoc.merkleRoot,
          { expectedTotalLeaves: cpDoc.disputeCount },
        )
      ) {
        throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", "audit checkpoint Merkle inclusion proof failed verification");
      }
    }
    if (opts?.expectedOutcome) {
      const outDoc = opts.expectedOutcome.document;
      if (!outDoc || outDoc.disputeId !== id || typeof outDoc.auditRoot !== "string" || typeof outDoc.outcomeHash !== "string") {
        throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", "expectedOutcome does not match disputeId or lacks auditRoot/outcomeHash");
      }
      const expectedStatus =
        outDoc.type === "agent-mediate/settlement-instruction/v1"
          ? outDoc.executionStatus
          : outDoc.type === "agent-mediate/unresolved-certificate/v1"
            ? "UNRESOLVED"
            : null;
      if (typeof expectedStatus !== "string") {
        throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", `expectedOutcome carries unsupported type ${String(outDoc.type)}`);
      }
      const outEntry = res.entries.find((e) => e.hash === outDoc.auditRoot);
      if (!outEntry) {
        throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", "expectedOutcome auditRoot is not present in the verified audit chain");
      }
      if (res.checkpoint) {
        const leaf = res.checkpoint.leaf;
        const isTerminalOutcome = expectedStatus === "HONORED" || expectedStatus === "BREACH_REPORTED" || expectedStatus === "UNRESOLVED";
        if (leaf.auditSeq > outEntry.seq && isTerminalOutcome) {
          throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", "checkpoint leaf advances beyond a terminal signed outcome");
        }
        if (leaf.auditSeq === outEntry.seq && (leaf.outcomeHash !== outDoc.outcomeHash || leaf.status !== expectedStatus)) {
          throw new AgentMediateError(0, "INVALID_AUDIT_CHAIN", "checkpoint leaf outcomeHash/status disagrees with expectedOutcome");
        }
      }
    }
    return {
      head: res.head,
      entries: res.entries,
      redacted: v.redacted,
      ...(res.checkpoint ? { checkpoint: res.checkpoint } : {}),
    };
  }

  /**
   * Fetch and verify stored RFC 9421 Ed25519 request signature proofs for `id` (`SEC3-5`, `M1`, `M6`).
   * Verifies `disputeId`, party DID consistency, HTTP `@method`/`@target-uri` binding for `id` + `action`,
   * Ed25519 signature, and `proofHash` on every unredacted entry.
   */
  async signatures(id: string, opts?: SignaturesOptions): Promise<{ disputeId: string; signatures: DisputeSignatureEntry[] }> {
    const strict = opts?.strict ?? true;
    const res = await this.get<{ disputeId: string; signatures: DisputeSignatureEntry[] }>(
      `/v1/disputes/${encodeURIComponent(id)}/signatures`,
    );
    if (!res || res.disputeId !== id || !Array.isArray(res.signatures)) {
      throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signatures response disputeId ${String(res?.disputeId)} does not match requested ${id}`);
    }
    const partyAgents: Partial<Record<"claimant" | "respondent", string>> = {};
    let seenFileDispute = false;
    const checked: DisputeSignatureEntry[] = [];

    for (const entry of res.signatures) {
      if (!entry || typeof entry !== "object") {
        throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signature #${String((entry as { id?: unknown })?.id)} is malformed`);
      }
      if (entry.redacted && entry.action === "confidential_action") {
        const validConfidentialSeqRange =
          entry.seqRange === null ||
          (Array.isArray(entry.seqRange) &&
            entry.seqRange.length === 2 &&
            Number.isSafeInteger(entry.seqRange[0]) &&
            Number.isSafeInteger(entry.seqRange[1]) &&
            entry.seqRange[0] > 1 &&
            entry.seqRange[1] >= entry.seqRange[0]);
        if (
          entry.party !== null ||
          entry.agentId !== null ||
          !seenFileDispute ||
          !validConfidentialSeqRange ||
          typeof entry.proofHash !== "string" ||
          !/^[a-f0-9]{64}$/.test(entry.proofHash)
        ) {
          throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signature #${entry.id} (confidential_action) has invalid redacted metadata`);
        }
        checked.push(entry);
        continue;
      }
      if ((entry.party !== "claimant" && entry.party !== "respondent") || !isDidKey(entry.agentId)) {
        throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signature #${String(entry.id)} has invalid party or agentId`);
      }
      if (entry.action === "file_dispute") {
        if (entry.party !== "claimant" || seenFileDispute || !Array.isArray(entry.seqRange) || entry.seqRange[0] !== 1) {
          throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signature #${entry.id} (file_dispute) has invalid party or sequence binding`);
        }
        seenFileDispute = true;
      } else if (entry.action === "join_dispute" && entry.party !== "respondent") {
        throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signature #${entry.id} (join_dispute) must belong to respondent`);
      }
      const existingPartyAgent = partyAgents[entry.party];
      if (existingPartyAgent !== undefined && existingPartyAgent !== entry.agentId) {
        throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `party ${entry.party} changed agentId across signatures`);
      }
      partyAgents[entry.party] = entry.agentId;
      if (partyAgents.claimant && partyAgents.respondent && partyAgents.claimant === partyAgents.respondent) {
        throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", "claimant and respondent cannot share the same agentId");
      }
      if (opts?.expectedParties?.[entry.party] !== undefined && entry.agentId !== opts.expectedParties[entry.party]) {
        throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `party ${entry.party} agentId ${entry.agentId} does not match expected ${opts.expectedParties[entry.party]}`);
      }
      if (entry.agentId === this.did && entry.redacted) {
        throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `own signature #${entry.id} must not be redacted`);
      }

      if (!entry.redacted) {
        let v: ReturnType<typeof verifyRequestProof>;
        try {
          v = verifyRequestProof(entry.proof, {
            expectedAgentId: entry.agentId,
            expectedProofHash: entry.proofHash,
            expectedBaseUrl: this.baseUrl,
            expectedDisputeId: id,
            expectedAction: entry.action,
          });
        } catch (e) {
          // CR-SDK-L2: a malformed server entry is annotated (or rejected in strict mode), never a raw TypeError.
          v = { ok: false, reason: `malformed proof: ${(e as Error).message}` };
        }
        if (!v.ok && strict) {
          throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signature #${entry.id} (${entry.action}) failed verification: ${v.reason}`);
        }
        checked.push({
          ...entry,
          verified: v.ok,
          ...(!v.ok ? { verifyReason: v.reason } : {}),
        });
      } else {
        if (entry.action !== "file_dispute" || typeof entry.proofHash !== "string" || !/^[a-f0-9]{64}$/.test(entry.proofHash)) {
          throw new AgentMediateError(
            0,
            "INVALID_REQUEST_PROOF",
            `signature #${entry.id} (${entry.action}) has an invalid redacted entry or non-confidential action`,
          );
        }
        checked.push(entry);
      }
    }

    if (res.signatures.length > 0 && !seenFileDispute) {
      throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signatures for ${id} are missing the claimant file_dispute entry`);
    }
    if (
      (partyAgents.claimant && partyAgents.respondent && this.did !== partyAgents.claimant && this.did !== partyAgents.respondent) ||
      (partyAgents.claimant &&
        this.did !== partyAgents.claimant &&
        partyAgents.respondent === undefined &&
        checked.some((s) => s.action === "confidential_action"))
    ) {
      throw new AgentMediateError(0, "INVALID_REQUEST_PROOF", `signatures for ${id} do not name this agent (${this.did}) as a party`);
    }
    if (
      opts?.expectedParties &&
      ((opts.expectedParties.claimant !== undefined && partyAgents.claimant === undefined) ||
        (opts.expectedParties.respondent !== undefined && partyAgents.respondent === undefined))
    ) {
      const { view } = await this.getDispute(id, { view: "compact" });
      const actualParties =
        view.you === "claimant"
          ? { claimant: this.did, respondent: view.counterpartId }
          : { claimant: view.counterpartId, respondent: this.did };
      for (const p of ["claimant", "respondent"] as const) {
        if (opts.expectedParties[p] !== undefined && actualParties[p] !== opts.expectedParties[p]) {
          throw new AgentMediateError(
            0,
            "INVALID_REQUEST_PROOF",
            `party ${p} agentId ${actualParties[p]} does not match expected ${opts.expectedParties[p]}`,
          );
        }
      }
    }
    return { disputeId: res.disputeId, signatures: checked };
  }

  getDispute(id: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>>;
  getDispute(id: string, opts: { view: "full" }): Promise<DisputeResponse<PartyView>>;
  getDispute(id: string, opts: { view: "compact" }): Promise<DisputeResponse<CompactPartyView>>;
  getDispute(id: string, opts?: { view?: ViewOption }): Promise<DisputeResponse<PartyView | CompactPartyView>>;
  getDispute(id: string, opts?: { view?: ViewOption }): Promise<DisputeResponse<PartyView | CompactPartyView>> {
    return this.get(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}`, opts?.view));
  }

  events(id: string, after = 0): Promise<{ events: Array<{ seq: number; type: string; at: number; data: unknown }>; nextAfter: number }> {
    return this.get(`/v1/disputes/${encodeURIComponent(id)}/events?after=${after}`);
  }

  async join(id: string, input: JoinInput, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    assertNotBareMandate(input);
    const key = idempotencyKey ?? `sdk-${randomUUID()}`;
    const { bounds, mandate, determinationConsent, determinationBounds, ...rest } = input;
    const scope = bounds && !mandate ? await this.scopeOf(id, key) : undefined;
    return this.post(
      this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/join`),
      {
        ...rest,
        mandate: this.resolveMandate(
          { bounds, mandate, determinationConsent, determinationBounds },
          scope ? { contractHash: scope.contractHash, counterpartyId: scope.counterpartyId } : undefined,
          `join:${id}:${key}`,
        ),
      },
      key,
    );
  }

  submitEvidence(
    id: string,
    items: Array<{ id: string; kind: string; description: string; sha256?: string; content?: string }>,
    idempotencyKey?: string,
  ): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    const payload = items.map(({ content, sha256, ...item }) => {
      if (!sha256 && content === undefined) throw new Error(`evidence ${item.id}: provide sha256 or content`);
      return { ...item, sha256: sha256 ?? contentHash(content!) };
    });
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/evidence`), { items: payload }, idempotencyKey);
  }

  closeEvidence(id: string, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/evidence/close`), {}, idempotencyKey);
  }

  async confirmIssues(
    id: string,
    issuesHash: string,
    mandateInput: MandateInput = {},
    idempotencyKey?: string,
  ): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    assertNotBareMandate(mandateInput);
    const key = idempotencyKey ?? `sdk-${randomUUID()}`;
    const ctx = mandateInput.bounds && !mandateInput.mandate ? await this.scopeOf(id, key) : undefined;
    const effectiveInput = mergePriorDeterminationBounds(mandateInput, ctx);
    const mandate =
      effectiveInput.bounds || effectiveInput.mandate
        ? this.resolveMandate(
            effectiveInput,
            ctx ? { contractHash: ctx.contractHash, counterpartyId: ctx.counterpartyId } : undefined,
            `confirm:${id}:${key}`,
            ctx ? { ...(ctx.prevIssuedAt !== undefined ? { minIssuedAt: ctx.prevIssuedAt + 1 } : {}), ...(ctx.prevExpiresAt !== undefined ? { minExpiresAt: ctx.prevExpiresAt } : {}) } : undefined,
          )
        : undefined;
    return this.post(
      this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/issues/confirm`),
      { issuesHash, ...(mandate ? { mandate } : {}) },
      key,
    );
  }

  rejectIssues(id: string, input: RejectIssuesInput, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    if (!input || typeof input.issuesHash !== "string" || input.issuesHash.length === 0) {
      throw new Error("rejectIssues requires input.issuesHash");
    }
    return this.post(
      this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/issues/reject`),
      {
        issuesHash: input.issuesHash,
        ...(input.adoptSuggestedIds ? { adoptSuggestedIds: input.adoptSuggestedIds } : {}),
      },
      idempotencyKey,
    );
  }

  /**
   * Monotonically widen your principal-signed mandate during `BARGAINING` or `DETERMINATION` (`v1.2.0`/`v1.3.0`).
   * At most 3 updates per party; `determinationConsent` and Round-1 declared private inputs remain frozen, and zero bits leak to the counterparty.
   */
  async updateMandate(id: string, mandateInput: MandateInput, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    assertNotBareMandate(mandateInput);
    const key = idempotencyKey ?? `sdk-${randomUUID()}`;
    const ctx = mandateInput.bounds && !mandateInput.mandate ? await this.scopeOf(id, key) : undefined;
    const effectiveInput = mergePriorDeterminationBounds(mandateInput, ctx);
    const mandate = this.resolveMandate(
      effectiveInput,
      ctx ? { contractHash: ctx.contractHash, counterpartyId: ctx.counterpartyId } : undefined,
      `update:${id}:${key}`,
      ctx ? { ...(ctx.prevIssuedAt !== undefined ? { minIssuedAt: ctx.prevIssuedAt + 1 } : {}), ...(ctx.prevExpiresAt !== undefined ? { minExpiresAt: ctx.prevExpiresAt } : {}) } : undefined,
    );
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/mandate`), { mandate }, key);
  }

  submitOffer(id: string, round: number, input: OfferInput, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/rounds/${round}/offer`), input, idempotencyKey);
  }

  /** Final offer in binding final-offer determination (contractual, by the published rule; not arbitration). */
  submitFinalOffer(id: string, offer: Package, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/determination/final-offer`), { offer }, idempotencyKey);
  }

  /** Accept or decline an open post-settlement Pareto improvement before submitting execution proof (MECH-10). */
  respondImprovement(id: string, response: ImprovementResponse, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/execution/improvement`), { response }, idempotencyKey);
  }

  submitExecutionProof(id: string, reference: string, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/execution/proof`), { reference }, idempotencyKey);
  }

  confirmExecution(id: string, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/execution/confirm`), {}, idempotencyKey);
  }

  contestExecution(id: string, reason: string, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/execution/contest`), { reason }, idempotencyKey);
  }

  /**
   * Acknowledge post-breach cure or waive a verified respondent no-show as the aggrieved counterparty (`$0.00`).
   * Appends an immutable RFC 9421 proof to `dispute_cures` and `dispute_signatures` without mutating `disputes.status`
   * or `SignedOutcome`, starting the 30-day Honours Roll probation cooldown.
   */
  acknowledgeCure(id: string, input: AcknowledgeCureInput = {}, idempotencyKey?: string): Promise<CureAcknowledgement> {
    return this.post(`/v1/disputes/${encodeURIComponent(id)}/cure`, input, idempotencyKey);
  }

  withdraw(id: string, idempotencyKey?: string): Promise<DisputeResponse<DefaultViewOf<DefaultView>>> {
    return this.post(this.viewPath(`/v1/disputes/${encodeURIComponent(id)}/withdraw`), {}, idempotencyKey);
  }

  private async verifyPlatformDocument(doc: SignedDocument<object>): Promise<boolean> {
    const docEnv = (doc?.document as Record<string, unknown> | undefined)?.environment;
    if (docEnv === "production" && !this.pinnedPlatformDid && !this.allowUnpinnedPlatformDid) {
      throw new AgentMediateError(
        0,
        "UNPINNED_PLATFORM_DID",
        "refusing unpinned TOFU verification for environment=production; pin platformDid out of band",
      );
    }
    const rootExpectedDid = this.pinnedPlatformDid ?? (await this.platform()).did;
    const fastExpectedDid = this.verifiedActivePlatformDid ?? rootExpectedDid;
    const now = this.now();
    if (verifyDocument(doc, fastExpectedDid, { now })) return true;
    if (doc?.proof?.verificationMethod && doc.proof.verificationMethod !== fastExpectedDid) {
      try {
        const wasCached = this.keyHistoryCache !== null && now - this.keyHistoryCache.fetchedAt < KEY_HISTORY_CACHE_TTL_MS;
        let history = await this.keyHistory();
        const proofKeyId = doc.proof.keyId;
        const hasKey = history.document.keys.some(
          (k) => k.did === doc.proof.verificationMethod && (proofKeyId === undefined || k.keyId === proofKeyId),
        );
        if (!hasKey && wasCached && now - this.keyHistoryRefreshAt >= KEY_HISTORY_REFRESH_COOLDOWN_MS) {
          this.keyHistoryRefreshAt = now;
          history = await this.keyHistory(true);
        }
        return verifyDocumentWithKeyHistory(doc, history, {
          expectedActiveDid: rootExpectedDid,
          now,
          maxAgeMs: DEFAULT_KEY_HISTORY_TTL_MS,
          ...(this.keyHistoryState.minUpdatedAt > 0 ? { minUpdatedAt: this.keyHistoryState.minUpdatedAt } : {}),
        }).ok;
      } catch {
        return false;
      }
    }
    return false;
  }

  /**
   * Verify a platform-signed Notice of Dispute (`agent-mediate/dispute-notice/v1`) received via `/n/:token`,
   * webhook, A2A Agent Card, or email (`PR-L10`, `CR3-SDK-L1`). Verifies the platform Ed25519 signature (or
   * `key-history.json`), `expectedEnvironment`, `opts.rulesVersion`, `${this.baseUrl}/` endpoint prefixes, and
   * respondent/dispute/contract bindings.
   */
  async verifyNotice(
    signedNotice: SignedDocument<DisputeNoticeDocument>,
    opts: VerifyNoticeOptions = {},
  ): Promise<DisputeNoticeDocument> {
    const doc = signedNotice?.document;
    if (!doc || doc.type !== "agent-mediate/dispute-notice/v1") {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `unexpected notice document.type ${String((doc as { type?: unknown })?.type)}`);
    }
    if (
      typeof doc.disputeId !== "string" ||
      doc.disputeId.length === 0 ||
      !isDidKey(doc.claimantId) ||
      !isDidKey(doc.respondentId) ||
      typeof doc.contractHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(doc.contractHash)
    ) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", "dispute notice document fields are malformed");
    }
    const basePrefix = `${this.baseUrl}/`;
    for (const urlField of ["noticeUrl", "joinEndpoint", "disputeEndpoint", "llmsTxtUrl"] as const) {
      const val = (doc as unknown as Record<string, unknown>)[urlField];
      if (val !== undefined && (typeof val !== "string" || !val.startsWith(basePrefix))) {
        throw new AgentMediateError(0, "NOTICE_MISMATCH", `notice ${urlField} does not start with baseUrl ${basePrefix}`);
      }
    }
    if ((doc as { rulesVersion?: unknown }).rulesVersion !== undefined && (typeof doc.rulesVersion !== "string" || doc.rulesVersion.length === 0)) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", "notice rulesVersion is malformed");
    }
    if (opts.rulesVersion !== undefined && doc.rulesVersion !== opts.rulesVersion) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `notice rulesVersion ${String(doc.rulesVersion)} does not match expected ${opts.rulesVersion}`);
    }
    if (opts.disputeId !== undefined && doc.disputeId !== opts.disputeId) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `notice disputeId ${doc.disputeId} does not match expected ${opts.disputeId}`);
    }
    if (opts.claimantId !== undefined && doc.claimantId !== opts.claimantId) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `notice claimantId ${doc.claimantId} does not match expected ${opts.claimantId}`);
    }
    const expectedRespondent = opts.respondentId ?? (opts.allowThirdParty ? undefined : this.did);
    if (expectedRespondent !== undefined && doc.respondentId !== expectedRespondent) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `notice respondentId ${doc.respondentId} does not match expected ${expectedRespondent}`);
    }
    if (opts.contractHash !== undefined && doc.contractHash !== opts.contractHash) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `notice contractHash ${doc.contractHash} does not match expected ${opts.contractHash}`);
    }
    if (this.expectedEnvironment !== undefined && doc.environment !== this.expectedEnvironment) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `notice environment ${String(doc.environment)} does not match expected ${this.expectedEnvironment}`);
    }
    if (!(await this.verifyPlatformDocument(signedNotice))) {
      throw new AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "dispute notice signature failed verification");
    }
    return doc;
  }

  /**
   * Verify a platform-signed Pre-Filing Mediation Invite (`agent-mediate/dispute-invite/v1`) received via `/i/:token`,
   * webhook, A2A Agent Card, or email (`CR3-SDK-L1`). Verifies the platform Ed25519 signature (or `key-history.json`),
   * `expectedEnvironment`, `opts.rulesVersion`, `${this.baseUrl}/` endpoint prefixes, and claimant/respondent/contract bindings.
   */
  async verifyInvite(
    signedInvite: SignedDocument<DisputeInviteDocument>,
    opts: VerifyInviteOptions = {},
  ): Promise<DisputeInviteDocument> {
    const doc = signedInvite?.document;
    if (!doc || doc.type !== DISPUTE_INVITE_TYPE) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `unexpected invite document.type ${String((doc as { type?: unknown })?.type)}`);
    }
    if (
      typeof doc.inviteId !== "string" ||
      doc.inviteId.length === 0 ||
      !isDidKey(doc.claimantId) ||
      (doc.respondentId !== null && !isDidKey(doc.respondentId)) ||
      typeof doc.contractHash !== "string" ||
      !/^[a-f0-9]{64}$/.test(doc.contractHash) ||
      typeof doc.rulesVersion !== "string" ||
      doc.rulesVersion.length === 0
    ) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", "dispute invite document fields are malformed");
    }
    const basePrefix = `${this.baseUrl}/`;
    for (const urlField of ["inviteUrl", "acceptEndpoint", "inviteEndpoint"] as const) {
      const val = doc[urlField];
      if (typeof val !== "string" || !val.startsWith(basePrefix)) {
        throw new AgentMediateError(0, "INVITE_MISMATCH", `invite ${urlField} does not start with baseUrl ${basePrefix}`);
      }
    }
    if (doc.llmsTxtUrl !== undefined && (typeof doc.llmsTxtUrl !== "string" || !doc.llmsTxtUrl.startsWith(basePrefix))) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `invite llmsTxtUrl does not start with baseUrl ${basePrefix}`);
    }
    if (opts.rulesVersion !== undefined && doc.rulesVersion !== opts.rulesVersion) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `invite rulesVersion ${doc.rulesVersion} does not match expected ${opts.rulesVersion}`);
    }
    if (opts.inviteId !== undefined && doc.inviteId !== opts.inviteId) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `invite inviteId ${doc.inviteId} does not match expected ${opts.inviteId}`);
    }
    if (opts.claimantId !== undefined && doc.claimantId !== opts.claimantId) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `invite claimantId ${doc.claimantId} does not match expected ${opts.claimantId}`);
    }
    if (opts.respondentId !== undefined && doc.respondentId !== opts.respondentId) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `invite respondentId ${String(doc.respondentId)} does not match expected ${opts.respondentId}`);
    } else if (opts.respondentId === undefined && !opts.allowThirdParty && doc.respondentId !== null && doc.respondentId !== this.did) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `invite respondentId ${doc.respondentId} does not match this agent (${this.did})`);
    }
    if (opts.contractHash !== undefined && doc.contractHash !== opts.contractHash) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `invite contractHash ${doc.contractHash} does not match expected ${opts.contractHash}`);
    }
    if (this.expectedEnvironment !== undefined && doc.environment !== this.expectedEnvironment) {
      throw new AgentMediateError(0, "INVITE_MISMATCH", `invite environment ${String(doc.environment)} does not match expected ${this.expectedEnvironment}`);
    }
    if (!(await this.verifyPlatformDocument(signedInvite))) {
      throw new AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "dispute invite signature failed verification");
    }
    return doc;
  }

  private async verifyFilingNotice(
    signedNotice: SignedDocument<DisputeNoticeDocument>,
    expected: { disputeId: string; respondentId: string; contractHash: string; noticeUrl?: string },
  ): Promise<void> {
    const doc = signedNotice?.document;
    if (!doc || doc.type !== "agent-mediate/dispute-notice/v1") {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `unexpected notice document.type ${String((doc as { type?: unknown })?.type)}`);
    }
    if (
      doc.disputeId !== expected.disputeId ||
      doc.claimantId !== this.did ||
      doc.respondentId !== expected.respondentId ||
      doc.contractHash !== expected.contractHash
    ) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", "filing notice document fields do not match the filed dispute");
    }
    if ((expected.noticeUrl !== undefined || doc.noticeUrl !== undefined) && doc.noticeUrl !== expected.noticeUrl) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", "filing noticeUrl does not match signedNotice.document.noticeUrl");
    }
    const basePrefix = `${this.baseUrl}/`;
    for (const urlField of ["noticeUrl", "joinEndpoint", "disputeEndpoint", "llmsTxtUrl"] as const) {
      const val = (doc as unknown as Record<string, unknown>)[urlField];
      if (val !== undefined && (typeof val !== "string" || !val.startsWith(basePrefix))) {
        throw new AgentMediateError(0, "NOTICE_MISMATCH", `filing notice ${urlField} does not start with baseUrl ${basePrefix}`);
      }
    }
    if (this.expectedEnvironment !== undefined && doc.environment !== this.expectedEnvironment) {
      throw new AgentMediateError(0, "NOTICE_MISMATCH", `filing notice environment ${String(doc.environment)} does not match expected ${this.expectedEnvironment}`);
    }
    if (!(await this.verifyPlatformDocument(signedNotice))) {
      throw new AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "filing notice signature failed verification");
    }
  }

  /**
   * The platform-signed outcome (DISC-4, SEC3-8, SEC3-4, KEY-1). Verifies the signature against `platformDid`
   * (or a retired key signed into `/.well-known/key-history.json` by `platformDid`), and checks `disputeId`,
   * party membership, `expectedEnvironment`, and `expectedRulesHash` when configured.
   */
  async outcome(id: string): Promise<SignedDocument<Record<string, unknown>>> {
    const doc = await this.get<SignedDocument<Record<string, unknown>>>(`/v1/disputes/${encodeURIComponent(id)}/outcome`);
    if (!(await this.verifyPlatformDocument(doc))) {
      throw new AgentMediateError(0, "INVALID_PLATFORM_SIGNATURE", "outcome signature does not verify against the platform did");
    }
    const payload = doc.document;
    if (
      payload.type !== "agent-mediate/settlement-instruction/v1" &&
      payload.type !== "agent-mediate/unresolved-certificate/v1"
    ) {
      throw new AgentMediateError(0, "OUTCOME_MISMATCH", `unexpected outcome document.type ${String(payload.type)}`);
    }
    if (payload.disputeId !== id) {
      throw new AgentMediateError(0, "OUTCOME_MISMATCH", `outcome disputeId ${String(payload.disputeId)} does not match requested ${id}`);
    }
    if (this.expectedEnvironment !== undefined && payload.environment !== this.expectedEnvironment) {
      throw new AgentMediateError(0, "OUTCOME_MISMATCH", `outcome environment ${String(payload.environment)} does not match expected ${this.expectedEnvironment}`);
    }
    if (this.expectedRulesHash !== undefined && payload.rulesHash !== this.expectedRulesHash) {
      throw new AgentMediateError(0, "OUTCOME_MISMATCH", `outcome rulesHash ${String(payload.rulesHash)} does not match expected ${this.expectedRulesHash}`);
    }
    const parties = payload.parties as { claimant?: { agentId?: string } | null; respondent?: { agentId?: string } | null } | undefined;
    if (parties?.claimant?.agentId !== this.did && parties?.respondent?.agentId !== this.did) {
      throw new AgentMediateError(0, "OUTCOME_MISMATCH", `outcome for ${id} does not name this agent (${this.did}) as a party`);
    }
    if (typeof payload.outcomeHash !== "string" || !/^[a-f0-9]{64}$/.test(payload.outcomeHash)) {
      throw new AgentMediateError(0, "OUTCOME_MISMATCH", "outcome document is missing a valid 64-hex outcomeHash");
    }
    if (typeof payload.auditRoot !== "string" || !/^[a-f0-9]{64}$/.test(payload.auditRoot)) {
      throw new AgentMediateError(0, "OUTCOME_MISMATCH", "outcome document is missing a valid 64-hex auditRoot");
    }
    if (payload.type === "agent-mediate/settlement-instruction/v1") {
      if (
        payload.status !== "SETTLED" ||
        (payload.executionStatus !== "EXECUTION_PENDING" &&
          payload.executionStatus !== "HONORED" &&
          payload.executionStatus !== "BREACH_REPORTED") ||
        typeof payload.method !== "string" ||
        !(SETTLEMENT_METHODS as readonly string[]).includes(payload.method) ||
        !Number.isSafeInteger(payload.settledAt) ||
        !Number.isSafeInteger(payload.roundsCompleted) ||
        (payload.roundsCompleted as number) < 0 ||
        !payload.terms ||
        typeof payload.terms !== "object" ||
        Array.isArray(payload.terms) ||
        computeTermsHash(payload.terms as Package) !== payload.termsHash ||
        computeOutcomeHash(
          {
            kind: "SETTLED",
            method: payload.method as SettlementMethod,
            terms: payload.terms as Package,
            at: payload.settledAt as number,
            roundsCompleted: payload.roundsCompleted as number,
          },
          payload.executionStatus,
        ) !== payload.outcomeHash
      ) {
        throw new AgentMediateError(0, "OUTCOME_MISMATCH", "settlement instruction outcomeHash, termsHash, or status is inconsistent");
      }
    } else {
      if (
        payload.status !== "UNRESOLVED" ||
        typeof payload.reason !== "string" ||
        !Number.isSafeInteger(payload.issuedAt) ||
        !Number.isSafeInteger(payload.roundsCompleted) ||
        computeOutcomeHash(
          {
            kind: "UNRESOLVED",
            reason: payload.reason as ReasonCode,
            at: payload.issuedAt as number,
            roundsCompleted: payload.roundsCompleted as number,
          },
          "UNRESOLVED",
        ) !== payload.outcomeHash
      ) {
        throw new AgentMediateError(0, "OUTCOME_MISMATCH", "unresolved certificate outcomeHash or status is inconsistent");
      }
    }
    return doc;
  }

  /** Poll until `predicate(view)` holds or the timeout passes. Returns the last response. */
  waitFor(id: string, predicate: (view: DefaultViewOf<DefaultView>) => boolean, opts?: { timeoutMs?: number; intervalMs?: number; signal?: AbortSignal }): Promise<DisputeResponse<DefaultViewOf<DefaultView>>>;
  waitFor(id: string, predicate: (view: PartyView) => boolean, opts: { timeoutMs?: number; intervalMs?: number; view: "full"; signal?: AbortSignal }): Promise<DisputeResponse<PartyView>>;
  waitFor(id: string, predicate: (view: CompactPartyView) => boolean, opts: { timeoutMs?: number; intervalMs?: number; view: "compact"; signal?: AbortSignal }): Promise<DisputeResponse<CompactPartyView>>;
  waitFor(
    id: string,
    predicate: (view: PartyView | CompactPartyView) => boolean,
    opts?: { timeoutMs?: number; intervalMs?: number; view?: ViewOption; signal?: AbortSignal },
  ): Promise<DisputeResponse<PartyView | CompactPartyView>>;
  async waitFor(
    id: string,
    predicate: (view: any) => boolean,
    opts: { timeoutMs?: number; intervalMs?: number; view?: ViewOption; signal?: AbortSignal } = {},
  ): Promise<DisputeResponse<PartyView | CompactPartyView>> {
    const deadline = this.now() + (opts.timeoutMs ?? 60_000);
    for (;;) {
      opts.signal?.throwIfAborted();
      const res = await this.getDispute(id, opts.view !== undefined ? { view: opts.view } : undefined);
      if (predicate(res.view) || this.now() >= deadline) return res;
      await sleep(opts.intervalMs ?? 1000, opts.signal);
    }
  }

  /** Poll until it is your turn to act (`view.nextActions[0] !== "wait_for_change"`) or the timeout passes. */
  waitForTurn(id: string, opts?: { timeoutMs?: number; intervalMs?: number; signal?: AbortSignal }): Promise<DisputeResponse<DefaultViewOf<DefaultView>>>;
  waitForTurn(id: string, opts: { timeoutMs?: number; intervalMs?: number; view: "full"; signal?: AbortSignal }): Promise<DisputeResponse<PartyView>>;
  waitForTurn(id: string, opts: { timeoutMs?: number; intervalMs?: number; view: "compact"; signal?: AbortSignal }): Promise<DisputeResponse<CompactPartyView>>;
  waitForTurn(id: string, opts?: { timeoutMs?: number; intervalMs?: number; view?: ViewOption; signal?: AbortSignal }): Promise<DisputeResponse<PartyView | CompactPartyView>>;
  waitForTurn(
    id: string,
    opts: { timeoutMs?: number; intervalMs?: number; view?: ViewOption; signal?: AbortSignal } = {},
  ): Promise<DisputeResponse<PartyView | CompactPartyView>> {
    return this.waitFor(id, (v) => v.nextActions[0] !== "wait_for_change", opts);
  }

  /**
   * Verify a webhook delivery (security review L3, I3): signed by the platform did with the webhook tag, for this
   * URL, within the clock skew, and (with `agentId` / `disputeId`) addressed to you and about that dispute.
   * Returns the signature `nonce` and `created`: remember nonces for 10 minutes and refuse repeats. Deliveries are
   * at least once and may arrive out of order: deduplicate on (disputeId, seq) and order by seq.
   * The third argument may also be `now` (unix ms), as before.
   */
  static verifyWebhook(req: { url: string; headers: Record<string, string>; body: string }, platformDid: string, opts: number | VerifyWebhookOptions = {}): VerifiedWebhook {
    const o: VerifyWebhookOptions = typeof opts === "number" ? { now: opts } : opts;
    const nowMs = o.now ?? Date.now();
    const lower = Object.fromEntries(Object.entries(req.headers).map(([k, v]) => [k.toLowerCase(), v]));
    const v = verifyRequest({ method: "POST", targetUri: req.url, header: (n) => lower[n] ?? null, body: req.body, now: nowMs, expectTag: WEBHOOK_SIGNATURE_TAG });
    if (!v.ok) return { ok: false, reason: v.reason };
    if (v.keyid !== platformDid) {
      if (!o.keyHistory) return { ok: false, reason: "signed by an unexpected key" };
      const kh = verifyKeyHistory(o.keyHistory, { expectedActiveDid: platformDid, now: nowMs, maxAgeMs: DEFAULT_KEY_HISTORY_TTL_MS });
      if (!kh.ok) return { ok: false, reason: `keyHistory invalid: ${kh.reason}` };
      const hist = o.keyHistory.document.keys.find((k) => k.did === v.keyid);
      const allowedStatus = hist?.status === "retired" || (hist?.status === "active" && v.keyid === o.keyHistory.document.activeDid);
      if (
        !hist ||
        !allowedStatus ||
        hist.compromisedAfter !== undefined ||
        hist.revokedAt !== undefined ||
        Math.floor(hist.validFrom / 1000) > v.created ||
        (hist.validUntil !== undefined && v.created > Math.floor(hist.validUntil / 1000))
      ) {
        return { ok: false, reason: "signed by an unexpected key" };
      }
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(req.body);
    } catch {
      return { ok: false, reason: "body is not JSON" };
    }
    if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
      return { ok: false, reason: "body is not a JSON object" };
    }
    const event = parsed as WebhookEvent;
    if (o.disputeId !== undefined && event.disputeId !== o.disputeId) return { ok: false, reason: "event is for another dispute" };
    if (o.inviteId !== undefined && event.inviteId !== o.inviteId) return { ok: false, reason: "event is for another invite" };
    if (o.agentId !== undefined && event.recipient?.agentId !== o.agentId) {
      const isUnboundInvite =
        o.allowUnboundInvite === true &&
        event.type === "DISPUTE_INVITE" &&
        (event.recipient?.agentId === undefined || event.recipient?.agentId === null);
      if (!isUnboundInvite) return { ok: false, reason: "event is addressed to another agent" };
    }
    return { ok: true, event, nonce: v.nonce, created: v.created };
  }

  // --- Transport --------------------------------------------------------------

  private signalForRequest(): { signal?: AbortSignal } {
    return this.timeoutMs > 0 ? { signal: AbortSignal.timeout(this.timeoutMs) } : {};
  }

  private async backoff(attempt: number, res?: Response): Promise<boolean> {
    if (attempt >= this.maxRetries) return false;
    const retryAfterMs = res ? parseRetryAfterMs(res.headers.get("retry-after"), this.now()) : 0;
    await sleep(retryAfterMs > 0 ? retryAfterMs : 250 * 2 ** attempt);
    return true;
  }

  private async getPublic<T>(path: string, errorCode = "HTTP_ERROR", errorDetail = `could not read ${path}`): Promise<T> {
    for (let attempt = 0; ; attempt++) {
      let res: Response;
      try {
        res = await this.fetchImpl(`${this.baseUrl}${path}`, {
          method: "GET",
          headers: {},
          redirect: "error",
          ...this.signalForRequest(),
        });
      } catch (e) {
        if (isRedirectFetchError(e)) {
          throw new AgentMediateError(302, "UNEXPECTED_REDIRECT", `refusing HTTP redirect from ${path}`);
        }
        if (await this.backoff(attempt)) continue;
        throw new AgentMediateError(0, "NETWORK_ERROR", (e as Error).message);
      }
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => {});
        throw new AgentMediateError(res.status, "UNEXPECTED_REDIRECT", `refusing HTTP ${res.status} redirect from ${path}`);
      }
      if ((res.status === 429 || res.status >= 500) && (await this.backoff(attempt, res))) continue;
      const json = await readJsonBounded(res);
      if (!res.ok) {
        const code = errorCode === "HTTP_ERROR" && typeof json.code === "string" ? json.code : errorCode;
        const detail = typeof json.detail === "string" ? json.detail : errorDetail;
        throw new AgentMediateError(res.status, code, detail, json);
      }
      return json as T;
    }
  }

  private mandateFingerprint(input: MandateInput, scope?: { contractHash: string; counterpartyId: string }): string {
    return canonicalJson({
      baseUrl: this.baseUrl,
      agentId: this.did,
      bounds: input.bounds ?? null,
      determinationConsent: input.determinationConsent ?? null,
      determinationBounds: input.determinationBounds ?? null,
      scope: scope ?? null,
    });
  }

  private resolveMandate(
    input: MandateInput,
    scope?: { contractHash: string; counterpartyId: string },
    idempotencyKey?: string,
    timing?: { minIssuedAt?: number; minExpiresAt?: number },
  ): Mandate {
    assertNotBareMandate(input);
    if (input.mandate) {
      if (input.determinationConsent !== undefined && (input.mandate.determinationConsent === true) !== input.determinationConsent) {
        throw new Error("determinationConsent must be signed inside mandate.determinationConsent when providing a pre-signed mandate");
      }
      if (input.determinationBounds !== undefined) {
        throw new Error("determinationBounds must be signed inside mandate.determinationBounds when providing a pre-signed mandate");
      }
      return input.mandate;
    }
    if (input.bounds) {
      const now = this.now();
      const fingerprint = this.mandateFingerprint(input, scope);
      if (idempotencyKey) {
        const cached = this.mandateCache.get(idempotencyKey);
        if (
          cached &&
          cached.fingerprint === fingerprint &&
          now - cached.at < PENDING_PAID_TTL_MS &&
          cached.mandate.expiresAt > now + 60_000 &&
          (timing?.minIssuedAt === undefined || (cached.mandate.issuedAt ?? 0) >= timing.minIssuedAt) &&
          (timing?.minExpiresAt === undefined || cached.mandate.expiresAt >= timing.minExpiresAt)
        ) {
          return cached.mandate;
        }
      }
      const created = this.mandate(input.bounds, undefined, scope, {
        ...(input.determinationConsent !== undefined ? { determinationConsent: input.determinationConsent } : {}),
        ...(input.determinationBounds ? { determinationBounds: input.determinationBounds } : {}),
        ...(timing?.minIssuedAt !== undefined ? { minIssuedAt: timing.minIssuedAt } : {}),
        ...(timing?.minExpiresAt !== undefined ? { minExpiresAt: timing.minExpiresAt } : {}),
      });
      if (idempotencyKey) {
        if (!this.mandateCache.has(idempotencyKey) && this.mandateCache.size >= PENDING_PAID_MAX) {
          const oldest = this.mandateCache.keys().next().value;
          if (oldest !== undefined) this.mandateCache.delete(oldest);
        }
        this.mandateCache.set(idempotencyKey, { fingerprint, mandate: created, at: now });
      }
      return created;
    }
    throw new Error("provide a mandate or bounds");
  }

  /** The signed scope and existing mandate metadata for a self-signed mandate in an existing dispute (CR2-11, SA-SDK-M1, BUG-4, PERF-5). */
  private async scopeOf(id: string, idempotencyKey?: string): Promise<MandateContext> {
    const cacheKey = idempotencyKey ? `${id}:${idempotencyKey}` : undefined;
    if (cacheKey) {
      const cached = this.scopeCache.get(cacheKey);
      if (cached && this.now() - cached.at < PENDING_PAID_TTL_MS) {
        const { at: _at, ...rest } = cached;
        return rest;
      }
    }
    const { view } = await this.getDispute(id, { view: "compact" });
    const scope: MandateContext = {
      contractHash: view.contractHash,
      counterpartyId: view.counterpartId,
      ...(view.yourMandate?.issuedAt !== undefined ? { prevIssuedAt: view.yourMandate.issuedAt } : {}),
      ...(view.yourMandate?.expiresAt !== undefined ? { prevExpiresAt: view.yourMandate.expiresAt } : {}),
      ...(view.yourMandate?.determinationConsent !== undefined ? { prevDeterminationConsent: view.yourMandate.determinationConsent } : {}),
      ...(view.yourMandate?.bounds !== undefined ? { prevBounds: view.yourMandate.bounds } : {}),
      ...(view.yourMandate?.determinationBounds !== undefined ? { prevDeterminationBounds: view.yourMandate.determinationBounds } : {}),
    };
    if (cacheKey) {
      if (!this.scopeCache.has(cacheKey) && this.scopeCache.size >= PENDING_PAID_MAX) {
        const oldest = this.scopeCache.keys().next().value;
        if (oldest !== undefined) this.scopeCache.delete(oldest);
      }
      this.scopeCache.set(cacheKey, { ...scope, at: this.now() });
    }
    return scope;
  }

  /** Cross-check unsigned `/v1/platform` `fees.payTo` against the Ed25519 JWS-signed `/.well-known/agent-card.json` (`SEC-5`). */
  private async verifiedPlatformPayTo(info: PlatformInfo): Promise<string | undefined> {
    const feesObj = info && typeof info.fees === "object" && info.fees !== null ? (info.fees as Record<string, unknown>) : null;
    const rawPayTo = typeof feesObj?.payTo === "string" ? feesObj.payTo : undefined;
    if (!rawPayTo) return undefined;
    if (this.verifiedPayTo !== null && this.verifiedPayTo.toLowerCase() === rawPayTo.toLowerCase()) {
      return this.verifiedPayTo;
    }
    let expectedDid = this.verifiedActivePlatformDid ?? this.pinnedPlatformDid ?? info.did;
    let card: Record<string, unknown>;
    try {
      card = await this.getPublic<Record<string, unknown>>(
        "/.well-known/agent-card.json",
        "HTTP_ERROR",
        "could not read /.well-known/agent-card.json",
      );
    } catch (e) {
      throw new PaymentPolicyError(`could not verify /.well-known/agent-card.json for payTo: ${(e as Error).message}`);
    }
    let sigOk = verifyAgentCardSignature(card, expectedDid);
    if (!sigOk && this.pinnedPlatformDid) {
      try {
        const hist = await this.keyHistory(true);
        if (hist.document.activeDid !== expectedDid) {
          expectedDid = hist.document.activeDid;
          sigOk = verifyAgentCardSignature(card, expectedDid);
        }
      } catch {
        sigOk = false;
      }
    }
    if (!sigOk) {
      throw new PaymentPolicyError("/.well-known/agent-card.json failed platform signature verification");
    }
    const normBase = this.baseUrl.replace(/\/+$/, "");
    const checkOrigin = (candidate: unknown, label: string): void => {
      if (typeof candidate === "string" && candidate.replace(/\/+$/, "") !== normBase) {
        throw new PaymentPolicyError(`/.well-known/agent-card.json ${label} (${candidate}) does not match baseUrl (${normBase})`);
      }
    };
    checkOrigin(card.url, "url");
    const provider = card.provider as { url?: unknown } | undefined;
    checkOrigin(provider?.url, "provider.url");
    const caps = card.capabilities as { extensions?: Array<{ uri?: string; params?: Record<string, unknown> }> } | undefined;
    const restExt = Array.isArray(caps?.extensions)
      ? caps.extensions.find((ext) => ext?.uri === "urn:agent-mediate:ext:rest-api:v1")
      : undefined;
    checkOrigin(restExt?.params?.baseUrl, "rest-api baseUrl");
    let expectedDidWeb: string | null = null;
    try {
      expectedDidWeb = didWebFromUrl(normBase);
    } catch {
      expectedDidWeb = null;
    }
    if (expectedDidWeb && Array.isArray(card.signatures)) {
      for (const sigEntry of card.signatures as Array<{ protected?: unknown }>) {
        if (typeof sigEntry?.protected !== "string") continue;
        try {
          const hdr = JSON.parse(Buffer.from(sigEntry.protected, "base64url").toString("utf8")) as { kid?: unknown };
          if (typeof hdr?.kid === "string" && hdr.kid.startsWith("did:web:") && hdr.kid.split("#")[0] !== expectedDidWeb) {
            throw new PaymentPolicyError(
              `/.well-known/agent-card.json JWS kid (${hdr.kid}) does not match expected ${expectedDidWeb}`,
            );
          }
        } catch (err) {
          if (err instanceof PaymentPolicyError) throw err;
        }
      }
    }
    const feeExt = Array.isArray(caps?.extensions)
      ? caps.extensions.find((ext) => ext?.uri === "urn:agent-mediate:ext:x402-fees:v1")
      : undefined;
    const signedPayTo = typeof feeExt?.params?.payTo === "string" ? feeExt.params.payTo : undefined;
    if (!signedPayTo || signedPayTo.toLowerCase() !== rawPayTo.toLowerCase()) {
      throw new PaymentPolicyError(
        `/v1/platform fees.payTo (${rawPayTo}) does not match signed /.well-known/agent-card.json payTo (${String(signedPayTo)})`,
      );
    }
    this.verifiedPayTo = signedPayTo;
    return signedPayTo;
  }

  private get<T>(path: string): Promise<T> {
    return this.request<T>("GET", path);
  }

  private post<T>(
    path: string,
    body: unknown,
    idempotencyKey?: string,
    paidOperation?: PaidOperation,
    mandateMeta?: { mandate: Mandate; fingerprint: string },
  ): Promise<T> {
    return this.request<T>("POST", path, body, idempotencyKey ?? `sdk-${randomUUID()}`, paidOperation, mandateMeta);
  }

  private put<T>(path: string, body: unknown, idempotencyKey?: string): Promise<T> {
    return this.request<T>("PUT", path, body, idempotencyKey ?? `sdk-${randomUUID()}`);
  }

  private async request<T>(
    method: "GET" | "POST" | "PUT",
    requestPath: string,
    body?: unknown,
    idempotencyKey?: string,
    paidOperation?: PaidOperation,
    mandateMeta?: { mandate: Mandate; fingerprint: string },
  ): Promise<T> {
    let path = requestPath;
    let raw = body === undefined ? "" : JSON.stringify(body);
    let payment: string | null = null;
    let attempt = 0;
    // CR-SDK-M1: a retry of a paid call that failed ambiguously after paying resends the identical request + payment.
    const pendingKey = idempotencyKey && paidOperation ? `${method} ${requestPath.split("?")[0]} ${idempotencyKey}` : undefined;
    if (pendingKey) {
      const prior = this.pendingPaid.get(pendingKey);
      if (prior && this.now() - prior.at < PENDING_PAID_TTL_MS) {
        if (body !== undefined && canonicalJson(body) !== canonicalJson(JSON.parse(prior.raw))) {
          throw new AgentMediateError(
            422,
            "IDEMPOTENCY_CONFLICT",
            "Idempotency-Key has a pending payment for a different request body",
            undefined,
            { idempotencyKey, paymentSent: true },
          );
        }
        path = prior.path;
        raw = prior.raw;
        payment = prior.payment;
      } else if (prior) {
        this.pendingPaid.delete(pendingKey);
      }
    }
    // Every error from a keyed (mutating) request carries its Idempotency-Key, and says so loudly once a payment was
    // attached, so a caller (or an LLM via MCP) retries with the SAME key instead of paying twice.
    const fail = (status: number, code: string, message: string, errBody?: unknown): AgentMediateError => {
      // H-05: Only ambiguous transport/facilitator failures may have settled a payment in flight.
      // Definitive client/protocol rejections (402 invalid payment, 400/404/409/410/422, redirects) never settled ($0.00 charged):
      // report paymentSent=false, clear pendingPaid, and release the unsettled EIP-3009 authorization so budget reclaims after validBefore + 60s.
      const retainPendingPaid =
        payment !== null &&
        code !== "RESPONDENT_UNREACHABLE" &&
        (status === 0 || status === 429 || status >= 500 || AMBIGUOUS_PAYMENT_CODES.has(code));
      const paymentSent = retainPendingPaid;
      if (payment !== null && !retainPendingPaid) {
        this.payer?.releaseUnsettled?.(payment);
      }
      if (pendingKey) {
        if (payment !== null && retainPendingPaid) {
          if (!this.pendingPaid.has(pendingKey) && this.pendingPaid.size >= PENDING_PAID_MAX) {
            const oldest = this.pendingPaid.keys().next().value;
            if (oldest !== undefined) this.pendingPaid.delete(oldest);
          }
          const existing = this.pendingPaid.get(pendingKey);
          this.pendingPaid.set(pendingKey, {
            method,
            path,
            raw,
            payment,
            at: this.now(),
            ...(mandateMeta
              ? { mandate: mandateMeta.mandate, mandateFingerprint: mandateMeta.fingerprint }
              : existing?.mandate && existing?.mandateFingerprint
                ? { mandate: existing.mandate, mandateFingerprint: existing.mandateFingerprint }
                : {}),
          });
        } else {
          this.pendingPaid.delete(pendingKey);
        }
      }
      const suffix =
        idempotencyKey && paymentSent
          ? ` (a payment authorisation was already sent: retry with idempotencyKey "${idempotencyKey}" to avoid a second charge)`
          : "";
      return new AgentMediateError(status, code, message + suffix, errBody, { ...(idempotencyKey ? { idempotencyKey } : {}), paymentSent });
    };
    for (;;) {
      const headers: Record<string, string> = {};
      if (raw) headers["content-type"] = "application/json";
      if (idempotencyKey) headers["idempotency-key"] = idempotencyKey;
      Object.assign(
        headers,
        signRequest({
          method,
          targetUri: this.baseUrl + path,
          headers,
          body: raw || undefined,
          key: this.agentKey,
          created: Math.floor(this.now() / 1000),
          nonce: randomUUID(),
        }),
      );
      if (payment) headers["payment-signature"] = payment;

      let res: Response;
      try {
        res = await this.fetchImpl(this.baseUrl + path, {
          method,
          headers,
          redirect: "error",
          ...(raw ? { body: raw } : {}),
          ...this.signalForRequest(),
        });
      } catch (e) {
        if (isRedirectFetchError(e)) {
          throw fail(302, "UNEXPECTED_REDIRECT", `refusing HTTP redirect from ${path}`);
        }
        if (await this.backoff(attempt++)) continue;
        throw fail(0, "NETWORK_ERROR", (e as Error).message);
      }
      if (res.status >= 300 && res.status < 400) {
        await res.body?.cancel().catch(() => {});
        throw fail(res.status, "UNEXPECTED_REDIRECT", `refusing HTTP ${res.status} redirect from ${path}`);
      }
      let json: Record<string, unknown>;
      try {
        json = await readJsonBounded(res);
      } catch (e) {
        if (e instanceof AgentMediateError) {
          throw fail(e.status || res.status, e.code, e.message);
        }
        throw fail(res.status, "HTTP_ERROR", (e as Error).message);
      }

      if (res.status === 402 && json.code === "PAYMENT_REQUIRED" && !payment) {
        const header = res.headers.get("payment-required");
        let challenge: PaymentRequired;
        try {
          challenge = (header ? JSON.parse(Buffer.from(header, "base64").toString("utf8")) : json.paymentRequired) as PaymentRequired;
        } catch {
          throw fail(402, "MALFORMED_PAYMENT_REQUIRED", "the payment-required header is not valid base64 JSON", json);
        }
        if (challenge === null || typeof challenge !== "object") {
          throw fail(402, "MALFORMED_PAYMENT_REQUIRED", "the 402 response carries no payment challenge", json);
        }
        // Only filing carries a fee: never pay for a 402 anywhere else (security review M10).
        if (!paidOperation) throw fail(402, "UNEXPECTED_PAYMENT_REQUEST", `${method} ${path} is not a paid operation; refusing to pay`, json);
        if (!this.payer) throw new PaymentRequiredError(challenge, json, idempotencyKey);
        const info = await this.platform();
        const feesObj = info && typeof info.fees === "object" && info.fees !== null ? (info.fees as Record<string, unknown>) : {};
        // CR-SDK-L6: enforce out-of-band platformDid pinning on Base mainnet even when a custom Payer omits payer.network.
        const isMainnet =
          this.payer.network === BASE_MAINNET ||
          feesObj.network === BASE_MAINNET ||
          (Array.isArray(challenge.accepts) && challenge.accepts.some((a) => a?.network === BASE_MAINNET));
        if (isMainnet && !this.pinnedPlatformDid) {
          throw new PaymentPolicyError("on Base mainnet, platformDid must be pinned out of band (constructor option)");
        }
        const expectedPayTo = await this.verifiedPlatformPayTo(info);
        payment = await this.payer.pay(challenge, {
          operation: paidOperation,
          ...(expectedPayTo !== undefined ? { expectedPayTo } : {}),
        });
        continue; // same Idempotency-Key, now with payment (does not consume a transport retry, FS-M13)
      }
      if ((res.status === 429 || res.status >= 500) && (await this.backoff(attempt++, res))) continue;
      if (!res.ok) {
        throw fail(res.status, String(json.code ?? "HTTP_ERROR"), String(json.detail ?? res.statusText), json);
      }
      if (pendingKey) this.pendingPaid.delete(pendingKey);
      return json as T;
    }
  }
}

export interface WebhookReplayGuardOptions {
  /** Nonce retention window in milliseconds (default `600_000` = 10 minutes, 2x the +/-300s RFC 9421 skew window). */
  ttlMs?: number;
  /** Maximum tracked nonces before oldest entries are evicted (default `10_000`). */
  maxEntries?: number;
  /** Clock override in Unix ms (defaults to `Date.now`). */
  now?: () => number;
}

export interface WebhookReplayGuard {
  /** Record a verified webhook nonce and return `true` on first sight or `false` on replay within `ttlMs`. */
  check(nonceOrVerified: string | { nonce: string; created?: number }, nowMs?: number): boolean;
  /** Verify a webhook signature via `AgentMediateClient.verifyWebhook` and reject replayed nonces within `ttlMs` (`IT6-P2-1`). */
  verify(
    req: { url: string; headers: Record<string, string>; body: string },
    platformDid: string,
    opts?: number | VerifyWebhookOptions,
  ): VerifiedWebhook;
  /** Number of currently remembered nonces (excluding expired entries after pruning). */
  size(): number;
  /** Forget all remembered nonces. */
  clear(): void;
}

/**
 * Bounded in-memory RFC 9421 webhook nonce replay guard (`IT6-P2-1`).
 * Pair with `AgentMediateClient.verifyWebhook` (or call `guard.verify(...)` directly) so captured platform
 * webhook deliveries cannot be replayed within the 5-minute signature clock-skew window.
 */
export function createWebhookReplayGuard(opts: WebhookReplayGuardOptions = {}): WebhookReplayGuard {
  const ttlMs = opts.ttlMs ?? 600_000;
  const maxEntries = opts.maxEntries ?? 10_000;
  const clock = opts.now ?? Date.now;
  if (!Number.isFinite(ttlMs) || ttlMs <= 0) {
    throw new Error("WebhookReplayGuard ttlMs must be a positive number");
  }
  if (!Number.isSafeInteger(maxEntries) || maxEntries < 1) {
    throw new Error("WebhookReplayGuard maxEntries must be a positive safe integer");
  }
  const seen = new Map<string, number>();
  const prune = (nowMs: number): void => {
    for (const [k, exp] of seen) {
      if (exp <= nowMs) {
        seen.delete(k);
      } else {
        break;
      }
    }
  };
  const check = (nonceOrVerified: string | { nonce: string; created?: number }, nowMs?: number): boolean => {
    const nonce = typeof nonceOrVerified === "string" ? nonceOrVerified : nonceOrVerified?.nonce;
    if (typeof nonce !== "string" || nonce.length === 0) return false;
    const t = nowMs ?? clock();
    prune(t);
    const existing = seen.get(nonce);
    if (existing !== undefined && existing > t) return false;
    if (existing !== undefined) seen.delete(nonce);
    while (seen.size >= maxEntries) {
      const oldest = seen.keys().next().value;
      if (oldest === undefined) break;
      seen.delete(oldest);
    }
    seen.set(nonce, t + ttlMs);
    return true;
  };
  const verify: WebhookReplayGuard["verify"] = (req, platformDid, verifyOpts = {}) => {
    const verified = AgentMediateClient.verifyWebhook(req, platformDid, verifyOpts);
    if (!verified.ok) return verified;
    const t = typeof verifyOpts === "number" ? verifyOpts : (verifyOpts.now ?? clock());
    if (!check(verified, t)) {
      return { ok: false, reason: "replayed webhook nonce" };
    }
    return verified;
  };
  return {
    check,
    verify,
    size: () => {
      prune(clock());
      return seen.size;
    },
    clear: () => seen.clear(),
  };
}

/** sha256 hex of evidence content (the content itself is never uploaded). */
export function contentHash(content: string | Uint8Array): string {
  return createHash("sha256").update(content).digest("hex");
}
