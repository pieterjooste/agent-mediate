/**
 * Input validation. Every function throws DomainError on bad input, so callers
 * can validate inline and the reducer turns throws into `{ ok: false }`.
 */
import { gridTolerance, isOnGrid, ownEntry, range, snap } from "./mechanism.ts";
import type {
  DisputeConfig,
  ErrorCode,
  Issue,
  IssueId,
  IssueLimits,
  Mandate,
  NoticeDelivery,
  NoticeMethod,
  Package,
  PrivateInputs,
} from "./types.ts";

export class DomainError extends Error {
  readonly code: ErrorCode;
  constructor(code: ErrorCode, message: string) {
    super(message);
    this.code = code;
    this.name = "DomainError";
  }
}

export function fail(code: ErrorCode, message: string): never {
  throw new DomainError(code, message);
}

const MINUTE = 60_000;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;

/**
 * Platform-fixed limits for configurable windows (security review M2). The claimant chooses the
 * config, and a missed deadline yields a platform-signed adverse outcome (RESPONDENT_NO_SHOW, TIMEOUT,
 * BREACH_REPORTED, a determination without your final offer), so every window a party must react
 * in has a floor the claimant cannot go below. The join window is the strictest: the respondent
 * hasn't engaged yet and may only learn of the filing by polling.
 */
export const CONFIG_LIMITS = {
  // CR2-9: 2 minutes, so an agent that polls (rather than receiving webhooks) can still answer a round.
  roundTimeoutMs: { min: 2 * MINUTE, max: HOUR },
  bargainingWallClockMs: { min: 10 * MINUTE, max: HOUR },
  joinTimeoutMs: { min: DAY, max: 30 * DAY },
  stageTimeoutMs: { min: 10 * MINUTE, max: 7 * DAY },
  determinationTimeoutMs: { min: 5 * MINUTE, max: DAY },
  executionTimeoutMs: { min: DAY, max: 90 * DAY },
} as const satisfies Record<string, { min: number; max: number }>;

export const DEFAULT_CONFIG: DisputeConfig = {
  maxRounds: 6,
  stallThreshold: 0.05,
  stallWindow: 2,
  roundTimeoutMs: 2 * MINUTE,
  bargainingWallClockMs: 15 * MINUTE,
  joinTimeoutMs: 24 * 60 * MINUTE,
  stageTimeoutMs: 30 * MINUTE,
  determinationTimeoutMs: 10 * MINUTE,
  executionTimeoutMs: 7 * 24 * 60 * MINUTE,
  proposalFromRound: 2,
  proposalBasis: "declared",
  maxIssueProposals: 3,
  feeMode: "FILER_PAYS",
};

export const MAX_ISSUES = 5;
/** Maximum in-place principal mandate widenings (`UPDATE_MANDATE`) per party after `ISSUE_CONFIRMATION` (`v1.2.0`). */
export const MAX_MANDATE_UPDATES = 3;
const MAX_ADOPTED_SUGGESTIONS = 2;
const MAX_GRID_POINTS = 1_000_000;
const MAX_ISSUE_MAGNITUDE = 1e15;
const MAX_FRACTIONAL_ISSUE_MAGNITUDE = 1e6;
const MIN_ISSUE_STEP = 1e-6;
/**
 * Issue ids are short lowerCamelCase identifiers (security review CR2-7): they become JSON keys in offers,
 * mandates and outcome documents, so they must not carry free text. Stored disputes with older ids still load
 * (only new issue lists are validated).
 */
export const ISSUE_ID_PATTERN = /^[a-z][A-Za-z0-9]{0,23}$/;
/**
 * Ids that match ISSUE_ID_PATTERN but name Object.prototype members (CR-CORE-M2). As JSON keys they are harmless,
 * but any `record[id]` lookup in a JS verifier resolves them to inherited functions, so they are refused outright
 * (identical list in the Python SDK for parity).
 */
export const RESERVED_ISSUE_IDS: ReadonlySet<string> = new Set([
  "constructor",
  "hasOwnProperty",
  "isPrototypeOf",
  "propertyIsEnumerable",
  "toLocaleString",
  "toString",
  "valueOf",
]);
const ID_PATTERN = ISSUE_ID_PATTERN;
const SHA256_PATTERN = /^[a-f0-9]{64}$/;

export function resolveConfig(partial: Partial<DisputeConfig> | undefined): DisputeConfig {
  const c: DisputeConfig = { ...DEFAULT_CONFIG, ...(partial ?? {}) };
  requireInt(c.maxRounds, 3, 8, "maxRounds");
  requireRange(c.stallThreshold, 0, 0.05, "stallThreshold");
  requireInt(c.stallWindow, 2, 5, "stallWindow");
  for (const [key, { min, max }] of Object.entries(CONFIG_LIMITS) as Array<[keyof typeof CONFIG_LIMITS, { min: number; max: number }]>) {
    requireInt(c[key], min, max, key);
  }
  if (c.bargainingWallClockMs < c.roundTimeoutMs) {
    fail("INVALID_INPUT", "bargainingWallClockMs must be at least roundTimeoutMs");
  }
  requireInt(c.proposalFromRound, 2, 99, "proposalFromRound");
  if (c.proposalBasis !== "declared" && c.proposalBasis !== "offers") fail("INVALID_INPUT", "proposalBasis must be declared or offers");
  requireInt(c.maxIssueProposals, 1, 5, "maxIssueProposals");
  if (c.feeMode !== "FILER_PAYS") fail("INVALID_INPUT", "feeMode must be FILER_PAYS");
  return c;
}

const ISSUE_KEYS: ReadonlySet<string> = new Set([
  "id",
  "label",
  "unit",
  "min",
  "max",
  "step",
  "claimantPrefers",
  "obligor",
]);

export function validateIssues(issues: Issue[]): void {
  if (!Array.isArray(issues) || issues.length < 1 || issues.length > MAX_ISSUES) {
    fail("INVALID_INPUT", `between 1 and ${MAX_ISSUES} issues required`);
  }
  const seen = new Set<string>();
  for (const issue of issues) {
    if (!isPlainObject(issue) || Object.keys(issue).some((k) => !ISSUE_KEYS.has(k))) {
      fail("INVALID_INPUT", "each issue must be a plain object with only the supported Issue fields");
    }
    if (typeof issue.id !== "string" || !ID_PATTERN.test(issue.id)) fail("INVALID_INPUT", `invalid issue id "${String(issue.id).slice(0, 32)}": use lowerCamelCase, 1-24 letters and digits`);
    if (RESERVED_ISSUE_IDS.has(issue.id)) fail("INVALID_INPUT", `issue id "${issue.id}" is reserved; choose another name`);
    if (seen.has(issue.id)) fail("INVALID_INPUT", `duplicate issue id "${issue.id}"`);
    seen.add(issue.id);
    requireText(issue.label, 1, 200, `issue ${issue.id} label`);
    requireText(issue.unit, 1, 32, `issue ${issue.id} unit`);
    if (![issue.min, issue.max, issue.step].every(Number.isFinite)) fail("INVALID_INPUT", `issue ${issue.id} bounds must be finite`);
    if (Math.abs(issue.min) > MAX_ISSUE_MAGNITUDE || Math.abs(issue.max) > MAX_ISSUE_MAGNITUDE) {
      fail("INVALID_INPUT", `issue ${issue.id}: min and max magnitude must not exceed 1e15`);
    }
    if (!(issue.max > issue.min)) fail("INVALID_INPUT", `issue ${issue.id}: max must exceed min`);
    if (!(issue.step >= MIN_ISSUE_STEP)) fail("INVALID_INPUT", `issue ${issue.id}: step must be at least 1e-6`);
    if (!Number.isInteger(issue.min) || !Number.isInteger(issue.step)) {
      if (Math.abs(issue.min) > MAX_FRACTIONAL_ISSUE_MAGNITUDE || Math.abs(issue.max) > MAX_FRACTIONAL_ISSUE_MAGNITUDE) {
        fail("INVALID_INPUT", `issue ${issue.id}: fractional-grid min and max magnitude must not exceed 1e6`);
      }
      if (
        Math.abs(Math.round(issue.step * 1e6) - issue.step * 1e6) > 1e-9 ||
        Math.abs(Math.round(issue.min * 1e6) - issue.min * 1e6) > 1e-9
      ) {
        fail("INVALID_INPUT", `issue ${issue.id}: fractional min and step must have at most 6 decimal places`);
      }
    }
    const points = range(issue) / issue.step;
    // Absolute tolerance (CR-CORE-M3, SA-CORE-M1): on integer grids (max - min) must be an exact integer multiple of step;
    // on fractional grids (max - min) must be a multiple of step up to floating-point noise.
    if (Number.isInteger(issue.min) && Number.isInteger(issue.step)) {
      if (!Number.isSafeInteger(issue.max) || (issue.max - issue.min) % issue.step !== 0) {
        fail("INVALID_INPUT", `issue ${issue.id}: (max - min) must be a multiple of step`);
      }
    } else if (Math.abs(points - Math.round(points)) > gridTolerance(issue, issue.max)) {
      fail("INVALID_INPUT", `issue ${issue.id}: (max - min) must be a multiple of step`);
    }
    if (points > MAX_GRID_POINTS) fail("INVALID_INPUT", `issue ${issue.id}: grid too fine`);
    if (issue.claimantPrefers !== "higher" && issue.claimantPrefers !== "lower") {
      fail("INVALID_INPUT", `issue ${issue.id}: claimantPrefers must be higher or lower`);
    }
    if (issue.obligor !== "claimant" && issue.obligor !== "respondent") {
      fail("INVALID_INPUT", `issue ${issue.id}: obligor must be claimant or respondent`);
    }
  }
}

function isPlainObject(v: unknown): v is Record<string, unknown> {
  if (v === null || typeof v !== "object" || Array.isArray(v)) return false;
  const proto = Object.getPrototypeOf(v);
  return proto === null || proto === Object.prototype;
}

function effectiveGridBounds(issue: Issue, b: { min: number; max: number }): { min: number; max: number } {
  const clampedLo = Math.max(issue.min, b.min);
  const clampedHi = Math.min(issue.max, b.max);
  if (clampedLo > clampedHi + 1e-9) return { min: 1, max: 0 };
  let lo = snap(issue, clampedLo, "ceil");
  let hi = snap(issue, clampedHi, "floor");
  if (lo < b.min - 1e-9 && lo < issue.max) lo = snap(issue, lo + issue.step, "nearest");
  if (hi > b.max + 1e-9 && hi > issue.min) hi = snap(issue, hi - issue.step, "nearest");
  if (lo < b.min - 1e-9 || hi > b.max + 1e-9 || lo > hi + 1e-9) return { min: 1, max: 0 };
  return { min: lo, max: hi };
}

function hasGridPointInBounds(issue: Issue, b: { min: number; max: number } | undefined): boolean {
  if (!isPlainObject(b) || !Number.isFinite(b.min) || !Number.isFinite(b.max) || b.min > b.max) return false;
  const eff = effectiveGridBounds(issue, b);
  return eff.min <= eff.max + 1e-9;
}

const MANDATE_ALLOWED_KEYS = new Set([
  "id",
  "principalId",
  "agentId",
  "bounds",
  "expiresAt",
  "scope",
  "issuedAt",
  "determinationConsent",
  "determinationBounds",
  "signature",
]);
const MANDATE_SCOPE_ALLOWED_KEYS = new Set(["contractHash", "counterpartyId"]);
const MANDATE_BOUND_ALLOWED_KEYS = new Set(["min", "max"]);

/** Structure only; coverage of issues is checked once issues are confirmed. */
export function validateMandateShape(mandate: Mandate, agentId: string, now: number): void {
  if (!isPlainObject(mandate)) fail("INVALID_INPUT", "mandate required");
  for (const key of Object.keys(mandate)) {
    if (!MANDATE_ALLOWED_KEYS.has(key)) fail("INVALID_INPUT", `mandate.${key} is not a supported field`);
  }
  requireText(mandate.id, 1, 128, "mandate.id");
  requireText(mandate.principalId, 1, 256, "mandate.principalId");
  if (mandate.issuedAt !== undefined && (!Number.isSafeInteger(mandate.issuedAt) || mandate.issuedAt <= 0 || mandate.issuedAt > now + 5 * MINUTE)) {
    fail("INVALID_INPUT", "mandate.issuedAt must be a positive unix-ms timestamp not in the future");
  }
  if (mandate.agentId !== agentId) fail("NOT_AUTHORIZED", "mandate was not issued to this agent");
  if (!Number.isSafeInteger(mandate.expiresAt)) fail("INVALID_INPUT", "mandate.expiresAt must be a unix-ms integer timestamp");
  if (mandate.issuedAt !== undefined && mandate.issuedAt >= mandate.expiresAt) {
    fail("INVALID_INPUT", "mandate.issuedAt must be strictly before mandate.expiresAt");
  }
  if (mandate.expiresAt <= now) fail("MANDATE_EXPIRED", "mandate has expired");
  if (!isPlainObject(mandate.bounds)) fail("INVALID_INPUT", "mandate.bounds must be an object");
  for (const [id, b] of Object.entries(mandate.bounds)) {
    if (!isPlainObject(b)) fail("INVALID_INPUT", `mandate bounds for ${id} are invalid`);
    for (const bk of Object.keys(b)) {
      if (!MANDATE_BOUND_ALLOWED_KEYS.has(bk)) fail("INVALID_INPUT", `mandate bounds for ${id} contain unsupported field ${bk}`);
    }
    if (!Number.isFinite(b.min) || !Number.isFinite(b.max) || b.min > b.max) {
      fail("INVALID_INPUT", `mandate bounds for ${id} are invalid`);
    }
  }
  if (mandate.scope !== undefined) {
    if (!isPlainObject(mandate.scope)) fail("INVALID_INPUT", "mandate.scope must be an object");
    for (const sk of Object.keys(mandate.scope)) {
      if (!MANDATE_SCOPE_ALLOWED_KEYS.has(sk)) fail("INVALID_INPUT", `mandate.scope.${sk} is not a supported scope field`);
    }
    if (mandate.scope.contractHash === undefined && mandate.scope.counterpartyId === undefined) {
      fail("INVALID_INPUT", "mandate.scope must specify contractHash and/or counterpartyId");
    }
    if (mandate.scope.contractHash !== undefined && (typeof mandate.scope.contractHash !== "string" || mandate.scope.contractHash.length === 0)) {
      fail("INVALID_INPUT", "mandate.scope.contractHash must be a non-empty string");
    }
    if (mandate.scope.counterpartyId !== undefined && (typeof mandate.scope.counterpartyId !== "string" || mandate.scope.counterpartyId.length === 0)) {
      fail("INVALID_INPUT", "mandate.scope.counterpartyId must be a non-empty string");
    }
  }
  if (mandate.determinationConsent !== undefined && typeof mandate.determinationConsent !== "boolean") {
    fail("INVALID_INPUT", "mandate.determinationConsent must be a boolean");
  }
  if (mandate.determinationBounds !== undefined) {
    if (!isPlainObject(mandate.determinationBounds)) {
      fail("INVALID_INPUT", "mandate.determinationBounds must be an object");
    }
    for (const [id, b] of Object.entries(mandate.determinationBounds)) {
      if (!isPlainObject(b)) fail("INVALID_INPUT", `mandate determinationBounds for ${id} are invalid`);
      for (const bk of Object.keys(b)) {
        if (!MANDATE_BOUND_ALLOWED_KEYS.has(bk)) fail("INVALID_INPUT", `mandate determinationBounds for ${id} contain unsupported field ${bk}`);
      }
      if (!Number.isFinite(b.min) || !Number.isFinite(b.max) || b.min > b.max) {
        fail("INVALID_INPUT", `mandate determinationBounds for ${id} are invalid`);
      }
    }
  }
}

/** A scoped mandate may only be used for its contract and against its counterparty (security review H2). */
export function requireMandateScope(mandate: Mandate, ctx: { contractHash: string; counterpartyId: string }): void {
  if (!isPlainObject(mandate)) fail("INVALID_INPUT", "mandate required");
  const scope = mandate.scope;
  if (scope === undefined) return;
  if (!isPlainObject(scope)) fail("INVALID_INPUT", "mandate.scope must be an object");
  if (scope.contractHash !== undefined && scope.contractHash !== ctx.contractHash) fail("MANDATE_VIOLATION", "mandate is scoped to a different contract");
  if (scope.counterpartyId !== undefined && scope.counterpartyId !== ctx.counterpartyId) fail("MANDATE_VIOLATION", "mandate is scoped to a different counterparty");
}

export function requireMandateCovers(mandate: Mandate, issues: Issue[]): void {
  if (!isPlainObject(mandate) || !isPlainObject(mandate.bounds)) fail("INVALID_INPUT", "mandate.bounds must be an object");
  for (const issue of issues) {
    const b = ownEntry(mandate.bounds, issue.id);
    if (!b) fail("MANDATE_VIOLATION", `mandate has no bounds for issue ${issue.id}`);
    if (!hasGridPointInBounds(issue, b)) {
      fail("MANDATE_VIOLATION", `mandate bounds for ${issue.id} cover no on-grid value in [${issue.min}, ${issue.max}]`);
    }
    const db = ownEntry(mandate.determinationBounds, issue.id);
    if (db && !hasGridPointInBounds(issue, db)) {
      fail("MANDATE_VIOLATION", `mandate determinationBounds for ${issue.id} cover no on-grid value in [${issue.min}, ${issue.max}]`);
    }
  }
}

/** Same rule as requireMandateCovers, as a predicate: the mandate authorises at least one on-grid value on this issue. */
export function mandateCovers(mandate: Mandate, issue: Issue): boolean {
  if (!isPlainObject(mandate) || !isPlainObject(mandate.bounds)) return false;
  const b = ownEntry(mandate.bounds, issue.id);
  return hasGridPointInBounds(issue, b);
}

export function requireActiveMandate(mandate: Mandate, now: number): void {
  if (mandate.expiresAt <= now) fail("MANDATE_EXPIRED", "mandate has expired");
}

export function withinMandate(issues: Issue[], mandate: Mandate, pkg: Package): boolean {
  return issues.every((i) => {
    const b = ownEntry(mandate.bounds, i.id);
    if (!b) return false;
    const v = pkg[i.id]!;
    return v >= b.min - 1e-9 && v <= b.max + 1e-9;
  });
}

export function withinMandateLimits(issues: Issue[], mandate: Mandate, limits: IssueLimits): boolean {
  return issues.every((i) => {
    const lim = ownEntry(limits, i.id);
    if (!lim) return true;
    const b = ownEntry(mandate.bounds, i.id);
    if (!b) return false;
    return lim.min >= b.min - 1e-9 && lim.max <= b.max + 1e-9;
  });
}

/** Bounds governing binding final-offer determination: `determinationBounds[id]` when set, else `bounds[id]` (MECH-1). */
export function withinDeterminationMandate(issues: Issue[], mandate: Mandate, pkg: Package): boolean {
  return issues.every((i) => {
    const b = ownEntry(mandate.determinationBounds, i.id) ?? ownEntry(mandate.bounds, i.id);
    if (!b) return false;
    const v = pkg[i.id]!;
    return v >= b.min - 1e-9 && v <= b.max + 1e-9;
  });
}

/** Validate 1..2 unique lowerCamelCase issue IDs requested on `REJECT_ISSUES` (`v1.2.0`). */
export function validateAdoptSuggestedIds(ids: unknown): IssueId[] {
  if (!Array.isArray(ids) || ids.length < 1 || ids.length > MAX_ADOPTED_SUGGESTIONS) {
    fail("INVALID_INPUT", `adoptSuggestedIds must contain between 1 and ${MAX_ADOPTED_SUGGESTIONS} issue ids`);
  }
  const seen = new Set<string>();
  const out: IssueId[] = [];
  for (const id of ids) {
    if (typeof id !== "string" || !ID_PATTERN.test(id)) {
      fail("INVALID_INPUT", `invalid adoptSuggestedIds entry "${String(id).slice(0, 32)}"`);
    }
    if (RESERVED_ISSUE_IDS.has(id)) {
      fail("INVALID_INPUT", `issue id "${id}" is reserved; choose another name`);
    }
    if (seen.has(id)) {
      fail("INVALID_INPUT", `duplicate adoptSuggestedIds entry "${id}"`);
    }
    seen.add(id);
    out.push(id);
  }
  return out;
}

/**
 * Monotonic widening invariant for `UPDATE_MANDATE` (`v1.3.0`):
 * - `expiresAt` cannot shorten;
 * - `determinationConsent` is frozen once `BARGAINING` starts (cannot be revoked or newly enabled mid-bargaining);
 * - both raw and on-grid effective `bounds` (and, when `prevDetConsent`, effective `determinationBounds`)
 *   must be a superset of the previous mandate on every confirmed issue.
 * Caller must invoke `requireMandateCovers(next, issues)` beforehand.
 */
export function requireMandateMonotonicExpansion(
  issues: Issue[],
  previous: Mandate,
  prevDetConsent: boolean,
  next: Mandate,
): void {
  if (next.expiresAt < previous.expiresAt) {
    fail("MANDATE_VIOLATION", "updated mandate cannot shorten expiresAt");
  }
  const nextDetConsent = next.determinationConsent === true;
  if (nextDetConsent !== prevDetConsent) {
    fail(
      "MANDATE_VIOLATION",
      prevDetConsent
        ? "updated mandate cannot revoke determinationConsent"
        : "updated mandate cannot enable determinationConsent after bargaining begins",
    );
  }
  for (const issue of issues) {
    const prevRaw = ownEntry(previous.bounds, issue.id)!;
    const nextRaw = ownEntry(next.bounds, issue.id)!;
    const prevB = effectiveGridBounds(issue, prevRaw);
    const nextB = effectiveGridBounds(issue, nextRaw);
    if (
      nextRaw.min > prevRaw.min ||
      nextRaw.max < prevRaw.max ||
      nextB.min > prevB.min + 1e-9 ||
      nextB.max < prevB.max - 1e-9
    ) {
      fail("MANDATE_VIOLATION", `updated mandate cannot narrow bounds for ${issue.id}`);
    }
    if (prevDetConsent) {
      const prevDetRaw = (ownEntry(previous.determinationBounds, issue.id) ?? prevRaw)!;
      const nextDetRaw = (ownEntry(next.determinationBounds, issue.id) ?? nextRaw)!;
      const prevDb = effectiveGridBounds(issue, prevDetRaw);
      const nextDb = effectiveGridBounds(issue, nextDetRaw);
      if (
        nextDetRaw.min > prevDetRaw.min ||
        nextDetRaw.max < prevDetRaw.max ||
        nextDb.min > prevDb.min + 1e-9 ||
        nextDb.max < prevDb.max - 1e-9
      ) {
        fail("MANDATE_VIOLATION", `updated mandate cannot narrow determinationBounds for ${issue.id}`);
      }
    }
  }
}

/** Exactly one on-grid value per issue, no extra keys. */
export function validatePackage(issues: Issue[], pkg: Package, label: string): void {
  if (!isPlainObject(pkg)) fail("INVALID_INPUT", `${label} required`);
  const keys = Object.keys(pkg);
  if (keys.length !== issues.length) fail("INVALID_INPUT", `${label} must contain exactly the confirmed issues`);
  for (const issue of issues) {
    const v = pkg[issue.id];
    if (typeof v !== "number" || !isOnGrid(issue, v)) {
      fail("INVALID_INPUT", `${label}.${issue.id} must be within [${issue.min}, ${issue.max}] in steps of ${issue.step}`);
    }
  }
}

export function validatePrivate(issues: Issue[], p: PrivateInputs): void {
  if (!isPlainObject(p)) fail("INVALID_INPUT", "private inputs required");
  for (const k of Object.keys(p)) {
    if (k !== "weights" && k !== "walkaway" && k !== "limits") {
      fail("INVALID_INPUT", `private inputs contain unknown field "${k}"`);
    }
  }
  if (!isPlainObject(p.weights)) fail("INVALID_INPUT", "private.weights must be an object");
  const keys = Object.keys(p.weights);
  if (keys.length !== issues.length) fail("INVALID_INPUT", "private.weights must contain exactly the confirmed issues");
  let sum = 0;
  for (const issue of issues) {
    const w = p.weights[issue.id];
    if (typeof w !== "number" || !Number.isFinite(w) || w < 0) fail("INVALID_INPUT", `private.weights.${issue.id} invalid`);
    sum += w;
  }
  if (Math.abs(sum - 1) > 1e-6) fail("INVALID_INPUT", "private.weights must sum to 1");
  validatePackage(issues, p.walkaway, "private.walkaway");
  if (p.limits !== undefined) {
    if (!isPlainObject(p.limits)) {
      fail("INVALID_INPUT", "private.limits must be an object");
    }
    const byId = new Map(issues.map((i) => [i.id, i]));
    for (const [id, lim] of Object.entries(p.limits)) {
      const issue = byId.get(id);
      if (!issue) fail("INVALID_INPUT", `private.limits contains unknown issue "${id}"`);
      if (
        !isPlainObject(lim) ||
        !Object.keys(lim).every((k) => k === "min" || k === "max") ||
        typeof lim.min !== "number" ||
        typeof lim.max !== "number" ||
        !Number.isFinite(lim.min) ||
        !Number.isFinite(lim.max) ||
        lim.min > lim.max
      ) {
        fail("INVALID_INPUT", `private.limits.${id} bounds are invalid`);
      }
      if (lim.min < issue.min - 1e-9 || lim.max > issue.max + 1e-9) {
        fail("INVALID_INPUT", `private.limits.${id} must lie within [${issue.min}, ${issue.max}]`);
      }
      if (snap(issue, lim.min, "ceil") > snap(issue, lim.max, "floor") + 1e-9) {
        fail("INVALID_INPUT", `private.limits.${id} contains no on-grid value`);
      }
      const wv = p.walkaway[id]!;
      if (wv < lim.min - 1e-9 || wv > lim.max + 1e-9) {
        fail("INVALID_INPUT", `private.walkaway.${id} must lie within private.limits.${id}`);
      }
    }
  }
}

export const NOTICE_METHODS: ReadonlySet<NoticeMethod> = new Set([
  "none",
  "standing",
  "standing_webhook",
  "clause_endpoint",
  "a2a_card",
  "did_web",
  "email",
  "unverified_contact",
]);

export function validateNoticeDelivery(nd: NoticeDelivery): void {
  if (!isPlainObject(nd)) fail("INVALID_INPUT", "noticeDelivery must be an object");
  if (typeof nd.method !== "string" || !NOTICE_METHODS.has(nd.method as NoticeMethod)) {
    fail("INVALID_INPUT", "noticeDelivery.method is invalid");
  }
  if (typeof nd.delivered !== "boolean" || typeof nd.verifiedEndpoint !== "boolean") {
    fail("INVALID_INPUT", "noticeDelivery.delivered and verifiedEndpoint must be booleans");
  }
  if (!Array.isArray(nd.attempted) || !nd.attempted.every((m) => typeof m === "string" && NOTICE_METHODS.has(m as NoticeMethod))) {
    fail("INVALID_INPUT", "noticeDelivery.attempted must be an array of valid notice methods");
  }
  if (!Number.isSafeInteger(nd.at) || nd.at <= 0) {
    fail("INVALID_INPUT", "noticeDelivery.at must be a positive unix-ms integer timestamp");
  }
  if (nd.method === "none" && (nd.delivered || nd.verifiedEndpoint)) {
    fail("INVALID_INPUT", "noticeDelivery with method 'none' cannot set delivered or verifiedEndpoint");
  }
  if (nd.method !== "none" && !nd.delivered) {
    fail("INVALID_INPUT", "noticeDelivery with a delivery method must have delivered === true");
  }
  if (!nd.delivered && nd.verifiedEndpoint) {
    fail("INVALID_INPUT", "undelivered notice cannot set verifiedEndpoint");
  }
  if (nd.method === "unverified_contact" && nd.verifiedEndpoint) {
    fail("INVALID_INPUT", "unverified_contact notice cannot set verifiedEndpoint");
  }
}

/**
 * Evidence ids are identifiers that both parties, the AI advisory and the operator console reference, so they are
 * restricted to a plain charset (security review L9): no spaces, quotes or markup, hence no room for instructions.
 */
export const EVIDENCE_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_.:-]{0,63}$/;

export function validateEvidenceItem(item: { id: string; kind: string; sha256: string; description: string }): void {
  if (typeof item.id !== "string" || !EVIDENCE_ID_PATTERN.test(item.id)) {
    fail("INVALID_INPUT", "evidence.id must be 1-64 characters: letters, digits, '_', '.', ':' or '-', starting with a letter or digit");
  }
  requireText(item.kind, 1, 64, "evidence.kind");
  if (typeof item.sha256 !== "string" || !SHA256_PATTERN.test(item.sha256)) {
    fail("INVALID_INPUT", "evidence.sha256 must be 64 lowercase hex characters");
  }
  requireText(item.description, 0, 2000, "evidence.description");
}

export function requireText(v: unknown, min: number, max: number, label: string): void {
  if (typeof v !== "string" || v.length < min || v.length > max) {
    fail("INVALID_INPUT", `${label} must be a string of ${min}-${max} characters`);
  }
}

function requireInt(v: number, min: number, max: number, label: string): void {
  if (!Number.isInteger(v) || v < min || v > max) fail("INVALID_INPUT", `${label} must be an integer in [${min}, ${max}]`);
}

function requireRange(v: number, min: number, max: number, label: string): void {
  if (!Number.isFinite(v) || v < min || v > max) fail("INVALID_INPUT", `${label} must be in [${min}, ${max}]`);
}
