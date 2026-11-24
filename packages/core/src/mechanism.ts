/**
 * Pure bargaining mathematics. No state, no I/O, no LLM.
 *
 * Utility model: per issue, the claimant's normalised share of the range is
 * share ∈ [0, 1] (1 = claimant's preferred extreme). The respondent's share is
 * 1 - share. A party's utility for a package is the weighted sum of its shares,
 * using that party's private weights (summing to 1).
 */
import { createHmac } from "node:crypto";
import { canonicalJson, sha256Hex } from "./canonical.ts";
import type { Issue, IssueId, IssueLimits, Mandate, Package, Party, PrivateInputs } from "./types.ts";

const EPS = 1e-9;

/**
 * Own-property lookup for id-keyed records (CR-CORE-M2): `rec["valueOf"]` would otherwise return an inherited
 * Object.prototype function, which is truthy and poisons bound/limit arithmetic with NaN.
 */
export function ownEntry<T>(rec: Readonly<Record<string, T>> | undefined | null, key: string): T | undefined {
  return rec !== undefined && rec !== null && Object.prototype.hasOwnProperty.call(rec, key) ? rec[key] : undefined;
}

/** Bounds of the secret per-dispute proposal split (security review H1). */
export const SPLIT_MIN = 0.3;
export const SPLIT_MAX = 0.7;

/**
 * One-way per-dispute proposal salt derived from `auditSalt` for unkeyed ("salted") mode (review M8).
 * Committing to and opening this derived 256-bit hex value verifies `α` without ever revealing `auditSalt`
 * (which also blinds audit `dataCommitment`s, `mandateCommitment`s, and `partySalt`s).
 */
export function deriveProposalSalt(auditSalt: string, disputeId: string): string {
  return sha256Hex(`${auditSalt}:${disputeId}:proposal-split`);
}

export function proposalSplitFromSalt(proposalSalt: string): number {
  const u = parseInt(proposalSalt.slice(0, 12), 16) / 0x1000000000000;
  return SPLIT_MIN + (SPLIT_MAX - SPLIT_MIN) * u;
}

/**
 * The secret per-dispute split α for platform proposals, derived from the never-disclosed audit salt:
 * deterministic and replayable for the platform, unpredictable for the parties, fixed for the whole
 * dispute so it can't be averaged out across rounds.
 */
export function proposalSplit(auditSalt: string, disputeId: string): number {
  return proposalSplitFromSalt(deriveProposalSalt(auditSalt, disputeId));
}

/**
 * Per-pair proposal key (security review CR2-2(b), CR2-14): HMAC-SHA256 under the platform's PROPOSAL_SECRET
 * over a domain tag, the sorted party pair and the contract hash. Same pair + same contract → same key, so
 * repeat filings can't redraw α and average it out; parties can't compute it.
 */
export function deriveProposalKey(platformSecret: string, partyA: string, partyB: string, contractHash: string): string {
  const [x, y] = [partyA, partyB].sort();
  return createHmac("sha256", platformSecret).update(`agent-mediate/proposal-key/v1\n${x}\n${y}\n${contractHash}`).digest("hex");
}

/**
 * α for a proposal: HMAC under the pair's proposal key over the basis the proposal is computed from (the frozen
 * declared inputs). Identical inputs → identical α (no averaging by refiling); different inputs → an
 * independent α, so an adversary who varies its own walkaway across refilings can't solve the linear system
 * P = (1 − α)·own + α·other that a fixed α would give. Under the research-only `offers` basis the basis changes
 * every round, which re-derives α per round.
 */
export function proposalSplitFromKey(proposalKey: string, basis: Record<Party, PrivateInputs>): number {
  const mac = createHmac("sha256", proposalKey).update(`agent-mediate/proposal-split/v1\n${canonicalJson(basis)}`).digest("hex");
  const u = parseInt(mac.slice(0, 12), 16) / 0x1000000000000;
  return SPLIT_MIN + (SPLIT_MAX - SPLIT_MIN) * u;
}

export function other(party: Party): Party {
  return party === "claimant" ? "respondent" : "claimant";
}

export function range(issue: Issue): number {
  return issue.max - issue.min;
}

/** Claimant's normalised share of the issue range for value `v`. */
export function claimantShare(issue: Issue, v: number): number {
  const s = (v - issue.min) / range(issue);
  return issue.claimantPrefers === "higher" ? s : 1 - s;
}

/** Inverse of claimantShare. */
export function valueForShare(issue: Issue, share: number): number {
  const s = issue.claimantPrefers === "higher" ? share : 1 - share;
  return clean(issue.min + s * range(issue));
}

export function utility(issues: Issue[], weights: Record<string, number>, pkg: Package, party: Party): number {
  let u = 0;
  for (const issue of issues) {
    const share = claimantShare(issue, pkg[issue.id]!);
    u += weights[issue.id]! * (party === "claimant" ? share : 1 - share);
  }
  return u;
}

export function gridIndex(issue: Issue, v: number): number {
  return (v - issue.min) / issue.step;
}

/**
 * Tolerance (in grid-index units) for an on-grid test: 1e-9 plus the floating-point noise of `(v - min) / step`
 * (a few ulps of the operands, scaled by 1/step). Absolute, not relative to the index (CR-CORE-M3): a relative
 * `1e-9 * idx` accepted `999999.0009` on an integer grid as on-grid, which then became a signed settlement term.
 */
export function gridTolerance(issue: Issue, v: number): number {
  if (Number.isInteger(issue.min) && Number.isInteger(issue.step)) {
    return 0;
  }
  return Math.min(0.25, EPS + (8 * Number.EPSILON * (Math.abs(v) + Math.abs(issue.min))) / issue.step);
}

export function isOnGrid(issue: Issue, v: number): boolean {
  if (!Number.isFinite(v) || v < issue.min - EPS || v > issue.max + EPS) return false;
  if (Number.isInteger(issue.min) && Number.isInteger(issue.step)) {
    return Number.isSafeInteger(v) && v >= issue.min && v <= issue.max && (v - issue.min) % issue.step === 0;
  }
  const idx = gridIndex(issue, v);
  return Math.abs(idx - Math.round(idx)) <= gridTolerance(issue, v);
}

/**
 * Tolerance (in grid-index units) for `snap` (H-10): scales ULP noise by `(abs(v) + abs(min) + range) / step`
 * and caps at 0.25 (matching `gridTolerance`) so exact on-grid fractional and large-step points never jump
 * to an adjacent grid index under `floor` / `ceil`.
 */
function snapIdxTolerance(issue: Issue, v: number, idx: number): number {
  const ulpIdx =
    (16 * Number.EPSILON * (Math.abs(v) + Math.abs(issue.min) + range(issue))) / issue.step +
    8 * Number.EPSILON * Math.max(1, Math.abs(idx));
  const base = Number.isInteger(issue.min) && Number.isInteger(issue.step) ? EPS : Math.max(EPS, EPS / issue.step);
  return Math.min(0.25, base + ulpIdx);
}

/** Snap a value to the issue grid. `nearest` rounds exact halves to the even grid index (unbiased). */
export function snap(issue: Issue, v: number, mode: "floor" | "ceil" | "nearest"): number {
  if (
    Number.isInteger(issue.min) &&
    Number.isInteger(issue.step) &&
    Number.isSafeInteger(v) &&
    v >= issue.min &&
    v <= issue.max &&
    (v - issue.min) % issue.step === 0
  ) {
    return v === 0 ? 0 : v;
  }
  const idx = gridIndex(issue, v);
  const tol = snapIdxTolerance(issue, v, idx);
  let i: number;
  if (mode === "floor") i = Math.floor(idx + tol);
  else if (mode === "ceil") i = Math.ceil(idx - tol);
  else {
    const f = Math.floor(idx);
    const frac = idx - f;
    if (Math.abs(frac - 0.5) < tol) i = f % 2 === 0 ? f : f + 1;
    else i = Math.round(idx);
  }
  const maxIdx = Math.round(range(issue) / issue.step);
  i = Math.min(Math.max(i, 0), maxIdx);
  if (Number.isInteger(issue.min) && Number.isInteger(issue.step)) {
    const r = issue.min + i * issue.step;
    return r === 0 ? 0 : r;
  }
  return clean(issue.min + i * issue.step);
}

/**
 * Normalised distance between the parties' offers: mean over issues of how far
 * the claimant's ask exceeds the respondent's offer, as a fraction of the range.
 * 0 means every issue meets or crosses.
 */
export function computeGap(issues: Issue[], claimantOffer: Package, respondentOffer: Package): number {
  let total = 0;
  for (const issue of issues) {
    const shortfall = claimantShare(issue, claimantOffer[issue.id]!) - claimantShare(issue, respondentOffer[issue.id]!);
    total += Math.max(0, shortfall);
  }
  return clean(total / issues.length);
}

/** Mean absolute normalised distance between two packages. Weight-free, so it is publicly explainable. */
export function distance(issues: Issue[], a: Package, b: Package): number {
  let total = 0;
  for (const issue of issues) total += Math.abs(a[issue.id]! - b[issue.id]!) / range(issue);
  return clean(total / issues.length);
}

/**
 * Importance-weighted normalised L1 distance between two packages (MECH-8).
 * Weights are normalised by their sum; falls back to uniform `distance` if all weights are zero.
 */
export function weightedDistance(issues: Issue[], a: Package, b: Package, weights: Record<IssueId, number>): number {
  let wSum = 0;
  for (const issue of issues) wSum += Math.max(0, weights[issue.id] ?? 0);
  if (wSum <= EPS) return distance(issues, a, b);
  let total = 0;
  for (const issue of issues) {
    const w = Math.max(0, weights[issue.id] ?? 0) / wSum;
    total += w * (Math.abs(a[issue.id]! - b[issue.id]!) / range(issue));
  }
  return clean(total);
}

/**
 * True when each of the last `window` rounds reduced the remaining gap by less than
 * a `threshold` fraction of that round's starting gap (MECH-3).
 */
export function isStalled(gaps: number[], window: number, threshold: number): boolean {
  if (threshold <= 0 || gaps.length < window + 1) return false;
  for (let j = 0; j < window; j++) {
    const newer = gaps[gaps.length - 1 - j]!;
    const older = gaps[gaps.length - 2 - j]!;
    if (older <= EPS) return false;
    if (older - newer >= threshold * older - EPS) return false;
  }
  return true;
}

/** Per-issue midpoint, snapped to the grid. */
export function midpointPackage(issues: Issue[], a: Package, b: Package): Package {
  const out: Package = {};
  for (const issue of issues) out[issue.id] = snap(issue, (a[issue.id]! + b[issue.id]!) / 2, "nearest");
  return out;
}

/**
 * Offers cross when each party is offered at least as much (by its own private
 * weights) as it asked for itself. Returns the midpoint package, or null.
 */
export function crossingTerms(
  issues: Issue[],
  offers: Record<Party, Package>,
  privates: Record<Party, PrivateInputs>,
): Package | null {
  const wc = privates.claimant.weights;
  const wr = privates.respondent.weights;
  const claimantGetsEnough =
    utility(issues, wc, offers.respondent, "claimant") >= utility(issues, wc, offers.claimant, "claimant") - EPS;
  const respondentGetsEnough =
    utility(issues, wr, offers.claimant, "respondent") >= utility(issues, wr, offers.respondent, "respondent") - EPS;
  if (!claimantGetsEnough || !respondentGetsEnough) return null;
  return midpointPackage(issues, offers.claimant, offers.respondent);
}

type ShareInterval = { lo: number; hi: number; minVal: number; maxVal: number };
type ShareBox = Record<IssueId, ShareInterval>;

function fullShareBox(issues: Issue[]): ShareBox {
  const box: ShareBox = {};
  for (const issue of issues) box[issue.id] = { lo: 0, hi: 1, minVal: issue.min, maxVal: issue.max };
  return box;
}

/**
 * Convert per-issue value bounds into grid-snapped claimant-share intervals `[lo, hi]` carrying exact
 * grid-snapped `[minVal, maxVal]` endpoints (H-10) so `nashOnBox` never re-derives bounds via lossy `valueForShare`.
 * Returns `null` if any issue contains no on-grid point inside the bounds.
 */
function shareBoxFromLimits(issues: Issue[], limits: IssueLimits | undefined): ShareBox | null {
  if (!limits) return fullShareBox(issues);
  const box: ShareBox = {};
  for (const issue of issues) {
    const b = ownEntry(limits, issue.id);
    if (!b) {
      box[issue.id] = { lo: 0, hi: 1, minVal: issue.min, maxVal: issue.max };
      continue;
    }
    const gMin = snap(issue, Math.max(issue.min, b.min), "ceil");
    const gMax = snap(issue, Math.min(issue.max, b.max), "floor");
    if (gMin > gMax + EPS) return null;
    const clampedMin = Math.min(gMin, gMax);
    const sMin = claimantShare(issue, clampedMin);
    const sMax = claimantShare(issue, gMax);
    box[issue.id] = { lo: Math.min(sMin, sMax), hi: Math.max(sMin, sMax), minVal: clampedMin, maxVal: gMax };
  }
  return box;
}

function intersectShareBoxes(issues: Issue[], a: ShareBox | null, b: ShareBox | null): ShareBox | null {
  if (!a || !b) return null;
  const out: ShareBox = {};
  for (const issue of issues) {
    const minVal = Math.max(a[issue.id]!.minVal, b[issue.id]!.minVal);
    const maxVal = Math.min(a[issue.id]!.maxVal, b[issue.id]!.maxVal);
    if (minVal > maxVal + EPS) return null;
    const clampedMin = Math.min(minVal, maxVal);
    const sMin = claimantShare(issue, clampedMin);
    const sMax = claimantShare(issue, maxVal);
    out[issue.id] = { lo: Math.min(sMin, sMax), hi: Math.max(sMin, sMax), minVal: clampedMin, maxVal };
  }
  return out;
}

function pkgInBounds(issues: Issue[], bounds: IssueLimits, pkg: Package): boolean {
  return issues.every((i) => {
    const b = ownEntry(bounds, i.id);
    if (!b) return false;
    const v = pkg[i.id]!;
    return v >= b.min - EPS && v <= b.max + EPS;
  });
}

function pkgInOptionalLimits(issues: Issue[], limits: IssueLimits | undefined, pkg: Package): boolean {
  if (!limits) return true;
  return issues.every((i) => {
    const b = ownEntry(limits, i.id);
    if (!b) return true;
    const v = pkg[i.id]!;
    return v >= b.min - EPS && v <= b.max + EPS;
  });
}

/**
 * Mandate-clamped crossing settlement (MECH-6).
 *
 * When two valid offers cross in aggregate utility (`Uc(r) >= Uc(c)` and `Ur(c) >= Ur(r)`), returns their
 * per-issue `midpointPackage` if it already lies inside both mandates. If a multi-issue trade-off places the
 * raw per-issue midpoint outside one party's mandate on an issue, clamps onto the intersection of both mandates
 * and, if clamping dipped one party below its own offer's utility, compensates minimally along the remaining
 * issues inside the joint mandate box (falling back to the symmetric Nash grid solution over `(Uc(c), Ur(r))`
 * on the joint mandate box). Uses only offers, weights, and mandate bounds — never declared walkaways.
 */
export function clampedCrossingTerms(
  issues: Issue[],
  offers: Record<Party, Package>,
  privates: Record<Party, PrivateInputs>,
  mandates: Record<Party, Mandate>,
): Package | null {
  const mid = crossingTerms(issues, offers, privates);
  if (mid === null) return null;
  if (pkgInBounds(issues, mandates.claimant.bounds, mid) && pkgInBounds(issues, mandates.respondent.bounds, mid)) {
    return mid;
  }

  const wc = privates.claimant.weights;
  const wr = privates.respondent.weights;
  const ucAsk = utility(issues, wc, offers.claimant, "claimant");
  const urAsk = utility(issues, wr, offers.respondent, "respondent");

  const gridBounds: Record<IssueId, { min: number; max: number }> = {};
  const clamped: Package = {};
  for (const issue of issues) {
    const bc = ownEntry(mandates.claimant.bounds, issue.id);
    const br = ownEntry(mandates.respondent.bounds, issue.id);
    if (!bc || !br) return null;
    const gMin = snap(issue, Math.max(issue.min, bc.min, br.min), "ceil");
    const gMax = snap(issue, Math.min(issue.max, bc.max, br.max), "floor");
    if (gMin > gMax + EPS) return null;
    gridBounds[issue.id] = { min: gMin, max: gMax };
    clamped[issue.id] = Math.min(gMax, Math.max(gMin, mid[issue.id]!));
  }

  let uc = utility(issues, wc, clamped, "claimant");
  let ur = utility(issues, wr, clamped, "respondent");
  if (uc >= ucAsk - EPS && ur >= urAsk - EPS) return orderLike(issues, clamped);

  // Minimal-step compensation toward whichever party fell below its own offer's utility after clamping.
  if ((uc < ucAsk - EPS) !== (ur < urAsk - EPS)) {
    const shortParty: Party = uc < ucAsk - EPS ? "claimant" : "respondent";
    const wShort = shortParty === "claimant" ? wc : wr;
    const wOther = shortParty === "claimant" ? wr : wc;
    let deficit = (shortParty === "claimant" ? ucAsk - uc : urAsk - ur);
    let slackOther = (shortParty === "claimant" ? ur - urAsk : uc - ucAsk);
    const ratio = (i: Issue) => (wOther[i.id]! <= EPS ? Number.POSITIVE_INFINITY : wShort[i.id]! / wOther[i.id]!);
    const order = [...issues]
      .filter((i) => wShort[i.id]! > EPS)
      .sort((x, y) => {
        const d = ratio(y) - ratio(x);
        if (d !== 0 && !Number.isNaN(d)) return d;
        return x.id < y.id ? -1 : x.id > y.id ? 1 : 0;
      });

    const adjusted: Package = { ...clamped };
    for (const issue of order) {
      if (deficit <= EPS) break;
      const gb = gridBounds[issue.id]!;
      const shortPrefersHigher =
        (shortParty === "claimant" && issue.claimantPrefers === "higher") ||
        (shortParty === "respondent" && issue.claimantPrefers === "lower");
      const cur = adjusted[issue.id]!;
      const availSteps = Math.round((shortPrefersHigher ? gb.max - cur : cur - gb.min) / issue.step);
      if (availSteps <= 0) continue;
      const gainPerStep = (wShort[issue.id]! * issue.step) / range(issue);
      const costPerStep = (wOther[issue.id]! * issue.step) / range(issue);
      const maxAffordableSteps = costPerStep <= EPS ? availSteps : Math.floor((slackOther + EPS) / costPerStep);
      if (maxAffordableSteps <= 0) continue;
      const neededSteps = Math.ceil((deficit - EPS) / gainPerStep);
      const steps = Math.min(availSteps, maxAffordableSteps, Math.max(0, neededSteps));
      if (steps <= 0) continue;
      adjusted[issue.id] = snap(issue, cur + (shortPrefersHigher ? 1 : -1) * steps * issue.step, "nearest");
      deficit -= steps * gainPerStep;
      slackOther -= steps * costPerStep;
    }
    uc = utility(issues, wc, adjusted, "claimant");
    ur = utility(issues, wr, adjusted, "respondent");
    if (uc >= ucAsk - EPS && ur >= urAsk - EPS && pkgInBounds(issues, mandates.claimant.bounds, adjusted) && pkgInBounds(issues, mandates.respondent.bounds, adjusted)) {
      return orderLike(issues, adjusted);
    }
  }

  // Fallback: symmetric Nash solution over (ucAsk, urAsk) inside the joint mandate box.
  const jointMandateBox = intersectShareBoxes(
    issues,
    shareBoxFromLimits(issues, mandates.claimant.bounds),
    shareBoxFromLimits(issues, mandates.respondent.bounds),
  );
  if (!jointMandateBox) return null;
  const fallback = nashOnBox(issues, wc, wr, ucAsk, urAsk, 0.5, jointMandateBox);
  if (
    fallback !== null &&
    pkgInBounds(issues, mandates.claimant.bounds, fallback) &&
    pkgInBounds(issues, mandates.respondent.bounds, fallback)
  ) {
    return fallback;
  }
  return null;
}

/**
 * Offer-independent reference package for binding final-offer determination (MECH-8).
 *
 * Uses only the round-1 frozen declared inputs (`weights`, `walkaway`, optional `limits`): returns the
 * symmetric (`split = 0.5`) Nash bargaining solution when a zone of agreement exists, or the per-issue
 * midpoint of the declared walkaways when no zone exists. Bargaining concessions in rounds 1..N never move
 * this reference, eliminating the chilling effect of last-offer-midpoint arbitration.
 */
export function declaredReferenceTerms(issues: Issue[], privates: Record<Party, PrivateInputs>): Package {
  return nashProposal(issues, privates, 0.5) ?? midpointPackage(issues, privates.claimant.walkaway, privates.respondent.walkaway);
}

/**
 * Optional post-settlement Pareto frontier improvement (MECH-10, hardened in H-09).
 *
 * Given an already-settled `baselineTerms` package, searches `fullShareBox(issues)` (never narrowing the
 * optimization box by private `mandate.bounds` — SA-CORE-M2 — or private `private.limits` — H-09) for a
 * grid package maximising Nash gain above `(Uc(baselineTerms), Ur(baselineTerms))` using the dispute's
 * secret `split` (`α ∈ [0.3, 0.7]`, preventing algebraic inversion of 2-issue `private.weights`).
 * Returns `null` unless the candidate weakly improves both parties, increases combined utility by more than
 * `1e-6`, and lies within both parties' principal mandates and declared `private.limits`.
 */
export function paretoImproveTerms(
  issues: Issue[],
  baselineTerms: Package,
  privates: Record<Party, PrivateInputs>,
  mandates: Record<Party, Mandate>,
  split = 0.5,
): Package | null {
  if (issues.length <= 1) return null;

  const wc = privates.claimant.weights;
  const wr = privates.respondent.weights;
  const ucBase = utility(issues, wc, baselineTerms, "claimant");
  const urBase = utility(issues, wr, baselineTerms, "respondent");
  const candidate = nashOnBox(issues, wc, wr, ucBase, urBase, split, fullShareBox(issues));
  if (!candidate) return null;

  const ucNew = utility(issues, wc, candidate, "claimant");
  const urNew = utility(issues, wr, candidate, "respondent");
  if (ucNew < ucBase - EPS || urNew < urBase - EPS) return null;
  if (ucNew - ucBase + (urNew - urBase) <= 1e-6) return null;
  if (
    !pkgInBounds(issues, mandates.claimant.bounds, candidate) ||
    !pkgInBounds(issues, mandates.respondent.bounds, candidate) ||
    !pkgInOptionalLimits(issues, privates.claimant.limits, candidate) ||
    !pkgInOptionalLimits(issues, privates.respondent.limits, candidate)
  ) {
    return null;
  }
  return candidate;
}

/**
 * Platform proposal (single negotiating text): the package maximising the
 * (asymmetric) Nash product (Uc - Rc)^α (Ur - Rr)^(1-α) subject to both parties
 * being at or above their declared walkaway utility and inside any declared per-issue
 * `private.limits` (MECH-7). Returns null when the declared walkaways or limits leave
 * no zone of agreement.
 *
 * `split` (α) defaults to 0.5, the symmetric Nash solution. Disputes use a secret
 * per-dispute α in [0.3, 0.7] (see proposalSplit): with α known, a single-issue
 * proposal P = Wc + α(Wr − Wc) would let either side solve for the other's
 * walkaway exactly (security review H1); with α secret it only bounds it.
 *
 * With linear utilities over a box [lo_i, hi_i], the Pareto frontier is still a
 * fractional-knapsack path: issues are handed to the claimant from `lo_i` to `hi_i`
 * in descending order of wc/wr. Only one pivot issue takes a non-extreme value and
 * needs snapping to the grid inside `[lo_k, hi_k]`.
 */
export function nashProposal(issues: Issue[], privates: Record<Party, PrivateInputs>, split = 0.5): Package | null {
  const boxC = shareBoxFromLimits(issues, privates.claimant.limits);
  const boxR = shareBoxFromLimits(issues, privates.respondent.limits);
  const joint = intersectShareBoxes(issues, boxC, boxR);
  if (!joint) return null;
  const wc = privates.claimant.weights;
  const wr = privates.respondent.weights;
  const rc = utility(issues, wc, privates.claimant.walkaway, "claimant");
  const rr = utility(issues, wr, privates.respondent.walkaway, "respondent");
  return nashOnBox(issues, wc, wr, rc, rr, split, joint);
}

/**
 * Highest utility the other side can get on the Pareto frontier while `me` gets at least `rMe`, or −1 if `rMe`
 * is out of reach. With linear utilities the frontier hands issues to `me` in descending order of wMe/wThem.
 */
export function frontierMax(issues: Issue[], wMe: Record<string, number>, wThem: Record<string, number>, rMe: number): number {
  return frontierMaxOnBox(issues, wMe, wThem, rMe, "claimant", fullShareBox(issues));
}

function frontierMaxOnBox(
  issues: Issue[],
  wMe: Record<string, number>,
  wThem: Record<string, number>,
  rMe: number,
  meParty: Party,
  box: ShareBox,
): number {
  let uMe = 0;
  let uThem = 0;
  for (const issue of issues) {
    const iv = box[issue.id]!;
    const meLo = meParty === "claimant" ? iv.lo : 1 - iv.hi;
    uMe += wMe[issue.id]! * meLo;
    uThem += wThem[issue.id]! * (1 - meLo);
  }
  if (rMe <= uMe + EPS) return uThem;
  const ratio = (i: Issue) => (wThem[i.id]! <= EPS ? Number.POSITIVE_INFINITY : wMe[i.id]! / wThem[i.id]!);
  const order = [...issues].sort((x, y) => {
    const d = ratio(y) - ratio(x);
    if (d !== 0 && !Number.isNaN(d)) return d;
    return x.id < y.id ? -1 : x.id > y.id ? 1 : 0;
  });
  for (const issue of order) {
    const iv = box[issue.id]!;
    const delta = iv.hi - iv.lo;
    if (delta <= EPS) continue;
    const a = wMe[issue.id]! * delta;
    const b = wThem[issue.id]! * delta;
    if (uMe + a >= rMe - EPS) {
      const t = a > EPS ? Math.min(1, Math.max(0, (rMe - uMe) / a)) : 0;
      return uThem - b * t;
    }
    uMe += a;
    uThem -= b;
  }
  return -1;
}

/**
 * What each party is shown as the platform proposal (security review CR2-2, option 1, extended for MECH-7 `limits`).
 *
 * With a zone of agreement both see the Nash proposal and it can settle. Without one, each party X sees a
 * personal stand-in inside X's own declared `limits` and at or above X's own `walkaway`, computed by REFLECTING
 * the counterparty's reservation (and any disjoint limit deficit) through the frontier. So X's stand-in sits
 * above X's own walkaway by α times a distance between the reservations, never violates X's own limits, and X
 * can't tell from existence, shape or position relative to its own walkaway whether a zone exists. A stand-in
 * never settles; accepting it looks exactly like the counterparty rejecting.
 */
export function presentProposal(issues: Issue[], basis: Record<Party, PrivateInputs>, split: number): { views: Record<Party, Package>; settles: boolean } {
  const real = nashProposal(issues, basis, split);
  if (real) return { views: { claimant: real, respondent: structuredClone(real) }, settles: true };

  const wc = basis.claimant.weights;
  const wr = basis.respondent.weights;
  const rc = utility(issues, wc, basis.claimant.walkaway, "claimant");
  const rr = utility(issues, wr, basis.respondent.walkaway, "respondent");

  const boxC = shareBoxFromLimits(issues, basis.claimant.limits) ?? fullShareBox(issues);
  const boxR = shareBoxFromLimits(issues, basis.respondent.limits) ?? fullShareBox(issues);
  const joint = intersectShareBoxes(issues, boxC, boxR);

  // Claimant stand-in (H-09): ALWAYS optimize on Claimant's own `boxC` (never `joint`, which would clamp
  // Claimant's stand-in onto Respondent's secret `private.limits`), folding any joint/disjoint limit deficit
  // into the scalar reflected disagreement utility `rrRef` blinded by secret `split`.
  const urAtRc = frontierMaxOnBox(issues, wc, wr, rc, "claimant", boxC);
  const urAtRcJoint = joint ? frontierMaxOnBox(issues, wc, wr, rc, "claimant", joint) : -1;
  let boxDeficitC = 0;
  for (const i of issues) {
    boxDeficitC += wr[i.id]! * Math.max(0, boxC[i.id]!.lo - boxR[i.id]!.hi, boxR[i.id]!.lo - boxC[i.id]!.hi);
  }
  const maxUcJoint = joint ? frontierMaxOnBox(issues, wr, wc, 0, "respondent", joint) : 0;
  const jointDeficitC =
    joint === null ? 0 : urAtRcJoint >= 0 ? Math.max(0, rr - urAtRcJoint) : Math.max(0, rc - maxUcJoint);
  const deficitC = Math.max(Math.max(0, rr - urAtRc), jointDeficitC) + boxDeficitC;
  const rrRef = Math.max(0, urAtRc - deficitC);
  const forClaimant =
    nashOnBox(issues, wc, wr, rc, rrRef, split, boxC) ??
    nashOnBox(issues, wc, wr, rc, 0, split, boxC) ??
    structuredClone(basis.claimant.walkaway);

  // Respondent stand-in (H-09): symmetric on Respondent's own `boxR` (never `joint`).
  const ucAtRr = frontierMaxOnBox(issues, wr, wc, rr, "respondent", boxR);
  const ucAtRrJoint = joint ? frontierMaxOnBox(issues, wr, wc, rr, "respondent", joint) : -1;
  let boxDeficitR = 0;
  for (const i of issues) {
    boxDeficitR += wc[i.id]! * Math.max(0, boxC[i.id]!.lo - boxR[i.id]!.hi, boxR[i.id]!.lo - boxC[i.id]!.hi);
  }
  const maxUrJoint = joint ? frontierMaxOnBox(issues, wc, wr, 0, "claimant", joint) : 0;
  const jointDeficitR =
    joint === null ? 0 : ucAtRrJoint >= 0 ? Math.max(0, rc - ucAtRrJoint) : Math.max(0, rr - maxUrJoint);
  const deficitR = Math.max(Math.max(0, rc - ucAtRr), jointDeficitR) + boxDeficitR;
  const rcRef = Math.max(0, ucAtRr - deficitR);
  const forRespondent =
    nashOnBox(issues, wc, wr, rcRef, rr, split, boxR) ??
    nashOnBox(issues, wc, wr, 0, rr, split, boxR) ??
    structuredClone(basis.respondent.walkaway);

  return { views: { claimant: forClaimant, respondent: forRespondent }, settles: false };
}

function nashOnBox(
  issues: Issue[],
  wc: Record<string, number>,
  wr: Record<string, number>,
  rc: number,
  rr: number,
  split: number,
  box: ShareBox,
): Package | null {
  if (!(split > 0 && split < 1)) throw new Error("split must be in (0, 1)");

  const isFixed = (i: Issue) => box[i.id]!.maxVal - box[i.id]!.minVal <= EPS;
  const movableWeighted = issues.filter((i) => !isFixed(i) && (wc[i.id]! > EPS || wr[i.id]! > EPS));
  const fixedIssues = issues.filter((i) => isFixed(i));
  const zeroWeightMovable = issues.filter((i) => !isFixed(i) && !(wc[i.id]! > EPS || wr[i.id]! > EPS));

  const ratio = (i: Issue) => (wr[i.id]! <= EPS ? Number.POSITIVE_INFINITY : wc[i.id]! / wr[i.id]!);
  const order = [...movableWeighted].sort((x, y) => {
    const d = ratio(y) - ratio(x);
    if (d !== 0 && !Number.isNaN(d)) return d;
    return x.id < y.id ? -1 : x.id > y.id ? 1 : 0;
  });

  let ucBase = 0;
  let urBase = 0;
  for (const issue of issues) {
    const iv = box[issue.id]!;
    ucBase += wc[issue.id]! * iv.lo;
    urBase += wr[issue.id]! * (1 - iv.hi);
  }

  const nash = (uc: number, ur: number) => Math.max(0, uc - rc) ** split * Math.max(0, ur - rr) ** (1 - split);
  const feasible = (uc: number, ur: number) => uc >= rc - EPS && ur >= rr - EPS;

  const boxValueBounds = (issue: Issue): { min: number; max: number } => {
    const iv = box[issue.id]!;
    return { min: iv.minVal, max: iv.maxVal };
  };

  if (order.length === 0) {
    const single: Package = {};
    for (const issue of fixedIssues) single[issue.id] = box[issue.id]!.minVal;
    for (const issue of zeroWeightMovable) {
      const vb = boxValueBounds(issue);
      single[issue.id] = Math.min(vb.max, Math.max(vb.min, snap(issue, (vb.min + vb.max) / 2, "nearest")));
    }
    const uc = utility(issues, wc, single, "claimant");
    const ur = utility(issues, wr, single, "respondent");
    return feasible(uc, ur) ? orderLike(issues, single) : null;
  }

  // Search the continuous frontier of `box` for the best segment position `t in [0, 1]`.
  let best: { k: number; t: number; n: number } | null = null;
  for (let k = 0; k < order.length; k++) {
    const pivotIssue = order[k]!;
    const deltaK = box[pivotIssue.id]!.hi - box[pivotIssue.id]!.lo;
    const a = wc[pivotIssue.id]! * deltaK;
    const b = wr[pivotIssue.id]! * deltaK;
    let ak = 0;
    for (let j = 0; j < k; j++) {
      const ij = order[j]!;
      ak += wc[ij.id]! * (box[ij.id]!.hi - box[ij.id]!.lo);
    }
    let bk = 0;
    for (let j = k + 1; j < order.length; j++) {
      const ij = order[j]!;
      bk += wr[ij.id]! * (box[ij.id]!.hi - box[ij.id]!.lo);
    }

    const candidates = [0, 1];
    if (a > EPS && b > EPS) {
      // Stationary point of α·ln(uc − rc) + (1 − α)·ln(ur − rr) along t ∈ [0, 1].
      const t = (split * a * (urBase + bk + b - rr) - (1 - split) * b * (ucBase + ak - rc)) / (a * b);
      candidates.push(Math.min(1, Math.max(0, t)));
    }
    for (const t of candidates) {
      const uc = ucBase + ak + a * t;
      const ur = urBase + bk + b * (1 - t);
      if (!feasible(uc, ur)) continue;
      const n = nash(uc, ur);
      if (best === null || n > best.n + EPS) best = { k, t, n };
    }
  }
  if (best === null) return null;

  const base: Package = {};
  order.forEach((issue, j) => {
    const iv = box[issue.id]!;
    if (j < best.k) {
      base[issue.id] = issue.claimantPrefers === "higher" ? iv.maxVal : iv.minVal;
    } else if (j > best.k) {
      base[issue.id] = issue.claimantPrefers === "higher" ? iv.minVal : iv.maxVal;
    } else {
      const share = iv.lo + (iv.hi - iv.lo) * best.t;
      base[issue.id] = valueForShare(issue, share);
    }
  });
  for (const issue of fixedIssues) base[issue.id] = box[issue.id]!.minVal;
  for (const issue of zeroWeightMovable) {
    const vb = boxValueBounds(issue);
    base[issue.id] = Math.min(vb.max, Math.max(vb.min, snap(issue, (vb.min + vb.max) / 2, "nearest")));
  }

  // Snap the fractional pivot issue inside its on-grid box bounds and recursively re-optimize remaining issues on the sub-box.
  const pivot = order[best.k]!;
  const pivotBounds = boxValueBounds(pivot);
  const exact = base[pivot.id]!;
  const snappedFloor = Math.min(pivotBounds.max, Math.max(pivotBounds.min, snap(pivot, exact, "floor")));
  const snappedCeil = Math.min(pivotBounds.max, Math.max(pivotBounds.min, snap(pivot, exact, "ceil")));
  const snappedValues = Math.abs(snappedFloor - snappedCeil) <= EPS ? [snappedFloor] : [snappedFloor, snappedCeil];
  let chosen: { pkg: Package; n: number; dist: number; evenIdx: boolean } | null = null;
  for (const snapped of snappedValues) {
    let pkg: Package | null;
    if (snappedValues.length === 1) {
      pkg = { ...base, [pivot.id]: snapped };
    } else {
      const sShare = Math.min(box[pivot.id]!.hi, Math.max(box[pivot.id]!.lo, claimantShare(pivot, snapped)));
      pkg = nashOnBox(issues, wc, wr, rc, rr, split, {
        ...box,
        [pivot.id]: { lo: sShare, hi: sShare, minVal: snapped, maxVal: snapped },
      });
    }
    if (!pkg) continue;
    const uc = utility(issues, wc, pkg, "claimant");
    const ur = utility(issues, wr, pkg, "respondent");
    if (!feasible(uc, ur)) continue;
    const n = nash(uc, ur);
    const dist = Math.abs(pkg[pivot.id]! - exact);
    const evenIdx = Math.abs(Math.round(gridIndex(pivot, pkg[pivot.id]!))) % 2 === 0;
    const betterNash = chosen !== null && n > chosen.n + EPS;
    const tiedNash = chosen !== null && Math.abs(n - chosen.n) <= EPS;
    const betterDist = tiedNash && dist < chosen!.dist - EPS;
    const betterParity = tiedNash && Math.abs(dist - chosen!.dist) <= EPS && evenIdx && !chosen!.evenIdx;
    if (chosen === null || betterNash || betterDist || betterParity) {
      chosen = { pkg, n, dist, evenIdx };
    }
  }
  return chosen === null ? null : orderLike(issues, chosen.pkg);
}

/** Coarse, opt-in disclosure of the final gap. */
export function gapBucket(gap: number): "<10%" | "10-25%" | "25-50%" | ">50%" {
  if (gap < 0.1) return "<10%";
  if (gap < 0.25) return "10-25%";
  if (gap < 0.5) return "25-50%";
  return ">50%";
}

function orderLike(issues: Issue[], pkg: Package): Package {
  const out: Package = {};
  for (const issue of issues) out[issue.id] = pkg[issue.id]!;
  return out;
}

/** Remove floating-point noise so values compare and serialise cleanly. */
function clean(x: number): number {
  if (Number.isSafeInteger(x)) return x === 0 ? 0 : x;
  if (Math.abs(x) <= Number.MAX_SAFE_INTEGER) {
    const nearestInt = Math.round(x);
    if (Number.isSafeInteger(nearestInt) && Math.abs(x - nearestInt) <= EPS) {
      return nearestInt === 0 ? 0 : nearestInt;
    }
  }
  if (Math.abs(x) > 1e6) return x === 0 ? 0 : x;
  const r = Math.round(x * 1e9) / 1e9;
  return r === 0 ? 0 : r;
}
