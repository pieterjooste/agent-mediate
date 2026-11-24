/**
 * Cryptographic verifiability primitives (Phase 4: DISC-11, SEC3-4, SEC3-5, DISC-12):
 *
 * - Canonical `MECHANISM_SPEC` and deterministic `RULES_HASH` (`DISC-11`).
 * - Creation-time `proposalKeyCommitment` and salted Round-1 `declaredInputCommitment`s, plus
 *   bilateral/auditor `verifyProposalOpening` that verifies `α`, platform proposals, and the
 *   binding determination reference without ever exposing low-entropy walkaways to a single
 *   counterparty (`SEC3-5`, preserving `H1` / `D47` / `D75`).
 * - Outcome & terms commitments (`computeTermsHash`, `computeOutcomeHash`) committed inside
 *   append-only domain events (`SEC3-4`).
 * - RFC 6962-style domain-separated SHA-256 Merkle tree and Base calldata encoding for public
 *   audit-head transparency checkpoints (`SEC3-5`, `DISC-12`).
 */
import { canonicalJson, RULES_VERSION, sha256Hex } from "./canonical.ts";
import {
  declaredReferenceTerms,
  presentProposal,
  proposalSplitFromKey,
  proposalSplitFromSalt,
  SPLIT_MAX,
  SPLIT_MIN,
} from "./mechanism.ts";
import { PARTIES, type Issue, type Outcome, type Package, type Party, type PrivateInputs, type Status } from "./types.ts";
import { CONFIG_LIMITS, DEFAULT_CONFIG, MAX_ISSUES, MAX_MANDATE_UPDATES, validateIssues, validatePrivate } from "./validation.ts";

// ---------------------------------------------------------------------------
// DISC-11: Canonical Mechanism Specification & RULES_HASH
// ---------------------------------------------------------------------------

function deepFreeze<T>(obj: T): T {
  if (obj !== null && typeof obj === "object") {
    for (const value of Object.values(obj as Record<string, unknown>)) {
      deepFreeze(value);
    }
    Object.freeze(obj);
  }
  return obj;
}

export const MECHANISM_SPEC = deepFreeze({
  schema: "agent-mediate/mechanism-spec/v1",
  rulesVersion: RULES_VERSION,
  canonicalization: "RFC 8785 (JCS) + SHA-256",
  grid: {
    maxIssues: MAX_ISSUES,
    stepAlignment: "exact_integer_and_ulp_scaled_fractional_grid_H10",
    monotonicity: "per_issue_no_retraction",
  },
  crossingSettlement: {
    method: "OVERLAP_MIDPOINT",
    clamping: "mandate_box_minimal_utility_compensation_MECH_6",
  },
  platformProposal: {
    fromRoundDefault: DEFAULT_CONFIG.proposalFromRound,
    alwaysPresented: true,
    splitRange: [SPLIT_MIN, SPLIT_MAX],
    splitKeyDomain: "agent-mediate/proposal-key/v1",
    splitHmacDomain: "agent-mediate/proposal-split/v1",
    keyCommitDomain: "agent-mediate/proposal-key-commit/v1",
    declaredCommitDomain: "agent-mediate/declared-input-commit/v1",
    objective: "asymmetric_nash_product_within_declared_limits_MECH_7",
    noZoneBehavior: "non_settling_reflected_stand_in_within_viewer_box_H09",
  },
  postSettlementImprovement: {
    enabled: true,
    split: "secret_per_dispute_alpha_H09",
    optimizationBox: "full_issue_grid_post_hoc_mandates_and_limits_H09",
    baseline: "settled_terms_never_walkaways_MECH_10",
    acceptance: "unanimous_within_mandates_before_execution_proof",
  },
  stallDetection: {
    metric: "relative_fraction_of_previous_gap_MECH_3",
    defaultThreshold: DEFAULT_CONFIG.stallThreshold,
    defaultWindow: DEFAULT_CONFIG.stallWindow,
  },
  finalOfferDetermination: {
    contractualNotArbitration: true,
    consentSource: "principal_signed_mandate_determinationConsent_MECH_1",
    reference: "round1_declared_symmetric_nash_or_walkaway_midpoint_MECH_8",
    distance: "mean_declared_weight_normalised_L1_MECH_8",
    tieBreakDomain: "arbitration-tiebreak",
  },
  issueNegotiation: {
    adoptSuggestedOnReject: true,
    rejectRequiresIssuesHash: true,
    maxProposals: DEFAULT_CONFIG.maxIssueProposals,
  },
  mandateEscalation: {
    allowedStatuses: ["BARGAINING", "DETERMINATION"],
    maxUpdatesPerParty: MAX_MANDATE_UPDATES,
    monotonicWideningOnly: true,
    freezesDeterminationConsentAtBargainingStart: true,
    preservesFrozenRound1Private: true,
  },
  outageGrace: {
    mandateExpiryGuard: "recheck_both_mandates_at_confirm_and_before_timeout_M10",
  },
  execution: {
    zeroObligationImmediateHonored: true,
    uncontestedProofAtDeadline: "HONORED_MECH_2",
    contestedOrMissingProofAtDeadline: "BREACH_REPORTED",
  },
  defaults: {
    maxRounds: DEFAULT_CONFIG.maxRounds,
    maxIssueProposals: DEFAULT_CONFIG.maxIssueProposals,
    feeMode: DEFAULT_CONFIG.feeMode,
    windowsMs: {
      joinTimeoutMs: DEFAULT_CONFIG.joinTimeoutMs,
      stageTimeoutMs: DEFAULT_CONFIG.stageTimeoutMs,
      roundTimeoutMs: DEFAULT_CONFIG.roundTimeoutMs,
      bargainingWallClockMs: DEFAULT_CONFIG.bargainingWallClockMs,
      determinationTimeoutMs: DEFAULT_CONFIG.determinationTimeoutMs,
      executionTimeoutMs: DEFAULT_CONFIG.executionTimeoutMs,
    },
  },
  windowLimitsMs: structuredClone(CONFIG_LIMITS),
} as const);

/** SHA-256 of the RFC 8785 JCS canonical `MECHANISM_SPEC` for `RULES_VERSION` (DISC-11). */
export const RULES_HASH: string = sha256Hex(canonicalJson(MECHANISM_SPEC));

/** Canonical historical `RULES_HASH` map for prior published rules versions (graceful clause & verifier continuity). */
export const HISTORICAL_RULES_HASHES: Readonly<Record<string, string>> = Object.freeze({
  "1.3.0": "8d7e67e1145097e3ce20d8828e451db20453d864782c91ccb08be2e9e613cdc4",
});

// ---------------------------------------------------------------------------
// SEC3-4: Outcome & Terms Commitments
// ---------------------------------------------------------------------------

export function computeTermsHash(terms: Package): string {
  return sha256Hex(canonicalJson(terms));
}

export function computeOutcomeHash(outcome: Outcome, status: Status): string {
  return sha256Hex(canonicalJson({ status, outcome }));
}

// ---------------------------------------------------------------------------
// SEC3-5: Creation-time Proposal Key Commitment & Declared-Input Commitments
// ---------------------------------------------------------------------------

export const PROPOSAL_KEY_COMMIT_DOMAIN = "agent-mediate/proposal-key-commit/v1\n";
export const DECLARED_INPUT_COMMIT_DOMAIN = "agent-mediate/declared-input-commit/v1\n";

export type ProposalKeyMode = "keyed" | "salted";

/**
 * Hiding 256-bit commitment to a dispute's proposal split source (`proposalKey` when `PROPOSAL_SECRET`
 * is configured, or `deriveProposalSalt(auditSalt, disputeId)` in local/unkeyed mode), emitted in
 * `DISPUTE_FILED` before any Round-1 private inputs exist so the operator cannot pick `α` after seeing
 * walkaways (SEC3-5).
 *
 * Security note (review H5 / M8):
 * - In `"keyed"` mode, `proposalKey` is shared across disputes for `(pair, contractHash)` so repeat filings
 *   cannot average out `α` (CR2-2, CR2-14). It must **never** be disclosed to a disputing party — only to a
 *   confidentiality-bound independent auditor, or retired/rotated if ever opened.
 * - In `"salted"` mode, `proposalKeyOrSalt` is the one-way derived `proposalSalt` (never `audit.salt`).
 */
export function computeProposalKeyCommitment(
  disputeId: string,
  proposalKeyOrSalt: string,
  mode: ProposalKeyMode = "keyed",
): string {
  return sha256Hex(`${PROPOSAL_KEY_COMMIT_DOMAIN}${disputeId}\n${mode}\n${proposalKeyOrSalt}`);
}

/**
 * Per-party 256-bit blinding salt derived one-way from `auditSalt`. Shown ONLY to `party` (never to
 * the counterparty) so `party` can verify its own Round-1 `declaredCommitment` immediately while the
 * counterparty learns zero bits about `party`'s low-entropy walkaway (`H1`, `D75`).
 */
export function derivePartyInputSalt(auditSalt: string, disputeId: string, party: Party): string {
  return sha256Hex(`${DECLARED_INPUT_COMMIT_DOMAIN}salt\n${disputeId}\n${party}\n${auditSalt}`);
}

export function computeDeclaredInputCommitment(
  disputeId: string,
  party: Party,
  partySalt: string,
  priv: PrivateInputs,
): string {
  return sha256Hex(`${DECLARED_INPUT_COMMIT_DOMAIN}commit\n${disputeId}\n${party}\n${partySalt}\n${canonicalJson(priv)}`);
}

export interface ProposalAuditOpening {
  disputeId: string;
  issues: Issue[];
  /** Optional confirmed `issuesHash` (`sha256Hex(canonicalJson(issues))` from `ISSUES_CONFIRMED`) to bind `issues`. */
  expectedIssuesHash?: string;
  mode: ProposalKeyMode;
  proposalKeyOrSalt: string;
  proposalKeyCommitment: string;
  declared: Record<Party, { private: PrivateInputs; partySalt: string; commitment: string }>;
  /** Observed per-party round proposals (e.g. from `PROPOSAL_PRESENTED`) to verify. */
  observedProposals?: Array<{ round: number; views: Partial<Record<Party, Package>> }>;
  /** Optional binding final-offer determination reference to verify (MECH-8). */
  observedDeterminationReference?: Package | null;
}

export type VerifiedProposalOpening =
  | {
      ok: true;
      alpha: number;
      expectedProposal: { views: Record<Party, Package>; settles: boolean };
      expectedDeterminationReference: Package;
    }
  | { ok: false; reason: string };

/**
 * Independent-auditor verifier for `SEC3-5` (or bilateral verifier in unkeyed `"salted"` mode).
 *
 * Warning (review H5): in `"keyed"` mode, `proposalKey` is shared across all disputes for `(pair, contractHash)`.
 * Never reveal a live `"keyed"` `proposalKey` to a disputing party (only to a confidentiality-bound third-party
 * auditor, or after rotating `PROPOSAL_SECRET`); otherwise a refiling party could compute `α` for guessed
 * counterparty inputs and invert low-entropy walkaways. In `"salted"` mode, `proposalKeyOrSalt` is the per-dispute
 * `deriveProposalSalt(auditSalt, disputeId)` 64-hex digest, which reveals zero bits of `audit.salt` (review M8).
 *
 * Given `proposalKeyCommitment` from `DISPUTE_FILED`, both parties' `declaredCommitments` from the signed outcome
 * document, and the opened inputs (`proposalKeyOrSalt` + both `{ private, partySalt }`), verifies without throwing:
 * 1. `issues` match `expectedIssuesHash` (when supplied) and pass grid validation.
 * 2. `proposalKeyOrSalt` matches `proposalKeyCommitment`.
 * 3. Both parties' declared inputs match their Round-1 commitments.
 * 4. `α` and every observed round proposal match the published deterministic mechanism.
 * 5. Any observed binding determination reference matches `declaredReferenceTerms`.
 */
export function verifyProposalOpening(opening: ProposalAuditOpening): VerifiedProposalOpening {
  try {
    if (!opening || typeof opening !== "object") {
      return { ok: false, reason: "opening must be an object" };
    }
    if (typeof opening.disputeId !== "string" || opening.disputeId.length === 0) {
      return { ok: false, reason: "disputeId must be a non-empty string" };
    }
    if (opening.mode !== "keyed" && opening.mode !== "salted") {
      return { ok: false, reason: "mode must be 'keyed' or 'salted'" };
    }
    if (typeof opening.proposalKeyOrSalt !== "string" || opening.proposalKeyOrSalt.length === 0) {
      return { ok: false, reason: "proposalKeyOrSalt must be a non-empty string" };
    }
    if (opening.mode === "salted" && !/^[a-f0-9]{64}$/.test(opening.proposalKeyOrSalt)) {
      return { ok: false, reason: "salted mode requires 64-hex derived proposalSalt (never raw audit.salt)" };
    }
    if (typeof opening.proposalKeyCommitment !== "string" || !/^[a-f0-9]{64}$/.test(opening.proposalKeyCommitment)) {
      return { ok: false, reason: "proposalKeyCommitment must be 64 lowercase hex characters" };
    }
    if (!Array.isArray(opening.issues)) {
      return { ok: false, reason: "issues must be an array" };
    }
    validateIssues(opening.issues);
    if (opening.expectedIssuesHash !== undefined) {
      if (typeof opening.expectedIssuesHash !== "string" || sha256Hex(canonicalJson(opening.issues)) !== opening.expectedIssuesHash) {
        return { ok: false, reason: "issues do not match expectedIssuesHash" };
      }
    }
    const expectedKeyCommit = computeProposalKeyCommitment(opening.disputeId, opening.proposalKeyOrSalt, opening.mode);
    if (expectedKeyCommit !== opening.proposalKeyCommitment) {
      return { ok: false, reason: "proposalKeyOrSalt does not match creation-time proposalKeyCommitment" };
    }
    if (!opening.declared || typeof opening.declared !== "object") {
      return { ok: false, reason: "declared openings must be an object" };
    }
    for (const p of PARTIES) {
      const entry = opening.declared[p];
      if (!entry || typeof entry !== "object") return { ok: false, reason: `missing declared opening for ${p}` };
      if (
        typeof entry.partySalt !== "string" ||
        !/^[a-f0-9]{64}$/.test(entry.partySalt) ||
        typeof entry.commitment !== "string" ||
        !/^[a-f0-9]{64}$/.test(entry.commitment)
      ) {
        return { ok: false, reason: `invalid declared opening fields for ${p}` };
      }
      validatePrivate(opening.issues, entry.private);
      const expectedCommit = computeDeclaredInputCommitment(opening.disputeId, p, entry.partySalt, entry.private);
      if (expectedCommit !== entry.commitment) {
        return { ok: false, reason: `${p} declared inputs do not match Round-1 commitment` };
      }
    }
    const privates = { claimant: opening.declared.claimant.private, respondent: opening.declared.respondent.private };
    const alpha =
      opening.mode === "keyed"
        ? proposalSplitFromKey(opening.proposalKeyOrSalt, privates)
        : proposalSplitFromSalt(opening.proposalKeyOrSalt);
    const expectedProposal = presentProposal(opening.issues, privates, alpha);
    if (opening.observedProposals !== undefined && !Array.isArray(opening.observedProposals)) {
      return { ok: false, reason: "observedProposals must be an array" };
    }
    for (const obs of opening.observedProposals ?? []) {
      if (!obs || typeof obs !== "object" || !obs.views || typeof obs.views !== "object" || Array.isArray(obs.views)) {
        return { ok: false, reason: "malformed observedProposals entry" };
      }
      let checked = 0;
      for (const p of PARTIES) {
        const seen = obs.views[p];
        if (seen === undefined || seen === null) continue;
        checked++;
        if (canonicalJson(seen) !== canonicalJson(expectedProposal.views[p])) {
          return { ok: false, reason: `round ${obs.round} proposal for ${p} does not match deterministic mechanism output` };
        }
      }
      if (checked === 0) {
        return { ok: false, reason: "observedProposals entry must include at least one party view" };
      }
    }
    const expectedDeterminationReference = declaredReferenceTerms(opening.issues, privates);
    if (opening.observedDeterminationReference !== undefined && opening.observedDeterminationReference !== null) {
      if (canonicalJson(opening.observedDeterminationReference) !== canonicalJson(expectedDeterminationReference)) {
        return { ok: false, reason: "determination reference does not match deterministic declaredReferenceTerms" };
      }
    }
    return { ok: true, alpha, expectedProposal, expectedDeterminationReference };
  } catch (err) {
    return { ok: false, reason: err instanceof Error ? err.message : "invalid proposal opening" };
  }
}

// ---------------------------------------------------------------------------
// SEC3-5 & DISC-12: Transparency Checkpoint Merkle Tree & Base Calldata
// ---------------------------------------------------------------------------

export const CHECKPOINT_LEAF_DOMAIN = "agent-mediate/checkpoint-leaf/v1\n";
export const CHECKPOINT_NODE_DOMAIN = "agent-mediate/checkpoint-node/v1\n";
export const EMPTY_MERKLE_ROOT: string = sha256Hex("agent-mediate/checkpoint-empty/v1\n");
/** 4-byte ASCII magic `"AMCP"` (`0x414d4350`) for Base L2 calldata anchoring. */
export const BASE_ANCHOR_MAGIC = "414d4350";

export interface CheckpointLeafInput {
  disputeId: string;
  status: Status;
  auditSeq: number;
  auditHead: string;
  outcomeHash: string | null;
}

export interface MerkleSibling {
  /** Whether this sibling sits on the left or right of the running hash. */
  side: "left" | "right";
  hash: string;
}

export interface MerkleInclusionProof {
  leafHash: string;
  leafIndex: number;
  totalLeaves: number;
  siblings: MerkleSibling[];
}

export function checkpointLeafHash(leaf: CheckpointLeafInput): string {
  return sha256Hex(CHECKPOINT_LEAF_DOMAIN + canonicalJson(leaf));
}

export function checkpointNodeHash(left: string, right: string): string {
  return sha256Hex(`${CHECKPOINT_NODE_DOMAIN}${left}\n${right}`);
}

/** Largest power of 2 strictly less than `n` (RFC 6962 §2.1 binary Merkle split). */
function largestPowerOfTwoLessThan(n: number): number {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
}

interface CachedMerkleNode {
  hash: string;
  count: number;
  split: number;
  left: CachedMerkleNode | null;
  right: CachedMerkleNode | null;
}

function buildCachedMerkleSubtree(hashes: string[], start: number, end: number): CachedMerkleNode {
  const count = end - start;
  if (count === 0) {
    return { hash: EMPTY_MERKLE_ROOT, count: 0, split: 0, left: null, right: null };
  }
  if (count === 1) {
    return { hash: hashes[start]!, count: 1, split: 0, left: null, right: null };
  }
  const k = largestPowerOfTwoLessThan(count);
  const left = buildCachedMerkleSubtree(hashes, start, start + k);
  const right = buildCachedMerkleSubtree(hashes, start + k, end);
  return {
    hash: checkpointNodeHash(left.hash, right.hash),
    count,
    split: k,
    left,
    right,
  };
}

function collectCachedMerkleSiblings(node: CachedMerkleNode, index: number): MerkleSibling[] {
  if (node.count <= 1 || !node.left || !node.right) return [];
  if (index < node.split) {
    const inner = collectCachedMerkleSiblings(node.left, index);
    inner.push({ side: "right", hash: node.right.hash });
    return inner;
  }
  const inner = collectCachedMerkleSiblings(node.right, index - node.split);
  inner.push({ side: "left", hash: node.left.hash });
  return inner;
}

export interface CheckpointMerkleTree {
  merkleRoot: string;
  leafCount: number;
  proofFor(disputeId: string): MerkleInclusionProof | null;
}

/**
 * Deterministic binary Merkle tree using the RFC 6962 §2.1 largest-power-of-two split topology with explicit
 * string domain prefixes (`agent-mediate/checkpoint-leaf/v1\n` and `agent-mediate/checkpoint-node/v1\n`, rather
 * than `0x00`/`0x01`) over per-checkpoint dispute snapshot tuples `(disputeId, status, auditSeq, auditHead, outcomeHash)`
 * sorted by unique `disputeId`. Because leaves are mutable per-dispute snapshots rather than an append-only event log,
 * cross-checkpoint equivocation is prevented by comparing the signed/Base-anchored `(checkpointSeq, merkleRoot)` across
 * claimant, respondent, and L2 calldata (`M3`).
 */
export function buildCheckpointMerkleTree(leaves: CheckpointLeafInput[]): CheckpointMerkleTree {
  const sorted = [...leaves].sort((a, b) => (a.disputeId < b.disputeId ? -1 : a.disputeId > b.disputeId ? 1 : 0));
  for (let i = 1; i < sorted.length; i++) {
    if (sorted[i]!.disputeId === sorted[i - 1]!.disputeId) {
      throw new Error(`duplicate disputeId in checkpoint tree: ${sorted[i]!.disputeId}`);
    }
  }
  const leafHashes = sorted.map(checkpointLeafHash);
  const indexById = new Map<string, number>();
  sorted.forEach((l, idx) => indexById.set(l.disputeId, idx));
  const rootNode = buildCachedMerkleSubtree(leafHashes, 0, leafHashes.length);

  return {
    merkleRoot: rootNode.hash,
    leafCount: sorted.length,
    proofFor(disputeId: string): MerkleInclusionProof | null {
      const idx = indexById.get(disputeId);
      if (idx === undefined) return null;
      return {
        leafHash: leafHashes[idx]!,
        leafIndex: idx,
        totalLeaves: sorted.length,
        siblings: collectCachedMerkleSiblings(rootNode, idx),
      };
    },
  };
}

function expectedMerkleSides(totalLeaves: number, leafIndex: number): Array<"left" | "right"> {
  if (totalLeaves <= 1) return [];
  const k = largestPowerOfTwoLessThan(totalLeaves);
  if (leafIndex < k) {
    return [...expectedMerkleSides(k, leafIndex), "right"];
  }
  return [...expectedMerkleSides(totalLeaves - k, leafIndex - k), "left"];
}

export function verifyCheckpointInclusion(
  leaf: CheckpointLeafInput,
  proof: MerkleInclusionProof,
  expectedMerkleRoot: string,
  opts?: { expectedTotalLeaves?: number },
): boolean {
  try {
    if (!leaf || typeof leaf !== "object" || !proof || typeof proof !== "object") return false;
    if (typeof leaf.disputeId !== "string" || typeof leaf.status !== "string") return false;
    if (!Number.isSafeInteger(leaf.auditSeq) || leaf.auditSeq < 1) return false;
    if (typeof leaf.auditHead !== "string" || !/^[a-f0-9]{64}$/.test(leaf.auditHead)) return false;
    if (leaf.outcomeHash !== null && (typeof leaf.outcomeHash !== "string" || !/^[a-f0-9]{64}$/.test(leaf.outcomeHash))) {
      return false;
    }
    if (typeof expectedMerkleRoot !== "string" || !/^[a-f0-9]{64}$/.test(expectedMerkleRoot)) return false;
    if (!Number.isSafeInteger(proof.totalLeaves) || proof.totalLeaves < 1) return false;
    if (opts?.expectedTotalLeaves !== undefined) {
      if (!Number.isSafeInteger(opts.expectedTotalLeaves) || proof.totalLeaves !== opts.expectedTotalLeaves) {
        return false;
      }
    }
    if (!Number.isSafeInteger(proof.leafIndex) || proof.leafIndex < 0 || proof.leafIndex >= proof.totalLeaves) return false;
    const expectedSides = expectedMerkleSides(proof.totalLeaves, proof.leafIndex);
    if (!Array.isArray(proof.siblings) || proof.siblings.length !== expectedSides.length) return false;
    const computedLeaf = checkpointLeafHash(leaf);
    if (computedLeaf !== proof.leafHash) return false;
    let acc = computedLeaf;
    for (let i = 0; i < proof.siblings.length; i++) {
      const sib = proof.siblings[i];
      if (!sib || typeof sib !== "object") return false;
      if (sib.side !== expectedSides[i] || typeof sib.hash !== "string" || !/^[a-f0-9]{64}$/.test(sib.hash)) return false;
      acc = sib.side === "left" ? checkpointNodeHash(sib.hash, acc) : checkpointNodeHash(acc, sib.hash);
    }
    return acc === expectedMerkleRoot;
  } catch {
    return false;
  }
}

/**
 * Deterministic 44-byte EVM calldata (`0x` + 4B `"AMCP"` magic + 8B big-endian `checkpointSeq` + 32B `merkleRoot`)
 * suitable for anchoring a daily checkpoint root on Base L2 via a 0-ETH self-transaction.
 */
export function encodeBaseAnchorCalldata(checkpointSeq: number, merkleRoot: string): string {
  if (!Number.isSafeInteger(checkpointSeq) || checkpointSeq < 1) throw new Error("checkpointSeq must be a positive safe integer");
  if (!/^[a-f0-9]{64}$/.test(merkleRoot)) throw new Error("merkleRoot must be 64 lowercase hex characters");
  const seqHex = BigInt(checkpointSeq).toString(16).padStart(16, "0");
  return `0x${BASE_ANCHOR_MAGIC}${seqHex}${merkleRoot}`;
}

export function decodeBaseAnchorCalldata(calldata: string): { checkpointSeq: number; merkleRoot: string } | null {
  const m = /^0x414d4350([0-9a-f]{16})([0-9a-f]{64})$/i.exec(calldata);
  if (!m) return null;
  const seq = Number(BigInt(`0x${m[1]!}`));
  if (!Number.isSafeInteger(seq) || seq < 1) return null;
  return { checkpointSeq: seq, merkleRoot: m[2]!.toLowerCase() };
}
