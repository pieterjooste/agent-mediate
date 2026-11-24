export * from "./types.ts";
export { canonicalJson, contractHash, RULES_VERSION, sha256Hex } from "./canonical.ts";

/** Canonical public production API base URL. */
export const PRODUCTION_API_URL = "https://api.ai-agents-mediation.com";

/** Canonical production apex URL (308-redirected to `PRODUCTION_API_URL` at the edge). */
export const PRODUCTION_APEX_URL = "https://ai-agents-mediation.com";

/**
 * Canonicalise an HTTP(S) API `baseUrl` (`P1-2`): lowercases scheme & host, strips default ports (`:443` / `:80`)
 * and trailing slashes, rejects embedded credentials / query / fragment, and rewrites the bare production apex
 * `https://ai-agents-mediation.com` to `PRODUCTION_API_URL` so callers never bypass `DEFAULT_PRODUCTION_PLATFORM_DIDS`
 * or hit `308` redirects on RFC 9421 signed mutations.
 */
export function normalizeBaseUrl(rawUrl: string): string {
  const trimmed = typeof rawUrl === "string" ? rawUrl.trim() : "";
  if (!trimmed) throw new Error("baseUrl must be a non-empty http(s) URL");
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    throw new Error(`baseUrl is not a valid URL: ${rawUrl}`);
  }
  if (parsed.protocol !== "https:" && parsed.protocol !== "http:") {
    throw new Error(`baseUrl must use http:// or https://, got ${parsed.protocol}`);
  }
  if (parsed.username || parsed.password || parsed.search || parsed.hash) {
    throw new Error("baseUrl must not contain credentials, query parameters, or fragments");
  }
  const cleanPath = parsed.pathname === "/" ? "" : parsed.pathname.replace(/\/+$/, "");
  const normalized = `${parsed.origin}${cleanPath}`;
  return normalized === PRODUCTION_APEX_URL ? PRODUCTION_API_URL : normalized;
}

/**
 * Out-of-band pinned production platform signing DIDs by normalised API base URL (`SEC3-8` / `H-1`).
 * Forward key rotations signed by retired keys verify through `/.well-known/key-history.json` (`P1-1`).
 */
export const DEFAULT_PRODUCTION_PLATFORM_DIDS: Readonly<Record<string, string>> = Object.freeze({
  [PRODUCTION_API_URL]: "did:key:z6Mkg7r4aHyPrNKYy1gbWGXu15VgyN9fCbhqKVwftdhHxJ3W",
});
export { chainHash, commitData, GENESIS_HASH, publicAuditEntry, verifyAuditChain, verifyPublicAuditChain, type PublicAuditEntry } from "./audit.ts";
export {
  CONFIG_LIMITS,
  DEFAULT_CONFIG,
  DomainError,
  EVIDENCE_ID_PATTERN,
  ISSUE_ID_PATTERN,
  MAX_ISSUES,
  MAX_MANDATE_UPDATES,
  mandateCovers,
  NOTICE_METHODS,
  requireMandateCovers,
  requireMandateMonotonicExpansion,
  requireMandateScope,
  RESERVED_ISSUE_IDS,
  resolveConfig,
  validateAdoptSuggestedIds,
  validateEvidenceItem,
  validateIssues,
  validateMandateShape,
  validateNoticeDelivery,
  validatePackage,
  validatePrivate,
  withinDeterminationMandate,
  withinMandate,
  withinMandateLimits,
} from "./validation.ts";
export {
  claimantShare,
  clampedCrossingTerms,
  computeGap,
  crossingTerms,
  declaredReferenceTerms,
  deriveProposalKey,
  deriveProposalSalt,
  distance,
  frontierMax,
  gapBucket,
  isOnGrid,
  isStalled,
  midpointPackage,
  nashProposal,
  other,
  ownEntry,
  paretoImproveTerms,
  presentProposal,
  proposalSplit,
  proposalSplitFromKey,
  proposalSplitFromSalt,
  snap,
  SPLIT_MAX,
  SPLIT_MIN,
  utility,
  weightedDistance,
} from "./mechanism.ts";
export { apply, createDispute, extendDeadlines, isTerminal, issuesHash, MAX_OUTAGE_EXTENSION_MS, nextDeadline, partyProposal, proposalTermsFor, type CreateDisputeInput } from "./machine.ts";
export {
  buildSettlementInstruction,
  buildUnresolvedCertificate,
  compactViewFor,
  findLeaks,
  nextActionsFor,
  NO_SHOW_NOTICE,
  UNTRUSTED_NOTICE,
  untrustedEventFields,
  untrustedFields,
  viewFor,
  type CompactPartyView,
  type Leak,
  type PartyView,
  type UntrustedAuthor,
  type UntrustedContent,
} from "./disclosure.ts";
export {
  BASE_ANCHOR_MAGIC,
  buildCheckpointMerkleTree,
  CHECKPOINT_LEAF_DOMAIN,
  CHECKPOINT_NODE_DOMAIN,
  checkpointLeafHash,
  checkpointNodeHash,
  computeDeclaredInputCommitment,
  computeOutcomeHash,
  computeProposalKeyCommitment,
  computeTermsHash,
  decodeBaseAnchorCalldata,
  DECLARED_INPUT_COMMIT_DOMAIN,
  derivePartyInputSalt,
  EMPTY_MERKLE_ROOT,
  encodeBaseAnchorCalldata,
  HISTORICAL_RULES_HASHES,
  MECHANISM_SPEC,
  PROPOSAL_KEY_COMMIT_DOMAIN,
  RULES_HASH,
  verifyCheckpointInclusion,
  verifyProposalOpening,
  type CheckpointLeafInput,
  type CheckpointMerkleTree,
  type MerkleInclusionProof,
  type MerkleSibling,
  type ProposalAuditOpening,
  type ProposalKeyMode,
  type VerifiedProposalOpening,
} from "./verifiability.ts";
