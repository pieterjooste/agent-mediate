/**
 * Domain types for the A-ADR core. Everything here is plain data so state can be
 * persisted as JSON and replayed deterministically.
 */

export type Party = "claimant" | "respondent";
export const PARTIES: readonly Party[] = ["claimant", "respondent"];

export type IssueId = string;

/** A single negotiable dimension, e.g. refund amount or redelivery deadline. */
export interface Issue {
  id: IssueId;
  label: string;
  unit: string;
  min: number;
  max: number;
  /** Granularity. (max - min) must be an exact multiple of step. */
  step: number;
  /** Direction the claimant prefers. The respondent always prefers the opposite. */
  claimantPrefers: "higher" | "lower";
  /** Party that must perform this term once settled. */
  obligor: Party;
}

/** A value for every confirmed issue. */
export type Package = Record<IssueId, number>;

/**
 * Principal-signed delegation. Signature verification happens at the API layer;
 * the core enforces the bounds and expiry.
 */
export interface Mandate {
  id: string;
  principalId: string;
  /** Must equal the party's agent id. */
  agentId: string;
  /** Inclusive per-issue bounds the principal authorised this agent to agree to. */
  bounds: Record<IssueId, { min: number; max: number }>;
  expiresAt: number;
  /**
   * Optional, signed: restrict the mandate to one contract and/or one counterparty, so it can't be
   * replayed in another dispute (security review H2). Enforced at filing, joining and replacement.
   */
  scope?: { contractHash?: string; counterpartyId?: string };
  /**
   * Signed issue time (unix ms). A replacement mandate must be strictly newer than the one it replaces, so an
   * older, wider mandate from the same principal can't be swapped back in (security review CR2-11).
   */
  issuedAt?: number;
  /**
   * Signed opt-in to binding final-offer determination (MECH-1). Consent must be signed by the
   * principal inside the mandate, not asserted unilaterally by the agent.
   */
  determinationConsent?: boolean;
  /**
   * Optional signed per-issue bounds for binding final-offer determination (MECH-1). May be wider or tighter
   * than voluntary bargaining `bounds` (allowing cautious bargaining authority paired with wider deadlock-breaking
   * determination authority); defaults to `bounds` for any issue omitted here.
   */
  determinationBounds?: Record<IssueId, { min: number; max: number }>;
  /** Principal's Ed25519 signature over the canonical mandate. Verified by the API layer. */
  signature?: string;
}

/** Per-issue inclusive value bounds. */
export type IssueLimits = Record<IssueId, { min: number; max: number }>;

/** Confidential inputs. Never leave the core except in the submitting party's own view. */
export interface PrivateInputs {
  /** Non-negative, one per issue, summing to 1. */
  weights: Record<IssueId, number>;
  /** The worst package this party would still accept. */
  walkaway: Package;
  /**
   * Optional per-issue hard limits for platform proposals and post-settlement Pareto improvements (MECH-7).
   * Any omitted issue defaults to `[issue.min, issue.max]`. Must contain `walkaway` and lie within your mandate bounds.
   */
  limits?: IssueLimits;
}

export type ProposalResponse = "accept" | "reject";
export type ImprovementResponse = "accept" | "decline";
export type FeeMode = "FILER_PAYS";

export interface DisputeConfig {
  /** 3–8, default 6. */
  maxRounds: number;
  /** Minimum per-round gap reduction (fraction of the remaining gap, MECH-3) to count as progress. 0 disables stall detection. */
  stallThreshold: number;
  /** Consecutive low-progress rounds that trigger STALLED. 2–5. */
  stallWindow: number;
  roundTimeoutMs: number;
  /** Hard ceiling for the whole bargaining stage. 1–60 min. */
  bargainingWallClockMs: number;
  joinTimeoutMs: number;
  /** Deadline for the evidence and issue-confirmation stages. */
  stageTimeoutMs: number;
  determinationTimeoutMs: number;
  executionTimeoutMs: number;
  /** First round in which a platform proposal (single negotiating text) is presented. */
  proposalFromRound: number;
  /**
   * What the platform proposal is computed from:
   * - "declared": Nash solution over the parties' declared walkaways (default).
   * - "offers": Nash solution using each party's utility from the OTHER side's current
   *   offer as its disagreement point; declared walkaways do not affect it.
   */
  proposalBasis: "declared" | "offers";
  maxIssueProposals: number;
  feeMode: FeeMode;
}

export const STATUSES = [
  "AWAITING_RESPONDENT",
  "EVIDENCE",
  "ISSUE_CONFIRMATION",
  "BARGAINING",
  "DETERMINATION",
  "EXECUTION_PENDING",
  "HONORED",
  "BREACH_REPORTED",
  "UNRESOLVED",
] as const;

export type Status = (typeof STATUSES)[number];

export const TERMINAL_STATUSES: readonly Status[] = ["HONORED", "BREACH_REPORTED", "UNRESOLVED"];

export const REASON_CODES = [
  "RESPONDENT_NO_SHOW",
  "UNNOTIFIED_EXPIRY",
  "ISSUES_NOT_AGREED",
  "NO_OVERLAP_AT_CAP",
  "STALLED",
  "TIMEOUT",
  "WITHDRAWN",
  "DETERMINATION_FAILED",
] as const;

export type ReasonCode =
  /** Respondent did not join despite verified delivery (DISC-2(d)). */
  | "RESPONDENT_NO_SHOW"
  /** Join window expired when no verified respondent notice channel acknowledged delivery (DISC-2(d)). */
  | "UNNOTIFIED_EXPIRY"
  | "ISSUES_NOT_AGREED"
  /** Round cap or bargaining wall-clock reached without a deal. */
  | "NO_OVERLAP_AT_CAP"
  | "STALLED"
  /** A party failed to participate (no offer at all, or two missed rounds). */
  | "TIMEOUT"
  | "WITHDRAWN"
  /** Final-offer determination opened but no reference was supplied before its deadline, or the winning offer exceeded a party's signed determination mandate (MECH-1). */
  | "DETERMINATION_FAILED";

export type NoticeMethod =
  | "none"
  | "standing"
  | "standing_webhook"
  | "clause_endpoint"
  | "a2a_card"
  | "did_web"
  | "email"
  | "unverified_contact";

export interface NoticeDelivery {
  /** Highest-trust channel that accepted the notice, or "none" if undelivered. */
  method: NoticeMethod;
  /** True when at least one outbound channel acknowledged receipt. */
  delivered: boolean;
  /**
   * True only when the channel was authenticated/published by the respondent (standing registration,
   * respondent-signed dispute clause, respondent's did:web, or respondent-signed A2A Agent Card).
   * Unverified claimant-supplied contacts cannot trigger RESPONDENT_NO_SHOW (DISC-2(d), SEC3-6).
   */
  verifiedEndpoint: boolean;
  attempted: NoticeMethod[];
  at: number;
}

export const SETTLEMENT_METHODS = ["PROPOSAL_ACCEPTED", "OVERLAP_MIDPOINT", "FINAL_OFFER_DETERMINATION"] as const;
export type SettlementMethod = (typeof SETTLEMENT_METHODS)[number];

export interface EvidenceItem {
  id: string;
  submittedBy: Party;
  kind: string;
  sha256: string;
  description: string;
  at: number;
}

export interface PartyState {
  id: string;
  mandate: Mandate;
  feePaid: boolean;
  determinationConsent: boolean;
  discloseGapOnFailure: boolean;
  /** Number of in-place principal mandate widenings (`UPDATE_MANDATE`) applied after `ISSUE_CONFIRMATION` (`v1.2.0`). */
  mandateUpdates?: number;
}

export interface RoundSubmission {
  offer: Package;
  proposalResponse: ProposalResponse | null;
  at: number;
}

/**
 * A platform proposal (security review CR2-2, option 1). From `proposalFromRound` every round presents one to
 * each party, whether or not the declared walkaways leave a zone of agreement: `views` holds what each party
 * sees. With a zone, both views are the same Nash proposal and `settles` is true (it settles if both accept
 * and it lies within both mandates). Without one, each party sees a personal stand-in of the same shape and
 * `settles` is false: accepting it behaves exactly like a counterparty rejection. `settles` is never shown.
 * Legacy proposals (before CR2-2) have only `terms`.
 */
export interface Proposal {
  id: string;
  round: number;
  views?: Record<Party, Package>;
  settles?: boolean;
  /** Legacy shape only. */
  terms?: Package;
}

/** What a party sees of a proposal. */
export interface PartyProposal {
  id: string;
  round: number;
  terms: Package;
}

export interface RoundRecord {
  round: number;
  submitted: Record<Party, boolean>;
  /** Standing offers when the round closed. */
  offers: Record<Party, Package | null>;
  proposal: Proposal | null;
  responses: Record<Party, ProposalResponse | null>;
  gap: number | null;
}

export interface BargainingState {
  round: number;
  startedAt: number;
  wallClockDeadline: number;
  roundDeadline: number;
  submissions: Record<Party, RoundSubmission | null>;
  lastOffer: Record<Party, Package | null>;
  private: Record<Party, PrivateInputs | null>;
  misses: Record<Party, number>;
  gaps: number[];
  /** Proposal open for responses in the current round. */
  proposal: Proposal | null;
  history: RoundRecord[];
}

export interface DeterminationState {
  startedAt?: number;
  deadline: number;
  triggeredBy: "STALLED" | "NO_OVERLAP_AT_CAP";
  finalOffers: Record<Party, Package | null>;
  reference: Package | null;
}

export type Outcome =
  | { kind: "SETTLED"; method: SettlementMethod; terms: Package; at: number; roundsCompleted: number }
  | { kind: "UNRESOLVED"; reason: ReasonCode; at: number; roundsCompleted: number };

export interface ExecutionImprovement {
  terms: Package;
  status: "OPEN" | "ACCEPTED" | "DECLINED";
  responses: Record<Party, ImprovementResponse | null>;
}

export interface ExecutionState {
  deadline: number;
  obligors: Party[];
  proofs: Record<Party, { reference: string; at: number } | null>;
  /** Keyed by obligor: has the counterparty confirmed that obligor's performance? */
  confirmed: Record<Party, boolean>;
  /** Keyed by obligor: has the counterparty contested that obligor's performance? (MECH-2) */
  contested?: Record<Party, { reason: string; at: number } | null>;
  /** Optional post-settlement Pareto-superior package open for mutual acceptance before execution proof (MECH-10). */
  improvement?: ExecutionImprovement | null;
}

export interface DisputeState {
  id: string;
  createdAt: number;
  status: Status;
  config: DisputeConfig;
  contractHash: string;
  claim: { summary: string; requestedRemedy: string };
  respondentId: string;
  parties: { claimant: PartyState; respondent: PartyState | null };
  /** Deadline for AWAITING_RESPONDENT, EVIDENCE and ISSUE_CONFIRMATION. */
  stageDeadline: number | null;
  evidence: EvidenceItem[];
  evidenceClosed: Record<Party, boolean>;
  issueNegotiation: {
    proposalCount: number;
    proposed: Issue[] | null;
    proposedHash: string | null;
    confirmed: Record<Party, boolean>;
    /** Optional `advisory.suggestedIssues` IDs requested by the rejecting party for the next issue proposal (`v1.2.0`). */
    requestedSuggestedIds?: IssueId[];
    /** Consecutive `adoptSuggestedIds` groups carried forward across sequential re-proposals until a plain reset or confirmation (`v1.3.0`). */
    priorAdoptedSuggestedIds?: IssueId[][];
  };
  /** Confirmed issue list; null until both parties confirm. */
  issues: Issue[] | null;
  bargaining: BargainingState | null;
  determination: DeterminationState | null;
  outcome: Outcome | null;
  execution: ExecutionState | null;
  /** `salt` makes audit commitments hiding; never disclosed. */
  audit: { salt: string; seq: number; head: string };
  /**
   * Key for the secret proposal split α (security review CR2-2, CR2-14): HMAC of a platform secret over the
   * party pair and contract, so repeat filings between the same pair on the same contract can't average α.
   * Never disclosed. Absent on disputes created before CR2-2 (they keep the salt-derived split).
   */
  proposalKey?: string;
  /** Creation-time SHA-256 commitment to `proposalKey` (or `audit.salt`), disclosed to both parties at filing (SEC3-5). */
  proposalKeyCommitment?: string;
  /** Per-party salted SHA-256 commitments to Round-1 declared private inputs (SEC3-5). */
  declaredCommitments?: Partial<Record<Party, string>>;
  /** Total deadline extension granted for platform outages so far (capped, CR2-6). */
  outageExtensionMs?: number;
  /** Respondent notification provenance recorded at/after filing (DISC-2). Holds method codes only, never URLs or emails. */
  noticeDelivery?: NoticeDelivery;
}

/** Windows a respondent may raise when joining (CR2-9). */
export type JoinWindowKey = "roundTimeoutMs" | "bargainingWallClockMs" | "stageTimeoutMs" | "determinationTimeoutMs" | "executionTimeoutMs";
export const JOIN_WINDOW_KEYS: readonly JoinWindowKey[] = ["roundTimeoutMs", "bargainingWallClockMs", "stageTimeoutMs", "determinationTimeoutMs", "executionTimeoutMs"];

/** Who may see an event. `internal` events carry confidential data. */
export type Visibility = Party | "both" | "internal";

export interface DomainEvent {
  seq: number;
  type: string;
  at: number;
  visibility: Visibility;
  data: Record<string, unknown>;
  /** sha256(salt + canonical(data)). Publishable: hides low-entropy private values. */
  dataCommitment: string;
  prevHash: string;
  hash: string;
}

export type Command =
  | {
      type: "JOIN";
      actor: "respondent";
      respondentId: string;
      mandate: Mandate;
      feePaid?: boolean;
      discloseGapOnFailure: boolean;
      /** The respondent may lengthen (never shorten) the windows the claimant chose (CR2-9). */
      windows?: Partial<Pick<DisputeConfig, JoinWindowKey>>;
    }
  | {
      type: "SUBMIT_EVIDENCE";
      actor: Party;
      items: Array<{ id: string; kind: string; sha256: string; description: string }>;
    }
  | { type: "CLOSE_EVIDENCE"; actor: Party }
  | { type: "PROPOSE_ISSUES"; actor: "system"; issues: Issue[] }
  | { type: "CONFIRM_ISSUES"; actor: Party; issuesHash: string; mandate?: Mandate }
  | { type: "REJECT_ISSUES"; actor: Party; issuesHash: string; adoptSuggestedIds?: IssueId[] }
  | { type: "UPDATE_MANDATE"; actor: Party; mandate: Mandate }
  | {
      type: "SUBMIT_ROUND";
      actor: Party;
      round: number;
      offer: Package;
      /** Required in a party's first submission; fixed afterwards (later submissions may omit it or repeat it unchanged). */
      private?: PrivateInputs;
      /** Required when a proposal is open. */
      proposalResponse?: ProposalResponse;
    }
  | { type: "SET_DETERMINATION_REFERENCE"; actor: "system"; terms: Package }
  | { type: "SUBMIT_FINAL_OFFER"; actor: Party; offer: Package }
  | { type: "RESPOND_IMPROVEMENT"; actor: Party; response: ImprovementResponse }
  | { type: "SUBMIT_EXECUTION_PROOF"; actor: Party; reference: string }
  | { type: "CONFIRM_EXECUTION"; actor: Party }
  | { type: "CONTEST_EXECUTION"; actor: Party; reason: string }
  | { type: "WITHDRAW"; actor: Party }
  /** Record respondent notification provenance while AWAITING_RESPONDENT (DISC-2). */
  | { type: "RECORD_NOTICE"; actor: "system"; noticeDelivery: NoticeDelivery }
  /** Scheduler heartbeat: processes any deadline that has passed. */
  | { type: "TICK"; actor: "system" };

export type ErrorCode =
  | "INVALID_INPUT"
  | "INVALID_STATE"
  | "NOT_AUTHORIZED"
  | "FEE_REQUIRED"
  | "MANDATE_VIOLATION"
  | "MANDATE_EXPIRED"
  | "RETRACTION"
  | "WRONG_ROUND"
  | "ALREADY_SUBMITTED"
  | "HASH_MISMATCH";

export interface DomainErrorShape {
  code: ErrorCode;
  message: string;
}

export type ApplyResult =
  | { ok: true; state: DisputeState; events: DomainEvent[] }
  | { ok: false; error: DomainErrorShape };
