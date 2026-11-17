import assert from "node:assert/strict";
import {
  apply,
  createDispute,
  issuesHash,
  type ApplyResult,
  type Command,
  type DisputeConfig,
  type DisputeState,
  type DomainEvent,
  type Issue,
  type Mandate,
  type Package,
  type PrivateInputs,
  type ProposalResponse,
} from "../src/index.ts";

export const MIN = 60_000;
export const DAY = 24 * 60 * MIN;
export const T0 = Date.UTC(2026, 9, 14, 8, 0, 0);
export const SALT = "test-salt-".padEnd(48, "x");
export const CONTRACT = "c".repeat(64);
export const CLAIMANT = "agent:buyer.example";
export const RESPONDENT = "agent:vendor.example";

export const REFUND: Issue = {
  id: "refundUsd",
  label: "Refund",
  unit: "USD",
  min: 0,
  max: 1000,
  step: 10,
  claimantPrefers: "higher",
  obligor: "respondent",
};
export const CREDIT: Issue = {
  id: "serviceCreditUsd",
  label: "Service credit",
  unit: "USD",
  min: 0,
  max: 500,
  step: 10,
  claimantPrefers: "higher",
  obligor: "respondent",
};

export function fullBounds(issues: Issue[]): Mandate["bounds"] {
  return Object.fromEntries(issues.map((i) => [i.id, { min: i.min, max: i.max }]));
}

/** `issuedAt` defaults to a minute before T0; a replacement must pass a later one (CR2-11). */
export function mandate(
  agentId: string,
  bounds: Mandate["bounds"],
  expiresAt = T0 + 30 * DAY,
  issuedAt = T0 - 60_000,
  extra: Pick<Mandate, "determinationConsent" | "determinationBounds" | "scope"> = {},
): Mandate {
  return { id: `mnd:${agentId}`, principalId: `principal:${agentId}`, agentId, bounds, expiresAt, issuedAt, ...extra };
}

export interface HarnessOptions {
  issues?: Issue[];
  config?: Partial<DisputeConfig>;
  claimantBounds?: Mandate["bounds"];
  respondentBounds?: Mandate["bounds"];
  claimantDeterminationBounds?: Mandate["determinationBounds"];
  respondentDeterminationBounds?: Mandate["determinationBounds"];
  claimantMandateExpiry?: number;
  respondentMandateExpiry?: number;
  determination?: { claimant: boolean; respondent: boolean };
  gapDisclosure?: { claimant: boolean; respondent: boolean };
  proposalKey?: string;
}

export interface Move {
  offer: Package;
  private?: PrivateInputs;
  response?: ProposalResponse;
}

/** Drives a dispute through the reducer, failing loudly on any rejected command. */
export class Harness {
  state: DisputeState;
  now = T0;
  readonly events: DomainEvent[] = [];
  readonly issues: Issue[];
  readonly opts: HarnessOptions;

  constructor(opts: HarnessOptions = {}) {
    this.opts = opts;
    this.issues = opts.issues ?? [REFUND];
    const r = createDispute(
      {
        id: "dsp_test",
        auditSalt: SALT,
        claimantId: CLAIMANT,
        claimantMandate: mandate(CLAIMANT, opts.claimantBounds ?? fullBounds(this.issues), opts.claimantMandateExpiry, undefined, {
          ...(opts.determination?.claimant !== undefined ? { determinationConsent: opts.determination.claimant } : {}),
          ...(opts.claimantDeterminationBounds ? { determinationBounds: opts.claimantDeterminationBounds } : {}),
        }),
        respondentId: RESPONDENT,
        contractHash: CONTRACT,
        claim: { summary: "API was down 47 minutes against a 99.9% SLA", requestedRemedy: "Refund" },
        feePaid: true,
        discloseGapOnFailure: opts.gapDisclosure?.claimant ?? false,
        config: opts.config,
        ...(opts.proposalKey ? { proposalKey: opts.proposalKey } : {}),
      },
      this.now,
    );
    this.state = expectOk(r, "createDispute").state;
    this.events.push(...expectOk(r, "createDispute").events);
  }

  advance(ms: number): this {
    this.now += ms;
    return this;
  }

  send(cmd: Command): this {
    const r = apply(this.state, cmd, this.now);
    const ok = expectOk(r, cmd.type);
    this.state = ok.state;
    this.events.push(...ok.events);
    return this;
  }

  /** Apply without committing; for asserting rejections. */
  attempt(cmd: Command): ApplyResult {
    return apply(this.state, cmd, this.now);
  }

  join(feePaid = true): this {
    return this.send({
      type: "JOIN",
      actor: "respondent",
      respondentId: RESPONDENT,
      mandate: mandate(RESPONDENT, this.opts.respondentBounds ?? fullBounds(this.issues), this.opts.respondentMandateExpiry, undefined, {
        ...(this.opts.determination?.respondent !== undefined ? { determinationConsent: this.opts.determination.respondent } : {}),
        ...(this.opts.respondentDeterminationBounds ? { determinationBounds: this.opts.respondentDeterminationBounds } : {}),
      }),
      feePaid,
      discloseGapOnFailure: this.opts.gapDisclosure?.respondent ?? false,
    });
  }

  toIssueConfirmation(): this {
    return this.join().send({ type: "CLOSE_EVIDENCE", actor: "claimant" }).send({ type: "CLOSE_EVIDENCE", actor: "respondent" });
  }

  toBargaining(): this {
    this.toIssueConfirmation().send({ type: "PROPOSE_ISSUES", actor: "system", issues: this.issues });
    const hash = issuesHash(this.issues);
    return this.send({ type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: hash }).send({
      type: "CONFIRM_ISSUES",
      actor: "respondent",
      issuesHash: hash,
    });
  }

  submit(actor: "claimant" | "respondent", move: Move): this {
    return this.send({
      type: "SUBMIT_ROUND",
      actor,
      round: this.state.bargaining!.round,
      offer: move.offer,
      ...(move.private ? { private: move.private } : {}),
      ...(move.response ? { proposalResponse: move.response } : {}),
    });
  }

  round(claimant: Move, respondent: Move): this {
    return this.submit("claimant", claimant).submit("respondent", respondent);
  }

  /** Jump to the next deadline and TICK. */
  expire(): this {
    const d =
      this.state.status === "BARGAINING"
        ? this.state.bargaining!.roundDeadline
        : this.state.status === "DETERMINATION"
          ? this.state.determination!.deadline
          : this.state.status === "EXECUTION_PENDING"
            ? this.state.execution!.deadline
            : this.state.stageDeadline!;
    this.now = Math.max(this.now, d);
    return this.send({ type: "TICK", actor: "system" });
  }
}

export function expectOk(r: ApplyResult, label: string): Extract<ApplyResult, { ok: true }> {
  if (!r.ok) assert.fail(`${label} rejected: ${r.error.code} ${r.error.message}`);
  return r;
}

export function expectError(r: ApplyResult, code: string): void {
  assert.equal(r.ok, false, `expected ${code} but command succeeded`);
  if (!r.ok) assert.equal(r.error.code, code, r.error.message);
}

/** Single-issue private inputs. */
export function single(walkawayRefund: number): PrivateInputs {
  return { weights: { refundUsd: 1 }, walkaway: { refundUsd: walkawayRefund } };
}

/** Deterministic PRNG (mulberry32). */
export function rng(seed: number): () => number {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
