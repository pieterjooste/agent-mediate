/**
 * Zero-Crypto Reference Adapter & Runnable E2E Demo:
 *   Google AP2 (Closed Payment Mandate) + Stripe ACP Pre-Chargeback Mediation
 *
 * Demonstrates how an upstream commerce platform using AP2 mandates and Stripe Checkout/PaymentIntents
 * resolves post-delivery SLA or partial-fulfillment disputes in <10 seconds BEFORE a slow, binary
 * card chargeback ($15-$25 dispute fee, 30-90 day hold):
 *
 *   1. Deterministically bind an AP2 Closed Payment Mandate (`vct: "mandate.payment.1"`) and Stripe
 *      Checkout/PaymentIntent reference into an RFC 8785 (JCS) `contractHash`.
 *   2. Co-sign an `agent-mediate/clause/v1` pre-dispute clause and negotiate a 2-issue partial
 *      settlement (`refundCents` + `storeCreditCents`) via sealed offers — keeping both parties'
 *      confidential walkaways and margin weights private.
 *   3. Fail-closed verify the platform-signed `Ed25519Signature2026` settlement instruction
 *      (`verifySettlementForStripeRefund`) against pinned `platformDid`, `RULES_HASH`, AP2
 *      `contractHash`, `termsHash`, `outcomeHash`, and original charged amount cap.
 *   4. Execute an idempotent Stripe `POST /v1/refunds` call (`Idempotency-Key: agent-mediate-refund:<disputeId>`)
 *      and record `stripe:refund:<re_id>` as execution proof until `HONORED`.
 *   5. Show the `buildChargebackEvidenceBundle` fallback if a dispute ever ends `UNRESOLVED`.
 *
 * Usage:
 *   # Run completely offline (air-gapped / CI mode, <0.2s, zero network calls):
 *   npm run build && node examples/ap2-stripe-prechargeback.ts --offline
 *
 *   # Run live against https://api.ai-agents-mediation.com ($0.00 Mode A, zero crypto wallet, mock Stripe):
 *   npm run build && node examples/ap2-stripe-prechargeback.ts
 *
 *   # Optionally save the verified settlement instruction JSON for https://ai-agents-mediation.com/verify:
 *   node examples/ap2-stripe-prechargeback.ts --save-outcome /tmp/ap2-stripe-settlement.json
 *
 *   # Optional live Stripe test-mode refund (requires a real sk_test_... key and pi_... PaymentIntent):
 *   STRIPE_SECRET_KEY=sk_test_... STRIPE_PAYMENT_INTENT=pi_... node examples/ap2-stripe-prechargeback.ts
 */
import { randomBytes } from "node:crypto";
import { realpathSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import {
  apply,
  buildSettlementInstruction,
  buildUnresolvedCertificate,
  compactViewFor,
  createDispute,
  DEFAULT_PRODUCTION_PLATFORM_DIDS,
  deriveProposalKey,
  normalizeBaseUrl,
  PRODUCTION_API_URL,
  publicAuditEntry,
  RULES_HASH,
  RULES_VERSION,
  sha256Hex,
  viewFor,
  type Command,
  type DisputeState,
  type DomainEvent,
  type Issue,
  type Mandate,
  type Party,
  type SettlementMethod,
  type Status,
} from "@agent-mediate/core";
import {
  buildClause,
  buildSignedKeyHistory,
  computeOutcomeHash,
  computeTermsHash,
  contractHash,
  didWebFromUrl,
  generateAgentKey,
  signClause,
  signDocument,
  signMandate,
  verifyClause,
  verifyDocument,
  verifyRequest,
  type AgentKey,
  type SignedDocument,
} from "@agent-mediate/protocol";
import { AgentMediateClient } from "@agent-mediate/sdk";

// ---------------------------------------------------------------------------
// 1. Upstream AP2 (v0.2+) & Stripe ACP Schema Types
// ---------------------------------------------------------------------------

/** Closed AP2 Payment Mandate (`vct: "mandate.payment.1"`) issued at checkout. */
export interface Ap2PaymentMandate {
  vct: "mandate.payment.1";
  /** Base64url SHA-256 hash of the signed Checkout Mandate JWT (`hash(checkout_jwt)`). */
  transaction_id: string;
  payee: {
    id: string;
    name: string;
    domain: string;
  };
  payment_amount: {
    /** ISO 4217 currency code (e.g. "USD"). */
    currency: string;
    /** Total authorized charge in integer minor units (e.g. 50000 = $500.00). */
    amount: number;
  };
  payment_instrument: {
    type: "stripe_spt" | "card_network_token" | string;
    token_ref: string;
  };
  /** Optional Unix timestamp (seconds) expiry of the mandate. */
  exp?: number;
}

/** Stripe Agentic Commerce Protocol (ACP) order & payment identifiers bound to the AP2 mandate. */
export interface StripeAcpCheckoutRef {
  checkoutSessionId: string;
  paymentIntentId: string;
  orderId: string;
  merchantDomain: string;
}

export interface SettlementInstructionDocument {
  type: "agent-mediate/settlement-instruction/v1";
  rulesVersion: string;
  rulesHash: string;
  disputeId: string;
  environment?: string;
  parties: {
    contractHash: string;
    claimant: { agentId: string; principalId: string | null; mandateCommitment: string | null } | null;
    respondent: { agentId: string; principalId: string | null; mandateCommitment: string | null };
  };
  status: "SETTLED";
  executionStatus: Status;
  method: SettlementMethod;
  terms: Record<string, number>;
  termsHash: string;
  roundsCompleted: number;
  outcomeHash: string;
  settledAt: number;
  auditRoot: string;
}

export interface ExpectedStripeSettlementContext {
  platformDid: string;
  disputeId: string;
  contractHash: string;
  claimantDid: string;
  merchantDid: string;
  /** Hard upper cap in minor currency units (must equal `ap2PaymentMandate.payment_amount.amount`). */
  maxChargeAmountMinor: number;
}

export interface VerifiedStripeSettlement {
  disputeId: string;
  refundCents: number;
  storeCreditCents: number;
  method: SettlementMethod;
  executionStatus: Status;
  termsHash: string;
  outcomeHash: string;
  auditRoot: string;
}

export interface ExecutedStripeRefund {
  refundId: string | null;
  amountCents: number;
  storeCreditCents: number;
  status: string;
  idempotencyKey: string;
  executionProofRef: string;
  verifiedSettlement: VerifiedStripeSettlement;
}

// ---------------------------------------------------------------------------
// 2. Reusable Adapter Primitives (Contract Binding, Fail-Closed Verifier, Stripe Executor)
// ---------------------------------------------------------------------------

/**
 * Deterministically binds an AP2 Closed Payment Mandate and Stripe ACP Checkout/PaymentIntent
 * into a 64-hex Agent-Mediate `contractHash` using RFC 8785 canonical JSON (JCS).
 */
export function deriveAp2ContractHash(mandate: Ap2PaymentMandate, checkout: StripeAcpCheckoutRef): string {
  if (mandate.vct !== "mandate.payment.1") {
    throw new Error(`expected closed AP2 payment mandate (vct="mandate.payment.1"), got "${String(mandate.vct)}"`);
  }
  if (!Number.isSafeInteger(mandate.payment_amount.amount) || mandate.payment_amount.amount <= 0) {
    throw new Error("AP2 payment_amount.amount must be a positive integer in minor currency units");
  }
  return contractHash({
    protocol: "ap2+stripe-acp/v1",
    ap2PaymentMandate: {
      vct: mandate.vct,
      transaction_id: mandate.transaction_id,
      payee: {
        id: mandate.payee.id,
        domain: mandate.payee.domain.toLowerCase(),
      },
      payment_amount: {
        currency: mandate.payment_amount.currency.toUpperCase(),
        amount: mandate.payment_amount.amount,
      },
      payment_instrument: {
        type: mandate.payment_instrument.type,
        token_ref: mandate.payment_instrument.token_ref,
      },
    },
    stripeAcp: {
      checkoutSessionId: checkout.checkoutSessionId,
      paymentIntentId: checkout.paymentIntentId,
      orderId: checkout.orderId,
      merchantDomain: checkout.merchantDomain.toLowerCase(),
    },
  });
}

/**
 * Builds a 2-issue integrative pre-chargeback grid in integer minor units:
 *   - `refundCents`: cash reversal via Stripe `POST /v1/refunds` (capped at original AP2 charge)
 *   - `storeCreditCents`: merchant API / store credit (lets the merchant offer higher total value
 *     while reducing cash outflow — unlocking settlements that binary chargebacks miss).
 */
export function buildPreChargebackIssues(mandate: Ap2PaymentMandate, stepMinor = 500): Issue[] {
  const chargeMinor = mandate.payment_amount.amount;
  const currency = mandate.payment_amount.currency.toUpperCase();
  if (!Number.isSafeInteger(chargeMinor) || chargeMinor < stepMinor) {
    throw new Error(`charge amount (${chargeMinor}) must be >= stepMinor (${stepMinor})`);
  }
  const maxRefund = Math.floor(chargeMinor / stepMinor) * stepMinor;
  const maxCredit = Math.min(20_000, maxRefund);
  return [
    {
      id: "refundCents",
      label: `Partial Stripe Refund (${currency} minor units)`,
      unit: `${currency} cents`,
      min: 0,
      max: maxRefund,
      step: stepMinor,
      claimantPrefers: "higher",
      obligor: "respondent",
    },
    {
      id: "storeCreditCents",
      label: `Merchant Account Credit (${currency} minor units)`,
      unit: `${currency} cents`,
      min: 0,
      max: maxCredit,
      step: stepMinor,
      claimantPrefers: "higher",
      obligor: "respondent",
    },
  ];
}

/**
 * Deterministic Stripe `Idempotency-Key` scoped strictly to `disputeId` so retried network calls
 * or duplicate webhook triggers can NEVER double-refund the same PaymentIntent for one dispute.
 */
export function buildStripeRefundIdempotencyKey(disputeId: string): string {
  if (!/^dsp_[a-f0-9]{16,64}$/i.test(disputeId)) {
    throw new Error(`invalid Agent-Mediate disputeId: ${disputeId}`);
  }
  return `agent-mediate-refund:${disputeId}`;
}

/**
 * Fail-closed cryptographic verification gate that MUST run before calling Stripe `POST /v1/refunds`.
 * Rejects invalid Ed25519 signatures, mismatched `RULES_HASH` / `contractHash` / party DIDs,
 * tampered `terms` / `termsHash` / `outcomeHash`, or any refund exceeding the original AP2 charge.
 */
export function verifySettlementForStripeRefund(
  signedOutcome: SignedDocument<SettlementInstructionDocument>,
  expected: ExpectedStripeSettlementContext,
): VerifiedStripeSettlement {
  if (!verifyDocument(signedOutcome, expected.platformDid)) {
    throw new Error("settlement instruction Ed25519 signature failed verification against pinned platformDid");
  }
  const doc = signedOutcome.document;
  if (doc.type !== "agent-mediate/settlement-instruction/v1" || doc.status !== "SETTLED") {
    throw new Error(`expected SETTLED settlement-instruction/v1, got type=${String(doc.type)} status=${String(doc.status)}`);
  }
  if (doc.rulesHash !== RULES_HASH) {
    throw new Error(`rulesHash mismatch: expected ${RULES_HASH}, got ${doc.rulesHash}`);
  }
  if (doc.disputeId !== expected.disputeId) {
    throw new Error(`disputeId mismatch: expected ${expected.disputeId}, got ${doc.disputeId}`);
  }
  if (doc.parties?.contractHash !== expected.contractHash) {
    throw new Error(`contractHash mismatch: settlement is not bound to this AP2 Payment Mandate + Stripe checkout`);
  }
  if (doc.parties.claimant?.agentId !== expected.claimantDid || doc.parties.respondent?.agentId !== expected.merchantDid) {
    throw new Error("party DID mismatch between settlement instruction and expected buyer/merchant agents");
  }

  const recomputedTermsHash = computeTermsHash(doc.terms);
  if (doc.termsHash !== recomputedTermsHash) {
    throw new Error("termsHash mismatch: settled terms were tampered with");
  }
  const recomputedOutcomeHash = computeOutcomeHash(
    {
      kind: "SETTLED",
      method: doc.method,
      terms: doc.terms,
      at: doc.settledAt,
      roundsCompleted: doc.roundsCompleted,
    },
    doc.executionStatus,
  );
  if (doc.outcomeHash !== recomputedOutcomeHash) {
    throw new Error("outcomeHash mismatch: settlement outcome metadata failed integrity verification");
  }

  const refundCents = doc.terms.refundCents;
  const storeCreditCents = doc.terms.storeCreditCents ?? 0;
  if (typeof refundCents !== "number" || !Number.isSafeInteger(refundCents) || refundCents < 0) {
    throw new Error(`invalid refundCents term: ${String(refundCents)}`);
  }
  if (refundCents > expected.maxChargeAmountMinor) {
    throw new Error(`settled refundCents (${refundCents}) exceeds AP2 payment_amount.amount (${expected.maxChargeAmountMinor})`);
  }
  if (typeof storeCreditCents !== "number" || !Number.isSafeInteger(storeCreditCents) || storeCreditCents < 0) {
    throw new Error(`invalid storeCreditCents term: ${String(storeCreditCents)}`);
  }

  return {
    disputeId: doc.disputeId,
    refundCents,
    storeCreditCents,
    method: doc.method,
    executionStatus: doc.executionStatus,
    termsHash: doc.termsHash,
    outcomeHash: doc.outcomeHash,
    auditRoot: doc.auditRoot,
  };
}

/**
 * Verifies the Agent-Mediate settlement instruction fail-closed, then executes a single idempotent
 * Stripe `POST /v1/refunds` request (zero external Stripe SDK dependency).
 */
export async function executeVerifiedStripeRefund(opts: {
  signedOutcome: SignedDocument<SettlementInstructionDocument>;
  expected: ExpectedStripeSettlementContext;
  paymentIntentId: string;
  ap2TransactionId: string;
  stripeSecretKey: string;
  stripeApiBase?: string;
  fetchImpl?: typeof globalThis.fetch;
}): Promise<ExecutedStripeRefund> {
  const verified = verifySettlementForStripeRefund(opts.signedOutcome, opts.expected);
  const idempotencyKey = buildStripeRefundIdempotencyKey(verified.disputeId);

  if (verified.refundCents === 0) {
    return {
      refundId: null,
      amountCents: 0,
      storeCreditCents: verified.storeCreditCents,
      status: "credit_only",
      idempotencyKey,
      executionProofRef: `merchant:credit:${verified.disputeId}:${verified.storeCreditCents}`,
      verifiedSettlement: verified,
    };
  }

  const base = (opts.stripeApiBase ?? "https://api.stripe.com").replace(/\/+$/, "");
  const fetchFn = opts.fetchImpl ?? globalThis.fetch;
  const form = new URLSearchParams({
    payment_intent: opts.paymentIntentId,
    amount: String(verified.refundCents),
    reason: "requested_by_customer",
    "metadata[agent_mediate_dispute_id]": verified.disputeId,
    "metadata[agent_mediate_outcome_hash]": verified.outcomeHash,
    "metadata[ap2_transaction_id]": opts.ap2TransactionId,
    "metadata[store_credit_cents]": String(verified.storeCreditCents),
  });

  const res = await fetchFn(`${base}/v1/refunds`, {
    method: "POST",
    headers: {
      authorization: `Bearer ${opts.stripeSecretKey}`,
      "content-type": "application/x-www-form-urlencoded",
      "idempotency-key": idempotencyKey,
    },
    body: form.toString(),
  });
  const payload = (await res.json()) as { id?: string; status?: string; amount?: number; error?: { message?: string } };
  if (!res.ok || !payload.id) {
    throw new Error(`Stripe /v1/refunds failed (HTTP ${res.status}): ${payload.error?.message ?? JSON.stringify(payload)}`);
  }

  return {
    refundId: payload.id,
    amountCents: verified.refundCents,
    storeCreditCents: verified.storeCreditCents,
    status: payload.status ?? "succeeded",
    idempotencyKey,
    executionProofRef: `stripe:refund:${payload.id}`,
    verifiedSettlement: verified,
  };
}

/**
 * Fallback helper when pre-chargeback mediation ends `UNRESOLVED` (e.g. `NO_OVERLAP_AT_CAP` or
 * `RESPONDENT_NO_SHOW`): packages the AP2 Payment Mandate, Stripe identifiers, platform-signed
 * `unresolved-certificate/v1`, and audit chain head for card-network / PSP dispute submission.
 */
export function buildChargebackEvidenceBundle(opts: {
  ap2PaymentMandate: Ap2PaymentMandate;
  stripeAcp: StripeAcpCheckoutRef;
  signedOutcome: SignedDocument<Record<string, unknown>>;
  auditHead: string;
}) {
  return {
    bundleType: "ap2-stripe-chargeback-evidence/v1",
    generatedAt: new Date().toISOString(),
    contractHash: deriveAp2ContractHash(opts.ap2PaymentMandate, opts.stripeAcp),
    ap2TransactionId: opts.ap2PaymentMandate.transaction_id,
    stripePaymentIntentId: opts.stripeAcp.paymentIntentId,
    stripeCheckoutSessionId: opts.stripeAcp.checkoutSessionId,
    mediatorOutcome: opts.signedOutcome,
    auditHead: opts.auditHead,
  };
}

// ---------------------------------------------------------------------------
// 3. In-Process Offline Reference Mediator + Mock Stripe Refund Endpoint
// ---------------------------------------------------------------------------

function createMockStripeFetch() {
  const seenIdempotency = new Map<string, { id: string; status: string; amount: number; payment_intent: string }>();
  const requests: Array<{ idempotencyKey: string; paymentIntent: string; amount: number; metadata: Record<string, string> }> = [];

  const mockFetch = (async (input: string | URL | Request, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    if (!url.endsWith("/v1/refunds") || init?.method !== "POST") {
      return new Response(JSON.stringify({ error: { message: "unsupported mock route" } }), { status: 404 });
    }
    const headers = new Headers(init.headers);
    const auth = headers.get("authorization") ?? "";
    const idem = headers.get("idempotency-key") ?? "";
    if (!auth.startsWith("Bearer ") || !idem) {
      return new Response(JSON.stringify({ error: { message: "missing Bearer auth or Idempotency-Key" } }), { status: 401 });
    }
    const prior = seenIdempotency.get(idem);
    if (prior) {
      return new Response(JSON.stringify(prior), { status: 200, headers: { "content-type": "application/json" } });
    }
    const params = new URLSearchParams(String(init.body ?? ""));
    const paymentIntent = params.get("payment_intent") ?? "";
    const amount = Number(params.get("amount") ?? 0);
    const metadata: Record<string, string> = {};
    for (const [k, v] of params.entries()) {
      const m = /^metadata\[(.+)\]$/.exec(k);
      if (m) metadata[m[1]!] = v;
    }
    const refund = {
      id: `re_mock_${sha256Hex(`${idem}:${paymentIntent}:${amount}`).slice(0, 16)}`,
      object: "refund",
      status: "succeeded",
      amount,
      payment_intent: paymentIntent,
      metadata,
    };
    seenIdempotency.set(idem, refund);
    requests.push({ idempotencyKey: idem, paymentIntent, amount, metadata });
    return new Response(JSON.stringify(refund), { status: 200, headers: { "content-type": "application/json" } });
  }) as typeof globalThis.fetch;

  return { mockFetch, requests };
}

function createOfflineReferenceMediator() {
  const baseUrl = "https://offline-ap2-demo.agent-mediate.local";
  const platformKey: AgentKey = generateAgentKey();
  const proposalSecret = randomBytes(32).toString("hex");
  const disputes = new Map<
    string,
    { state: DisputeState; events: DomainEvent[]; proposedIssues: Issue[]; signedOutcome?: SignedDocument<Record<string, unknown>> }
  >();

  const json = (status: number, body: unknown) =>
    new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json; charset=utf-8" } });

  const fetchImpl = (async (input: string | URL | Request, init?: RequestInit) => {
    const rawUrl = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = (init?.method ?? "GET").toUpperCase();
    const url = new URL(rawUrl, baseUrl);
    const now = Date.now();
    const headers = new Headers(init?.headers);
    const rawBody = typeof init?.body === "string" ? init.body : "";

    if (method === "GET" && url.pathname === "/v1/platform") {
      return json(200, {
        did: platformKey.did,
        didWeb: didWebFromUrl(baseUrl),
        keyHistory: `${baseUrl}/.well-known/key-history.json`,
        rulesVersion: RULES_VERSION,
        rulesHash: RULES_HASH,
        fees: { waived: true },
      });
    }
    if (method === "GET" && url.pathname === "/.well-known/key-history.json") {
      return json(
        200,
        buildSignedKeyHistory({ baseUrl, activeKey: platformKey, activeValidFrom: now - 60_000, updatedAt: now }),
      );
    }

    const v = verifyRequest({
      method,
      targetUri: baseUrl + url.pathname + url.search,
      header: (name) => headers.get(name),
      body: rawBody,
      now,
    });
    if (!v.ok) return json(401, { code: "UNAUTHENTICATED", detail: v.reason });

    const callerDid = v.keyid;
    const body = rawBody ? (JSON.parse(rawBody) as Record<string, unknown>) : {};
    const wantCompact = url.searchParams.get("view") === "compact";
    const viewPayload = (rec: { state: DisputeState }, party: Party) => ({
      disputeId: rec.state.id,
      view: wantCompact ? compactViewFor(rec.state, party) : viewFor(rec.state, party),
    });

    if (method === "POST" && url.pathname === "/v1/disputes") {
      const disputeId = `dsp_${randomBytes(16).toString("hex")}`;
      const respondentId = String(body.respondentId);
      const cHash = String(body.contractHash);
      const created = createDispute(
        {
          id: disputeId,
          auditSalt: randomBytes(32).toString("hex"),
          claimantId: callerDid,
          claimantMandate: body.mandate as Mandate,
          respondentId,
          contractHash: cHash,
          claim: body.claim as { summary: string; requestedRemedy: string },
          feePaid: true,
          discloseGapOnFailure: Boolean(body.discloseGapOnFailure),
          proposalKey: deriveProposalKey(proposalSecret, callerDid, respondentId, cHash),
          noticeDelivery: { method: "none", delivered: false, verifiedEndpoint: false, attempted: [], at: now },
        },
        now,
      );
      if (!created.ok) return json(400, { code: created.error.code, detail: created.error.message });
      const rec = { state: created.state, events: [...created.events], proposedIssues: body.proposedIssues as Issue[] };
      disputes.set(disputeId, rec);
      return json(201, viewPayload(rec, "claimant"));
    }

    const m = /^\/v1\/disputes\/([^/]+)(?:\/(.*))?$/.exec(url.pathname);
    if (!m) return json(404, { code: "NOT_FOUND", detail: "no such route" });
    const rec = disputes.get(decodeURIComponent(m[1]!));
    if (!rec) return json(404, { code: "NOT_FOUND", detail: "dispute not found" });
    const sub = m[2] ?? "";
    const party: Party | null =
      callerDid === rec.state.parties.claimant.id ? "claimant" : callerDid === rec.state.respondentId ? "respondent" : null;
    if (!party) return json(403, { code: "NOT_AUTHORIZED", detail: "not a party" });

    const runCmd = (cmd: Command): Response | null => {
      const applied = apply(rec.state, cmd, now);
      if (!applied.ok) return json(409, { code: applied.error.code, detail: applied.error.message });
      rec.state = applied.state;
      rec.events.push(...applied.events);
      if (rec.state.status === "ISSUE_CONFIRMATION" && rec.state.issueNegotiation.proposed === null) {
        const prop = apply(rec.state, { type: "PROPOSE_ISSUES", actor: "system", issues: rec.proposedIssues }, now);
        if (prop.ok) {
          rec.state = prop.state;
          rec.events.push(...prop.events);
        }
      }
      if (rec.state.outcome?.kind === "SETTLED") {
        rec.signedOutcome = signDocument({ ...buildSettlementInstruction(rec.state), environment: "development" }, platformKey, {
          created: now,
        });
      } else if (rec.state.outcome?.kind === "UNRESOLVED") {
        rec.signedOutcome = signDocument({ ...buildUnresolvedCertificate(rec.state), environment: "development" }, platformKey, {
          created: now,
        });
      }
      return null;
    };

    if (method === "GET" && sub === "") return json(200, viewPayload(rec, party));
    if (method === "GET" && sub === "outcome") {
      return rec.signedOutcome ? json(200, rec.signedOutcome) : json(409, { code: "OUTCOME_NOT_AVAILABLE" });
    }
    if (method === "GET" && sub === "audit") {
      return json(200, {
        disputeId: rec.state.id,
        head: rec.state.audit.head,
        entries: rec.events.map((e) => publicAuditEntry(e, party)),
        checkpoint: null,
      });
    }
    if (method === "POST" && sub === "join") {
      const err = runCmd({
        type: "JOIN",
        actor: "respondent",
        respondentId: callerDid,
        mandate: body.mandate as Mandate,
        feePaid: true,
        discloseGapOnFailure: Boolean(body.discloseGapOnFailure),
      });
      return err ?? json(200, viewPayload(rec, party));
    }
    if (method === "POST" && sub === "evidence") {
      const err = runCmd({
        type: "SUBMIT_EVIDENCE",
        actor: party,
        items: body.items as Array<{ id: string; kind: string; sha256: string; description: string }>,
      });
      return err ?? json(200, viewPayload(rec, party));
    }
    if (method === "POST" && sub === "evidence/close") {
      return runCmd({ type: "CLOSE_EVIDENCE", actor: party }) ?? json(200, viewPayload(rec, party));
    }
    if (method === "POST" && sub === "issues/confirm") {
      return (
        runCmd({
          type: "CONFIRM_ISSUES",
          actor: party,
          issuesHash: String(body.issuesHash),
          ...(body.mandate ? { mandate: body.mandate as Mandate } : {}),
        }) ?? json(200, viewPayload(rec, party))
      );
    }
    const roundMatch = /^rounds\/(\d+)\/offer$/.exec(sub);
    if (method === "POST" && roundMatch) {
      return (
        runCmd({
          type: "SUBMIT_ROUND",
          actor: party,
          round: Number(roundMatch[1]),
          offer: body.offer as Record<string, number>,
          ...(body.private
            ? {
                private: body.private as {
                  weights: Record<string, number>;
                  walkaway: Record<string, number>;
                  limits?: Record<string, { min: number; max: number }>;
                },
              }
            : {}),
          ...(body.proposalResponse ? { proposalResponse: body.proposalResponse as "accept" | "reject" } : {}),
        }) ?? json(200, viewPayload(rec, party))
      );
    }
    if (method === "POST" && sub === "execution/proof") {
      return (
        runCmd({ type: "SUBMIT_EXECUTION_PROOF", actor: party, reference: String(body.reference) }) ??
        json(200, viewPayload(rec, party))
      );
    }
    if (method === "POST" && sub === "execution/confirm") {
      return runCmd({ type: "CONFIRM_EXECUTION", actor: party }) ?? json(200, viewPayload(rec, party));
    }
    return json(404, { code: "NOT_FOUND", detail: `unhandled offline route: ${method} ${url.pathname}` });
  }) as typeof globalThis.fetch;

  return { baseUrl, platformDid: platformKey.did, fetchImpl };
}

// ---------------------------------------------------------------------------
// 4. Runnable End-to-End Flow
// ---------------------------------------------------------------------------

const fmtUsd = (cents: number) => `$${(cents / 100).toFixed(2)}`;

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const offline = args.includes("--offline");
  const saveIdx = args.indexOf("--save-outcome");
  const savePath = saveIdx >= 0 ? args[saveIdx + 1] : undefined;

  const t0 = performance.now();
  const elapsed = () => `${((performance.now() - t0) / 1000).toFixed(2)}s`;

  const offlineMed = offline ? createOfflineReferenceMediator() : null;
  const baseUrl = offlineMed
    ? offlineMed.baseUrl
    : normalizeBaseUrl(process.env.AGENT_MEDIATE_URL ?? PRODUCTION_API_URL);
  const platformDid = offlineMed
    ? offlineMed.platformDid
    : process.env.AGENT_MEDIATE_PLATFORM_DID ?? DEFAULT_PRODUCTION_PLATFORM_DIDS[baseUrl];
  if (!platformDid) {
    throw new Error(`pin AGENT_MEDIATE_PLATFORM_DID for custom deployment ${baseUrl}`);
  }

  console.log(`==> Agent-Mediate AP2 + Stripe ACP Pre-Chargeback Demo (${offline ? "offline" : baseUrl})`);
  console.log(`    Platform DID:  ${platformDid}`);
  console.log(`    Mechanism:     RULES_HASH=${RULES_HASH.slice(0, 16)}... (v${RULES_VERSION})`);

  // 1. Upstream AP2 Closed Payment Mandate + Stripe ACP Checkout Reference ($500.00 order)
  const ap2Mandate: Ap2PaymentMandate = {
    vct: "mandate.payment.1",
    transaction_id: `ap2_tx_${randomBytes(12).toString("base64url")}`,
    payee: { id: "acct_acme_cloud_data", name: "Acme Cloud Data APIs", domain: "acme-data.example" },
    payment_amount: { currency: "USD", amount: 50_000 }, // $500.00 in minor units
    payment_instrument: { type: "stripe_spt", token_ref: `spt_demo_${randomBytes(8).toString("hex")}` },
    exp: Math.floor(Date.now() / 1000) + 86_400,
  };
  const stripeAcp: StripeAcpCheckoutRef = {
    checkoutSessionId: `cs_demo_${randomBytes(8).toString("hex")}`,
    paymentIntentId: process.env.STRIPE_PAYMENT_INTENT ?? `pi_demo_${randomBytes(8).toString("hex")}`,
    orderId: `ord_acp_${Date.now()}`,
    merchantDomain: ap2Mandate.payee.domain,
  };
  const cHash = deriveAp2ContractHash(ap2Mandate, stripeAcp);
  const issues = buildPreChargebackIssues(ap2Mandate, 500);

  // 2. Ephemeral Ed25519 agent & principal identities (zero crypto wallets required)
  const buyerKey = generateAgentKey();
  const buyerPrincipal = generateAgentKey();
  const merchantKey = generateAgentKey();
  const merchantPrincipal = generateAgentKey();

  const buyer = new AgentMediateClient({
    baseUrl,
    agentKey: buyerKey,
    platformDid,
    ...(offlineMed ? { fetch: offlineMed.fetchImpl } : {}),
  });
  const merchant = new AgentMediateClient({
    baseUrl,
    agentKey: merchantKey,
    platformDid,
    ...(offlineMed ? { fetch: offlineMed.fetchImpl } : {}),
  });

  // 3. Co-signed agent-mediate/clause/v1 binding the AP2 mandate + Stripe checkout
  const now = Date.now();
  let clause = buildClause({
    contractHash: cHash,
    platformDid,
    rulesHash: RULES_HASH,
    parties: [
      { agentId: buyerKey.did, principalId: buyerPrincipal.did },
      { agentId: merchantKey.did, principalId: merchantPrincipal.did },
    ],
    terms: { feeMode: "FILER_PAYS", determinationConsent: false },
    issuedAt: now,
  });
  clause = signClause(signClause(clause, buyerPrincipal), merchantPrincipal);
  const clauseCheck = verifyClause(clause, {
    expectedContractHash: cHash,
    expectedPlatformDid: platformDid,
    expectedRulesHash: RULES_HASH,
  });
  if (!clauseCheck.ok) throw new Error(`clause verification failed: ${clauseCheck.reason}`);
  console.log(`[${elapsed()}] 1. Bound AP2 mandate (${ap2Mandate.transaction_id}) + Stripe ${stripeAcp.paymentIntentId}`);
  console.log(`           contractHash=${cHash.slice(0, 16)}... · co-signed clause verified`);

  // 4. Principal-signed mandates & dispute filing ($0.00 Mode A)
  const buyerMandate = signMandate(
    {
      id: `mnd_buyer_${randomBytes(6).toString("hex")}`,
      principalId: buyerPrincipal.did,
      agentId: buyerKey.did,
      bounds: { refundCents: { min: 10_000, max: 50_000 }, storeCreditCents: { min: 0, max: 20_000 } },
      scope: { counterpartyId: merchantKey.did, contractHash: cHash },
      determinationConsent: false,
      issuedAt: now - 1_000,
      expiresAt: now + 7 * 86_400_000,
    },
    buyerPrincipal,
  );
  const merchantMandate = signMandate(
    {
      id: `mnd_merchant_${randomBytes(6).toString("hex")}`,
      principalId: merchantPrincipal.did,
      agentId: merchantKey.did,
      bounds: { refundCents: { min: 0, max: 30_000 }, storeCreditCents: { min: 0, max: 20_000 } },
      scope: { counterpartyId: buyerKey.did, contractHash: cHash },
      determinationConsent: false,
      issuedAt: now - 1_000,
      expiresAt: now + 7 * 86_400_000,
    },
    merchantPrincipal,
  );

  const filed = await buyer.fileDispute({
    respondentId: merchantKey.did,
    contractHash: cHash,
    claim: {
      summary: "AP2/ACP batch enrichment order missed 99% completeness SLA (18% records missing, 9h delay).",
      requestedRemedy: "Partial Stripe refund plus account credit before escalating to card chargeback.",
    },
    mandate: buyerMandate,
    proposedIssues: issues,
    clause,
  });
  const disputeId = filed.disputeId;
  await merchant.join(disputeId, { mandate: merchantMandate });
  console.log(`[${elapsed()}] 2. Dispute ${disputeId} filed & joined ($0.00 Mode A fees)`);

  // 5. Evidence hashes (AP2 mandate digest + delivery telemetry digest) & issue confirmation
  await buyer.submitEvidence(disputeId, [
    {
      id: "ev_ap2_mandate",
      kind: "ap2_payment_mandate",
      sha256: sha256Hex(JSON.stringify(ap2Mandate)),
      description: `Closed AP2 Payment Mandate ${ap2Mandate.transaction_id} (${fmtUsd(ap2Mandate.payment_amount.amount)})`,
    },
  ]);
  await merchant.submitEvidence(disputeId, [
    {
      id: "ev_delivery_log",
      kind: "sla_telemetry",
      sha256: sha256Hex(`${stripeAcp.orderId}:completeness=0.82:delayHours=9`),
      description: "Batch pipeline telemetry confirming 82% record completeness and 9h processing delay",
    },
  ]);
  await buyer.closeEvidence(disputeId);
  const closed = await merchant.closeEvidence(disputeId);
  const proposedHash = closed.view.issueNegotiation.proposedHash;
  if (!proposedHash) throw new Error("expected proposedHash after evidence close");
  await buyer.confirmIssues(disputeId, proposedHash);
  await merchant.confirmIssues(disputeId, proposedHash);
  console.log(`[${elapsed()}] 3. Evidence closed & 2-issue grid locked (refundCents + storeCreditCents)`);

  // 6. Sealed integrative bargaining:
  //    - Buyer values cash & store credit (weights 0.65 / 0.35), walkaway ($150 cash, $50 credit), hard floor $100 cash.
  //    - Merchant prefers credit over cash outflow (weights 0.80 / 0.20), walkaway ($220 cash, $150 credit).
  await buyer.submitOffer(disputeId, 1, {
    offer: { refundCents: 35_000, storeCreditCents: 10_000 },
    private: {
      weights: { refundCents: 0.65, storeCreditCents: 0.35 },
      walkaway: { refundCents: 15_000, storeCreditCents: 5_000 },
      limits: { refundCents: { min: 10_000, max: 50_000 }, storeCreditCents: { min: 0, max: 20_000 } },
    },
  });
  const r1 = await merchant.submitOffer(disputeId, 1, {
    offer: { refundCents: 10_000, storeCreditCents: 5_000 },
    private: {
      weights: { refundCents: 0.8, storeCreditCents: 0.2 },
      walkaway: { refundCents: 22_000, storeCreditCents: 15_000 },
      limits: { refundCents: { min: 0, max: 30_000 }, storeCreditCents: { min: 0, max: 20_000 } },
    },
  });

  if (r1.view.status === "BARGAINING") {
    const proposal = r1.view.bargaining?.openProposal?.terms;
    console.log(
      `[${elapsed()}] 4. Round 1 confidential proposal -> cash ${fmtUsd(proposal?.refundCents ?? 0)} + credit ${fmtUsd(proposal?.storeCreditCents ?? 0)} (walkaways stay private)`,
    );
    await buyer.submitOffer(disputeId, 2, {
      offer: { refundCents: 30_000, storeCreditCents: 10_000 },
      proposalResponse: "accept",
    });
    await merchant.submitOffer(disputeId, 2, {
      offer: { refundCents: 12_000, storeCreditCents: 10_000 },
      proposalResponse: "accept",
    });
  }

  // 7. Fetch signed settlement instruction & run fail-closed verification before calling Stripe
  const rawOutcome = await merchant.outcome(disputeId);
  const signedOutcome = rawOutcome as unknown as SignedDocument<SettlementInstructionDocument>;
  const expectedCtx: ExpectedStripeSettlementContext = {
    platformDid,
    disputeId,
    contractHash: cHash,
    claimantDid: buyerKey.did,
    merchantDid: merchantKey.did,
    maxChargeAmountMinor: ap2Mandate.payment_amount.amount,
  };

  // Sanity-check fail-closed tamper defense (mutated refund amount must throw before touching Stripe)
  const tampered = structuredClone(signedOutcome);
  tampered.document.terms.refundCents = (tampered.document.terms.refundCents ?? 0) + 10_000;
  let tamperRejected = false;
  try {
    verifySettlementForStripeRefund(tampered, expectedCtx);
  } catch {
    tamperRejected = true;
  }
  if (!tamperRejected) throw new Error("expected tampered settlement instruction to be rejected");

  // 8. Execute idempotent Stripe refund (live if STRIPE_SECRET_KEY is set, otherwise in-process mock)
  const liveStripeKey = process.env.STRIPE_SECRET_KEY;
  const mockStripe = liveStripeKey ? null : createMockStripeFetch();
  const refund = await executeVerifiedStripeRefund({
    signedOutcome,
    expected: expectedCtx,
    paymentIntentId: stripeAcp.paymentIntentId,
    ap2TransactionId: ap2Mandate.transaction_id,
    stripeSecretKey: liveStripeKey ?? "sk_test_mock_local_only",
    ...(mockStripe ? { fetchImpl: mockStripe.mockFetch } : {}),
  });
  console.log(
    `[${elapsed()}] 5. Verified Ed25519 settlement & executed Stripe refund (${liveStripeKey ? "live Stripe API" : "mock Stripe API"})`,
  );
  console.log(
    `           Refund:          ${fmtUsd(refund.amountCents)} cash (${refund.refundId ?? "none"}) + ${fmtUsd(refund.storeCreditCents)} store credit`,
  );
  console.log(`           Idempotency-Key: ${refund.idempotencyKey}`);

  // 9. Submit Stripe refund ID as execution proof -> Buyer confirms -> HONORED + dual audit verification
  await merchant.submitExecutionProof(disputeId, refund.executionProofRef);
  await buyer.confirmExecution(disputeId);

  const rawFinalOutcome = await buyer.outcome(disputeId);
  const finalOutcome = rawFinalOutcome as unknown as SignedDocument<SettlementInstructionDocument>;
  const buyerAudit = await buyer.audit(disputeId, { expectedOutcome: rawFinalOutcome });
  const merchantAudit = await merchant.audit(disputeId, { expectedOutcome: rawFinalOutcome });
  if (buyerAudit.head !== merchantAudit.head || buyerAudit.head !== finalOutcome.document.auditRoot) {
    throw new Error("audit chain verification failed after HONORED");
  }
  if (savePath) {
    writeFileSync(savePath, JSON.stringify(finalOutcome, null, 2) + "\n", "utf8");
  }

  console.log(`[${elapsed()}] 6. Settlement HONORED & dual-verified (zero chargeback filed!)`);
  console.log(`           Method:          ${finalOutcome.document.method} (executionStatus=${finalOutcome.document.executionStatus})`);
  console.log(`           Execution Proof: ${refund.executionProofRef}`);
  console.log(`           Audit Chain:     ${buyerAudit.entries.length} entries, head=${buyerAudit.head.slice(0, 16)}... (verified=true)`);
  if (savePath) console.log(`           Saved Outcome:   ${savePath} -> verify at https://ai-agents-mediation.com/verify`);
}

const isCli = (() => {
  if (!process.argv[1]) return false;
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    return false;
  }
})();

if (isCli) {
  main().catch((err) => {
    console.error(err instanceof Error ? err.stack ?? err.message : String(err));
    process.exit(1);
  });
}
