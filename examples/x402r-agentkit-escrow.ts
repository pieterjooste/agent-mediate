/**
 * Reference Adapter & Runnable E2E Demo:
 *   x402r (AuthCaptureEscrow) + Coinbase AgentKit Partial-Refund Mediation
 *
 * Demonstrates how an x402r escrow operator or Coinbase AgentKit wallet resolves partial-delivery
 * or SLA disputes on locked stablecoin escrows (`AuthCaptureEscrow`) in <10 seconds — replacing
 * blunt 0% / 100% binary slashing with a confidential multi-issue split (`refundMicroUsdc` +
 * `remediationHours`) while Agent-Mediate holds ZERO custody of funds:
 *
 *   1. Validate `x402r` `PaymentInfo` invariants (`preApprovalExpiry <= authorizationExpiry <= refundExpiry`,
 *      `minFeeBps <= maxFeeBps <= 10000`, `0 < capturedAmount <= maxAmount`) and bind it via RFC 8785 (JCS)
 *      into a deterministic Agent-Mediate `contractHash`.
 *   2. Co-sign an `agent-mediate/clause/v1` pre-dispute clause and negotiate a 2-issue integrative split
 *      (`refundMicroUsdc` in 6-decimal USDC atomic units + `remediationHours` SLA patch window) via sealed
 *      offers without exposing either agent's confidential walkaway or margin weights.
 *   3. Fail-closed verify the platform-signed `Ed25519Signature2026` settlement instruction
 *      (`verifySettlementForX402rEscrow`) against pinned `platformDid`, `RULES_HASH`, `PaymentInfo`
 *      `contractHash`, `termsHash`, `outcomeHash`, `refundExpiry`, and BigInt `capturedAmount` bounds.
 *   4. Execute `refundInEscrow(paymentInfo, refundAmountAtomic)` + `release(paymentInfo, remainderAtomic)`
 *      idempotently through an `X402rEscrowExecutor` (or Coinbase `AgentKit`-compatible `ActionProvider`),
 *      then record `eip155:8453:tx:<refundTxHash>` as execution proof until `HONORED`.
 *
 * Usage:
 *   # Run completely offline (air-gapped / CI mode, <0.2s, zero network calls, simulated AuthCaptureEscrow):
 *   npm run build && node examples/x402r-agentkit-escrow.ts --offline
 *
 *   # Run live against https://api.ai-agents-mediation.com ($0.00 Mode A, simulated AuthCaptureEscrow):
 *   npm run build && node examples/x402r-agentkit-escrow.ts
 *
 *   # Save the verified Ed25519 settlement instruction JSON for https://ai-agents-mediation.com/verify:
 *   node examples/x402r-agentkit-escrow.ts --save-outcome /tmp/x402r-escrow-settlement.json
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
// 1. x402r AuthCaptureEscrow & Coinbase AgentKit Types
// ---------------------------------------------------------------------------

/** Canonical Base mainnet USDC ERC-20 address (6 decimals). */
export const BASE_MAINNET_USDC = "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913";

/** Canonical x402r `AuthCaptureEscrow` EIP-712 `PaymentInfo` struct fields. */
export interface X402rPaymentInfo {
  /** Authorized escrow operator / captureAuthorizer EVM address. */
  operator: string;
  /** Buyer / payer EVM wallet address. */
  payer: string;
  /** Merchant / provider EVM wallet address (`requirements.payTo`). */
  receiver: string;
  /** ERC-20 token contract address (`requirements.asset`, e.g. Base USDC). */
  token: string;
  /** `uint120` max authorized amount in token atomic units (decimal string, e.g. "250000000" = 250 USDC). */
  maxAmount: string;
  /** `uint48` Unix seconds expiry for client pre-approval. */
  preApprovalExpiry: number;
  /** `uint48` Unix seconds deadline to capture funds (`>= preApprovalExpiry`). */
  authorizationExpiry: number;
  /** `uint48` Unix seconds deadline to process `refundInEscrow` (`>= authorizationExpiry`). */
  refundExpiry: number;
  /** `uint16` minimum operator fee in basis points (`0..10000`). */
  minFeeBps: number;
  /** `uint16` maximum operator fee in basis points (`minFeeBps..10000`). */
  maxFeeBps: number;
  /** Protocol/operator fee recipient EVM address. */
  feeReceiver: string;
  /** `uint256` unique salt generated per payment (decimal or `0x`-hex string). */
  salt: string;
}

/** Off-chain reference to the active `AuthCaptureEscrow` instance and captured balance. */
export interface X402rEscrowRef {
  /** CAIP-2 EVM network identifier (e.g. `"eip155:8453"` for Base mainnet, `"eip155:84532"` for Base Sepolia). */
  network: string;
  /** Deployed `AuthCaptureEscrow` contract EVM address. */
  escrowAddress: string;
  /** Actual amount currently held in escrow in token atomic units (`0 < capturedAmount <= maxAmount`). */
  capturedAmount: string;
  /** On-chain capture transaction hash (`0x` + 64 hex chars). */
  captureTxHash: string;
  /** Upstream marketplace or API job identifier. */
  jobId: string;
}

export interface X402rSettlementInstructionDoc {
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

export interface ExpectedX402rSettlementContext {
  platformDid: string;
  disputeId: string;
  contractHash: string;
  claimantDid: string;
  merchantDid: string;
  paymentInfo: X402rPaymentInfo;
  escrow: X402rEscrowRef;
  /** Current Unix timestamp in seconds (used to enforce `nowSec <= paymentInfo.refundExpiry`). */
  nowSec?: number;
}

export interface VerifiedX402rSettlement {
  disputeId: string;
  /** Partial or full refund to `paymentInfo.payer` in integer atomic units (BigInt). */
  refundAmountAtomic: bigint;
  /** Remaining escrow balance released to `paymentInfo.receiver` in integer atomic units (BigInt). */
  merchantReleaseAtomic: bigint;
  /** Settled SLA patch / redelivery window in hours (0 if single-issue). */
  remediationHours: number;
  method: SettlementMethod;
  executionStatus: Status;
  termsHash: string;
  outcomeHash: string;
  auditRoot: string;
  /** Deterministic 32-byte settlement reference hash for idempotent operator tracking. */
  settlementMemo: string;
}

/** Minimal escrow operator execution interface (plug in `@x402r/client`, `viem`, or Coinbase `AgentKit`). */
export interface X402rEscrowExecutor {
  refundInEscrow(args: {
    network: string;
    escrowAddress: string;
    paymentInfo: X402rPaymentInfo;
    amountAtomic: bigint;
    settlementMemo: string;
  }): Promise<{ txHash: string }>;
  releaseEscrow(args: {
    network: string;
    escrowAddress: string;
    paymentInfo: X402rPaymentInfo;
    amountAtomic: bigint;
    settlementMemo: string;
  }): Promise<{ txHash: string }>;
}

export interface ExecutedX402rSettlement {
  refundTxHash: string | null;
  releaseTxHash: string | null;
  refundAmountAtomic: bigint;
  merchantReleaseAtomic: bigint;
  remediationHours: number;
  settlementMemo: string;
  executionProofRef: string;
  verifiedSettlement: VerifiedX402rSettlement;
}

/** Structural subset of `@coinbase/agentkit`'s `Network` and `WalletProvider` (zero hard dependency). */
export interface AgentKitNetworkLike {
  protocolFamily?: string;
  protocol?: string;
  chainId?: string | number;
  networkId?: string;
}

export interface AgentKitWalletProviderLike {
  getAddress(): string;
  getNetwork(): AgentKitNetworkLike;
}

export interface AgentKitActionLike<TArgs = Record<string, unknown>> {
  name: string;
  description: string;
  inputSchema: Record<string, unknown>;
  invoke(args: TArgs): Promise<string>;
}

export interface AgentKitActionProviderLike {
  name: string;
  supportsNetwork(network: AgentKitNetworkLike): boolean;
  getActions(walletProvider: AgentKitWalletProviderLike): AgentKitActionLike[];
}

// ---------------------------------------------------------------------------
// 2. Validation, RFC 8785 Binding, Fail-Closed Verifier & Escrow Executor
// ---------------------------------------------------------------------------

const EVM_ADDRESS_RE = /^0x[0-9a-fA-F]{40}$/;
const TX_HASH_RE = /^0x[0-9a-fA-F]{64}$/;
const CAIP2_EVM_RE = /^eip155:[1-9][0-9]*$/;
const UINT120_MAX = (1n << 120n) - 1n;

function parseUnsignedBigInt(raw: string, label: string): bigint {
  const s = raw.trim();
  if (!/^(?:0|[1-9][0-9]*)$/.test(s)) {
    throw new Error(`${label} must be a non-negative base-10 integer string, got "${raw}"`);
  }
  return BigInt(s);
}

function parseSaltNormalized(raw: string): string {
  const s = raw.trim();
  if (/^0x[0-9a-fA-F]{1,64}$/.test(s)) {
    return BigInt(s).toString(10);
  }
  if (/^(?:0|[1-9][0-9]{0,77})$/.test(s)) {
    const val = BigInt(s);
    if (val >= 1n << 256n) throw new Error("PaymentInfo.salt exceeds uint256");
    return val.toString(10);
  }
  throw new Error(`PaymentInfo.salt must be a uint256 decimal or 0x-hex string, got "${raw}"`);
}

/**
 * Validates `x402r` `AuthCaptureEscrow` `PaymentInfo` and `X402rEscrowRef` invariants
 * (addresses, expiry ordering, fee bps bounds, and `0 < capturedAmount <= maxAmount <= uint120`).
 */
export function validateX402rPaymentInfo(
  paymentInfo: X402rPaymentInfo,
  escrow: X402rEscrowRef,
): { maxAmountAtomic: bigint; capturedAmountAtomic: bigint; normalizedSalt: string } {
  for (const [name, addr] of [
    ["operator", paymentInfo.operator],
    ["payer", paymentInfo.payer],
    ["receiver", paymentInfo.receiver],
    ["token", paymentInfo.token],
    ["feeReceiver", paymentInfo.feeReceiver],
    ["escrowAddress", escrow.escrowAddress],
  ] as const) {
    if (!EVM_ADDRESS_RE.test(addr)) {
      throw new Error(`invalid EVM address for ${name}: ${addr}`);
    }
  }
  if (!CAIP2_EVM_RE.test(escrow.network)) {
    throw new Error(`escrow.network must be a CAIP-2 eip155:<chainId>, got "${escrow.network}"`);
  }
  if (!TX_HASH_RE.test(escrow.captureTxHash)) {
    throw new Error(`escrow.captureTxHash must be a 32-byte 0x hex hash, got "${escrow.captureTxHash}"`);
  }
  if (
    !Number.isSafeInteger(paymentInfo.preApprovalExpiry) ||
    !Number.isSafeInteger(paymentInfo.authorizationExpiry) ||
    !Number.isSafeInteger(paymentInfo.refundExpiry) ||
    paymentInfo.preApprovalExpiry <= 0 ||
    paymentInfo.preApprovalExpiry > paymentInfo.authorizationExpiry ||
    paymentInfo.authorizationExpiry > paymentInfo.refundExpiry
  ) {
    throw new Error("x402r PaymentInfo must satisfy 0 < preApprovalExpiry <= authorizationExpiry <= refundExpiry");
  }
  if (
    !Number.isInteger(paymentInfo.minFeeBps) ||
    !Number.isInteger(paymentInfo.maxFeeBps) ||
    paymentInfo.minFeeBps < 0 ||
    paymentInfo.minFeeBps > paymentInfo.maxFeeBps ||
    paymentInfo.maxFeeBps > 10_000
  ) {
    throw new Error("x402r PaymentInfo must satisfy 0 <= minFeeBps <= maxFeeBps <= 10000");
  }
  const maxAmountAtomic = parseUnsignedBigInt(paymentInfo.maxAmount, "PaymentInfo.maxAmount");
  const capturedAmountAtomic = parseUnsignedBigInt(escrow.capturedAmount, "escrow.capturedAmount");
  if (maxAmountAtomic <= 0n || maxAmountAtomic > UINT120_MAX) {
    throw new Error("PaymentInfo.maxAmount must be in (0, 2^120 - 1]");
  }
  if (capturedAmountAtomic <= 0n || capturedAmountAtomic > maxAmountAtomic) {
    throw new Error(`escrow.capturedAmount (${capturedAmountAtomic}) must be in (0, maxAmount ${maxAmountAtomic}]`);
  }
  const normalizedSalt = parseSaltNormalized(paymentInfo.salt);
  return { maxAmountAtomic, capturedAmountAtomic, normalizedSalt };
}

/**
 * Deterministically binds an `x402r` `AuthCaptureEscrow` `PaymentInfo` + escrow capture reference
 * into a 64-hex Agent-Mediate `contractHash` via RFC 8785 canonical JSON (JCS).
 */
export function deriveX402rContractHash(paymentInfo: X402rPaymentInfo, escrow: X402rEscrowRef): string {
  const { maxAmountAtomic, capturedAmountAtomic, normalizedSalt } = validateX402rPaymentInfo(paymentInfo, escrow);
  return contractHash({
    protocol: "x402r-auth-capture-escrow/v1",
    network: escrow.network,
    escrowAddress: escrow.escrowAddress.toLowerCase(),
    captureTxHash: escrow.captureTxHash.toLowerCase(),
    jobId: escrow.jobId,
    capturedAmount: capturedAmountAtomic.toString(10),
    paymentInfo: {
      operator: paymentInfo.operator.toLowerCase(),
      payer: paymentInfo.payer.toLowerCase(),
      receiver: paymentInfo.receiver.toLowerCase(),
      token: paymentInfo.token.toLowerCase(),
      maxAmount: maxAmountAtomic.toString(10),
      preApprovalExpiry: paymentInfo.preApprovalExpiry,
      authorizationExpiry: paymentInfo.authorizationExpiry,
      refundExpiry: paymentInfo.refundExpiry,
      minFeeBps: paymentInfo.minFeeBps,
      maxFeeBps: paymentInfo.maxFeeBps,
      feeReceiver: paymentInfo.feeReceiver.toLowerCase(),
      salt: normalizedSalt,
    },
  });
}

/**
 * Builds a 2-issue integrative mediation grid for a captured USDC escrow:
 *   - `refundMicroUsdc`: exact 6-decimal atomic USDC refunded via `AuthCaptureEscrow.refundInEscrow`
 *   - `remediationHours`: SLA fix/re-run deadline (lower = faster fix; enables integrative trade-offs)
 */
export function buildX402rEscrowIssues(
  paymentInfo: X402rPaymentInfo,
  escrow: X402rEscrowRef,
  stepMicroUsdc = 5_000_000, // 5.00 USDC step
): Issue[] {
  const { capturedAmountAtomic } = validateX402rPaymentInfo(paymentInfo, escrow);
  if (capturedAmountAtomic > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new Error("capturedAmount exceeds JS safe integer grid range; scale units before building numeric grid");
  }
  const capturedNum = Number(capturedAmountAtomic);
  if (!Number.isSafeInteger(stepMicroUsdc) || stepMicroUsdc <= 0 || capturedNum < stepMicroUsdc) {
    throw new Error(`capturedAmount (${capturedNum}) must be >= stepMicroUsdc (${stepMicroUsdc})`);
  }
  const maxRefund = Math.floor(capturedNum / stepMicroUsdc) * stepMicroUsdc;
  return [
    {
      id: "refundMicroUsdc",
      label: "x402r Escrow Partial Refund (USDC 6-dec atomic units)",
      unit: "micro-USDC",
      min: 0,
      max: maxRefund,
      step: stepMicroUsdc,
      claimantPrefers: "higher",
      obligor: "respondent",
    },
    {
      id: "remediationHours",
      label: "SLA Patch & Redelivery Window",
      unit: "hours",
      min: 2,
      max: 48,
      step: 2,
      claimantPrefers: "lower",
      obligor: "respondent",
    },
  ];
}

/**
 * Fail-closed cryptographic verification gate that MUST execute before an `x402r` operator
 * or Coinbase `AgentKit` wallet calls `AuthCaptureEscrow.refundInEscrow` / `release`.
 */
export function verifySettlementForX402rEscrow(
  signedOutcome: SignedDocument<X402rSettlementInstructionDoc>,
  expected: ExpectedX402rSettlementContext,
): VerifiedX402rSettlement {
  const { capturedAmountAtomic } = validateX402rPaymentInfo(expected.paymentInfo, expected.escrow);
  const nowSec = expected.nowSec ?? Math.floor(Date.now() / 1000);
  if (nowSec > expected.paymentInfo.refundExpiry) {
    throw new Error(
      `x402r refundExpiry (${expected.paymentInfo.refundExpiry}) has passed (now=${nowSec}); payer must call AuthCaptureEscrow.reclaim() directly`,
    );
  }
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
    throw new Error("contractHash mismatch: settlement instruction is not bound to this x402r PaymentInfo");
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

  const rawRefund = doc.terms.refundMicroUsdc;
  const remediationHours = doc.terms.remediationHours ?? 0;
  if (typeof rawRefund !== "number" || !Number.isSafeInteger(rawRefund) || rawRefund < 0) {
    throw new Error(`invalid refundMicroUsdc term: ${String(rawRefund)}`);
  }
  const refundAmountAtomic = BigInt(rawRefund);
  if (refundAmountAtomic > capturedAmountAtomic) {
    throw new Error(
      `settled refundMicroUsdc (${refundAmountAtomic}) exceeds captured escrow balance (${capturedAmountAtomic})`,
    );
  }
  if (typeof remediationHours !== "number" || !Number.isSafeInteger(remediationHours) || remediationHours < 0) {
    throw new Error(`invalid remediationHours term: ${String(remediationHours)}`);
  }

  const merchantReleaseAtomic = capturedAmountAtomic - refundAmountAtomic;
  const settlementMemo = `0x${sha256Hex(`x402r-settlement:${doc.disputeId}:${doc.outcomeHash}`)}`;

  return {
    disputeId: doc.disputeId,
    refundAmountAtomic,
    merchantReleaseAtomic,
    remediationHours,
    method: doc.method,
    executionStatus: doc.executionStatus,
    termsHash: doc.termsHash,
    outcomeHash: doc.outcomeHash,
    auditRoot: doc.auditRoot,
    settlementMemo,
  };
}

/**
 * Verifies the Agent-Mediate settlement instruction fail-closed, then instructs the `x402r` escrow
 * operator to execute `refundInEscrow(paymentInfo, refundAmountAtomic)` and `releaseEscrow(paymentInfo, remainder)`
 * so the sum of on-chain distributions equals `escrow.capturedAmount` exactly.
 */
export async function executeVerifiedX402rSettlement(opts: {
  signedOutcome: SignedDocument<X402rSettlementInstructionDoc>;
  expected: ExpectedX402rSettlementContext;
  executor: X402rEscrowExecutor;
}): Promise<ExecutedX402rSettlement> {
  const verified = verifySettlementForX402rEscrow(opts.signedOutcome, opts.expected);
  const { paymentInfo, escrow } = opts.expected;

  let refundTxHash: string | null = null;
  let releaseTxHash: string | null = null;

  if (verified.refundAmountAtomic > 0n) {
    const r = await opts.executor.refundInEscrow({
      network: escrow.network,
      escrowAddress: escrow.escrowAddress,
      paymentInfo,
      amountAtomic: verified.refundAmountAtomic,
      settlementMemo: verified.settlementMemo,
    });
    if (!TX_HASH_RE.test(r.txHash)) throw new Error(`invalid refundInEscrow txHash: ${r.txHash}`);
    refundTxHash = r.txHash;
  }

  if (verified.merchantReleaseAtomic > 0n) {
    const rel = await opts.executor.releaseEscrow({
      network: escrow.network,
      escrowAddress: escrow.escrowAddress,
      paymentInfo,
      amountAtomic: verified.merchantReleaseAtomic,
      settlementMemo: verified.settlementMemo,
    });
    if (!TX_HASH_RE.test(rel.txHash)) throw new Error(`invalid releaseEscrow txHash: ${rel.txHash}`);
    releaseTxHash = rel.txHash;
  }

  const primaryTx = refundTxHash ?? releaseTxHash ?? escrow.captureTxHash;
  return {
    refundTxHash,
    releaseTxHash,
    refundAmountAtomic: verified.refundAmountAtomic,
    merchantReleaseAtomic: verified.merchantReleaseAtomic,
    remediationHours: verified.remediationHours,
    settlementMemo: verified.settlementMemo,
    executionProofRef: `${escrow.network}:tx:${primaryTx}`,
    verifiedSettlement: verified,
  };
}

// ---------------------------------------------------------------------------
// 3. Coinbase AgentKit ActionProvider Adapter (Zero External Dependency)
// ---------------------------------------------------------------------------

/**
 * Drop-in Coinbase `AgentKit`-compatible `ActionProvider` exposing 3 structured agent actions:
 *   1. `mediate_x402r_escrow_dispute` — binds `PaymentInfo` into a principal-signed `Mandate` & files dispute
 *   2. `verify_x402r_settlement_instruction` — fail-closed Ed25519 + `contractHash` + `refundExpiry` verification
 *   3. `settle_x402r_escrow_from_outcome` — verifies signed outcome & triggers `refundInEscrow` + `releaseEscrow`
 *
 * Compatible with `@coinbase/agentkit` (`AgentKit.from({ walletProvider, actionProviders: [...] })`)
 * via thin `ActionProvider` subclassing or direct tool registration in LangChain / Vercel AI SDK / MCP.
 */
export function createAgentKitX402rProvider(opts: {
  client: AgentMediateClient;
  platformDid: string;
  executor?: X402rEscrowExecutor;
  principalKey?: AgentKey;
}): AgentKitActionProviderLike {
  return {
    name: "agent-mediate-x402r",
    supportsNetwork(network: AgentKitNetworkLike): boolean {
      const fam = (network.protocolFamily ?? network.protocol ?? "").toLowerCase();
      if (fam === "evm") return true;
      const cid = String(network.chainId ?? "");
      return cid === "8453" || cid === "84532" || (network.networkId ?? "").startsWith("base");
    },
    getActions(walletProvider: AgentKitWalletProviderLike): AgentKitActionLike[] {
      const walletAddr = walletProvider.getAddress().toLowerCase();
      return [
        {
          name: "mediate_x402r_escrow_dispute",
          description:
            "File a zero-custody Agent-Mediate partial-refund dispute bound to an x402r AuthCaptureEscrow PaymentInfo.",
          inputSchema: {
            type: "object",
            required: ["respondentDid", "paymentInfo", "escrow", "claimSummary", "minRefundMicroUsdc"],
            properties: {
              respondentDid: { type: "string" },
              paymentInfo: { type: "object" },
              escrow: { type: "object" },
              claimSummary: { type: "string" },
              minRefundMicroUsdc: { type: "integer", minimum: 0 },
              maxRemediationHours: { type: "integer", minimum: 2, maximum: 48 },
            },
          },
          async invoke(args) {
            const paymentInfo = args.paymentInfo as X402rPaymentInfo;
            const escrow = args.escrow as X402rEscrowRef;
            if (paymentInfo.payer.toLowerCase() !== walletAddr) {
              throw new Error(`AgentKit wallet ${walletAddr} does not match PaymentInfo.payer (${paymentInfo.payer})`);
            }
            const cHash = deriveX402rContractHash(paymentInfo, escrow);
            const issues = buildX402rEscrowIssues(paymentInfo, escrow);
            const maxRefund = issues[0]!.max;
            const minRefund = Number(args.minRefundMicroUsdc ?? 0);
            const maxHours = Number(args.maxRemediationHours ?? 24);
            if (!Number.isSafeInteger(minRefund) || minRefund < 0 || minRefund > maxRefund) {
              throw new Error(`minRefundMicroUsdc (${minRefund}) must be an integer in [0, ${maxRefund}]`);
            }
            if (!Number.isSafeInteger(maxHours) || maxHours < 2 || maxHours > 48) {
              throw new Error(`maxRemediationHours (${maxHours}) must be an integer in [2, 48]`);
            }
            const now = Date.now();
            const signer = opts.principalKey;
            const mandate = signer
              ? signMandate(
                  {
                    id: `mnd_ak_${randomBytes(6).toString("hex")}`,
                    principalId: signer.did,
                    agentId: opts.client.did,
                    bounds: {
                      refundMicroUsdc: { min: minRefund, max: maxRefund },
                      remediationHours: { min: 2, max: maxHours },
                    },
                    scope: { counterpartyId: String(args.respondentDid), contractHash: cHash },
                    determinationConsent: false,
                    issuedAt: now - 1_000,
                    expiresAt: Math.min(now + 7 * 86_400_000, paymentInfo.refundExpiry * 1000),
                  },
                  signer,
                )
              : undefined;
            const filed = await opts.client.fileDispute({
              respondentId: String(args.respondentDid),
              contractHash: cHash,
              claim: {
                summary: String(args.claimSummary),
                requestedRemedy: "Partial x402r escrow refund + bounded SLA remediation window.",
              },
              proposedIssues: issues,
              ...(mandate
                ? { mandate }
                : {
                    bounds: {
                      refundMicroUsdc: { min: minRefund, max: maxRefund },
                      remediationHours: { min: 2, max: maxHours },
                    },
                  }),
            });
            return JSON.stringify({
              disputeId: filed.disputeId,
              contractHash: cHash,
              network: escrow.network,
              escrowAddress: escrow.escrowAddress,
              walletAddress: walletProvider.getAddress(),
            });
          },
        },
        {
          name: "verify_x402r_settlement_instruction",
          description:
            "Cryptographically verify an Agent-Mediate Ed25519 settlement instruction against x402r PaymentInfo before on-chain refundInEscrow.",
          inputSchema: {
            type: "object",
            required: ["signedOutcome", "disputeId", "claimantDid", "merchantDid", "paymentInfo", "escrow"],
          },
          async invoke(args) {
            const paymentInfo = args.paymentInfo as X402rPaymentInfo;
            const escrow = args.escrow as X402rEscrowRef;
            const verified = verifySettlementForX402rEscrow(
              args.signedOutcome as SignedDocument<X402rSettlementInstructionDoc>,
              {
                platformDid: opts.platformDid,
                disputeId: String(args.disputeId),
                contractHash: deriveX402rContractHash(paymentInfo, escrow),
                claimantDid: String(args.claimantDid),
                merchantDid: String(args.merchantDid),
                paymentInfo,
                escrow,
              },
            );
            return JSON.stringify({
              ok: true,
              disputeId: verified.disputeId,
              refundAmountAtomic: verified.refundAmountAtomic.toString(10),
              merchantReleaseAtomic: verified.merchantReleaseAtomic.toString(10),
              remediationHours: verified.remediationHours,
              settlementMemo: verified.settlementMemo,
            });
          },
        },
        {
          name: "settle_x402r_escrow_from_outcome",
          description:
            "Verify an Agent-Mediate settlement instruction fail-closed and execute x402r AuthCaptureEscrow refundInEscrow + releaseEscrow.",
          inputSchema: {
            type: "object",
            required: ["signedOutcome", "disputeId", "claimantDid", "merchantDid", "paymentInfo", "escrow"],
          },
          async invoke(args) {
            if (!opts.executor) {
              throw new Error("no X402rEscrowExecutor configured on this AgentKit provider");
            }
            const paymentInfo = args.paymentInfo as X402rPaymentInfo;
            const escrow = args.escrow as X402rEscrowRef;
            const executed = await executeVerifiedX402rSettlement({
              signedOutcome: args.signedOutcome as SignedDocument<X402rSettlementInstructionDoc>,
              expected: {
                platformDid: opts.platformDid,
                disputeId: String(args.disputeId),
                contractHash: deriveX402rContractHash(paymentInfo, escrow),
                claimantDid: String(args.claimantDid),
                merchantDid: String(args.merchantDid),
                paymentInfo,
                escrow,
              },
              executor: opts.executor,
            });
            return JSON.stringify({
              refundTxHash: executed.refundTxHash,
              releaseTxHash: executed.releaseTxHash,
              refundAmountAtomic: executed.refundAmountAtomic.toString(10),
              merchantReleaseAtomic: executed.merchantReleaseAtomic.toString(10),
              remediationHours: executed.remediationHours,
              executionProofRef: executed.executionProofRef,
            });
          },
        },
      ];
    },
  };
}

// ---------------------------------------------------------------------------
// 4. In-Memory AuthCaptureEscrow Simulator + Offline Reference Mediator
// ---------------------------------------------------------------------------

/** Simulates an on-chain `AuthCaptureEscrow` contract with conservation-of-funds and idempotency checks. */
export function createSimulatedX402rEscrow(initialCapturedAtomic: bigint) {
  let remainingEscrow = initialCapturedAtomic;
  let refundedToPayer = 0n;
  let releasedToReceiver = 0n;
  const seenRefunds = new Map<string, string>();
  const seenReleases = new Map<string, string>();

  const executor: X402rEscrowExecutor = {
    async refundInEscrow({ network, escrowAddress, paymentInfo, amountAtomic, settlementMemo }) {
      const prior = seenRefunds.get(settlementMemo);
      if (prior) return { txHash: prior };
      if (amountAtomic <= 0n || amountAtomic > remainingEscrow) {
        throw new Error(`insufficient escrow balance for refundInEscrow: requested=${amountAtomic}, remaining=${remainingEscrow}`);
      }
      remainingEscrow -= amountAtomic;
      refundedToPayer += amountAtomic;
      const txHash = `0x${sha256Hex(`refundInEscrow:${network}:${escrowAddress}:${paymentInfo.salt}:${amountAtomic}:${settlementMemo}`)}`;
      seenRefunds.set(settlementMemo, txHash);
      return { txHash };
    },
    async releaseEscrow({ network, escrowAddress, paymentInfo, amountAtomic, settlementMemo }) {
      const prior = seenReleases.get(settlementMemo);
      if (prior) return { txHash: prior };
      if (amountAtomic <= 0n || amountAtomic > remainingEscrow) {
        throw new Error(`insufficient escrow balance for releaseEscrow: requested=${amountAtomic}, remaining=${remainingEscrow}`);
      }
      remainingEscrow -= amountAtomic;
      releasedToReceiver += amountAtomic;
      const txHash = `0x${sha256Hex(`releaseEscrow:${network}:${escrowAddress}:${paymentInfo.salt}:${amountAtomic}:${settlementMemo}`)}`;
      seenReleases.set(settlementMemo, txHash);
      return { txHash };
    },
  };

  return {
    executor,
    balances: () => ({ remainingEscrow, refundedToPayer, releasedToReceiver }),
  };
}

function createOfflineReferenceMediator() {
  const baseUrl = "https://offline-x402r-demo.agent-mediate.local";
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
      return (
        runCmd({
          type: "JOIN",
          actor: "respondent",
          respondentId: callerDid,
          mandate: body.mandate as Mandate,
          feePaid: true,
          discloseGapOnFailure: Boolean(body.discloseGapOnFailure),
        }) ?? json(200, viewPayload(rec, party))
      );
    }
    if (method === "POST" && sub === "evidence") {
      return (
        runCmd({
          type: "SUBMIT_EVIDENCE",
          actor: party,
          items: body.items as Array<{ id: string; kind: string; sha256: string; description: string }>,
        }) ?? json(200, viewPayload(rec, party))
      );
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
// 5. Runnable End-to-End Flow
// ---------------------------------------------------------------------------

const fmtUsdc = (microUsdc: bigint | number) => {
  const v = typeof microUsdc === "bigint" ? microUsdc : BigInt(Math.round(microUsdc));
  const sign = v < 0n ? "-" : "";
  const abs = v < 0n ? -v : v;
  const whole = abs / 1_000_000n;
  const cents = (abs % 1_000_000n) / 10_000n;
  return `${sign}${whole}.${cents.toString().padStart(2, "0")} USDC`;
};

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

  console.log(`==> Agent-Mediate x402r + Coinbase AgentKit Escrow Demo (${offline ? "offline" : baseUrl})`);
  console.log(`    Platform DID:  ${platformDid}`);
  console.log(`    Mechanism:     RULES_HASH=${RULES_HASH.slice(0, 16)}... (v${RULES_VERSION})`);

  // 1. Upstream x402r AuthCaptureEscrow PaymentInfo (250.00 USDC captured on Base)
  const nowSec = Math.floor(Date.now() / 1000);
  const payerAddress = "0x1111111111111111111111111111111111111111";
  const receiverAddress = "0x2222222222222222222222222222222222222222";
  const operatorAddress = "0x3333333333333333333333333333333333333333";
  const escrowAddress = "0x4444444444444444444444444444444444444444";

  const paymentInfo: X402rPaymentInfo = {
    operator: operatorAddress,
    payer: payerAddress,
    receiver: receiverAddress,
    token: BASE_MAINNET_USDC,
    maxAmount: "250000000", // 250.00 USDC (6 decimals)
    preApprovalExpiry: nowSec + 3_600,
    authorizationExpiry: nowSec + 86_400,
    refundExpiry: nowSec + 7 * 86_400,
    minFeeBps: 0,
    maxFeeBps: 100,
    feeReceiver: operatorAddress,
    salt: BigInt(`0x${randomBytes(16).toString("hex")}`).toString(10),
  };
  const escrowRef: X402rEscrowRef = {
    network: "eip155:8453",
    escrowAddress,
    capturedAmount: "250000000", // 250.00 USDC currently locked in AuthCaptureEscrow
    captureTxHash: `0x${randomBytes(32).toString("hex")}`,
    jobId: `x402r_job_${Date.now()}`,
  };
  const cHash = deriveX402rContractHash(paymentInfo, escrowRef);
  const issues = buildX402rEscrowIssues(paymentInfo, escrowRef, 5_000_000);

  // 2. Buyer (via Coinbase AgentKit ActionProvider) & Merchant agents
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

  const simEscrow = createSimulatedX402rEscrow(BigInt(escrowRef.capturedAmount));
  const buyerWallet: AgentKitWalletProviderLike = {
    getAddress: () => payerAddress,
    getNetwork: () => ({ protocolFamily: "evm", chainId: "8453", networkId: "base-mainnet" }),
  };
  const agentKitProvider = createAgentKitX402rProvider({
    client: buyer,
    platformDid,
    executor: simEscrow.executor,
    principalKey: buyerPrincipal,
  });
  if (!agentKitProvider.supportsNetwork(buyerWallet.getNetwork())) {
    throw new Error("AgentKit provider must support Base mainnet");
  }
  const actions = Object.fromEntries(agentKitProvider.getActions(buyerWallet).map((a) => [a.name, a]));

  // 3. Co-signed agent-mediate/clause/v1 binding PaymentInfo & AuthCaptureEscrow
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
  console.log(
    `[${elapsed()}] 1. Bound x402r AuthCaptureEscrow (${fmtUsdc(BigInt(escrowRef.capturedAmount))} on ${escrowRef.network})`,
  );
  console.log(`           contractHash=${cHash.slice(0, 16)}... · co-signed clause verified`);

  // 4. Buyer files dispute through the Coinbase AgentKit ActionProvider; Merchant joins
  const filedRaw = await actions.mediate_x402r_escrow_dispute!.invoke({
    respondentDid: merchantKey.did,
    paymentInfo,
    escrow: escrowRef,
    claimSummary: "Paid research-agent job delivered 76% of required JSON schema fields with stale pricing.",
    minRefundMicroUsdc: 40_000_000, // 40.00 USDC floor
    maxRemediationHours: 36,
  });
  const { disputeId } = JSON.parse(filedRaw) as { disputeId: string };
  const merchantMandate = signMandate(
    {
      id: `mnd_merch_${randomBytes(6).toString("hex")}`,
      principalId: merchantPrincipal.did,
      agentId: merchantKey.did,
      bounds: {
        refundMicroUsdc: { min: 0, max: 160_000_000 },
        remediationHours: { min: 2, max: 48 },
      },
      scope: { counterpartyId: buyerKey.did, contractHash: cHash },
      determinationConsent: false,
      issuedAt: now - 1_000,
      expiresAt: Math.min(now + 7 * 86_400_000, paymentInfo.refundExpiry * 1000),
    },
    merchantPrincipal,
  );
  await merchant.join(disputeId, { mandate: merchantMandate });
  console.log(`[${elapsed()}] 2. Dispute ${disputeId} filed via AgentKit action & joined ($0.00 Mode A)`);

  // 5. Evidence hashes (capture tx + output diff) & lock 2-issue grid
  await buyer.submitEvidence(disputeId, [
    {
      id: "ev_x402r_capture",
      kind: "x402r_capture_tx",
      sha256: sha256Hex(`${escrowRef.network}:${escrowRef.captureTxHash}:${escrowRef.capturedAmount}`),
      description: `x402r AuthCaptureEscrow capture ${escrowRef.captureTxHash.slice(0, 14)}... (250.00 USDC)`,
    },
  ]);
  await merchant.submitEvidence(disputeId, [
    {
      id: "ev_patch_estimate",
      kind: "remediation_plan",
      sha256: sha256Hex(`${escrowRef.jobId}:missingFields=24pct:patchEtaHours=8`),
      description: "Automated schema diff confirming missing 24% fields; hotfix pipeline ready in 8h",
    },
  ]);
  await buyer.closeEvidence(disputeId);
  const closed = await merchant.closeEvidence(disputeId);
  const proposedHash = closed.view.issueNegotiation.proposedHash;
  if (!proposedHash) throw new Error("expected proposedHash after evidence close");
  await buyer.confirmIssues(disputeId, proposedHash);
  await merchant.confirmIssues(disputeId, proposedHash);
  console.log(`[${elapsed()}] 3. Evidence closed & 2-issue grid locked (${issues.map((i) => i.id).join(" + ")})`);

  // 6. Sealed integrative bargaining:
  //    - Buyer values USDC refund (0.65) + fast remediation (0.35), walkaway (95 USDC, 24h), floor 40 USDC.
  //    - Merchant strongly prefers quick patch over USDC refund (refund 0.80, hours 0.20), walkaway (130 USDC, 6h).
  await buyer.submitOffer(disputeId, 1, {
    offer: { refundMicroUsdc: 165_000_000, remediationHours: 12 },
    private: {
      weights: { refundMicroUsdc: 0.65, remediationHours: 0.35 },
      walkaway: { refundMicroUsdc: 95_000_000, remediationHours: 24 },
      limits: { refundMicroUsdc: { min: 40_000_000, max: 250_000_000 }, remediationHours: { min: 2, max: 36 } },
    },
  });
  const r1 = await merchant.submitOffer(disputeId, 1, {
    offer: { refundMicroUsdc: 35_000_000, remediationHours: 24 },
    private: {
      weights: { refundMicroUsdc: 0.8, remediationHours: 0.2 },
      walkaway: { refundMicroUsdc: 130_000_000, remediationHours: 6 },
      limits: { refundMicroUsdc: { min: 0, max: 160_000_000 }, remediationHours: { min: 2, max: 48 } },
    },
  });

  if (r1.view.status === "BARGAINING") {
    const prop = r1.view.bargaining?.openProposal?.terms;
    console.log(
      `[${elapsed()}] 4. Round 1 confidential proposal -> refund ${fmtUsdc(prop?.refundMicroUsdc ?? 0)} + patch within ${prop?.remediationHours ?? 0}h`,
    );
    await buyer.submitOffer(disputeId, 2, {
      offer: { refundMicroUsdc: 140_000_000, remediationHours: 12 },
      proposalResponse: "accept",
    });
    await merchant.submitOffer(disputeId, 2, {
      offer: { refundMicroUsdc: 50_000_000, remediationHours: 18 },
      proposalResponse: "accept",
    });
  }

  // 7. Fetch signed outcome, verify via AgentKit action, and settle AuthCaptureEscrow
  const rawOutcome = await merchant.outcome(disputeId);
  const signedOutcome = rawOutcome as unknown as SignedDocument<X402rSettlementInstructionDoc>;

  // Sanity-check fail-closed tamper defense before invoking escrow operator
  const tampered = structuredClone(signedOutcome);
  tampered.document.terms.refundMicroUsdc = 245_000_000;
  let tamperRejected = false;
  try {
    verifySettlementForX402rEscrow(tampered, {
      platformDid,
      disputeId,
      contractHash: cHash,
      claimantDid: buyerKey.did,
      merchantDid: merchantKey.did,
      paymentInfo,
      escrow: escrowRef,
    });
  } catch {
    tamperRejected = true;
  }
  if (!tamperRejected) throw new Error("expected tampered x402r settlement instruction to be rejected");

  const settledRaw = await actions.settle_x402r_escrow_from_outcome!.invoke({
    signedOutcome,
    disputeId,
    claimantDid: buyerKey.did,
    merchantDid: merchantKey.did,
    paymentInfo,
    escrow: escrowRef,
  });
  const settled = JSON.parse(settledRaw) as {
    refundTxHash: string | null;
    releaseTxHash: string | null;
    refundAmountAtomic: string;
    merchantReleaseAtomic: string;
    remediationHours: number;
    executionProofRef: string;
  };
  const bal = simEscrow.balances();
  console.log(`[${elapsed()}] 5. Verified Ed25519 settlement & executed x402r AuthCaptureEscrow split`);
  console.log(
    `           refundInEscrow:  ${fmtUsdc(BigInt(settled.refundAmountAtomic))} -> payer (${settled.refundTxHash?.slice(0, 14)}...)`,
  );
  console.log(
    `           releaseEscrow:   ${fmtUsdc(BigInt(settled.merchantReleaseAtomic))} -> merchant (${settled.releaseTxHash?.slice(0, 14)}...)`,
  );
  console.log(`           Escrow Leftover: ${fmtUsdc(bal.remainingEscrow)} · SLA patch window: ${settled.remediationHours}h`);

  // 8. Submit on-chain tx ref as execution proof -> Buyer confirms -> HONORED + dual audit verification
  await merchant.submitExecutionProof(disputeId, settled.executionProofRef);
  await buyer.confirmExecution(disputeId);

  const rawFinalOutcome = await buyer.outcome(disputeId);
  const finalOutcome = rawFinalOutcome as unknown as SignedDocument<X402rSettlementInstructionDoc>;
  const buyerAudit = await buyer.audit(disputeId, { expectedOutcome: rawFinalOutcome });
  const merchantAudit = await merchant.audit(disputeId, { expectedOutcome: rawFinalOutcome });
  if (buyerAudit.head !== merchantAudit.head || buyerAudit.head !== finalOutcome.document.auditRoot) {
    throw new Error("audit chain verification failed after HONORED");
  }
  if (savePath) {
    writeFileSync(savePath, JSON.stringify(finalOutcome, null, 2) + "\n", "utf8");
  }

  console.log(`[${elapsed()}] 6. Settlement HONORED & dual-verified (zero binary slashing!)`);
  console.log(`           Method:          ${finalOutcome.document.method} (executionStatus=${finalOutcome.document.executionStatus})`);
  console.log(`           Execution Proof: ${settled.executionProofRef}`);
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
