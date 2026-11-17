/**
 * x402 v2 payer for the `exact` scheme on Base (EIP-3009 TransferWithAuthorization).
 *
 * Safety policy (security review M10). Everything that decides where money goes is pinned out of band,
 * in the constructor, never taken from the server being paid:
 * - network: Base Sepolia (testnet) unless you explicitly choose Base mainnet;
 * - asset and EIP-712 domain: the USDC contract for that network, from the table below;
 * - payTo: required on mainnet; on testnet it falls back to the platform's published address;
 * - amount: a cap per payment AND a cumulative budget across every authorisation this payer signs;
 * - validity: validBefore never exceeds `maxTimeoutSeconds` (default 300 s), whatever the server asks;
 * - purpose: the client only asks the payer to pay for filing (`operation`);
 *   a 402 on any other request is refused.
 */
import { randomBytes } from "node:crypto";
import { getAddress } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { AgentMediateError } from "./errors.ts";

export interface PaymentRequirements {
  scheme: string;
  network: string;
  amount: string;
  asset: string;
  payTo: string;
  maxTimeoutSeconds: number;
  extra?: { name?: string; version?: string };
}

export interface PaymentRequired {
  x402Version: number;
  error?: string;
  resource?: { url: string; description?: string; mimeType?: string };
  accepts: PaymentRequirements[];
}

/** The only operation that carries a fee. */
export type PaidOperation = "file";
export const PAID_OPERATIONS: readonly PaidOperation[] = ["file"];

export interface PaymentPolicy {
  /** Which paid operation this payment is for. Required: the payer refuses to pay for anything else. */
  operation: PaidOperation;
  /** payTo published by the platform (/v1/platform). Only used when no payTo is pinned (testnet). */
  expectedPayTo?: string;
}

export interface Payer {
  readonly address: string;
  /** CAIP-2 network identifier (e.g. eip155:84532 or eip155:8453), when exposed by the payer. */
  readonly network?: string;
  /** Atomic units signed so far (unsettled RESPONDENT_UNREACHABLE authorisations are reclaimed after validBefore + 60s). */
  readonly spentAtomic: bigint;
  /** Returns the base64 PAYMENT-SIGNATURE header value. Throws PaymentPolicyError if policy forbids paying. */
  pay(required: PaymentRequired, policy: PaymentPolicy): Promise<string>;
  /** Mark a signed PAYMENT-SIGNATURE header as definitively unsettled so its budget reclaims after `validBefore + 60s` (`CR3-SDK-M3`). */
  releaseUnsettled?(paymentHeader: string): void;
}

export class PaymentPolicyError extends AgentMediateError {
  constructor(message: string) {
    super(0, "PAYMENT_POLICY_ERROR", message);
    this.name = "PaymentPolicyError";
  }
}

/** USDC on Base: the asset and EIP-712 domain the payer will sign for (pinned in the SDK, not read from the server). */
export const USDC: Record<"eip155:84532" | "eip155:8453", { asset: `0x${string}`; name: string; version: string }> = {
  "eip155:84532": { asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", name: "USDC", version: "2" },
  "eip155:8453": { asset: "0x833589fCD6eDb6E08f4c7C32D4f71b54bdA02913", name: "USD Coin", version: "2" },
};
export const BASE_SEPOLIA = "eip155:84532";
export const BASE_MAINNET = "eip155:8453";

export interface X402PayerOptions {
  /** EVM private key of the paying wallet (0x-prefixed hex). */
  privateKey: `0x${string}`;
  /** Hard cap per payment in USDC atomic units (6 decimals). */
  maxAmountAtomic: bigint;
  /** Hard cap on the total of all authorisations this payer signs, in USDC atomic units. */
  budgetAtomic: bigint;
  /** CAIP-2 network. Default Base Sepolia (testnet). Base mainnet must be chosen explicitly. */
  network?: keyof typeof USDC;
  /** Fee recipient, pinned out of band. Required on mainnet. On testnet, defaults to the platform's published address. */
  payTo?: string;
  /** USDC contract. Defaults to the SDK's table; if given, it must match the table (a guard against typos). */
  asset?: string;
  /** Longest authorisation validity accepted, in seconds. Default 300. */
  maxTimeoutSeconds?: number;
  /** Optional clock override returning Unix milliseconds (default `Date.now`). */
  now?: () => number;
}

const ADDRESS = /^0x[0-9a-fA-F]{40}$/;
const eq = (a: string, b: string) => a.toLowerCase() === b.toLowerCase();
const MAX_ISSUED_HEADERS = 256;

function parsePinnedAddress(raw: string, label: string): `0x${string}` {
  if (!ADDRESS.test(raw)) throw new PaymentPolicyError(`${label} must be a 0x-prefixed 20-byte address`);
  const hex = raw.slice(2);
  const checksummed = getAddress(raw.toLowerCase() as `0x${string}`);
  if (hex !== hex.toLowerCase() && hex !== hex.toUpperCase() && checksummed !== raw) {
    throw new PaymentPolicyError(`${label} has an invalid EIP-55 address checksum`);
  }
  return checksummed;
}

export function createX402Payer(opts: X402PayerOptions): Payer {
  const account = privateKeyToAccount(opts.privateKey);
  const network = opts.network ?? BASE_SEPOLIA;
  const usdc = USDC[network];
  if (!usdc) throw new PaymentPolicyError(`unsupported network ${network}; Base Sepolia or Base mainnet only`);
  if (opts.asset !== undefined && !eq(opts.asset, usdc.asset)) throw new PaymentPolicyError(`asset ${opts.asset} is not USDC on ${network} (${usdc.asset})`);
  const pinnedPayTo = opts.payTo !== undefined ? parsePinnedAddress(opts.payTo, "payTo") : undefined;
  if (network === BASE_MAINNET && pinnedPayTo === undefined) throw new PaymentPolicyError("on Base mainnet, payTo must be pinned out of band (constructor option)");
  if (opts.maxAmountAtomic <= 0n) throw new PaymentPolicyError("maxAmountAtomic must be positive");
  if (opts.budgetAtomic <= 0n) throw new PaymentPolicyError("budgetAtomic must be positive");
  const maxTimeoutSeconds = opts.maxTimeoutSeconds ?? 300;
  if (!Number.isInteger(maxTimeoutSeconds) || maxTimeoutSeconds < 10) throw new PaymentPolicyError("maxTimeoutSeconds must be an integer of at least 10");
  const nowMs = opts.now ?? Date.now;
  let spent = 0n;
  const issued = new Map<string, { amount: bigint; validBeforeSec: number }>();
  const pendingReclaims: Array<{ amount: bigint; reclaimAtSec: number }> = [];

  const reclaimExpired = (): void => {
    if (pendingReclaims.length === 0) return;
    const nowSec = Math.floor(nowMs() / 1000);
    for (let i = pendingReclaims.length - 1; i >= 0; i--) {
      const item = pendingReclaims[i]!;
      if (nowSec > item.reclaimAtSec) {
        spent = spent > item.amount ? spent - item.amount : 0n;
        pendingReclaims.splice(i, 1);
      }
    }
  };

  return {
    address: account.address,
    network,
    get spentAtomic() {
      reclaimExpired();
      return spent;
    },
    releaseUnsettled(paymentHeader: string) {
      const entry = issued.get(paymentHeader);
      if (!entry) return;
      issued.delete(paymentHeader);
      // Wait until validBefore + 60s skew buffer has passed before reclaiming budget (`CR3-SDK-M3`).
      pendingReclaims.push({ amount: entry.amount, reclaimAtSec: entry.validBeforeSec + 60 });
      reclaimExpired();
    },
    async pay(required, policy) {
      reclaimExpired();
      if (!policy || !PAID_OPERATIONS.includes(policy.operation)) {
        throw new PaymentPolicyError(`refusing to pay: only ${PAID_OPERATIONS.join(", ")} carry a fee`);
      }
      if (required?.x402Version !== 2 || !Array.isArray(required.accepts)) throw new PaymentPolicyError(`unsupported x402 version ${required?.x402Version}`);
      const rawPayTo = pinnedPayTo ?? policy.expectedPayTo;
      if (!rawPayTo) throw new PaymentPolicyError("no payTo pinned and the platform publishes none");
      if (!ADDRESS.test(rawPayTo)) throw new PaymentPolicyError("payTo must be a 0x-prefixed 20-byte address");
      const payTo = pinnedPayTo ?? getAddress(rawPayTo.toLowerCase() as `0x${string}`);
      const req = required.accepts.find((a) => a.scheme === "exact" && a.network === network && typeof a.asset === "string" && eq(a.asset, usdc.asset));
      if (!req) throw new PaymentPolicyError(`no acceptable payment option (need scheme "exact", USDC ${usdc.asset} on ${network})`);
      if (typeof req.payTo !== "string" || !ADDRESS.test(req.payTo) || !eq(req.payTo, payTo)) {
        throw new PaymentPolicyError(`payTo ${req.payTo} does not match the pinned address ${payTo}`);
      }
      if (req.extra?.name !== undefined && req.extra.name !== usdc.name) throw new PaymentPolicyError(`unexpected EIP-712 domain name ${req.extra.name}`);
      if (req.extra?.version !== undefined && req.extra.version !== usdc.version) throw new PaymentPolicyError(`unexpected EIP-712 domain version ${req.extra.version}`);
      if (typeof req.amount !== "string" || !/^\d+$/.test(req.amount)) throw new PaymentPolicyError("invalid amount");
      const amount = BigInt(req.amount);
      if (amount <= 0n) throw new PaymentPolicyError("invalid amount");
      if (amount > opts.maxAmountAtomic) {
        throw new PaymentPolicyError(`fee ${amount} exceeds the configured cap ${opts.maxAmountAtomic} (USDC atomic units)`);
      }
      if (spent + amount > opts.budgetAtomic) {
        throw new PaymentPolicyError(`fee ${amount} would exceed the remaining budget ${opts.budgetAtomic - spent} of ${opts.budgetAtomic} (USDC atomic units)`);
      }
      if (!Number.isInteger(req.maxTimeoutSeconds) || req.maxTimeoutSeconds <= 0) {
        throw new PaymentPolicyError("maxTimeoutSeconds must be a positive integer");
      }
      const validity = Math.min(req.maxTimeoutSeconds, maxTimeoutSeconds);

      // Reserve before the first await, so concurrent calls can't both pass the budget check.
      spent += amount;
      const now = Math.floor(nowMs() / 1000);
      const validBeforeSec = now + validity;
      const authorization = {
        from: account.address,
        to: payTo,
        value: amount.toString(),
        validAfter: String(Math.max(0, now - 600)),
        validBefore: String(validBeforeSec),
        nonce: `0x${randomBytes(32).toString("hex")}` as `0x${string}`,
      };
      let signature: string;
      try {
        signature = await account.signTypedData({
          domain: { name: usdc.name, version: usdc.version, chainId: Number(network.split(":")[1]), verifyingContract: usdc.asset },
          types: {
            TransferWithAuthorization: [
              { name: "from", type: "address" },
              { name: "to", type: "address" },
              { name: "value", type: "uint256" },
              { name: "validAfter", type: "uint256" },
              { name: "validBefore", type: "uint256" },
              { name: "nonce", type: "bytes32" },
            ],
          },
          primaryType: "TransferWithAuthorization",
          message: {
            from: authorization.from,
            to: authorization.to,
            value: amount,
            validAfter: BigInt(authorization.validAfter),
            validBefore: BigInt(authorization.validBefore),
            nonce: authorization.nonce,
          },
        });
      } catch (e) {
        spent -= amount; // nothing was signed
        throw e;
      }
      const accepted = { scheme: "exact", network, amount: req.amount, asset: req.asset, payTo: req.payTo, maxTimeoutSeconds: req.maxTimeoutSeconds, extra: { name: usdc.name, version: usdc.version } };
      const payload = { x402Version: 2, resource: required.resource, accepted, payload: { signature, authorization } };
      const encoded = Buffer.from(JSON.stringify(payload)).toString("base64");
      if (issued.size >= MAX_ISSUED_HEADERS) {
        const oldest = issued.keys().next().value;
        if (oldest !== undefined) issued.delete(oldest);
      }
      issued.set(encoded, { amount, validBeforeSec });
      return encoded;
    },
  };
}
