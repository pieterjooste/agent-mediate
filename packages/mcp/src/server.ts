#!/usr/bin/env node
/**
 * stdio entry point.
 *
 *   AGENT_MEDIATE_URL             API base URL (required)
 *   AGENT_MEDIATE_AGENT_KEY_FILE  PKCS#8 PEM file with your Ed25519 agent key; created (mode 600) if missing
 *   AGENT_MEDIATE_MANDATE_FILE    optional JSON file with a principal-signed mandate (or an array of them).
 *                                 When set, the server never self-signs mandates from `bounds` (security review H2)
 *   AGENT_MEDIATE_PAYER_KEY       optional EVM private key (0x…) to pay fees automatically
 *   AGENT_MEDIATE_MAX_FEE_USDC    spending cap per payment, default 5.00
 *   AGENT_MEDIATE_BUDGET_USDC     spending cap across all payments of this process, default 10.00
 *   AGENT_MEDIATE_NETWORK         eip155:84532 (Base Sepolia, default) or eip155:8453 (Base mainnet)
 *   AGENT_MEDIATE_PAY_TO          fee recipient, pinned out of band (required on mainnet; see security review M10)
 *   AGENT_MEDIATE_PLATFORM_DID    platform did:key, pinned out of band (required on mainnet; see DISC-4 / SEC3-8)
 *   AGENT_MEDIATE_EXPECTED_ENV    optional expected outcome environment (e.g. "production")
 *   AGENT_MEDIATE_EXPECTED_RULES_HASH optional 64-hex expected mechanism rulesHash pin (CR-SDK-L8)
 *   AGENT_MEDIATE_WEBHOOK_URL     optional https webhook URL pinned by the operator: the model can never redirect
 *                                 your party-only dispute events elsewhere (CR-SDK-M3)
 *
 * Logs go to stderr; stdout carries the MCP protocol.
 */
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, statSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { StdioServerTransport } from "@modelcontextprotocol/sdk/server/stdio.js";
import {
  AgentMediateClient,
  agentKeyFromPem,
  createX402Payer,
  DEFAULT_PRODUCTION_PLATFORM_DIDS,
  generateAgentKey,
  isDidKey,
  normalizeBaseUrl,
  PRODUCTION_API_URL,
  USDC,
  type Mandate,
} from "@agent-mediate/sdk";
import { createMcpServer, validateConfiguredMandates } from "./index.ts";

const cliArgs = process.argv.slice(2);
if (cliArgs.includes("--version") || cliArgs.includes("-v")) {
  console.log("0.1.0");
  process.exit(0);
}
if (cliArgs.includes("--help") || cliArgs.includes("-h")) {
  console.log(
    [
      "agent-mediate-mcp v0.1.0 — Model Context Protocol (stdio) server for Agent-Mediate",
      "",
      "Required environment variables:",
      "  AGENT_MEDIATE_URL                 API base URL (e.g. https://api.ai-agents-mediation.com)",
      "  AGENT_MEDIATE_AGENT_KEY_FILE      PKCS#8 PEM Ed25519 key file (created with mode 0600 if missing)",
      "",
      "Optional environment variables:",
      "  AGENT_MEDIATE_PLATFORM_DID        Pinned platform did:key (required on Base mainnet eip155:8453)",
      "  AGENT_MEDIATE_EXPECTED_ENV        Expected signed outcome/checkpoint environment (e.g. production)",
      "  AGENT_MEDIATE_EXPECTED_RULES_HASH Expected 64-hex mechanism rulesHash pin",
      "  AGENT_MEDIATE_WEBHOOK_URL         Operator-pinned https:// webhook URL for party-only events",
      "  AGENT_MEDIATE_A2A_CARD_URL        Operator-pinned https:// A2A Agent Card URL for standing notifications",
      "  AGENT_MEDIATE_NOTIFY_EMAIL        Operator-pinned notification email address",
      "  AGENT_MEDIATE_ALLOW_DYNAMIC_WEBHOOKS Set 'true' to opt in to model-supplied notification URLs/emails (default false)",
      "  AGENT_MEDIATE_MANDATE_FILE        Path to principal-signed Mandate JSON (disables bounds self-signing)",
      "  AGENT_MEDIATE_PAYER_KEY           0x-prefixed EVM private key for automatic x402 USDC payment",
      "  AGENT_MEDIATE_NETWORK             eip155:84532 (Base Sepolia, default) or eip155:8453 (Base mainnet)",
      "  AGENT_MEDIATE_PAY_TO              Pinned 0x fee recipient address (required on Base mainnet)",
      "  AGENT_MEDIATE_MAX_FEE_USDC        Per-payment cap in USDC (default 5.00)",
      "  AGENT_MEDIATE_BUDGET_USDC         Process spending cap in USDC (default 10.00)",
    ].join("\n"),
  );
  process.exit(0);
}

const env = process.env;
const fatal = (msg: string): never => {
  console.error(`agent-mediate-mcp: ${msg}`);
  process.exit(1);
};
const readEnv = (name: string): string | undefined => {
  const raw = env[name];
  if (raw === undefined) return undefined;
  const trimmed = raw.trim();
  if (trimmed === "") fatal(`${name} must not be empty when set (unset ${name} to disable it)`);
  return trimmed;
};

const expandHome = (raw: string): string => {
  if (raw === "~") return homedir();
  if (raw.startsWith("~/") || raw.startsWith("~\\")) return join(homedir(), raw.slice(2));
  return raw;
};

const baseUrl = readEnv("AGENT_MEDIATE_URL") ?? fatal("AGENT_MEDIATE_URL is required");
const keyFile = expandHome(readEnv("AGENT_MEDIATE_AGENT_KEY_FILE") ?? fatal("AGENT_MEDIATE_AGENT_KEY_FILE is required"));
{
  // CR-SDK-L8, SA2-MCP-L1 & CR3-SKILL-M1: expand `~/`, ensure parent dir exists (mode 0700, non-symlink),
  // create a missing key file atomically with O_CREAT | O_EXCL (mode 0600), and refuse symbolic links.
  const parentDir = dirname(keyFile);
  if (parentDir && parentDir !== ".") {
    if (existsSync(parentDir)) {
      if (lstatSync(parentDir).isSymbolicLink()) {
        fatal(`AGENT_MEDIATE_AGENT_KEY_FILE parent directory (${parentDir}) must not be a symbolic link`);
      }
    } else {
      mkdirSync(parentDir, { recursive: true, mode: 0o700 });
      chmodSync(parentDir, 0o700);
    }
  }
  const generated = generateAgentKey();
  try {
    writeFileSync(keyFile, generated.privateKey.export({ type: "pkcs8", format: "pem" }) as string, {
      mode: 0o600,
      flag: "wx",
    });
    chmodSync(keyFile, 0o600);
    console.error(`agent-mediate-mcp: created a new agent key at ${keyFile} (${generated.did})`);
  } catch (e) {
    if ((e as NodeJS.ErrnoException).code !== "EEXIST") throw e;
    if (lstatSync(keyFile).isSymbolicLink()) {
      fatal(`AGENT_MEDIATE_AGENT_KEY_FILE (${keyFile}) must not be a symbolic link`);
    }
    if (process.platform !== "win32") {
      const mode = statSync(keyFile).mode & 0o777;
      if ((mode & 0o077) !== 0) {
        console.error(`agent-mediate-mcp: warning: ${keyFile} has permissive mode 0${mode.toString(8)} (expected 0600)`);
      }
    }
  }
}
if (lstatSync(keyFile).isSymbolicLink()) {
  fatal(`AGENT_MEDIATE_AGENT_KEY_FILE (${keyFile}) must not be a symbolic link`);
}
const agentKey = agentKeyFromPem(readFileSync(keyFile, "utf8"));

const usdcAtomic = (name: string, fallback: string): bigint => {
  const v = readEnv(name) ?? fallback;
  const m = /^(\d+)(?:\.(\d{1,6}))?$/.exec(v);
  return m ? BigInt(m[1]!) * 1_000_000n + BigInt((m[2] ?? "").padEnd(6, "0")) : fatal(`${name} must be a USDC amount like 5.00`);
};
const maxFee = usdcAtomic("AGENT_MEDIATE_MAX_FEE_USDC", "5.00");
const budget = usdcAtomic("AGENT_MEDIATE_BUDGET_USDC", "10.00");
const network = (readEnv("AGENT_MEDIATE_NETWORK") ?? "eip155:84532") as keyof typeof USDC;
if (!USDC[network]) fatal("AGENT_MEDIATE_NETWORK must be eip155:84532 or eip155:8453");

const payerKey = readEnv("AGENT_MEDIATE_PAYER_KEY");
const payTo = readEnv("AGENT_MEDIATE_PAY_TO");
if (payTo !== undefined && !/^0x[0-9a-fA-F]{40}$/.test(payTo)) {
  fatal("AGENT_MEDIATE_PAY_TO must be a 0x-prefixed 20-byte EVM address");
}

let payer;
try {
  payer = payerKey
    ? createX402Payer({
        privateKey: payerKey as `0x${string}`,
        maxAmountAtomic: maxFee,
        budgetAtomic: budget,
        network,
        ...(payTo ? { payTo } : {}),
      })
    : undefined;
} catch (e) {
  fatal((e as Error).message);
}

let mandates: Mandate[] | undefined;
const rawMandateFile = readEnv("AGENT_MEDIATE_MANDATE_FILE");
const mandateFile = rawMandateFile !== undefined ? expandHome(rawMandateFile) : undefined;
if (mandateFile !== undefined) {
  try {
    if (lstatSync(mandateFile).isSymbolicLink()) {
      fatal(`AGENT_MEDIATE_MANDATE_FILE (${mandateFile}) must not be a symbolic link`);
    }
    const parsed = JSON.parse(readFileSync(mandateFile, "utf8")) as Mandate | Mandate[];
    mandates = Array.isArray(parsed) ? parsed : [parsed];
    validateConfiguredMandates(mandates, agentKey.did, Date.now());
  } catch (e) {
    fatal(`invalid AGENT_MEDIATE_MANDATE_FILE (${mandateFile}): ${(e as Error).message}`);
  }
}

const normBaseUrl = (() => {
  try {
    return normalizeBaseUrl(baseUrl);
  } catch (e) {
    return fatal(`invalid AGENT_MEDIATE_URL (${baseUrl}): ${(e as Error).message}`);
  }
})();
const platformDid = readEnv("AGENT_MEDIATE_PLATFORM_DID") ?? DEFAULT_PRODUCTION_PLATFORM_DIDS[normBaseUrl];
if (platformDid !== undefined && !isDidKey(platformDid)) fatal("AGENT_MEDIATE_PLATFORM_DID must be a valid Ed25519 did:key");
const allowUnpinnedRaw = readEnv("AGENT_MEDIATE_ALLOW_UNPINNED_PLATFORM_DID");
if (allowUnpinnedRaw !== undefined && allowUnpinnedRaw !== "true" && allowUnpinnedRaw !== "false") {
  fatal("AGENT_MEDIATE_ALLOW_UNPINNED_PLATFORM_DID must be 'true' or 'false' when set");
}
const allowUnpinnedPlatformDid = allowUnpinnedRaw === "true";
const expectedEnvironment =
  readEnv("AGENT_MEDIATE_EXPECTED_ENV") ?? (normBaseUrl === PRODUCTION_API_URL ? "production" : undefined);
if (network === "eip155:8453" && !platformDid && !allowUnpinnedPlatformDid) {
  fatal("AGENT_MEDIATE_PLATFORM_DID is required on Base mainnet (eip155:8453)");
}
if (expectedEnvironment === "production" && !platformDid && !allowUnpinnedPlatformDid) {
  fatal("AGENT_MEDIATE_PLATFORM_DID is required in production (set AGENT_MEDIATE_PLATFORM_DID to the platform did:key)");
}
const expectedRulesHash = readEnv("AGENT_MEDIATE_EXPECTED_RULES_HASH");
if (expectedRulesHash !== undefined && !/^[a-f0-9]{64}$/.test(expectedRulesHash)) {
  fatal("AGENT_MEDIATE_EXPECTED_RULES_HASH must be a 64-character lowercase hex SHA-256 hash");
}
const pinnedWebhookUrl = readEnv("AGENT_MEDIATE_WEBHOOK_URL");
if (pinnedWebhookUrl !== undefined) {
  let parsedHook: URL | undefined;
  try {
    parsedHook = new URL(pinnedWebhookUrl);
  } catch {
    // reported below
  }
  if (!parsedHook || parsedHook.protocol !== "https:") fatal("AGENT_MEDIATE_WEBHOOK_URL must be an https:// URL");
}
const pinnedA2aCardUrl = readEnv("AGENT_MEDIATE_A2A_CARD_URL");
if (pinnedA2aCardUrl !== undefined) {
  let parsedCard: URL | undefined;
  try {
    parsedCard = new URL(pinnedA2aCardUrl);
  } catch {
    // reported below
  }
  if (!parsedCard || parsedCard.protocol !== "https:") fatal("AGENT_MEDIATE_A2A_CARD_URL must be an https:// URL");
}
const pinnedNotifyEmail = readEnv("AGENT_MEDIATE_NOTIFY_EMAIL");
if (
  pinnedNotifyEmail !== undefined &&
  !/^[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?(?:\.[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?)+$/.test(pinnedNotifyEmail)
) {
  fatal("AGENT_MEDIATE_NOTIFY_EMAIL must be a valid single email address");
}
const allowDynamicRaw = readEnv("AGENT_MEDIATE_ALLOW_DYNAMIC_WEBHOOKS");
if (allowDynamicRaw !== undefined && allowDynamicRaw !== "true" && allowDynamicRaw !== "false") {
  fatal("AGENT_MEDIATE_ALLOW_DYNAMIC_WEBHOOKS must be 'true' or 'false' when set");
}
const allowDynamicWebhooks = allowDynamicRaw === "true";

const client = new AgentMediateClient({
  baseUrl: normBaseUrl,
  agentKey,
  ...(platformDid ? { platformDid } : {}),
  ...(allowUnpinnedPlatformDid ? { allowUnpinnedPlatformDid: true } : {}),
  ...(expectedEnvironment ? { expectedEnvironment } : {}),
  ...(expectedRulesHash ? { expectedRulesHash } : {}),
  ...(payer ? { payer } : {}),
});
const server = createMcpServer(client, {
  ...(payer ? { payerAddress: payer.address } : {}),
  ...(mandates ? { mandates } : {}),
  ...(pinnedWebhookUrl ? { webhookUrl: pinnedWebhookUrl } : {}),
  ...(pinnedA2aCardUrl ? { a2aCardUrl: pinnedA2aCardUrl } : {}),
  ...(pinnedNotifyEmail ? { notifyEmail: pinnedNotifyEmail } : {}),
  ...(allowDynamicRaw !== undefined ? { allowDynamicWebhooks } : {}),
  ...(expectedEnvironment ? { expectedEnvironment } : {}),
  ...(expectedRulesHash ? { expectedRulesHash } : {}),
});
await server.connect(new StdioServerTransport());
const usdc = (a: bigint) => (Number(a) / 1e6).toFixed(2);
console.error(
  `agent-mediate-mcp: ready as ${agentKey.did}${payer ? `, paying from ${payer.address} on ${network} (cap ${usdc(maxFee)} USDC per payment, ${usdc(budget)} USDC in total)` : ", no payer configured"}${mandates ? `, ${mandates.length} principal-signed mandate(s)` : ""}`,
);
