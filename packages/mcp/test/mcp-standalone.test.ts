import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import { describe, it } from "node:test";
import { AgentMediateClient, generateAgentKey, RULES_HASH, signMandate } from "@agent-mediate/sdk";
import {
  createMcpServer,
  paidToolIdempotencyKey,
  pickMandate,
  unwrapUntrusted,
  validateConfiguredMandates,
} from "../src/index.ts";

describe("MCP standalone server & helper verification (zero server-app imports)", () => {
  it("instantiates createMcpServer, enforces mandate validation/selection, unwraps untrusted envelopes, and validates server.json", () => {
    const agentKey = generateAgentKey();
    const principalKey = generateAgentKey();
    const platformKey = generateAgentKey();
    const now = 1_760_000_000_000;

    const client = new AgentMediateClient({
      baseUrl: "https://api.ai-agents-mediation.com",
      agentKey,
      platformDid: platformKey.did,
      expectedRulesHash: RULES_HASH,
      now: () => now,
      fetch: async () => new Response(JSON.stringify({ ok: true }), { status: 200 }),
    });

    const mandate = signMandate(
      {
        id: "mnd_standalone_1",
        principalId: principalKey.did,
        agentId: agentKey.did,
        bounds: { refundUsd: { min: 0, max: 500 } },
        issuedAt: now - 1_000,
        expiresAt: now + 86_400_000,
      },
      principalKey,
    );

    validateConfiguredMandates([mandate], agentKey.did, now);
    const selected = pickMandate(
      [mandate],
      agentKey.did,
      { contractHash: "a".repeat(64), counterpartyId: generateAgentKey().did },
      now,
    );
    assert.equal(selected?.id, "mnd_standalone_1");

    const server = createMcpServer(client, { mandates: [mandate], now: () => now });
    assert.ok(server);

    // unwrapUntrusted restores raw strings while blocking prototype-pollution keys
    const wrapped = {
      summary: { untrusted: true as const, authoredBy: "claimant", text: "Late delivery" },
      nested: [{ untrusted: true as const, authoredBy: "ai", text: "item-1" }],
    };
    assert.deepEqual(unwrapUntrusted(wrapped), { summary: "Late delivery", nested: ["item-1"] });

    // paidToolIdempotencyKey normalizes wrapped vs unwrapped arguments deterministically
    const k1 = paidToolIdempotencyKey(agentKey.did, "file_dispute", { claim: wrapped }, "https://api.ai-agents-mediation.com/");
    const k2 = paidToolIdempotencyKey(
      agentKey.did,
      "file_dispute",
      { claim: { summary: "Late delivery", nested: ["item-1"] } },
      "https://api.ai-agents-mediation.com",
    );
    assert.equal(k1, k2);

    // MCP Registry server.json version parity with package.json
    const pkgJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "../package.json"), "utf8"));
    const serverJson = JSON.parse(readFileSync(resolve(import.meta.dirname, "../server.json"), "utf8"));
    assert.equal(serverJson.name, pkgJson.mcpName);
    assert.equal(serverJson.version, pkgJson.version);
    assert.equal(serverJson.packages[0].version, pkgJson.version);
  });

  it("executes the cross-language Python buyer + @agent-mediate/mcp vendor E2E demo offline", () => {
    const repoRoot = resolve(import.meta.dirname, "../../..");
    const demoScript = resolve(repoRoot, "examples/e2e-sla-demo.ts");
    const out = execFileSync(process.execPath, [demoScript, "--offline"], {
      cwd: repoRoot,
      encoding: "utf8",
      timeout: 30_000,
    });
    assert.match(out, /Co-signed agent-mediate\/clause\/v1 verified/);
    assert.match(out, /Settlement HONORED & dual-verified in Python \+ MCP!/);
  });
});
