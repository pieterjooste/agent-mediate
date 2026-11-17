/**
 * Cross-Language End-to-End Mediation Demo (<8 seconds live, <1 second offline):
 *
 *   - Buyer Agent:  Python 3 (`examples/langgraph_buyer_agent.py` using zero-dep `agent-mediate`)
 *   - Vendor Agent: TypeScript MCP client driving `@agent-mediate/mcp`
 *
 * Usage:
 *   # Run live against https://api.ai-agents-mediation.com ($0.00 Mode A, zero crypto wallet):
 *   node examples/e2e-sla-demo.ts
 *
 *   # Run against a custom / local API deployment:
 *   AGENT_MEDIATE_URL=http://localhost:8080 node examples/e2e-sla-demo.ts
 *
 *   # Run completely offline in air-gapped / socket-restricted CI sandboxes:
 *   node examples/e2e-sla-demo.ts --offline
 *
 *   # Optionally save the verified Ed25519 settlement instruction JSON for https://ai-agents-mediation.com/verify:
 *   node examples/e2e-sla-demo.ts --save-outcome ./verified-settlement.json
 */
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { createInterface } from "node:readline";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";
import { InMemoryTransport } from "@modelcontextprotocol/sdk/inMemory.js";
import {
  apply,
  buildSettlementInstruction,
  compactViewFor,
  createDispute,
  DEFAULT_PRODUCTION_PLATFORM_DIDS,
  deriveProposalKey,
  normalizeBaseUrl,
  PRODUCTION_API_URL,
  publicAuditEntry,
  RULES_HASH,
  RULES_VERSION,
  viewFor,
  type Command,
  type DisputeState,
  type DomainEvent,
  type Issue,
  type Mandate,
  type Party,
} from "@agent-mediate/core";
import { createMcpServer, unwrapUntrusted } from "@agent-mediate/mcp";
import {
  buildSignedKeyHistory,
  didWebFromUrl,
  generateAgentKey,
  signDocument,
  verifyRequest,
  type AgentKey,
} from "@agent-mediate/protocol";
import { AgentMediateClient } from "@agent-mediate/sdk";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const PY_WORKER_PATH = join(REPO_ROOT, "examples", "langgraph_buyer_agent.py");
const MCP_SERVER_DIST = join(REPO_ROOT, "packages", "mcp", "dist", "server.js");

interface HttpReply {
  status: number;
  headers: Record<string, string>;
  body: string;
}

type OfflineHttpHandler = (
  method: string,
  url: string,
  headers: Record<string, string>,
  body: string,
) => HttpReply;

interface PythonWorker {
  call<T = Record<string, unknown>>(cmd: string, payload?: Record<string, unknown>): Promise<T>;
  close(): Promise<void>;
}

function startPythonBuyerWorker(offlineHttp?: OfflineHttpHandler): PythonWorker {
  const proc = spawn("python3", [PY_WORKER_PATH, "--worker"], {
    cwd: REPO_ROOT,
    stdio: ["pipe", "pipe", "inherit"],
    env: {
      ...process.env,
      PYTHONPATH: join(REPO_ROOT, "packages", "python", "src"),
    },
  });
  const rl = createInterface({ input: proc.stdout });
  const pending: Array<{
    resolve: (val: unknown) => void;
    reject: (err: Error) => void;
  }> = [];

  rl.on("line", (line) => {
    try {
      const parsed = JSON.parse(line) as Record<string, unknown>;
      if (parsed.type === "http_request") {
        if (!offlineHttp) {
          proc.stdin.write(
            JSON.stringify({ status: 500, headers: {}, body: JSON.stringify({ code: "INTERNAL", detail: "no offline handler" }) }) + "\n",
          );
          return;
        }
        const reply = offlineHttp(
          String(parsed.method ?? "GET"),
          String(parsed.url ?? "/"),
          (parsed.headers as Record<string, string>) ?? {},
          String(parsed.body ?? ""),
        );
        proc.stdin.write(JSON.stringify(reply) + "\n");
        return;
      }
      const waiter = pending.shift();
      if (!waiter) return;
      if (parsed.ok) waiter.resolve(parsed.result);
      else waiter.reject(new Error(String(parsed.error ?? "Python worker error")));
    } catch (e) {
      pending.shift()?.reject(e as Error);
    }
  });

  proc.on("exit", (code) => {
    while (pending.length > 0) {
      pending.shift()?.reject(new Error(`Python worker exited prematurely (code=${code})`));
    }
  });

  return {
    call<T = Record<string, unknown>>(cmd: string, payload: Record<string, unknown> = {}): Promise<T> {
      return new Promise<T>((resolveCall, rejectCall) => {
        pending.push({ resolve: resolveCall as (val: unknown) => void, reject: rejectCall });
        proc.stdin.write(JSON.stringify({ cmd, ...payload }) + "\n");
      });
    },
    async close(): Promise<void> {
      rl.close();
      proc.stdin.end();
      await new Promise<void>((r) => {
        if (proc.exitCode !== null) r();
        else proc.once("exit", () => r());
      });
    },
  };
}

interface OfflineMediator {
  baseUrl: string;
  platformKey: AgentKey;
  handle: OfflineHttpHandler;
  fetch: typeof globalThis.fetch;
}

function createOfflineReferenceMediator(): OfflineMediator {
  const baseUrl = "https://offline-demo.agent-mediate.local";
  const platformKey = generateAgentKey();
  const proposalSecret = randomBytes(32).toString("hex");
  const disputes = new Map<
    string,
    { state: DisputeState; events: DomainEvent[]; proposedIssues: Issue[]; signedOutcome?: unknown }
  >();

  const jsonReply = (status: number, payload: unknown): HttpReply => ({
    status,
    headers: { "content-type": "application/json; charset=utf-8" },
    body: JSON.stringify(payload),
  });

  const handle: OfflineHttpHandler = (method, rawUrl, rawHeaders, rawBody) => {
    try {
      const url = new URL(rawUrl, baseUrl);
      const now = Date.now();
      const lowerHeaders: Record<string, string> = {};
      for (const [k, v] of Object.entries(rawHeaders)) {
        lowerHeaders[k.toLowerCase()] = v;
      }

      if (method === "GET" && url.pathname === "/v1/platform") {
        return jsonReply(200, {
          did: platformKey.did,
          didWeb: didWebFromUrl(baseUrl),
          keyHistory: `${baseUrl}/.well-known/key-history.json`,
          rulesVersion: RULES_VERSION,
          rulesHash: RULES_HASH,
          fees: { waived: true },
        });
      }

      if (method === "GET" && url.pathname === "/.well-known/key-history.json") {
        return jsonReply(
          200,
          buildSignedKeyHistory({
            baseUrl,
            activeKey: platformKey,
            activeValidFrom: now - 60_000,
            updatedAt: now,
          }),
        );
      }

      const verified = verifyRequest({
        method,
        targetUri: baseUrl + url.pathname + url.search,
        header: (name) => lowerHeaders[name.toLowerCase()] ?? null,
        body: rawBody,
        now,
      });
      if (!verified.ok) {
        return jsonReply(401, { code: "UNAUTHENTICATED", detail: verified.reason });
      }
      const callerDid = verified.keyid;
      const body = rawBody.length > 0 ? (JSON.parse(rawBody) as Record<string, unknown>) : {};
      const wantCompact = url.searchParams.get("view") === "compact";

      const renderPartyResponse = (rec: { state: DisputeState }, party: Party) => ({
        disputeId: rec.state.id,
        view: wantCompact ? compactViewFor(rec.state, party) : viewFor(rec.state, party),
      });

      if (method === "POST" && url.pathname === "/v1/disputes") {
        const disputeId = `dsp_${randomBytes(16).toString("hex")}`;
        const respondentId = String(body.respondentId);
        const contractHash = String(body.contractHash);
        const created = createDispute(
          {
            id: disputeId,
            auditSalt: randomBytes(32).toString("hex"),
            claimantId: callerDid,
            claimantMandate: body.mandate as Mandate,
            respondentId,
            contractHash,
            claim: body.claim as { summary: string; requestedRemedy: string },
            feePaid: true,
            discloseGapOnFailure: Boolean(body.discloseGapOnFailure),
            proposalKey: deriveProposalKey(proposalSecret, callerDid, respondentId, contractHash),
            noticeDelivery: {
              method: "none",
              delivered: false,
              verifiedEndpoint: false,
              attempted: [],
              at: now,
            },
          },
          now,
        );
        if (!created.ok) {
          return jsonReply(400, { code: created.error.code, detail: created.error.message });
        }
        const rec = {
          state: created.state,
          events: [...created.events],
          proposedIssues: body.proposedIssues as Issue[],
        };
        disputes.set(disputeId, rec);
        return jsonReply(201, renderPartyResponse(rec, "claimant"));
      }

      const m = /^\/v1\/disputes\/([^/]+)(?:\/(.*))?$/.exec(url.pathname);
      if (!m) return jsonReply(404, { code: "NOT_FOUND", detail: "no such route" });
      const rec = disputes.get(decodeURIComponent(m[1]!));
      if (!rec) return jsonReply(404, { code: "NOT_FOUND", detail: "dispute not found" });

      const sub = m[2] ?? "";
      const party: Party | null =
        callerDid === rec.state.parties.claimant.id
          ? "claimant"
          : callerDid === rec.state.respondentId
            ? "respondent"
            : null;
      if (!party) return jsonReply(403, { code: "NOT_AUTHORIZED", detail: "not a party" });

      const runCmd = (cmd: Command): HttpReply | null => {
        const applied = apply(rec.state, cmd, now);
        if (!applied.ok) {
          return jsonReply(409, { code: applied.error.code, detail: applied.error.message });
        }
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
          rec.signedOutcome = signDocument(
            { ...buildSettlementInstruction(rec.state), environment: "development" },
            platformKey,
            { created: now },
          );
        }
        return null;
      };

      if (method === "GET" && sub === "") return jsonReply(200, renderPartyResponse(rec, party));
      if (method === "GET" && sub === "outcome") {
        if (!rec.signedOutcome) return jsonReply(409, { code: "OUTCOME_NOT_AVAILABLE", detail: "outcome not available" });
        return jsonReply(200, rec.signedOutcome);
      }
      if (method === "GET" && sub === "audit") {
        return jsonReply(200, {
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
        return err ?? jsonReply(200, renderPartyResponse(rec, party));
      }
      if (method === "POST" && sub === "evidence") {
        const err = runCmd({
          type: "SUBMIT_EVIDENCE",
          actor: party,
          items: body.items as Array<{ id: string; kind: string; sha256: string; description: string }>,
        });
        return err ?? jsonReply(200, renderPartyResponse(rec, party));
      }
      if (method === "POST" && sub === "evidence/close") {
        const err = runCmd({ type: "CLOSE_EVIDENCE", actor: party });
        return err ?? jsonReply(200, renderPartyResponse(rec, party));
      }
      if (method === "POST" && sub === "issues/confirm") {
        const err = runCmd({
          type: "CONFIRM_ISSUES",
          actor: party,
          issuesHash: String(body.issuesHash),
          ...(body.mandate ? { mandate: body.mandate as Mandate } : {}),
        });
        return err ?? jsonReply(200, renderPartyResponse(rec, party));
      }
      const roundMatch = /^rounds\/(\d+)\/offer$/.exec(sub);
      if (method === "POST" && roundMatch) {
        const err = runCmd({
          type: "SUBMIT_ROUND",
          actor: party,
          round: Number(roundMatch[1]),
          offer: body.offer as Record<string, number>,
          ...(body.private
            ? { private: body.private as { weights: Record<string, number>; walkaway: Record<string, number> } }
            : {}),
          ...(body.proposalResponse ? { proposalResponse: body.proposalResponse as "accept" | "reject" } : {}),
        });
        return err ?? jsonReply(200, renderPartyResponse(rec, party));
      }
      if (method === "POST" && sub === "execution/proof") {
        const err = runCmd({ type: "SUBMIT_EXECUTION_PROOF", actor: party, reference: String(body.reference) });
        return err ?? jsonReply(200, renderPartyResponse(rec, party));
      }
      if (method === "POST" && sub === "execution/confirm") {
        const err = runCmd({ type: "CONFIRM_EXECUTION", actor: party });
        return err ?? jsonReply(200, renderPartyResponse(rec, party));
      }

      return jsonReply(404, { code: "NOT_FOUND", detail: `unhandled subroute ${sub}` });
    } catch (err) {
      return jsonReply(500, { code: "INTERNAL", detail: (err as Error).message });
    }
  };

  const customFetch: typeof globalThis.fetch = async (input, init) => {
    const reqUrl = typeof input === "string" ? input : input instanceof URL ? input.toString() : input.url;
    const method = init?.method ?? (input instanceof Request ? input.method : "GET");
    const hdrs: Record<string, string> = {};
    const srcHeaders = init?.headers ?? (input instanceof Request ? input.headers : undefined);
    if (srcHeaders) {
      new Headers(srcHeaders).forEach((val, key) => {
        hdrs[key] = val;
      });
    }
    let bodyStr = "";
    if (typeof init?.body === "string") {
      bodyStr = init.body;
    } else if (init?.body instanceof Uint8Array) {
      bodyStr = Buffer.from(init.body).toString("utf8");
    }
    const reply = handle(method, reqUrl, hdrs, bodyStr);
    return new Response(reply.body, { status: reply.status, headers: reply.headers });
  };

  return { baseUrl, platformKey, handle, fetch: customFetch };
}

async function callMcpJson(mcpClient: Client, name: string, args: Record<string, unknown> = {}): Promise<Record<string, unknown>> {
  const res = await mcpClient.callTool({ name, arguments: args });
  const content = Array.isArray(res.content) ? res.content : [];
  const textBlock = content.find((c): c is { type: "text"; text: string } => c?.type === "text" && typeof c.text === "string");
  if (!textBlock) {
    throw new Error(`MCP tool ${name} returned no text payload`);
  }
  if (res.isError) {
    throw new Error(`MCP tool ${name} failed: ${textBlock.text}`);
  }
  return JSON.parse(textBlock.text) as Record<string, unknown>;
}

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const offline = args.includes("--offline");
  const saveIdx = args.indexOf("--save-outcome");
  const saveOutcomePath = saveIdx >= 0 ? args[saveIdx + 1] : undefined;

  let offlineMediator: OfflineMediator | undefined;
  let baseUrl: string;
  let platformDid: string;
  let expectedEnv: string | undefined;

  if (offline) {
    offlineMediator = createOfflineReferenceMediator();
    baseUrl = offlineMediator.baseUrl;
    platformDid = offlineMediator.platformKey.did;
    expectedEnv = "development";
  } else {
    baseUrl = normalizeBaseUrl(process.env.AGENT_MEDIATE_URL ?? PRODUCTION_API_URL);
    const defaultPinned = DEFAULT_PRODUCTION_PLATFORM_DIDS[baseUrl];
    platformDid = (process.env.AGENT_MEDIATE_PLATFORM_DID ?? defaultPinned ?? "").trim();
    if (!platformDid) {
      const platformInfo = (await (await fetch(`${baseUrl}/v1/platform`)).json()) as { did: string };
      platformDid = platformInfo.did;
    }
    expectedEnv = process.env.AGENT_MEDIATE_EXPECTED_ENV ?? (baseUrl === PRODUCTION_API_URL ? "production" : undefined);
  }

  const workDir = mkdtempSync(join(tmpdir(), "am-e2e-demo-"));
  const vendorKeyFile = join(workDir, "vendor-ed25519.pem");

  const t0 = performance.now();
  const elapsed = () => `${((performance.now() - t0) / 1000).toFixed(2)}s`;

  console.log(`==> Agent-Mediate Cross-Language E2E Demo (${offline ? "offline reference engine" : baseUrl})`);
  console.log(`    Platform DID:  ${platformDid}`);
  console.log(`    Mechanism:     RULES_HASH=${RULES_HASH.slice(0, 16)}... (v${RULES_VERSION})`);

  const buyer = startPythonBuyerWorker(offlineMediator?.handle);
  const vendorMcp = new Client({ name: "vendor-sla-agent", version: "0.1.0" }, { capabilities: {} });
  let inMemoryMcpServer: ReturnType<typeof createMcpServer> | undefined;

  try {
    let connectVendorPromise: Promise<void>;
    if (offlineMediator) {
      const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
      const vendorSdkClient = new AgentMediateClient({
        baseUrl,
        agentKey: generateAgentKey(),
        platformDid,
        expectedEnvironment: expectedEnv,
        expectedRulesHash: RULES_HASH,
        defaultView: "compact",
        fetch: offlineMediator.fetch,
      });
      inMemoryMcpServer = createMcpServer(vendorSdkClient, {
        ...(expectedEnv ? { expectedEnvironment: expectedEnv } : {}),
        expectedRulesHash: RULES_HASH,
      });
      connectVendorPromise = Promise.all([
        inMemoryMcpServer.connect(serverTransport),
        vendorMcp.connect(clientTransport),
      ]).then(() => undefined);
    } else {
      const mcpTransport = new StdioClientTransport({
        command: process.execPath,
        args: [MCP_SERVER_DIST],
        env: {
          ...(process.env as Record<string, string>),
          AGENT_MEDIATE_URL: baseUrl,
          AGENT_MEDIATE_AGENT_KEY_FILE: vendorKeyFile,
          AGENT_MEDIATE_PLATFORM_DID: platformDid,
          AGENT_MEDIATE_EXPECTED_RULES_HASH: RULES_HASH,
          ...(expectedEnv ? { AGENT_MEDIATE_EXPECTED_ENV: expectedEnv } : {}),
        },
        stderr: "pipe",
      });
      connectVendorPromise = vendorMcp.connect(mcpTransport);
    }

    const [buyerInit] = await Promise.all([
      buyer.call<{ buyerDid: string; buyerPrincipalDid: string }>("init", {
        baseUrl,
        platformDid,
        stdioHttpBridge: Boolean(offlineMediator),
        ...(expectedEnv ? { expectedEnvironment: expectedEnv } : {}),
      }),
      connectVendorPromise,
    ]);
    const vendorWhoami = await callMcpJson(vendorMcp, "whoami");
    const vendorDid = String(vendorWhoami.did);

    console.log(`[${elapsed()}] 1. Identities ready`);
    console.log(`           Buyer  (Python / agent-mediate):   ${buyerInit.buyerDid}`);
    console.log(`           Vendor (TS / @agent-mediate/mcp):  ${vendorDid}`);

    // 1. Co-sign pre-dispute SLA clause across Python <-> MCP
    const contract = {
      service: "Inference Gateway v2",
      monthlyFeeUsd: 1000,
      uptimeSla: 0.999,
      creditCapUsd: 1000,
    };
    const drafted = await buyer.call<{ contractHash: string; clause: Record<string, unknown> }>("draft_clause", {
      contract,
      vendorDid,
    });
    const vendorCosigned = await callMcpJson(vendorMcp, "sign_dispute_clause", {
      existingClause: drafted.clause,
    });
    const cosignedClause = unwrapUntrusted(vendorCosigned) as Record<string, unknown>;
    await buyer.call("verify_clause", {
      clause: cosignedClause,
      contractHash: drafted.contractHash,
      vendorDid,
    });
    console.log(`[${elapsed()}] 2. Co-signed agent-mediate/clause/v1 verified (contractHash=${drafted.contractHash.slice(0, 16)}...)`);

    // 2. Python Buyer files dispute ($0.00 Mode A); MCP Vendor joins ($0.00)
    const filed = await buyer.call<{ disputeId: string; notice?: { noticeUrl?: string } }>("file_dispute", {
      vendorDid,
      contractHash: drafted.contractHash,
      clause: cosignedClause,
    });
    const disputeId = filed.disputeId;
    await callMcpJson(vendorMcp, "join_dispute", {
      disputeId,
      bounds: { refundUsd: { min: 0, max: 650 } },
      determinationConsent: true,
    });
    console.log(`[${elapsed()}] 3. Dispute ${disputeId} filed & joined ($0.00 fees, zero wallet custody)`);

    // 3. Both agents submit SHA-256 evidence hashes and close evidence
    await Promise.all([
      buyer.call("submit_evidence", { disputeId }),
      (async () => {
        await callMcpJson(vendorMcp, "submit_evidence", {
          disputeId,
          items: [
            {
              id: "vendor-lb-incident-report",
              kind: "incident-log",
              description: "Upstream load-balancer failover log confirming 47m degraded routing window.",
              content: "incident=INC-2026-1115 duration_min=47 impacted_routes=/v1/completions",
            },
          ],
        });
        await callMcpJson(vendorMcp, "close_evidence", { disputeId });
      })(),
    ]);

    // 4. Both agents confirm the canonical issue set
    const vendorIssueView = await callMcpJson(vendorMcp, "get_dispute", { disputeId });
    const proposedHash = ((vendorIssueView.view as Record<string, unknown>).issueNegotiation as { proposedHash: string })
      .proposedHash;
    await Promise.all([
      buyer.call("confirm_issues", { disputeId }),
      callMcpJson(vendorMcp, "confirm_issues", { disputeId, issuesHash: proposedHash }),
    ]);
    console.log(`[${elapsed()}] 4. Evidence closed & issue grid locked (issuesHash=${proposedHash.slice(0, 16)}...)`);

    // 5. Round 1 sealed offers: Buyer demands $650 (private walkaway $360); Vendor offers $420 (private walkaway $560)
    await Promise.all([
      buyer.call("round1_offer", { disputeId }),
      callMcpJson(vendorMcp, "submit_offer", {
        disputeId,
        round: 1,
        offer: { refundUsd: 420 },
        weights: { refundUsd: 1 },
        walkaway: { refundUsd: 560 },
      }),
    ]);

    // 6. Round 2: Platform proposes confidential split inside [$360, $560]; both accept without learning walkaways
    const vendorR2 = await callMcpJson(vendorMcp, "get_dispute", { disputeId });
    const r2View = vendorR2.view as {
      bargaining?: { openProposal?: { terms?: { refundUsd?: number } } };
      proposalWithinYourMandate?: boolean;
      proposalMeetsYourWalkaway?: boolean;
    };
    const proposedRefund = r2View.bargaining?.openProposal?.terms?.refundUsd;
    console.log(
      `[${elapsed()}] 5. Sealed offers evaluated -> confidential proposal: $${proposedRefund} USD (walkaways $360 & $560 stay private)`,
    );

    await Promise.all([
      buyer.call("round2_respond", { disputeId }),
      callMcpJson(vendorMcp, "submit_offer", {
        disputeId,
        round: 2,
        offer: { refundUsd: 440 },
        proposalResponse: r2View.proposalWithinYourMandate && r2View.proposalMeetsYourWalkaway ? "accept" : "reject",
      }),
    ]);

    // 7. Vendor submits execution proof; Buyer confirms; BOTH verify identical Ed25519 outcome + audit head
    await callMcpJson(vendorMcp, "submit_execution_proof", {
      disputeId,
      reference: "credit_memo_CRD-2026-1117-8841",
    });

    const buyerVerified = await buyer.call<{
      outcome: { document: { terms: { refundUsd: number }; method: string; executionStatus: string; auditRoot: string } };
      auditHead: string;
      auditEntries: number;
      redactedCounterpartyLinks: number;
    }>("confirm_and_verify", { disputeId });

    const [vendorOutcome, vendorAudit] = await Promise.all([
      callMcpJson(vendorMcp, "get_outcome", { disputeId }),
      callMcpJson(vendorMcp, "verify_audit", { disputeId }),
    ]);
    if (buyerVerified.auditHead !== String(vendorAudit.head)) {
      throw new Error(`Audit head mismatch: buyer=${buyerVerified.auditHead} vs vendor=${String(vendorAudit.head)}`);
    }

    const doc = buyerVerified.outcome.document;
    console.log(`[${elapsed()}] 6. Settlement HONORED & dual-verified in Python + MCP!`);
    console.log(`           Method:          ${doc.method} (executionStatus=${doc.executionStatus})`);
    console.log(`           Settled Terms:   refundUsd = $${doc.terms.refundUsd} USD`);
    console.log(`           Audit Chain:     ${buyerVerified.auditEntries} entries (${buyerVerified.redactedCounterpartyLinks} counterparty-redacted links), head=${buyerVerified.auditHead.slice(0, 16)}...`);
    console.log(`           MCP Audit Head:  ${String(vendorAudit.head).slice(0, 16)}... (verified=${String(vendorOutcome.verified)})`);
    console.log(`           Browser Verify:  https://ai-agents-mediation.com/verify`);

    if (saveOutcomePath) {
      writeFileSync(saveOutcomePath, JSON.stringify(buyerVerified.outcome, null, 2) + "\n");
      console.log(`           Saved signed outcome JSON to ${saveOutcomePath}`);
    }
  } finally {
    await Promise.allSettled([buyer.close(), vendorMcp.close(), inMemoryMcpServer?.close()]);
    rmSync(workDir, { recursive: true, force: true });
  }
}

await main();
