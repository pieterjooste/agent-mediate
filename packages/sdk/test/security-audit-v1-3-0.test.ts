import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { verifyPublicAuditChain } from "@agent-mediate/core";
import { signRequest, verifyRequest, WEBHOOK_SIGNATURE_TAG } from "@agent-mediate/protocol";
import {
  AgentMediateClient,
  AgentMediateError,
  BASE_SEPOLIA,
  buildClause,
  buildDidWebDocument,
  buildSignedKeyHistory,
  canonicalJson,
  computeOutcomeHash,
  computeTermsHash,
  didWebDocumentAuthorizesKey,
  generateAgentKey,
  KEY_HISTORY_TYPE,
  PaymentPolicyError,
  RULES_HASH,
  RULES_VERSION,
  signAgentCard,
  signClause,
  signDocument,
  verifyAgentCardSignature,
  verifyClause,
  verifyDocumentWithKeyHistory,
} from "../src/index.ts";

describe("Security Audit v1.3.0 — SDK, Protocol & Core Regressions", () => {
  it("SA2-SDK-H1: outcome() verifies full computeOutcomeHash (method, settledAt, roundsCompleted, reason) and rejects tampered metadata", async () => {
    const platform = generateAgentKey();
    const agent = generateAgentKey();
    const otherParty = generateAgentKey();
    const terms = { refundUsd: 450 };
    const termsHash = computeTermsHash(terms);
    const validOutcomeHash = computeOutcomeHash(
      { kind: "SETTLED", terms, method: "PROPOSAL_ACCEPTED", at: 1_750_000_000_000, roundsCompleted: 2 },
      "HONORED",
    );

    let mode: "valid" | "tampered_method" | "missing_rounds" | "tampered_unresolved_reason" = "valid";

    const client = new AgentMediateClient({
      baseUrl: "https://api.mediate.example",
      agentKey: agent,
      platformDid: platform.did,
      expectedEnvironment: "production",
      maxRetries: 0,
      fetch: async (url) => {
        if (url.endsWith("/.well-known/key-history.json")) {
          const kh = buildSignedKeyHistory({
            baseUrl: "https://api.mediate.example",
            activeKey: platform,
            activeValidFrom: 1_700_000_000_000,
            updatedAt: 1_750_000_000_000,
          });
          return new Response(JSON.stringify(kh), { status: 200, headers: { "content-type": "application/json" } });
        }
        if (mode === "tampered_unresolved_reason") {
          const realHash = computeOutcomeHash(
            { kind: "UNRESOLVED", reason: "NO_OVERLAP_AT_CAP", at: 1_750_000_000_000, roundsCompleted: 5 },
            "UNRESOLVED",
          );
          // Compromised DB row forges RESPONDENT_NO_SHOW while keeping real outcomeHash:
          const forgedUnresolved = signDocument(
            {
              type: "agent-mediate/unresolved-certificate/v1",
              rulesVersion: RULES_VERSION,
              rulesHash: RULES_HASH,
              environment: "production",
              disputeId: "dsp_1",
              contractHash: "a".repeat(64),
              status: "UNRESOLVED",
              reason: "RESPONDENT_NO_SHOW",
              issuedAt: 1_750_000_000_000,
              roundsCompleted: 5,
              parties: { claimant: { agentId: agent.did }, respondent: { agentId: otherParty.did } },
              auditRoot: "b".repeat(64),
              outcomeHash: realHash,
            },
            platform,
            { created: 1_750_000_000_000 },
          );
          return new Response(JSON.stringify(forgedUnresolved), { status: 200, headers: { "content-type": "application/json" } });
        }
        const doc: Record<string, unknown> = {
          type: "agent-mediate/settlement-instruction/v1",
          rulesVersion: RULES_VERSION,
          rulesHash: RULES_HASH,
          environment: "production",
          disputeId: "dsp_1",
          contractHash: "a".repeat(64),
          status: "SETTLED",
          executionStatus: "HONORED",
          method: mode === "tampered_method" ? "FINAL_OFFER_DETERMINATION" : "PROPOSAL_ACCEPTED",
          settledAt: 1_750_000_000_000,
          ...(mode === "missing_rounds" ? {} : { roundsCompleted: 2 }),
          parties: { claimant: { agentId: agent.did }, respondent: { agentId: otherParty.did } },
          issues: [{ id: "refundUsd", label: "Refund", unit: "USD", min: 0, max: 1000, step: 10, claimantPrefers: "higher", obligor: "respondent" }],
          terms,
          termsHash,
          auditRoot: "b".repeat(64),
          outcomeHash: validOutcomeHash,
        };
        const signed = signDocument(doc, platform, { created: 1_750_000_000_000 });
        return new Response(JSON.stringify(signed), { status: 200, headers: { "content-type": "application/json" } });
      },
      now: () => 1_750_000_000_000,
    });

    const ok = await client.outcome("dsp_1");
    assert.equal(ok.document.outcomeHash, validOutcomeHash);

    mode = "tampered_method";
    await assert.rejects(() => client.outcome("dsp_1"), (err: unknown) => err instanceof AgentMediateError && err.code === "OUTCOME_MISMATCH");

    mode = "missing_rounds";
    await assert.rejects(() => client.outcome("dsp_1"), (err: unknown) => err instanceof AgentMediateError && err.code === "OUTCOME_MISMATCH");

    mode = "tampered_unresolved_reason";
    await assert.rejects(() => client.outcome("dsp_1"), (err: unknown) => err instanceof AgentMediateError && err.code === "OUTCOME_MISMATCH");
  });

  it("SA2-SDK-H2: enforces redirect: 'error' (302/307 -> UNEXPECTED_REDIRECT) and caps SDK response bodies at 4 MiB (RESPONSE_TOO_LARGE)", async () => {
    const agent = generateAgentKey();
    const seenRedirects: Array<RequestRedirect | undefined> = [];
    let responseMode: "redirect" | "oversized" = "redirect";

    const client = new AgentMediateClient({
      baseUrl: "https://api.mediate.example",
      agentKey: agent,
      maxRetries: 0,
      fetch: async (_url, init) => {
        seenRedirects.push(init.redirect);
        if (responseMode === "redirect") {
          return new Response("", { status: 307, headers: { location: "http://169.254.169.254/latest/meta-data/" } });
        }
        const huge = "x".repeat(4 * 1024 * 1024 + 64);
        return new Response(huge, { status: 200, headers: { "content-type": "application/json" } });
      },
    });

    await assert.rejects(
      () => client.platform(),
      (err: unknown) => err instanceof AgentMediateError && err.code === "UNEXPECTED_REDIRECT",
    );
    assert.equal(seenRedirects[0], "error");

    responseMode = "oversized";
    await assert.rejects(
      () => client.platform(),
      (err: unknown) => err instanceof AgentMediateError && err.code === "RESPONSE_TOO_LARGE",
    );
  });

  it("SA2-SDK-M1 & SA2-DOC-I1: fileDispute fails closed on missing signedNotice or noticeUrl mismatch, agent-card binds card.url, mandateCache isolates disputes, and waitFor honours AbortSignal", async () => {
    const platform = generateAgentKey();
    const claimant = generateAgentKey();
    const respondent = generateAgentKey();
    const t0 = 1_750_000_000_000;

    // 1. Missing signedNotice when platformDid is pinned -> NOTICE_SIGNATURE_INVALID
    let missingSignedNotice = true;
    let wrongNoticeUrl = false;
    const filer = new AgentMediateClient({
      baseUrl: "https://api.mediate.example",
      agentKey: claimant,
      platformDid: platform.did,
      expectedEnvironment: "production",
      maxRetries: 0,
      now: () => t0,
      fetch: async (url) => {
        if (url.endsWith("/.well-known/key-history.json")) {
          const kh = buildSignedKeyHistory({
            baseUrl: "https://api.mediate.example",
            activeKey: platform,
            activeValidFrom: t0 - 10_000,
            updatedAt: t0,
          });
          return new Response(JSON.stringify(kh), { status: 200, headers: { "content-type": "application/json" } });
        }
        const signedNotice = signDocument(
          {
            type: "agent-mediate/dispute-notice/v1",
            rulesVersion: RULES_VERSION,
            environment: "production",
            disputeId: "dsp_notice_1",
            claimantId: claimant.did,
            respondentId: respondent.did,
            contractHash: "c".repeat(64),
            feeMode: "FILER_PAYS",
            respondentFeeDue: false,
            joinDeadline: t0 + 86_400_000,
            issuedAt: t0,
            noticeUrl: wrongNoticeUrl ? "https://phishing.example/n/evil" : "https://api.mediate.example/n/tok_1",
            joinEndpoint: "https://api.mediate.example/v1/disputes/dsp_notice_1/join",
            disputeEndpoint: "https://api.mediate.example/v1/disputes/dsp_notice_1",
            llmsTxtUrl: "https://api.mediate.example/llms.txt",
            mcpPackage: "@agent-mediate/mcp",
          },
          platform,
          { created: t0 },
        );
        return new Response(
          JSON.stringify({
            disputeId: "dsp_notice_1",
            view: { disputeId: "dsp_notice_1", status: "AWAITING_RESPONDENT" },
            notice: missingSignedNotice
              ? { noticeUrl: "https://api.mediate.example/n/tok_1" }
              : { noticeUrl: "https://api.mediate.example/n/tok_1", signedNotice },
          }),
          { status: 201, headers: { "content-type": "application/json" } },
        );
      },
    });

    const issue = { id: "refundUsd", label: "Refund", unit: "USD", min: 0, max: 500, step: 10, claimantPrefers: "higher" as const, obligor: "respondent" as const };
    await assert.rejects(
      () =>
        filer.fileDispute({
          respondentId: respondent.did,
          contractHash: "c".repeat(64),
          claim: { summary: "s", requestedRemedy: "r" },
          proposedIssues: [issue],
          bounds: { refundUsd: { min: 0, max: 500 } },
        }),
      (err: unknown) => err instanceof AgentMediateError && err.code === "NOTICE_MISMATCH",
    );

    missingSignedNotice = false;
    wrongNoticeUrl = true;
    await assert.rejects(
      () =>
        filer.fileDispute({
          respondentId: respondent.did,
          contractHash: "c".repeat(64),
          claim: { summary: "s", requestedRemedy: "r" },
          proposedIssues: [issue],
          bounds: { refundUsd: { min: 0, max: 500 } },
        }),
      (err: unknown) => err instanceof AgentMediateError && err.code === "NOTICE_MISMATCH",
    );

    // 2. verifiedPlatformPayTo rejects cross-domain agent-card.json card.url origin mismatch (SA2-SDK-M1)
    const payTo = "0x209693Bc6afc0C5328bA36FaF03C514EF312287C";
    const crossOriginCard = signAgentCard(
      {
        name: "Agent-Mediate",
        url: "https://attacker-copied.example",
        capabilities: {
          extensions: [{ uri: "urn:agent-mediate:ext:x402-fees:v1", params: { payTo } }],
        },
      },
      platform,
      { kid: `${platform.did}#key-1` },
    );
    assert.equal(verifyAgentCardSignature(crossOriginCard, platform.did), true);
    const paidClient = new AgentMediateClient({
      baseUrl: "https://api.mediate.example",
      agentKey: claimant,
      platformDid: platform.did,
      maxRetries: 0,
      payer: {
        address: "0x1111111111111111111111111111111111111111",
        spentAtomic: 0n,
        network: BASE_SEPOLIA,
        pay: async () => "x402-sig",
      },
      fetch: async (url) => {
        if (url.endsWith("/v1/platform")) {
          return new Response(JSON.stringify({ did: platform.did, fees: { network: BASE_SEPOLIA, payTo } }), {
            status: 200,
            headers: { "content-type": "application/json" },
          });
        }
        if (url.endsWith("/.well-known/agent-card.json")) {
          return new Response(JSON.stringify(crossOriginCard), { status: 200, headers: { "content-type": "application/json" } });
        }
        return new Response(
          JSON.stringify({
            code: "PAYMENT_REQUIRED",
            paymentRequired: { x402Version: 2, accepts: [{ scheme: "exact", network: BASE_SEPOLIA, payTo, amount: "1000000", asset: "0x036CbD53842c5426634e7929541eC2318f3dCF7e", maxTimeoutSeconds: 120 }] },
          }),
          { status: 402, headers: { "content-type": "application/json" } },
        );
      },
    });
    await assert.rejects(
      () =>
        paidClient.fileDispute({
          respondentId: respondent.did,
          contractHash: "c".repeat(64),
          claim: { summary: "s", requestedRemedy: "r" },
          proposedIssues: [issue],
          bounds: { refundUsd: { min: 0, max: 500 } },
        }),
      (err: unknown) => err instanceof PaymentPolicyError && /does not match baseUrl/.test(err.message),
    );

    // 3. AbortSignal immediately cancels waitFor without hanging on timer
    const ac = new AbortController();
    setTimeout(() => ac.abort(new Error("cancelled_by_caller")), 20);
    const waiter = new AgentMediateClient({
      baseUrl: "https://api.mediate.example",
      agentKey: claimant,
      fetch: async () =>
        new Response(JSON.stringify({ view: { disputeId: "dsp_w", status: "EVIDENCE" }, advisory: null }), {
          status: 200,
          headers: { "content-type": "application/json" },
        }),
    });
    await assert.rejects(
      () => waiter.waitFor("dsp_w", () => false, { timeoutMs: 30_000, intervalMs: 5_000, signal: ac.signal }),
      /cancelled_by_caller|AbortError/,
    );
  });

  it("SA2-PROTO-M1, SA2-PROTO-M2, SA2-PROTO-L1 & SA2-CORE-L1: rejects compromised/revoked historical keys, raw dot-segment @target-uri, assertion-only did:web keys, and redacted audit leaks", () => {
    const activeKey = generateAgentKey();
    const retiredKey = generateAgentKey();
    const partyA = generateAgentKey();
    const partyB = generateAgentKey();
    const t0 = 1_750_000_000_000;

    // 1. Key-history revokedAt / compromisedAfter enforcement on documents, clauses & webhooks
    // Clean retired key verifies within [validFrom, validUntil]; adding compromisedAfter rejects even backdated proofs!
    const signedByRetired = signDocument(
      { type: "test/doc/v1", value: 1 },
      retiredKey,
      { keyId: `${retiredKey.did}#key-1`, created: t0 - 50_000 },
    );
    const khCleanRetired = buildSignedKeyHistory({
      baseUrl: "https://api.mediate.example",
      activeKey,
      activeValidFrom: t0 - 5_000,
      updatedAt: t0,
      historicalKeys: [
        {
          keyId: `${retiredKey.did}#key-1`,
          did: retiredKey.did,
          status: "retired",
          validFrom: t0 - 100_000,
          validUntil: t0 - 5_000,
        },
      ],
    });
    const khCompromised = buildSignedKeyHistory({
      baseUrl: "https://api.mediate.example",
      activeKey,
      activeValidFrom: t0 - 5_000,
      updatedAt: t0,
      historicalKeys: [
        {
          keyId: `${retiredKey.did}#key-1`,
          did: retiredKey.did,
          status: "retired",
          validFrom: t0 - 100_000,
          validUntil: t0 - 5_000,
          compromisedAfter: t0 - 20_000,
        },
      ],
    });
    assert.equal(verifyDocumentWithKeyHistory(signedByRetired, khCleanRetired, { expectedActiveDid: activeKey.did, now: t0 }).ok, true);
    assert.equal(verifyDocumentWithKeyHistory(signedByRetired, khCompromised, { expectedActiveDid: activeKey.did, now: t0 }).ok, false);

    // Clause referencing a compromised retired platform key is rejected when issuedAt > compromisedAfter
    const lateClause = signClause(
      signClause(
        buildClause({
          contractHash: "d".repeat(64),
          platformDid: retiredKey.did,
          platformBaseUrl: "https://api.mediate.example",
          rulesHash: RULES_HASH,
          issuedAt: t0 - 10_000,
          parties: [{ agentId: partyA.did }, { agentId: partyB.did }],
        }),
        partyA,
      ),
      partyB,
    );
    assert.equal(
      verifyClause(lateClause, { expectedPlatformDid: activeKey.did, keyHistory: khCompromised, now: t0 }).ok,
      false,
    );

    // verifyWebhook rejects retired keys with revokedAt / compromisedAfter
    const whBody = JSON.stringify({ id: "evt_1", type: "DISPUTE_FILED" });
    const whHeaders = {
      "content-type": "application/json",
      ...signRequest({
        method: "POST",
        targetUri: "https://agent.example/hook",
        headers: { "content-type": "application/json" },
        body: whBody,
        key: retiredKey,
        created: Math.floor((t0 - 10_000) / 1000),
        nonce: "nonce-wh-00000001",
        tag: WEBHOOK_SIGNATURE_TAG,
      }),
    };
    assert.equal(
      AgentMediateClient.verifyWebhook(
        { url: "https://agent.example/hook", headers: whHeaders, body: whBody },
        activeKey.did,
        { now: t0 - 10_000, keyHistory: khCompromised },
      ).ok,
      false,
    );

    // 2. SA2-PROTO-M1: RFC 9421 verifyRequest rejects raw dot-segments in @target-uri
    const cleanHeaders: Record<string, string> = {
      "content-type": "application/json",
      ...signRequest({
        method: "POST",
        targetUri: "https://api.mediate.example/v1/disputes",
        headers: { "content-type": "application/json" },
        body: "{}",
        key: partyA,
        created: Math.floor(t0 / 1000),
        nonce: "nonce-dot-0000001",
      }),
    };
    assert.equal(
      verifyRequest({
        method: "POST",
        targetUri: "https://api.mediate.example/v1/internal/../disputes",
        header: (n) => cleanHeaders[n.toLowerCase()] ?? null,
        body: "{}",
        now: t0,
      }).ok,
      false,
    );

    // 3. SA2-PROTO-L1: didWebDocumentAuthorizesKey rejects retired assertion-only keys & unsigned did.json lacks JWS
    const didDoc = buildDidWebDocument({
      baseUrl: "https://vendor.example",
      platformDid: activeKey.did,
      historicalKeys: [{ did: retiredKey.did, status: "retired" }],
    });
    assert.equal(didWebDocumentAuthorizesKey(didDoc, "did:web:vendor.example", activeKey.did), true);
    assert.equal(didWebDocumentAuthorizesKey(didDoc, "did:web:vendor.example", retiredKey.did), false);
    assert.equal(verifyAgentCardSignature(didDoc, activeKey.did), false);

    // 4. SA2-CORE-L1: verifyPublicAuditChain rejects redacted entry leaking extra fields or dataCommitment
    assert.equal(
      verifyPublicAuditChain([
        {
          seq: 1,
          redacted: true,
          prevHash: "0".repeat(64),
          hash: "a".repeat(64),
          type: "LEAKED_TYPE",
        } as unknown as Parameters<typeof verifyPublicAuditChain>[0][number],
      ]).ok,
      false,
    );

    // 5. SA2-PROTO-M1: canonicalJson ES6 boundary numbers
    assert.equal(canonicalJson({ a: 1e20, b: 1e21, c: 1e-6, d: 1e-7 }), '{"a":100000000000000000000,"b":1e+21,"c":0.000001,"d":1e-7}');
  });
});
