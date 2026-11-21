import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  apply,
  createDispute,
  findLeaks,
  issuesHash,
  validateMandateShape,
  verifyPublicAuditChain,
} from "@agent-mediate/core";
import {
  signKeyRotation,
  signMandate,
  signRequest,
  validateIssuesAgainstClauseTemplates,
  verifyDisputeActionTarget,
  verifyKeyHistory,
  verifyRequest,
  WEBHOOK_SIGNATURE_TAG,
} from "@agent-mediate/protocol";
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
  discoverRespondent,
  DISPUTE_NOTICE_TYPE,
  ed25519PublicJwkFromDidKey,
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

  it("Batch 2 (v0.1.2) regressions: H-04, H-05, M-09a/b/c, M-11a/b/c, L-08, L-09", async () => {
    const kOld = generateAgentKey();
    const kNew = generateAgentKey();
    const kAttacker = generateAgentKey();
    const claimant = generateAgentKey();
    const respondent = generateAgentKey();
    const t0 = 1_800_000_000_000;
    const payTo = "0x1111111111111111111111111111111111111111";

    // --- H-04 & H-05: Paid filing after K_old -> K_new rotation + paymentSent / releaseUnsettled on definitive rejections ---
    const khRotated = buildSignedKeyHistory({
      baseUrl: "https://api.mediate.example",
      activeKey: kNew,
      activeValidFrom: t0 + 1_000,
      updatedAt: t0 + 1_000,
      historicalKeys: [
        {
          keyId: `${kOld.did}#key-1`,
          did: kOld.did,
          status: "retired",
          validFrom: t0 - 86_400_000,
          validUntil: t0 + 1_000,
          rotationEndorsement: signKeyRotation({
            baseUrl: "https://api.mediate.example",
            fromKey: kOld,
            toDid: kNew.did,
            rotatedAt: t0 + 1_000,
          }),
        },
      ],
    });
    const signedCardNew = signAgentCard(
      {
        name: "Agent-Mediate",
        url: "https://api.mediate.example",
        provider: { organization: "Agent-Mediate", url: "https://api.mediate.example" },
        capabilities: {
          extensions: [
            { uri: "urn:agent-mediate:ext:rest-api:v1", params: { baseUrl: "https://api.mediate.example" } },
            { uri: "urn:agent-mediate:ext:x402-fees:v1", params: { payTo } },
          ],
        },
      },
      kNew,
      { kid: "did:web:api.mediate.example#key-1" },
    );

    const releasedSigs: string[] = [];
    let payCalls = 0;
    let paidMode: "ok" | "reject_402" | "reject_422" | "ambiguous_503" | "attacker_card" = "ok";
    const challengeB64 = Buffer.from(
      JSON.stringify({
        x402Version: 2,
        accepts: [{ scheme: "exact", network: BASE_SEPOLIA, amount: "2000000", payTo }],
      }),
      "utf8",
    ).toString("base64");

    const makePaidClient = () =>
      new AgentMediateClient({
        baseUrl: "https://api.mediate.example",
        agentKey: claimant,
        platformDid: kOld.did,
        expectedEnvironment: "production",
        now: () => t0 + 5_000,
        maxRetries: 0,
        payer: {
          address: "0x2222222222222222222222222222222222222222",
          network: BASE_SEPOLIA,
          get spentAtomic() {
            return 0n;
          },
          pay: async (_ch, policy) => {
            assert.equal(policy.operation, "file");
            assert.equal(policy.expectedPayTo?.toLowerCase(), payTo.toLowerCase());
            return `mock-pay-sig-${++payCalls}`;
          },
          releaseUnsettled: (sig) => {
            releasedSigs.push(sig);
          },
        },
        fetch: async (url, init) => {
          if (url.endsWith("/v1/platform")) {
            return new Response(
              JSON.stringify({
                did: kNew.did,
                rulesVersion: RULES_VERSION,
                rulesHash: RULES_HASH,
                fees: { payTo, network: BASE_SEPOLIA, fullFeeAtomic: "2000000" },
              }),
              { status: 200, headers: { "content-type": "application/json" } },
            );
          }
          if (url.endsWith("/.well-known/key-history.json")) {
            return new Response(JSON.stringify(khRotated), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          }
          if (url.endsWith("/.well-known/agent-card.json")) {
            const card =
              paidMode === "attacker_card"
                ? signAgentCard(
                    { name: "Forged", url: "https://api.mediate.example" },
                    kAttacker,
                    { kid: kAttacker.did },
                  )
                : signedCardNew;
            return new Response(JSON.stringify(card), {
              status: 200,
              headers: { "content-type": "application/json" },
            });
          }
          if (url.endsWith("/v1/disputes")) {
            if (!init.headers["payment-signature"]) {
              return new Response(JSON.stringify({ code: "PAYMENT_REQUIRED" }), {
                status: 402,
                headers: { "content-type": "application/json", "payment-required": challengeB64 },
              });
            }
            if (paidMode === "reject_402") {
              return new Response(JSON.stringify({ code: "INVALID_PAYMENT", detail: "bad signature" }), {
                status: 402,
                headers: { "content-type": "application/json" },
              });
            }
            if (paidMode === "reject_422") {
              return new Response(JSON.stringify({ code: "INVALID_MANDATE", detail: "mandate rejected" }), {
                status: 422,
                headers: { "content-type": "application/json" },
              });
            }
            if (paidMode === "ambiguous_503") {
              return new Response(JSON.stringify({ code: "FACILITATOR_UNAVAILABLE", detail: "retry same key" }), {
                status: 503,
                headers: { "content-type": "application/json" },
              });
            }
            const signedNotice = signDocument(
              {
                type: DISPUTE_NOTICE_TYPE,
                disputeId: "dsp_rot_1",
                environment: "production",
                rulesVersion: RULES_VERSION,
                rulesHash: RULES_HASH,
                claimantId: claimant.did,
                respondentId: respondent.did,
                contractHash: "a".repeat(64),
                feeMode: "FILER_PAYS",
                respondentJoinFeeUsd: "0.00",
                joinDeadline: t0 + 86_400_000,
                noticeUrl: "https://api.mediate.example/n/tok_rot_1",
                issuedAt: t0 + 5_000,
              },
              kNew,
              { created: t0 + 5_000, expiresAt: t0 + 86_400_000 },
            );
            return new Response(
              JSON.stringify({
                disputeId: "dsp_rot_1",
                view: { status: "AWAITING_RESPONDENT" },
                notice: {
                  token: "tok_rot_1",
                  noticeUrl: "https://api.mediate.example/n/tok_rot_1",
                  signedNotice,
                  delivery: { delivered: false, attempts: [] },
                },
              }),
              { status: 201, headers: { "content-type": "application/json" } },
            );
          }
          return new Response("not found", { status: 404 });
        },
      });

    const fileInput = {
      respondentId: respondent.did,
      contractHash: "a".repeat(64),
      claim: { summary: "SLA breach", requestedRemedy: "Credit" },
      proposedIssues: [
        {
          id: "creditUsd",
          label: "Credit",
          unit: "USD",
          min: 0,
          max: 500,
          step: 25,
          claimantPrefers: "higher" as const,
          obligor: "respondent" as const,
        },
      ],
      bounds: { creditUsd: { min: 0, max: 500 } },
    };

    const paidOkClient = makePaidClient();
    const filed = await paidOkClient.fileDispute(fileInput, "idem-rot-ok");
    assert.equal(filed.disputeId, "dsp_rot_1");
    assert.equal(releasedSigs.length, 0);

    paidMode = "attacker_card";
    await assert.rejects(() => makePaidClient().fileDispute(fileInput, "idem-rot-atk"), PaymentPolicyError);

    paidMode = "reject_402";
    await assert.rejects(
      () => makePaidClient().fileDispute(fileInput, "idem-rej-402"),
      (err: unknown) => {
        assert.ok(err instanceof AgentMediateError);
        assert.equal(err.code, "INVALID_PAYMENT");
        assert.equal(err.paymentSent, false);
        return true;
      },
    );
    assert.equal(releasedSigs.length, 1);

    paidMode = "reject_422";
    const c422 = makePaidClient();
    await assert.rejects(
      () => c422.fileDispute(fileInput, "idem-rej-422"),
      (err: unknown) => {
        assert.ok(err instanceof AgentMediateError);
        assert.equal(err.code, "INVALID_MANDATE");
        assert.equal(err.paymentSent, false);
        return true;
      },
    );
    assert.equal(releasedSigs.length, 2);

    paidMode = "ambiguous_503";
    await assert.rejects(
      () => makePaidClient().fileDispute(fileInput, "idem-amb-503"),
      (err: unknown) => {
        assert.ok(err instanceof AgentMediateError);
        assert.equal(err.code, "FACILITATOR_UNAVAILABLE");
        assert.equal(err.paymentSent, true);
        return true;
      },
    );
    assert.equal(releasedSigs.length, 2, "ambiguous 503 must NOT release unsettled payment");

    // --- M-09a: Bare Mandate guard on fileDispute, join, confirmIssues, updateMandate ---
    let bareHttpCalls = 0;
    const bareGuardClient = new AgentMediateClient({
      baseUrl: "https://api.mediate.example",
      agentKey: claimant,
      platformDid: kOld.did,
      expectedEnvironment: "production",
      fetch: async () => {
        bareHttpCalls++;
        return new Response("{}", { status: 200 });
      },
    });
    const bareMandate = signMandate(
      {
        id: "mnd_bare_1",
        principalId: claimant.did,
        agentId: claimant.did,
        bounds: { creditUsd: { min: 0, max: 500 } },
        issuedAt: t0,
        expiresAt: t0 + 86_400_000,
      },
      claimant,
    );
    await assert.rejects(
      () => bareGuardClient.confirmIssues("dsp_1", "b".repeat(64), bareMandate as unknown as Parameters<typeof bareGuardClient.confirmIssues>[2]),
      /pass \{ mandate \}, not a bare Mandate object/,
    );
    await assert.rejects(
      () => bareGuardClient.updateMandate("dsp_1", bareMandate as unknown as Parameters<typeof bareGuardClient.updateMandate>[1]),
      /pass \{ mandate \}, not a bare Mandate object/,
    );
    await assert.rejects(
      () => bareGuardClient.join("dsp_1", bareMandate as unknown as Parameters<typeof bareGuardClient.join>[1]),
      /pass \{ mandate \}, not a bare Mandate object/,
    );
    assert.equal(bareHttpCalls, 0);

    // --- M-09b: Real Fetch TypeError('fetch failed', { cause: Error('unexpected redirect') }) -> immediate UNEXPECTED_REDIRECT ---
    let redirectCalls = 0;
    const redirectClient = new AgentMediateClient({
      baseUrl: "https://api.mediate.example",
      agentKey: claimant,
      platformDid: kOld.did,
      expectedEnvironment: "production",
      maxRetries: 3,
      fetch: async () => {
        redirectCalls++;
        throw new TypeError("fetch failed", { cause: new Error("unexpected redirect") });
      },
    });
    await assert.rejects(
      () => redirectClient.platform(),
      (err: unknown) => err instanceof AgentMediateError && err.code === "UNEXPECTED_REDIRECT" && err.status === 302,
    );
    assert.equal(redirectCalls, 1, "redirect TypeError must fail immediately without backoff retries");

    await assert.rejects(
      () => redirectClient.listDisputes(),
      (err: unknown) =>
        err instanceof AgentMediateError && err.code === "UNEXPECTED_REDIRECT" && err.status === 302 && err.paymentSent === false,
    );
    assert.equal(redirectCalls, 2);

    // --- M-09c & L-08: discoverRespondent JSON-RPC binding + cross-origin Agent Card suppression ---
    const jsonRpcCard = signAgentCard(
      {
        name: "Vendor A2A",
        supportedInterfaces: [{ url: "https://vendor.example/a2a", protocolBinding: "JSON-RPC" }],
      },
      respondent,
      { kid: respondent.did },
    );
    const discJsonRpc = await discoverRespondent("vendor.example", {
      resolveHost: async () => [{ address: "93.184.216.34", family: 4 }],
      fetch: async (url) => {
        if (url === "https://vendor.example/.well-known/agent-card.json") {
          return new Response(JSON.stringify(jsonRpcCard), { status: 200 });
        }
        return new Response("not found", { status: 404 });
      },
    });
    assert.equal(discJsonRpc.respondentId, respondent.did);
    assert.equal(discJsonRpc.hasVerifiedNoticeChannel, true);
    assert.equal(discJsonRpc.recommendedAction, "file_dispute");

    const discForeign = await discoverRespondent("cold.example", {
      resolveHost: async () => [{ address: "93.184.216.34", family: 4 }],
      fetch: async (url) => {
        if (url === "https://cold.example/.well-known/agent-card.json") {
          return new Response(
            JSON.stringify({
              name: "Foreign Card",
              url: "https://evil.example/a2a",
              provider: { url: "https://evil.example", email: "evil@evil.example" },
            }),
            { status: 200 },
          );
        }
        if (url === "https://cold.example/.well-known/security.txt") {
          return new Response("Contact: mailto:security@cold.example\n", { status: 200 });
        }
        return new Response("not found", { status: 404 });
      },
    });
    assert.equal(discForeign.respondentContact.a2aCardUrl, undefined);
    assert.equal(discForeign.respondentContact.email, "security@cold.example");
    assert.deepEqual(discForeign.sources, ["security_txt"]);

    // --- M-11a: verifyClause forward rotation & revocation + rotatedAt > validUntil rejection ---
    const clauseOnOld = signClause(
      signClause(
        buildClause({
          contractHash: "c".repeat(64),
          platformDid: kOld.did,
          platformBaseUrl: "https://api.mediate.example",
          rulesHash: RULES_HASH,
          issuedAt: t0 - 10_000,
          parties: [{ agentId: claimant.did }, { agentId: respondent.did }],
        }),
        claimant,
      ),
      respondent,
    );
    assert.equal(
      verifyClause(clauseOnOld, { expectedPlatformDid: kOld.did, keyHistory: khRotated, now: t0 + 5_000 }).ok,
      true,
    );
    const khRevokedOld = signDocument(
      {
        type: KEY_HISTORY_TYPE,
        platformDidWeb: "did:web:api.mediate.example",
        activeDid: kNew.did,
        activeKeyId: `${kNew.did}#key-1`,
        updatedAt: t0 + 1_000,
        keys: [
          {
            keyId: `${kNew.did}#key-1`,
            did: kNew.did,
            publicKeyJwk: ed25519PublicJwkFromDidKey(kNew.did),
            status: "active" as const,
            validFrom: t0 + 1_000,
          },
          {
            keyId: `${kOld.did}#key-1`,
            did: kOld.did,
            publicKeyJwk: ed25519PublicJwkFromDidKey(kOld.did),
            status: "revoked" as const,
            validFrom: t0 - 86_400_000,
            revokedAt: t0 + 1_000,
          },
        ],
        rotations: khRotated.document.rotations,
      },
      kNew,
      { keyId: `${kNew.did}#key-1`, created: t0 + 1_000, expiresAt: t0 + 600_000 },
    );
    assert.equal(
      verifyClause(clauseOnOld, { expectedPlatformDid: kOld.did, keyHistory: khRevokedOld, now: t0 + 5_000 }).ok,
      false,
    );
    const khLateRotation = signDocument(
      {
        ...khRotated.document,
        keys: [
          khRotated.document.keys[0]!,
          {
            ...khRotated.document.keys[1]!,
            validUntil: t0 + 500, // rotatedAt is t0 + 1_000 > validUntil
          },
        ],
      },
      kNew,
      { keyId: `${kNew.did}#key-1`, created: t0 + 1_000, expiresAt: t0 + 600_000 },
    );
    assert.equal(verifyKeyHistory(khLateRotation, { expectedActiveDid: kOld.did, now: t0 + 5_000 }).ok, false);

    // --- M-11b & M-11c: validateMandateShape unknown keys / issuedAt >= expiresAt & canonicalJson sparse / Array subclass ---
    assert.throws(
      () => validateMandateShape({ ...bareMandate, extraTop: 1 } as unknown as typeof bareMandate, claimant.did, t0 + 100),
      /not a supported field/,
    );
    assert.throws(
      () => validateMandateShape({ ...bareMandate, scope: {} } as unknown as typeof bareMandate, claimant.did, t0 + 100),
      /mandate\.scope/,
    );
    assert.throws(
      () =>
        validateMandateShape(
          { ...bareMandate, scope: { contractHash: "a".repeat(64), extra: 1 } } as unknown as typeof bareMandate,
          claimant.did,
          t0 + 100,
        ),
      /not a supported scope field/,
    );
    assert.throws(
      () =>
        validateMandateShape(
          { ...bareMandate, bounds: { creditUsd: { min: 0, max: 500, extra: 1 } } } as unknown as typeof bareMandate,
          claimant.did,
          t0 + 100,
        ),
      /unsupported field/,
    );
    assert.throws(
      () =>
        validateMandateShape(
          { ...bareMandate, issuedAt: t0 + 10_000, expiresAt: t0 + 10_000 },
          claimant.did,
          t0 + 100,
        ),
      /strictly before mandate\.expiresAt/,
    );

    const sparse: unknown[] = [];
    sparse[2] = 1;
    assert.equal(canonicalJson(sparse), "[null,null,1]");
    class SubArray extends Array {}
    assert.throws(() => canonicalJson(new SubArray()), /Non-plain array/);

    // --- L-09: findLeaks Markdown/comma lists, IMPROVEMENT_DECLINED privacy, RFC 9421 @target-uri & expectedRound, step & >16 JWS ---
    const unwrapApply = (res: ReturnType<typeof apply>) => {
      if (!res.ok) throw new Error(res.error.message);
      return res;
    };
    const iss = [
      { id: "a", label: "A", unit: "USD", min: 0, max: 1_000, step: 1, claimantPrefers: "higher" as const, obligor: "respondent" as const },
      { id: "b", label: "B", unit: "days", min: 0, max: 100, step: 1, claimantPrefers: "lower" as const, obligor: "respondent" as const },
    ];
    const mClaimant = signMandate(
      { id: "mc", principalId: claimant.did, agentId: claimant.did, bounds: { a: { min: 0, max: 1_000 }, b: { min: 0, max: 100 } }, issuedAt: t0, expiresAt: t0 + 10 * 86_400_000 },
      claimant,
    );
    const mRespondent = signMandate(
      { id: "mr", principalId: respondent.did, agentId: respondent.did, bounds: { a: { min: 0, max: 1_000 }, b: { min: 0, max: 100 } }, issuedAt: t0, expiresAt: t0 + 2 * 86_400_000 },
      respondent,
    );
    let st = unwrapApply(
      createDispute(
        {
          id: "dsp_imp",
          auditSalt: "s".repeat(32),
          contractHash: "a".repeat(64),
          claimantId: claimant.did,
          claimantMandate: mClaimant,
          respondentId: respondent.did,
          claim: { summary: "S", requestedRemedy: "R" },
          feePaid: true,
          discloseGapOnFailure: false,
        },
        t0,
      ),
    ).state;
    st = unwrapApply(
      apply(
        st,
        { type: "JOIN", actor: "respondent", respondentId: respondent.did, mandate: mRespondent, discloseGapOnFailure: false },
        t0 + 100,
      ),
    ).state;
    st = unwrapApply(apply(st, { type: "CLOSE_EVIDENCE", actor: "claimant" }, t0 + 200)).state;
    st = unwrapApply(apply(st, { type: "CLOSE_EVIDENCE", actor: "respondent" }, t0 + 200)).state;
    st = unwrapApply(apply(st, { type: "PROPOSE_ISSUES", actor: "system", issues: iss }, t0 + 250)).state;
    const iHash = issuesHash(st.issueNegotiation.proposed!);
    st = unwrapApply(apply(st, { type: "CONFIRM_ISSUES", actor: "claimant", issuesHash: iHash }, t0 + 300)).state;
    st = unwrapApply(apply(st, { type: "CONFIRM_ISSUES", actor: "respondent", issuesHash: iHash }, t0 + 300)).state;
    st = unwrapApply(
      apply(
        st,
        {
          type: "SUBMIT_ROUND",
          actor: "claimant",
          round: 1,
          offer: { a: 400, b: 60 },
          private: { weights: { a: 0.9, b: 0.1 }, walkaway: { a: 730, b: 80 } },
        },
        t0 + 400,
      ),
    ).state;
    // Check findLeaks against claimant's secret walkaway 730 visible to respondent across each format individually
    for (const leakedText of [
      "Target **730USD**",
      "Rate `730.00USD/mo`",
      "Floor _730USD_ now",
      "Cap 730USD/mo",
      "Range 100,730",
    ]) {
      assert.equal(findLeaks(leakedText, st, "respondent").length, 1, `expected leak detection for: ${leakedText}`);
    }
    assert.equal(findLeaks("Order ord_730_v2 cost $1,730 total", st, "respondent").length, 0);

    st = unwrapApply(
      apply(
        st,
        {
          type: "SUBMIT_ROUND",
          actor: "respondent",
          round: 1,
          offer: { a: 800, b: 60 },
          private: { weights: { a: 0.1, b: 0.9 }, walkaway: { a: 850, b: 20 } },
        },
        t0 + 400,
      ),
    ).state;
    assert.equal(st.execution?.improvement?.status, "OPEN");
    st = unwrapApply(apply(st, { type: "RESPOND_IMPROVEMENT", actor: "respondent", response: "accept" }, t0 + 600)).state;
    const declinedRes = unwrapApply(
      apply(st, { type: "RESPOND_IMPROVEMENT", actor: "claimant", response: "accept" }, t0 + 2 * 86_400_000 + 1_000),
    );
    const impDeclined = declinedRes.events.find((e) => e.type === "IMPROVEMENT_DECLINED");
    assert.ok(impDeclined);
    assert.deepEqual(impDeclined.data, {});

    // RFC 9421 @target-uri trailing whitespace & parameter quoting + expectedRound
    const cleanReqHdrs: Record<string, string> = {
      "content-type": "application/json",
      ...signRequest({
        method: "POST",
        targetUri: "https://api.mediate.example/v1/disputes/dsp_1/rounds/2/offer",
        headers: { "content-type": "application/json" },
        body: "{}",
        key: claimant,
        created: Math.floor(t0 / 1000),
        nonce: "nonce-b2-00000001",
      }),
    };
    assert.equal(
      verifyRequest({
        method: "POST",
        targetUri: "https://api.mediate.example/v1/disputes/dsp_1/rounds/2/offer ",
        header: (n) => cleanReqHdrs[n.toLowerCase()] ?? null,
        body: "{}",
        now: t0,
      }).ok,
      false,
    );
    assert.equal(
      verifyDisputeActionTarget(
        { method: "POST", targetUri: "https://api.mediate.example/v1/disputes/dsp_1/rounds/2/offer" },
        {
          expectedBaseUrl: "https://api.mediate.example",
          expectedDisputeId: "dsp_1",
          expectedAction: "submit_offer",
          expectedRound: 2,
        },
      ).ok,
      true,
    );
    assert.equal(
      verifyDisputeActionTarget(
        { method: "POST", targetUri: "https://api.mediate.example/v1/disputes/dsp_1/rounds/2/offer" },
        {
          expectedBaseUrl: "https://api.mediate.example",
          expectedDisputeId: "dsp_1",
          expectedAction: "submit_offer",
          expectedRound: 1,
        },
      ).ok,
      false,
    );

    assert.equal(
      validateIssuesAgainstClauseTemplates(
        [
          {
            id: "creditUsd",
            label: "Credit",
            unit: "USD",
            min: 0,
            max: 100,
            step: 1 + Number.EPSILON,
            claimantPrefers: "higher",
            obligor: "respondent",
          },
        ],
        [
          {
            id: "creditUsd",
            label: "Credit",
            unit: "USD",
            min: 0,
            max: 100,
            step: 1,
            claimantPrefers: "higher",
            obligor: "respondent",
          },
        ],
      ).ok,
      false,
    );
    assert.equal(
      verifyAgentCardSignature(
        {
          name: "Flooded Card",
          signatures: Array.from({ length: 17 }, () => ({ protected: "e30", signature: "AA" })),
        },
        kNew.did,
      ),
      false,
    );
  });
});
