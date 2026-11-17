/**
 * Regression tests for the 2026-11-11 production-readiness review findings in @agent-mediate/protocol:
 * - PR-PROTO-H1: verifyRequest, verifyClause, verifyDocument, verifyKeyHistory, verifyDocumentWithKeyHistory reject non-finite / <= 0 `now`
 * - PR-PROTO-M1: didWebFromUrl / urlFromDidWeb strict host/port validation; verifyDisputeActionTarget expectedBaseUrl & non-empty disputeId; trimmed contentDigest / idempotencyKey
 * - PR-L6: verifyKeyHistory rejects multiple active keys and proof.created < validFrom
 * - PR-L7: buildClause / verifyClause validate rulesVersion and party.notice contact fields
 */
import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildClause,
  buildSignedKeyHistory,
  didWebFromUrl,
  generateAgentKey,
  RULES_HASH,
  signClause,
  signDocument,
  signRequest,
  urlFromDidWeb,
  verifyClause,
  verifyDisputeActionTarget,
  verifyDocument,
  verifyDocumentWithKeyHistory,
  verifyKeyHistory,
  verifyRequest,
  verifyRequestProof,
} from "../src/index.ts";

const T0 = Date.UTC(2026, 10, 11, 10, 0, 0);

describe("2026-11-11 production-readiness: @agent-mediate/protocol", () => {
  it("PR-PROTO-H1: rejects NaN, Infinity, 0 and negative `now` across all time-sensitive verifiers", () => {
    const agent = generateAgentKey();
    const other = generateAgentKey();
    const platform = generateAgentKey();

    const body = JSON.stringify({ hello: "world" });
    const baseHeaders: Record<string, string> = { "content-type": "application/json", "idempotency-key": "idem-proto-h1" };
    const sigHeaders = signRequest({
      method: "POST",
      targetUri: "https://api.example.com/v1/disputes",
      headers: baseHeaders,
      body,
      key: agent,
      created: Math.floor(T0 / 1000),
      nonce: "nonce-proto-h1-001",
    });
    const allHeaders = { ...baseHeaders, ...sigHeaders };

    const clause = signClause(
      signClause(
        buildClause({
          contractHash: "a".repeat(64),
          platformDid: platform.did,
          rulesHash: RULES_HASH,
          issuedAt: T0,
          expiresAt: T0 + 60_000,
          parties: [{ agentId: agent.did }, { agentId: other.did }],
        }),
        agent,
        agent.did,
      ),
      other,
      other.did,
    );

    const doc = signDocument({ type: "test/v1", value: 1 }, platform, {
      keyId: `${platform.did}#key-1`,
      created: T0,
      expiresAt: T0 + 60_000,
    });

    const history = buildSignedKeyHistory({
      baseUrl: "https://api.example.com",
      activeKey: platform,
      activeKeyId: `${platform.did}#key-1`,
      activeValidFrom: T0 - 10_000,
      updatedAt: T0,
    });

    for (const badNow of [Number.NaN, Number.POSITIVE_INFINITY, Number.NEGATIVE_INFINITY, 0, -1]) {
      const reqVerdict = verifyRequest({
        method: "POST",
        targetUri: "https://api.example.com/v1/disputes",
        header: (n) => allHeaders[n.toLowerCase()] ?? null,
        body,
        now: badNow,
      });
      assert.equal(reqVerdict.ok, false, `verifyRequest accepted now=${String(badNow)}`);

      const clauseVerdict = verifyClause(clause, { expectedPlatformDid: platform.did, now: badNow });
      assert.equal(clauseVerdict.ok, false, `verifyClause accepted now=${String(badNow)}`);

      assert.equal(verifyDocument(doc, platform.did, { now: badNow }), false, `verifyDocument accepted now=${String(badNow)}`);
      assert.equal(verifyKeyHistory(history, { expectedActiveDid: platform.did, now: badNow }).ok, false);
      assert.equal(verifyDocumentWithKeyHistory(doc, history, { expectedActiveDid: platform.did, now: badNow }).ok, false);
    }

    // Valid `now` succeeds across all five
    assert.equal(
      verifyRequest({
        method: "POST",
        targetUri: "https://api.example.com/v1/disputes",
        header: (n) => allHeaders[n.toLowerCase()] ?? null,
        body,
        now: T0,
      }).ok,
      true,
    );
    assert.equal(verifyClause(clause, { expectedPlatformDid: platform.did, now: T0 }).ok, true);
    assert.equal(verifyDocument(doc, platform.did, { now: T0 }), true);
    assert.equal(verifyKeyHistory(history, { expectedActiveDid: platform.did, now: T0 }).ok, true);
    assert.equal(verifyDocumentWithKeyHistory(doc, history, { expectedActiveDid: platform.did, now: T0 }).ok, true);
  });

  it("PR-PROTO-M1: hardens did:web host/port parsing, verifyDisputeActionTarget, and proof header trimming", () => {
    for (const badUrl of [
      "https://[::1]/",
      "https://user:pass@example.com/",
      "https://example.com.:8443/",
      "ftp://example.com/",
      "https://example.com/?q=1",
    ]) {
      assert.throws(() => didWebFromUrl(badUrl), /did:web|URL|IP|credentials|trailing|query|HTTP/i, badUrl);
    }
    for (const badDidWeb of [
      "did:web:[::1]",
      "did:web:example.com.",
      "did:web:example.com%3A0",
      "did:web:example.com%3A08080",
      "did:web:example.com%3A70000",
    ]) {
      assert.throws(() => urlFromDidWeb(badDidWeb), /did:web|port|host|IP/i, badDidWeb);
    }
    assert.equal(urlFromDidWeb(didWebFromUrl("https://api.example.com:8443")), "https://api.example.com:8443/.well-known/did.json");

    // verifyDisputeActionTarget rejects empty disputeId and malformed expectedBaseUrl
    assert.equal(
      verifyDisputeActionTarget(
        { method: "POST", targetUri: "https://api.example.com/v1/disputes//join" },
        {
          expectedBaseUrl: "https://api.example.com",
          expectedDisputeId: "",
          expectedAction: "join_dispute",
        },
      ).ok,
      false,
    );
    assert.equal(
      verifyDisputeActionTarget(
        { method: "POST", targetUri: "https://api.example.com/v1/disputes/dsp_1/join" },
        {
          expectedBaseUrl: "https://api.example.com?bad=1",
          expectedDisputeId: "dsp_1",
          expectedAction: "join_dispute",
        },
      ).ok,
      false,
    );

    // Proof verification tolerates RFC 9110 OWS around contentDigest / idempotencyKey
    const signer = generateAgentKey();
    const rawBody = '{"x":1}';
    const h: Record<string, string> = { "content-type": "application/json", "idempotency-key": "idem-trim-001" };
    const signed = signRequest({
      method: "POST",
      targetUri: "https://api.example.com/v1/disputes/dsp_1/evidence/close",
      headers: h,
      body: rawBody,
      key: signer,
      created: Math.floor(T0 / 1000),
      nonce: "nonce-trim-000001",
    });
    const proof = {
      method: "POST",
      targetUri: "https://api.example.com/v1/disputes/dsp_1/evidence/close",
      contentDigest: `  ${signed["content-digest"]}  `,
      idempotencyKey: "  idem-trim-001  ",
      signatureInput: signed["signature-input"]!,
      signature: signed.signature!,
      keyid: signer.did,
      nonce: "nonce-trim-000001",
      created: Math.floor(T0 / 1000),
    };
    const res = verifyRequestProof(proof, {
      expectedAgentId: signer.did,
      expectedBaseUrl: "https://api.example.com",
      expectedDisputeId: "dsp_1",
      expectedAction: "close_evidence",
    });
    assert.equal(res.ok, true);
  });

  it("PR-L6 & PR-L7: enforces single active key + validFrom in verifyKeyHistory and validates clause rulesVersion + party.notice", () => {
    const k1 = generateAgentKey();
    const k2 = generateAgentKey();

    const baseHistory = buildSignedKeyHistory({
      baseUrl: "https://api.example.com",
      activeKey: k1,
      activeKeyId: `${k1.did}#key-1`,
      activeValidFrom: T0 - 5_000,
      updatedAt: T0,
    });
    const twoActive = signDocument(
      {
        ...baseHistory.document,
        keys: [
          ...baseHistory.document.keys,
          { ...baseHistory.document.keys[0]!, keyId: `${k2.did}#key-2`, did: k2.did, status: "active" as const },
        ],
      },
      k1,
      { keyId: `${k1.did}#key-1`, created: T0 },
    );
    assert.equal(verifyKeyHistory(twoActive, { expectedActiveDid: k1.did, now: T0 }).ok, false);

    const createdBeforeValidFrom = signDocument(
      {
        ...baseHistory.document,
        keys: [{ ...baseHistory.document.keys[0]!, validFrom: T0 + 60_000 }],
      },
      k1,
      { keyId: `${k1.did}#key-1`, created: T0 },
    );
    assert.equal(verifyKeyHistory(createdBeforeValidFrom, { expectedActiveDid: k1.did, now: T0 + 120_000 }).ok, false);

    // PR-L7: buildClause & verifyClause reject bad party.notice or empty rulesVersion
    assert.throws(() =>
      buildClause({
        contractHash: "b".repeat(64),
        platformDid: k1.did,
        parties: [
          { agentId: k1.did, notice: { webhookUrl: "ftp://bad.example/hook" } },
          { agentId: k2.did },
        ],
      }),
    );

    const validClause = signClause(
      signClause(
        buildClause({
          contractHash: "b".repeat(64),
          platformDid: k1.did,
          rulesHash: RULES_HASH,
          issuedAt: T0,
          parties: [{ agentId: k1.did }, { agentId: k2.did }],
        }),
        k1,
        k1.did,
      ),
      k2,
      k2.did,
    );
    const tamperedRulesVersion = {
      ...validClause,
      platform: { ...validClause.platform, rulesVersion: "" },
    };
    assert.equal(verifyClause(tamperedRulesVersion, { expectedPlatformDid: k1.did, now: T0 }).ok, false);
  });
});
