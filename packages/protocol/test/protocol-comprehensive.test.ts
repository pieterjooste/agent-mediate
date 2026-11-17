/**
 * Comprehensive unit test suite for @agent-mediate/protocol (TEST-1, SEC-2, SEC-9, PERF-6):
 * - identity.ts: weakPointReason torsion/non-canonical points, base58btcDecode length cap, signText/verifyText
 * - did-web.ts: urlFromDidWeb uppercase/path-traversal rejection, buildDidWebDocument, didWebDocumentAuthorizesKey,
 *               signAgentCard/verifyAgentCardSignature, normalizeHonoursDomainSubject & parseHonoursSubject
 * - signed-documents.ts: signMandate/verifyMandateSignature, signDocument/verifyDocument, verifyKeyHistory activeKey validUntil,
 *                        verifyDocumentWithKeyHistory retired vs revoked/compromised keys
 * - http-signatures.ts: verifyRequest uncovered Content-Digest on empty body, verifyRequestProof across all 13 dispute actions,
 *                       tag support, expectedContentDigest/expectedIdempotencyKey, required body digest enforcement
 * - clause.ts: strict unknown-key rejection across all nested objects, expectedPlatformBaseUrl, retired keyHistory support,
 *              and validateIssuesAgainstClauseTemplates
 */
import assert from "node:assert/strict";
import { generateKeyPairSync } from "node:crypto";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { describe, it } from "node:test";
import { canonicalJson, contractHash, RULES_VERSION, verifyProposalOpening, type Issue, type Mandate } from "@agent-mediate/core";
import {
  agentKeyFromPem,
  base58btcDecode,
  base58btcEncode,
  buildClause,
  buildDidWebDocument,
  buildJwks,
  buildSignedKeyHistory,
  contentDigest,
  didKeyFromEd25519Jwk,
  didKeyFromRawPublicKey,
  didWebDocumentAuthorizesKey,
  didWebFromUrl,
  ed25519PublicJwkFromDidKey,
  generateAgentKey,
  isDidKey,
  normalizeHonoursDomainSubject,
  parseHonoursSubject,
  publicKeyFromDidKey,
  RULES_HASH,
  signAgentCard,
  signClause,
  signDocument,
  signMandate,
  signRequest,
  urlFromDidWeb,
  validateIssuesAgainstClauseTemplates,
  verifyAgentCardSignature,
  verifyClause,
  verifyDisputeActionTarget,
  verifyDocument,
  verifyDocumentWithKeyHistory,
  verifyKeyHistory,
  verifyMandateSignature,
  verifyRequest,
  verifyRequestProof,
  verifyText,
  weakPointReason,
  WEBHOOK_SIGNATURE_TAG,
  type RequestSignatureProof,
} from "../src/index.ts";

const T0 = Date.UTC(2026, 10, 11, 12, 0, 0);

const REFUND_TMPL: Issue = {
  id: "refundUsd",
  label: "Refund",
  unit: "USD",
  min: 0,
  max: 1000,
  step: 10,
  claimantPrefers: "higher",
  obligor: "respondent",
};

const CREDIT_TMPL: Issue = {
  id: "serviceCreditUsd",
  label: "Service Credit",
  unit: "USD",
  min: 0,
  max: 500,
  step: 25,
  claimantPrefers: "higher",
  obligor: "respondent",
};

describe("@agent-mediate/protocol comprehensive module coverage", () => {
  it("identity.ts: enforces base58btc length cap, rejects small-order and non-canonical Ed25519 points, and loads PKCS#8 PEM", () => {
    assert.throws(() => base58btcDecode("1".repeat(257)), /too long/i);

    // Identity point (y = 1, x = 0) -> small-order torsion point
    const identityPoint = new Uint8Array(32);
    identityPoint[0] = 1;
    assert.equal(weakPointReason(identityPoint), "small-order point");
    const fakeDid = didKeyFromRawPublicKey(identityPoint);
    assert.equal(isDidKey(fakeDid), false);
    assert.throws(() => publicKeyFromDidKey(fakeDid), /small-order/);

    // Non-canonical x = 0 with sign bit set
    const negZeroX = new Uint8Array(32);
    negZeroX[0] = 1;
    negZeroX[31] = 0x80;
    assert.equal(weakPointReason(negZeroX), "non-canonical encoding");

    // Non-canonical y >= 2^255 - 19 (all 0xff with top bit cleared -> 2^255 - 1)
    const yAboveP = new Uint8Array(32).fill(0xff);
    yAboveP[31] = 0x7f;
    assert.equal(weakPointReason(yAboveP), "non-canonical encoding");

    // PEM roundtrip
    const kp = generateKeyPairSync("ed25519");
    const pem = kp.privateKey.export({ type: "pkcs8", format: "pem" }).toString();
    const loaded = agentKeyFromPem(pem);
    assert.equal(isDidKey(loaded.did), true);
    const encoded = base58btcEncode(new Uint8Array([0, 0, 1, 2, 3]));
    assert.deepEqual(base58btcDecode(encoded), new Uint8Array([0, 0, 1, 2, 3]));
    assert.equal(verifyText(loaded.did, "msg", "not-base64!"), false);
  });

  it("did-web.ts: rejects uppercase did:web hosts, verifies authentication vs retired keys, AgentCard JWS, and Honours subjects", () => {
    assert.throws(() => urlFromDidWeb("did:web:Example.COM"), /invalid did:web host/i);
    assert.throws(() => urlFromDidWeb("did:web:%45xample.com"), /invalid did:web host/i);
    assert.equal(urlFromDidWeb("did:web:api.example.com:agents:v1"), "https://api.example.com/agents/v1/did.json");

    const active = generateAgentKey();
    const retired = generateAgentKey();
    const revoked = generateAgentKey();
    const doc = buildDidWebDocument({
      baseUrl: "https://api.example.com",
      platformDid: active.did,
      historicalKeys: [
        { did: retired.did, status: "retired" },
        { did: revoked.did, status: "revoked" },
      ],
    });
    assert.equal(didWebDocumentAuthorizesKey(doc, "did:web:api.example.com", active.did), true);
    // Retired key is in assertionMethod/alsoKnownAs, NEVER in authentication!
    assert.equal(didWebDocumentAuthorizesKey(doc, "did:web:api.example.com", retired.did), false);
    assert.equal(didWebDocumentAuthorizesKey(doc, "did:web:api.example.com", revoked.did), false);

    const jwks = buildJwks({
      baseUrl: "https://api.example.com",
      platformDid: active.did,
      historicalKeys: [
        { did: retired.did, status: "retired" },
        { did: revoked.did, status: "revoked" },
      ],
    });
    assert.equal(jwks.keys.length, 2);
    assert.equal(didKeyFromEd25519Jwk(ed25519PublicJwkFromDidKey(active.did)), active.did);

    const card = signAgentCard(
      { name: "Agent-Mediate", url: "https://api.example.com", version: "1.3.0" },
      active,
      { kid: "did:web:api.example.com#key-1", jku: "https://api.example.com/.well-known/jwks.json" },
    );
    assert.equal(verifyAgentCardSignature(card, active.did), true);
    assert.equal(verifyAgentCardSignature(card, retired.did), false);
    assert.equal(verifyAgentCardSignature({ ...card, version: "tampered" }, active.did), false);

    assert.equal(normalizeHonoursDomainSubject("Example.COM.:443"), "example.com");
    assert.equal(normalizeHonoursDomainSubject("93.184.216.34"), null);
    assert.deepEqual(parseHonoursSubject(active.did), { kind: "agent", agentId: active.did });
    assert.equal(parseHonoursSubject("did:key:zInvalid"), null);
    assert.deepEqual(parseHonoursSubject("did:web:acme.example%3A443"), { kind: "did_web", domain: "acme.example" });
  });

  it("signed-documents.ts: verifies mandates, rejects expired activeKey.validUntil in verifyKeyHistory, and handles retired/revoked history", () => {
    const principal = generateAgentKey();
    const agent = generateAgentKey();
    const unsignedMandate: Omit<Mandate, "signature"> = {
      id: "mnd_01",
      principalId: principal.did,
      agentId: agent.did,
      issuedAt: T0,
      expiresAt: T0 + 3_600_000,
      bounds: { refundUsd: { min: 0, max: 500 } },
    };
    const signedMandate = signMandate(unsignedMandate, principal);
    assert.equal(verifyMandateSignature(signedMandate), true);
    assert.equal(verifyMandateSignature({ ...signedMandate, expiresAt: T0 + 7_200_000 }), false);

    const activeKey = generateAgentKey();
    const retiredKey = generateAgentKey();
    const revokedKey = generateAgentKey();

    const historyWithExpiry = buildSignedKeyHistory({
      baseUrl: "https://api.example.com",
      activeKey,
      activeValidFrom: T0 - 100_000,
      activeExpiresAt: T0 + 50_000,
      historicalKeys: [
        { did: retiredKey.did, status: "retired", validFrom: T0 - 500_000, validUntil: T0 - 100_000 },
        { did: revokedKey.did, status: "revoked", validFrom: T0 - 900_000, revokedAt: T0 - 600_000 },
      ],
      updatedAt: T0,
      documentExpiresAt: T0 + 1_000_000,
    });
    assert.equal(verifyKeyHistory(historyWithExpiry, { expectedActiveDid: activeKey.did, now: T0 + 10_000 }).ok, true);
    // SEC-9: once now >= activeKey.validUntil, verifyKeyHistory must reject even though documentExpiresAt is later!
    const expiredActive = verifyKeyHistory(historyWithExpiry, { expectedActiveDid: activeKey.did, now: T0 + 50_000 });
    assert.equal(expiredActive.ok, false);

    const retiredDoc = signDocument({ type: "settlement/v1", id: "dsp_1" }, retiredKey, { created: T0 - 200_000 });
    assert.equal(
      verifyDocumentWithKeyHistory(retiredDoc, historyWithExpiry, { expectedActiveDid: activeKey.did, now: T0 }).ok,
      true,
    );
    const revokedDoc = signDocument({ type: "settlement/v1", id: "dsp_2" }, revokedKey, { created: T0 - 700_000 });
    assert.equal(
      verifyDocumentWithKeyHistory(revokedDoc, historyWithExpiry, { expectedActiveDid: activeKey.did, now: T0 }).ok,
      false,
    );
    assert.equal(verifyDocument(retiredDoc, retiredKey.did, { now: T0 }), true);
  });

  it("http-signatures.ts: rejects uncovered Content-Digest on empty body, supports tag & digest binding, and checks all 13 dispute actions", () => {
    const signer = generateAgentKey();
    const baseUrl = "https://api.example.com";
    const emptySig = signRequest({
      method: "POST",
      targetUri: `${baseUrl}/v1/disputes/dsp_1/withdraw`,
      headers: { "idempotency-key": "idem-withdraw-01" },
      key: signer,
      created: Math.floor(T0 / 1000),
      nonce: "nonce-empty-body-0001",
    });
    // SEC-9: attacker injects an uncovered Content-Digest header alongside an empty body
    const injected = verifyRequest({
      method: "POST",
      targetUri: `${baseUrl}/v1/disputes/dsp_1/withdraw`,
      header: (n) => {
        if (n.toLowerCase() === "content-digest") return contentDigest('{"spoof":true}');
        if (n.toLowerCase() === "idempotency-key") return "idem-withdraw-01";
        return emptySig[n.toLowerCase()] ?? null;
      },
      body: "",
      now: T0,
    });
    assert.equal(injected.ok, false);

    // Webhook tag verification in verifyRequestProof
    const whBody = '{"event":"DISPUTE_FILED"}';
    const whHeaders = signRequest({
      method: "POST",
      targetUri: "https://agent.example.com/webhook",
      body: whBody,
      key: signer,
      created: Math.floor(T0 / 1000),
      nonce: "nonce-webhook-tag-01",
      tag: WEBHOOK_SIGNATURE_TAG,
    });
    const whVerified = verifyRequest({
      method: "POST",
      targetUri: "https://agent.example.com/webhook",
      header: (n) => whHeaders[n.toLowerCase()] ?? null,
      body: whBody,
      now: T0,
      expectTag: WEBHOOK_SIGNATURE_TAG,
    });
    assert.equal(whVerified.ok, true);
    if (whVerified.ok) {
      assert.equal(verifyRequestProof(whVerified.proof).ok, false, "unexpected tag rejected by default");
      assert.equal(verifyRequestProof(whVerified.proof, { expectTag: WEBHOOK_SIGNATURE_TAG }).ok, true);
    }

    // All 14 dispute actions in verifyDisputeActionTarget + required content-digest check in verifyRequestProof
    const actions: Array<[string, string, boolean]> = [
      ["file_dispute", "/v1/disputes", true],
      ["join_dispute", "/v1/disputes/dsp_1/join", true],
      ["submit_evidence", "/v1/disputes/dsp_1/evidence", true],
      ["close_evidence", "/v1/disputes/dsp_1/evidence/close", false],
      ["confirm_issues", "/v1/disputes/dsp_1/issues/confirm", true],
      ["reject_issues", "/v1/disputes/dsp_1/issues/reject", true],
      ["update_mandate", "/v1/disputes/dsp_1/mandate", true],
      ["submit_offer", "/v1/disputes/dsp_1/rounds/2/offer", true],
      ["submit_final_offer", "/v1/disputes/dsp_1/determination/final-offer", true],
      ["respond_improvement", "/v1/disputes/dsp_1/execution/improvement", true],
      ["submit_execution_proof", "/v1/disputes/dsp_1/execution/proof", true],
      ["confirm_execution", "/v1/disputes/dsp_1/execution/confirm", false],
      ["contest_execution", "/v1/disputes/dsp_1/execution/contest", true],
      ["acknowledge_cure", "/v1/disputes/dsp_1/cure", false],
      ["withdraw", "/v1/disputes/dsp_1/withdraw", false],
    ];

    for (const [action, path, bodyRequired] of actions) {
      assert.equal(
        verifyDisputeActionTarget(
          { method: "POST", targetUri: `${baseUrl}${path}` },
          { expectedDisputeId: "dsp_1", expectedAction: action, expectedBaseUrl: baseUrl },
        ).ok,
        true,
        action,
      );
      const noBodySig = signRequest({
        method: "POST",
        targetUri: `${baseUrl}${path}`,
        headers: { "idempotency-key": `idem-${action}` },
        key: signer,
        created: Math.floor(T0 / 1000),
        nonce: `nonce-act-${action.padEnd(16, "0")}`,
      });
      const noBodyProof: RequestSignatureProof = {
        method: "POST",
        targetUri: `${baseUrl}${path}`,
        contentDigest: null,
        idempotencyKey: `idem-${action}`,
        signatureInput: noBodySig["signature-input"]!,
        signature: noBodySig.signature!,
        created: Math.floor(T0 / 1000),
        nonce: `nonce-act-${action.padEnd(16, "0")}`,
        keyid: signer.did,
      };
      const res = verifyRequestProof(noBodyProof, {
        expectedAgentId: signer.did,
        expectedDisputeId: "dsp_1",
        expectedAction: action,
        expectedBaseUrl: baseUrl,
      });
      assert.equal(res.ok, !bodyRequired, `bodyRequired mismatch for ${action}`);
    }
  });

  it("clause.ts: rejects unknown keys, validates expectedPlatformBaseUrl & retired keyHistory, and checks validateIssuesAgainstClauseTemplates", () => {
    const oldPlatform = generateAgentKey();
    const activePlatform = generateAgentKey();
    const cAgent = generateAgentKey();
    const rAgent = generateAgentKey();

    const baseClause = signClause(
      signClause(
        buildClause({
          contractHash: "c".repeat(64),
          platformDid: oldPlatform.did,
          platformBaseUrl: "https://api.example.com",
          rulesHash: RULES_HASH,
          issuedAt: T0 - 200_000,
          parties: [
            { agentId: cAgent.did, notice: { email: "ops@claimant.example" } },
            { agentId: rAgent.did },
          ],
          terms: {
            determinationConsent: false,
            issueTemplates: [REFUND_TMPL, CREDIT_TMPL],
          },
        }),
        cAgent,
      ),
      rAgent,
    );

    // Unknown own keys on clause or nested objects must fail verifyClause
    assert.equal(verifyClause({ ...baseClause, extra: 1 } as never).ok, false);
    assert.equal(verifyClause({ ...baseClause, terms: { ...baseClause.terms, extra: 1 } } as never).ok, false);

    // Wrong baseUrl rejected
    assert.equal(
      verifyClause(baseClause, {
        expectedPlatformDid: oldPlatform.did,
        expectedPlatformBaseUrl: "https://other.example.com",
        now: T0,
      }).ok,
      false,
    );

    // Retired platform key accepted when verified against signed keyHistory!
    const keyHistory = buildSignedKeyHistory({
      baseUrl: "https://api.example.com",
      activeKey: activePlatform,
      activeValidFrom: T0 - 50_000,
      historicalKeys: [{ did: oldPlatform.did, status: "retired", validFrom: T0 - 500_000, validUntil: T0 - 50_000 }],
      updatedAt: T0,
    });
    assert.equal(
      verifyClause(baseClause, {
        expectedPlatformDid: activePlatform.did,
        expectedPlatformBaseUrl: "https://api.example.com/",
        keyHistory,
        now: T0,
      }).ok,
      true,
    );

    // validateIssuesAgainstClauseTemplates
    assert.equal(validateIssuesAgainstClauseTemplates([REFUND_TMPL], [REFUND_TMPL, CREDIT_TMPL]).ok, true);
    assert.equal(
      validateIssuesAgainstClauseTemplates([{ ...REFUND_TMPL, min: 100, max: 800 }], [REFUND_TMPL, CREDIT_TMPL]).ok,
      true,
    );
    assert.equal(
      validateIssuesAgainstClauseTemplates([{ ...REFUND_TMPL, max: 1200 }], [REFUND_TMPL, CREDIT_TMPL]).ok,
      false,
    );
    assert.equal(
      validateIssuesAgainstClauseTemplates([{ ...REFUND_TMPL, id: "unlistedUsd" }], [REFUND_TMPL, CREDIT_TMPL]).ok,
      false,
    );
    assert.equal(
      validateIssuesAgainstClauseTemplates([{ ...REFUND_TMPL, obligor: "claimant" }], [REFUND_TMPL, CREDIT_TMPL]).ok,
      false,
    );
  });

  it("conformance-vectors.json: validates shared cross-language vectors (ARCH-3, TEST-3)", () => {
    const vectorsPath = fileURLToPath(new URL("../../../testdata/conformance-vectors.json", import.meta.url));
    const vectors = JSON.parse(readFileSync(vectorsPath, "utf8")) as Record<string, any>;

    assert.equal(RULES_VERSION, vectors.rules.rulesVersion);
    assert.equal(RULES_HASH, vectors.rules.rulesHash);
    assert.equal(agentKeyFromPem(vectors.keys.pkcs8V1PemA).did, vectors.keys.didA);

    for (const item of vectors.jcs) {
      assert.equal(canonicalJson(item.input), item.canonical, item.label);
      assert.equal(contractHash(item.input), item.sha256, item.label);
    }
    for (const v of vectors.didWeb.valid) {
      assert.equal(urlFromDidWeb(v.didWeb), v.url);
    }
    for (const bad of vectors.didWeb.invalid) {
      assert.throws(() => urlFromDidWeb(bad), /did:web/i, bad);
    }
    for (const wp of vectors.weakPoints) {
      assert.equal(weakPointReason(Buffer.from(wp.hex, "hex")), wp.reason);
    }
    for (const po of vectors.proposalOpenings) {
      const res = verifyProposalOpening(po.opening);
      assert.equal(res.ok, true, po.label);
      if (res.ok) {
        assert.deepEqual(res.expectedProposal, po.expectedProposal);
        assert.deepEqual(res.expectedDeterminationReference, po.expectedDeterminationReference);
      }
    }
    assert.equal(
      verifyClause(vectors.clause.valid, {
        expectedPlatformDid: vectors.clause.expectedPlatformDid,
        expectedPlatformBaseUrl: vectors.clause.expectedPlatformBaseUrl,
      }).ok,
      true,
    );
    for (const mut of vectors.clause.invalidMutations) {
      assert.equal(
        verifyClause(
          { ...vectors.clause.valid, ...mut.patch },
          { expectedPlatformDid: vectors.clause.expectedPlatformDid },
        ).ok,
        false,
        mut.label,
      );
    }
    const rp = vectors.requestProof;
    assert.equal(
      verifyRequestProof(rp.proof, {
        expectedAgentId: rp.agentId,
        expectedProofHash: rp.proofHash,
        expectedBaseUrl: rp.baseUrl,
        expectedDisputeId: rp.disputeId,
        expectedAction: rp.action,
        expectedContentDigest: rp.contentDigest,
        expectedIdempotencyKey: rp.idempotencyKey,
      }).ok,
      true,
    );
  });
});
