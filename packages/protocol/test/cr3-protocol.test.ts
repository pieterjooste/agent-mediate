import assert from "node:assert/strict";
import { describe, it } from "node:test";
import {
  buildClause,
  buildDidWebDocument,
  buildJwks,
  buildSignedKeyHistory,
  generateAgentKey,
  signClause,
  signDocument,
  verifyClause,
  verifyDocumentWithKeyHistory,
  verifyKeyHistory,
} from "../src/index.ts";

const T0 = Date.UTC(2026, 10, 14, 0, 0, 0);

describe("CR3 protocol key-history, DID/JWKS, and clause URL invariants", () => {
  it("CR3-PROTO-M1: buildDidWebDocument and buildJwks publish clean retired keys for historical JWS verification but exclude retired keys with revokedAt or compromisedAfter", () => {
    const active = generateAgentKey();
    const cleanRetired = generateAgentKey();
    const revokedRetired = generateAgentKey();
    const compromisedRetired = generateAgentKey();
    const revoked = generateAgentKey();

    const baseUrl = "https://api.mediate.example";
    const historicalKeys = [
      { did: cleanRetired.did, status: "retired" as const, validFrom: T0 - 100_000, validUntil: T0 - 50_000 },
      { did: revokedRetired.did, status: "retired" as const, validFrom: T0 - 200_000, validUntil: T0 - 150_000, revokedAt: T0 - 120_000 },
      {
        did: compromisedRetired.did,
        status: "retired" as const,
        validFrom: T0 - 300_000,
        validUntil: T0 - 250_000,
        compromisedAfter: T0 - 260_000,
      },
      { did: revoked.did, status: "revoked" as const, validFrom: T0 - 400_000, revokedAt: T0 - 350_000 },
    ];

    const didDoc = buildDidWebDocument({
      baseUrl,
      platformDid: active.did,
      historicalKeys: historicalKeys.map((h) => ({
        did: h.did,
        keyId: `did:web:api.mediate.example#hist-${h.did.slice(-6)}`,
        status: h.status,
        ...(h.revokedAt !== undefined ? { revokedAt: h.revokedAt } : {}),
        ...(h.compromisedAfter !== undefined ? { compromisedAfter: h.compromisedAfter } : {}),
      })),
    });

    // Active key has 2 verification methods (#key-1 JsonWebKey2020 + #key-1-multikey Multikey); cleanRetired adds 2; compromised/revoked add 0.
    assert.equal(didDoc.verificationMethod.length, 4);
    assert.equal(didDoc.authentication.length, 2, "only active key appears in authentication");
    assert.equal(didDoc.assertionMethod.length, 4, "active + clean retired keys appear in assertionMethod");
    assert.ok(didDoc.alsoKnownAs.includes(active.did));
    assert.ok(didDoc.alsoKnownAs.includes(cleanRetired.did));
    assert.ok(!didDoc.alsoKnownAs.includes(revokedRetired.did));
    assert.ok(!didDoc.alsoKnownAs.includes(compromisedRetired.did));
    assert.ok(!didDoc.alsoKnownAs.includes(revoked.did));

    const jwks = buildJwks({
      baseUrl,
      platformDid: active.did,
      historicalKeys: historicalKeys.map((h) => ({
        did: h.did,
        keyId: `did:web:api.mediate.example#hist-${h.did.slice(-6)}`,
        status: h.status,
        ...(h.revokedAt !== undefined ? { revokedAt: h.revokedAt } : {}),
        ...(h.compromisedAfter !== undefined ? { compromisedAfter: h.compromisedAfter } : {}),
      })),
    });
    assert.equal(jwks.keys.length, 2, "JWKS contains active + clean retired key only");
  });

  it("CR3-PROTO-M2: verifyKeyHistory and verifyDocumentWithKeyHistory enforce maxAgeMs, minUpdatedAt anti-rollback, and reject retired keys carrying revokedAt or compromisedAfter", () => {
    const active = generateAgentKey();
    const cleanRetired = generateAgentKey();
    const compromisedRetired = generateAgentKey();
    const revokedRetired = generateAgentKey();

    const kh = buildSignedKeyHistory({
      baseUrl: "https://api.mediate.example",
      activeKey: active,
      activeValidFrom: T0 - 10_000,
      updatedAt: T0,
      historicalKeys: [
        { did: cleanRetired.did, status: "retired", validFrom: T0 - 100_000, validUntil: T0 - 20_000 },
        {
          did: compromisedRetired.did,
          status: "retired",
          validFrom: T0 - 200_000,
          validUntil: T0 - 110_000,
          compromisedAfter: T0 - 150_000,
        },
        {
          did: revokedRetired.did,
          status: "retired",
          validFrom: T0 - 300_000,
          validUntil: T0 - 210_000,
          revokedAt: T0 - 220_000,
        },
      ],
    });

    // Freshness & monotonic updatedAt guards
    assert.equal(verifyKeyHistory(kh, { expectedActiveDid: active.did, now: T0 + 5_000, maxAgeMs: 10_000 }).ok, true);
    const staleAge = verifyKeyHistory(kh, { expectedActiveDid: active.did, now: T0 + 15_000, maxAgeMs: 10_000 });
    assert.equal(staleAge.ok, false);
    if (!staleAge.ok) assert.match(staleAge.reason, /exceeds maxAgeMs/);

    const rollback = verifyKeyHistory(kh, { expectedActiveDid: active.did, now: T0 + 1_000, minUpdatedAt: T0 + 500 });
    assert.equal(rollback.ok, false);
    if (!rollback.ok) assert.match(rollback.reason, /precedes minUpdatedAt/);

    // Clean retired key within [validFrom, validUntil] verifies
    const cleanDoc = signDocument({ disputeId: "dsp_clean" }, cleanRetired, {
      keyId: `${cleanRetired.did}#key-1`,
      created: T0 - 50_000,
    });
    assert.equal(
      verifyDocumentWithKeyHistory(cleanDoc, kh, { expectedActiveDid: active.did, now: T0 + 1_000 }).ok,
      true,
    );

    // Retired key with compromisedAfter or revokedAt is rejected unconditionally
    const compDoc = signDocument({ disputeId: "dsp_comp" }, compromisedRetired, {
      keyId: `${compromisedRetired.did}#key-1`,
      created: T0 - 180_000,
    });
    const compRes = verifyDocumentWithKeyHistory(compDoc, kh, { expectedActiveDid: active.did, now: T0 + 1_000 });
    assert.equal(compRes.ok, false);
    if (!compRes.ok) assert.match(compRes.reason, /compromise/);

    const revDoc = signDocument({ disputeId: "dsp_rev" }, revokedRetired, {
      keyId: `${revokedRetired.did}#key-1`,
      created: T0 - 250_000,
    });
    const revRes = verifyDocumentWithKeyHistory(revDoc, kh, { expectedActiveDid: active.did, now: T0 + 1_000 });
    assert.equal(revRes.ok, false);
    if (!revRes.ok) assert.match(revRes.reason, /revoked/);
  });

  it("CR3-PROTO-L2: buildClause and verifyClause reject schemeless http:example.com URLs and raw whitespace/controls", () => {
    const platform = generateAgentKey();
    const a = generateAgentKey();
    const b = generateAgentKey();

    for (const badUrl of ["http:example.com/hook", "https:example.com/card.json", "https://bad host.example/hook"]) {
      assert.throws(
        () =>
          buildClause({
            platformDid: platform.did,
            contractHash: "a".repeat(64),
            parties: [
              { principalId: a.did, agentId: a.did, notice: { webhookUrl: badUrl } },
              { principalId: b.did, agentId: b.did },
            ],
            issuedAt: T0,
          }),
        /URL/i,
      );
    }

    const validUnsigned = buildClause({
      platformDid: platform.did,
      contractHash: "a".repeat(64),
      parties: [
        { principalId: a.did, agentId: a.did, notice: { webhookUrl: "https://ok.example/hook" } },
        { principalId: b.did, agentId: b.did },
      ],
      issuedAt: T0,
    });
    const signed = signClause(signClause(validUnsigned, a), b);
    assert.equal(verifyClause(signed, { expectedPlatformDid: platform.did }).ok, true);

    const mutated = structuredClone(signed);
    mutated.parties[0]!.notice!.webhookUrl = "http:example.com/hook";
    assert.equal(verifyClause(mutated, { expectedPlatformDid: platform.did }).ok, false);
  });
});
