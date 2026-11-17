import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { randomUUID } from "node:crypto";
import {
  base58btcDecode,
  base58btcEncode,
  contentDigest,
  didKeyFromPublicKey,
  generateAgentKey,
  isDidKey,
  publicKeyFromDidKey,
  signDocument,
  signMandate,
  signRequest,
  verifyDocument,
  verifyMandateSignature,
  verifyRequest,
} from "../src/index.ts";

const NOW = Date.UTC(2026, 9, 14, 8, 0, 0);
const URI = "https://api.agent-mediate.test/v1/disputes";

describe("did:key identities", () => {
  it("round-trips base58btc including leading zeros", () => {
    const bytes = Uint8Array.from([0, 0, 1, 2, 255, 128]);
    assert.deepEqual(base58btcDecode(base58btcEncode(bytes)), bytes);
  });

  it("encodes Ed25519 keys with the standard z6Mk prefix and decodes back to the same key", () => {
    const k = generateAgentKey();
    assert.match(k.did, /^did:key:z6Mk[1-9A-HJ-NP-Za-km-z]+$/);
    assert.equal(didKeyFromPublicKey(publicKeyFromDidKey(k.did)), k.did);
  });

  it("rejects malformed or non-Ed25519 did:keys", () => {
    assert.equal(isDidKey("did:key:z6MkInvalid0OIl"), false);
    assert.equal(isDidKey("did:web:example.com"), false);
    assert.equal(isDidKey("did:key:z" + base58btcEncode(Uint8Array.from([0x12, 0x00, ...new Array(32).fill(1)]))), false);
  });
});

describe("RFC 9421 request signatures", () => {
  const key = generateAgentKey();
  const body = JSON.stringify({ hello: "world" });
  const sign = (over: Partial<Parameters<typeof signRequest>[0]> = {}) =>
    signRequest({
      method: "POST",
      targetUri: URI,
      headers: { "idempotency-key": "idem-12345678" },
      body,
      key,
      created: Math.floor(NOW / 1000),
      nonce: randomUUID(),
      ...over,
    });
  const verify = (headers: Record<string, string>, over: Partial<Parameters<typeof verifyRequest>[0]> = {}) =>
    verifyRequest({
      method: "POST",
      targetUri: URI,
      header: (n) => ({ "idempotency-key": "idem-12345678", ...headers })[n] ?? null,
      body,
      now: NOW,
      ...over,
    });

  it("verifies a valid signature and returns the did:key as identity", () => {
    const r = verify(sign());
    assert.ok(r.ok, !r.ok ? r.reason : "");
    assert.equal(r.ok && r.keyid, key.did);
  });

  it("rejects a tampered body, path, method or idempotency key", () => {
    const h = sign();
    assert.equal(verify(h, { body: JSON.stringify({ hello: "mallory" }) }).ok, false);
    assert.equal(verify(h, { targetUri: URI + "/other" }).ok, false);
    assert.equal(verify(h, { method: "PUT" }).ok, false);
    assert.equal(verify({ ...h, "idempotency-key": "idem-99999999" }).ok, false);
  });

  it("rejects stale or future timestamps beyond 5 minutes", () => {
    assert.equal(verify(sign({ created: Math.floor(NOW / 1000) - 301 })).ok, false);
    assert.equal(verify(sign({ created: Math.floor(NOW / 1000) + 301 })).ok, false);
    assert.equal(verify(sign({ created: Math.floor(NOW / 1000) - 299 })).ok, true);
  });

  it("rejects a signature made by a different key than keyid claims", () => {
    const h = sign();
    const forged = sign({ key: generateAgentKey() });
    assert.equal(verify({ ...h, signature: forged.signature! }).ok, false);
  });

  it("requires content-digest to be covered when there is a body", () => {
    const h = sign({ body: undefined });
    assert.equal(verify({ ...h, "content-digest": contentDigest(body) }).ok, false);
  });

  it("rejects unsupported components and parameters", () => {
    const h = sign();
    assert.equal(verify({ ...h, "signature-input": h["signature-input"]!.replace('"@method"', '"@query"') }).ok, false);
    assert.equal(verify({ ...h, "signature-input": h["signature-input"] + ';expires=1' }).ok, false);
  });
});

describe("signed mandates and documents", () => {
  const principal = generateAgentKey();
  const agentKey = generateAgentKey();
  const unsigned = {
    id: "mnd-1",
    principalId: principal.did,
    agentId: agentKey.did,
    bounds: { refundUsd: { min: 0, max: 600 } },
    expiresAt: NOW + 86_400_000,
  };

  it("verifies a principal-signed mandate and detects tampering", () => {
    const m = signMandate(unsigned, principal);
    assert.equal(verifyMandateSignature(m), true);
    assert.equal(verifyMandateSignature({ ...m, bounds: { refundUsd: { min: 0, max: 1000 } } }), false, "agent widened its own bounds");
    assert.equal(verifyMandateSignature({ ...m, principalId: agentKey.did }), false);
  });

  it("refuses to sign a mandate for a different principal", () => {
    assert.throws(() => signMandate(unsigned, agentKey));
  });

  it("verifies platform-signed documents and binds them to the signer", () => {
    const platform = generateAgentKey();
    const doc = signDocument({ disputeId: "d1", status: "UNRESOLVED", reason: "STALLED" }, platform);
    assert.equal(verifyDocument(doc, platform.did), true);
    assert.equal(verifyDocument({ ...doc, document: { ...doc.document, reason: "TIMEOUT" } }, platform.did), false);
    assert.equal(verifyDocument(doc, generateAgentKey().did), false);
  });
});
