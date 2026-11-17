/**
 * Signed documents: principal mandates, and platform-signed outcomes
 * (settlement instructions, UNRESOLVED certificates).
 *
 * Every signature covers a domain-separation prefix + canonical JSON, so a
 * signature made for one purpose can never be replayed as another.
 */
import { canonicalJson, type Mandate } from "@agent-mediate/core";
import { didKeyFromEd25519Jwk, didWebFromUrl, ed25519PublicJwkFromDidKey, urlFromDidWeb, type Ed25519PublicJwk } from "./did-web.ts";
import { isDidKey, signText, verifyText, type AgentKey } from "./identity.ts";

const MANDATE_DOMAIN = "agent-mediate/mandate/v1\n";
export const DOCUMENT_DOMAIN_V1 = "agent-mediate/document/v1\n";
export const DOCUMENT_DOMAIN_V2 = "agent-mediate/document/v2\n";
export const KEY_HISTORY_TYPE = "agent-mediate/key-history/v1" as const;
export const KEY_ROTATION_TYPE = "agent-mediate/key-rotation/v1" as const;
export const MAX_KEY_ROTATION_HOPS = 8;
export const HONOURS_ATTESTATION_TYPE = "agent-mediate/honours-attestation/v1" as const;
/** Default freshness lifetime of a signed `KeyHistoryDocument` (7 days; the API re-signs every 60 s, `CR3-PROTO-M2`). */
export const DEFAULT_KEY_HISTORY_TTL_MS = 7 * 86_400_000;

export interface HonoursAttestationDocument {
  type: typeof HONOURS_ATTESTATION_TYPE;
  rulesVersion: string;
  rulesHash: string;
  environment: string;
  domain: string;
  /** Verified `did:web:<domain>` when verified via `/.well-known/did.json`, or `null` for `a2a_card`-only domains (`CR-SVC-L6`). */
  didWeb: string | null;
  agentIds: string[];
  memberSince: number;
  verifiedAt: number;
  qualifiedHonoredCount: number;
  totalHonoredObligations: number;
  confirmedByCounterpartyCount: number;
  distinctCounterparties: number;
  verifiedDomainCounterparties: number;
  curedLateCount: number;
  fulfilmentRate: 1;
  lastHonoredAt: number;
  issuedAt: number;
}

export function defaultPlatformKeyId(did: string): string {
  return `${did}#key-1`;
}

export function mandateSigningPayload(mandate: Mandate): string {
  const { signature: _ignored, ...unsigned } = mandate;
  return MANDATE_DOMAIN + canonicalJson(unsigned);
}

/** Principal signs a mandate for its agent. `principalId` must be the principal's did:key. */
export function signMandate(unsigned: Omit<Mandate, "signature">, principal: AgentKey): Mandate {
  if (unsigned.principalId !== principal.did) throw new Error("principalId must equal the signing key's did");
  const mandate: Mandate = { ...unsigned };
  return { ...mandate, signature: signText(principal, mandateSigningPayload(mandate)) };
}

export function verifyMandateSignature(mandate: Mandate): boolean {
  try {
    if (!mandate || typeof mandate !== "object" || typeof mandate.signature !== "string" || typeof mandate.principalId !== "string") {
      return false;
    }
    return verifyText(mandate.principalId, mandateSigningPayload(mandate), mandate.signature);
  } catch {
    return false;
  }
}

export interface SignedDocumentProof {
  type: "Ed25519Signature2026";
  verificationMethod: string;
  /** Signed verification key identifier (`KEY-1`). Present on all v2 proofs. */
  keyId?: string;
  /** Signed Unix timestamp in ms (`KEY-1`). Present on all v2 proofs. */
  created?: number;
  /** Optional signed expiry timestamp in ms (`KEY-1`). */
  expiresAt?: number;
  signatureValue: string;
}

export interface SignedDocument<T> {
  document: T;
  proof: SignedDocumentProof;
}

export interface SignDocumentOptions {
  keyId?: string;
  created?: number;
  expiresAt?: number;
}

export interface VerifyDocumentOptions {
  /** When provided, rejects expired signatures (`now >= proof.expiresAt`) (`KEY-1`). */
  now?: number;
  /** When provided, requires `proof.keyId === expectedKeyId`. */
  expectedKeyId?: string;
}

export function signDocument<T extends object>(
  document: T,
  platform: AgentKey,
  opts?: SignDocumentOptions,
): SignedDocument<T> {
  const keyId = opts?.keyId ?? defaultPlatformKeyId(platform.did);
  const created = opts?.created ?? Date.now();
  if (!keyId || typeof keyId !== "string") throw new Error("keyId must be a non-empty string");
  if (!Number.isSafeInteger(created) || created <= 0) throw new Error("created must be a positive integer timestamp");
  if (opts?.expiresAt !== undefined && (!Number.isSafeInteger(opts.expiresAt) || opts.expiresAt <= created)) {
    throw new Error("expiresAt must be an integer timestamp after created");
  }
  const proofWithoutSig = {
    type: "Ed25519Signature2026" as const,
    verificationMethod: platform.did,
    keyId,
    created,
    ...(opts?.expiresAt !== undefined ? { expiresAt: opts.expiresAt } : {}),
  };
  const payload = DOCUMENT_DOMAIN_V2 + canonicalJson({ document, proof: proofWithoutSig });
  return {
    document,
    proof: {
      ...proofWithoutSig,
      signatureValue: signText(platform, payload),
    },
  };
}

export function verifyDocument(
  signed: SignedDocument<object>,
  expectedSigner: string,
  opts?: VerifyDocumentOptions,
): boolean {
  try {
    if (!signed || typeof signed !== "object" || !signed.document || typeof signed.document !== "object") return false;
    const proof = signed.proof;
    if (!proof || typeof proof !== "object") return false;
    if (proof.type !== "Ed25519Signature2026") return false;
    if (proof.verificationMethod !== expectedSigner) return false;
    if (typeof proof.signatureValue !== "string") return false;
    if (opts?.now !== undefined && (!Number.isFinite(opts.now) || opts.now <= 0)) return false;
    if (opts?.expectedKeyId !== undefined && proof.keyId !== opts.expectedKeyId) return false;

    const hasV2Field = proof.keyId !== undefined || proof.created !== undefined || proof.expiresAt !== undefined;
    if (hasV2Field) {
      if (typeof proof.keyId !== "string" || proof.keyId.length === 0) return false;
      if (typeof proof.created !== "number" || !Number.isSafeInteger(proof.created) || proof.created <= 0) return false;
      if (proof.expiresAt !== undefined) {
        if (typeof proof.expiresAt !== "number" || !Number.isSafeInteger(proof.expiresAt) || proof.expiresAt <= proof.created) {
          return false;
        }
        if (opts?.now !== undefined && opts.now >= proof.expiresAt) return false;
      }
      const allowedKeys = new Set(["type", "verificationMethod", "keyId", "created", "expiresAt", "signatureValue"]);
      if (Object.keys(proof).some((k) => !allowedKeys.has(k))) return false;
      const { signatureValue, ...proofWithoutSig } = proof;
      const payload = DOCUMENT_DOMAIN_V2 + canonicalJson({ document: signed.document, proof: proofWithoutSig });
      return verifyText(expectedSigner, payload, signatureValue);
    }

    // Legacy v1 fallback: allowed ONLY when all v2 proof metadata fields are absent.
    // Because v2 signatures cover `DOCUMENT_DOMAIN_V2 + { document, proof }`, stripping `expiresAt`/`keyId`/`created`
    // from a v2 document cannot verify under `DOCUMENT_DOMAIN_V1`.
    const v1Keys = new Set(["type", "verificationMethod", "signatureValue"]);
    if (Object.keys(proof).some((k) => !v1Keys.has(k))) return false;
    return verifyText(expectedSigner, DOCUMENT_DOMAIN_V1 + canonicalJson(signed.document), proof.signatureValue);
  } catch {
    return false;
  }
}

// ---------------------------------------------------------------------------
// KEY-1: Signed Platform Key History (`/.well-known/key-history.json`)
// ---------------------------------------------------------------------------

export type KeyHistoryStatus = "active" | "retired" | "revoked";

export interface KeyRotationDocument {
  type: typeof KEY_ROTATION_TYPE;
  platformDidWeb: string;
  fromDid: string;
  toDid: string;
  rotatedAt: number;
}

/**
 * Sign a one-time forward key-rotation handoff (`K_old -> K_new`, `P1-1`) with the retiring platform key `fromKey`.
 * Embedded inside `/.well-known/key-history.json` (`rotations`) so published clients pinned to `K_old` via
 * `DEFAULT_PRODUCTION_PLATFORM_DIDS` can cryptographically roll forward to `K_new` on planned rotations without
 * keeping `K_old` mounted on the runtime server, while compromised/revoked keys still fail closed.
 */
export function signKeyRotation(opts: {
  baseUrl: string;
  fromKey: AgentKey;
  fromKeyId?: string;
  toDid: string;
  rotatedAt: number;
}): SignedDocument<KeyRotationDocument> {
  if (!isDidKey(opts.toDid)) throw new Error("toDid must be a valid Ed25519 did:key");
  if (opts.toDid === opts.fromKey.did) throw new Error("toDid must differ from fromKey.did");
  if (!Number.isSafeInteger(opts.rotatedAt) || opts.rotatedAt <= 0) {
    throw new Error("rotatedAt must be a positive integer timestamp");
  }
  const fromKeyId = opts.fromKeyId ?? defaultPlatformKeyId(opts.fromKey.did);
  const doc: KeyRotationDocument = {
    type: KEY_ROTATION_TYPE,
    platformDidWeb: didWebFromUrl(opts.baseUrl),
    fromDid: opts.fromKey.did,
    toDid: opts.toDid,
    rotatedAt: opts.rotatedAt,
  };
  return signDocument(doc, opts.fromKey, { keyId: fromKeyId, created: opts.rotatedAt });
}

export interface HistoricalPlatformKey {
  did: string;
  keyId?: string;
  status: "retired" | "revoked";
  validFrom: number;
  validUntil?: number;
  revokedAt?: number;
  compromisedAfter?: number;
  reason?: string;
  /** Optional forward `fromDid -> toDid` handoff signed by this retired key (`P1-1`). */
  rotationEndorsement?: SignedDocument<KeyRotationDocument>;
}

export interface KeyHistoryEntry {
  keyId: string;
  did: string;
  publicKeyJwk: Ed25519PublicJwk;
  status: KeyHistoryStatus;
  validFrom: number;
  validUntil?: number;
  revokedAt?: number;
  compromisedAfter?: number;
  reason?: string;
}

export interface KeyHistoryDocument {
  type: typeof KEY_HISTORY_TYPE;
  platformDidWeb: string;
  activeDid: string;
  activeKeyId: string;
  updatedAt: number;
  keys: KeyHistoryEntry[];
  /** Optional forward `K_old -> K_new` rotation endorsements signed by retired keys (`P1-1`). */
  rotations?: Array<SignedDocument<KeyRotationDocument>>;
}

export function buildSignedKeyHistory(opts: {
  baseUrl: string;
  activeKey: AgentKey;
  activeKeyId?: string;
  activeValidFrom: number;
  activeExpiresAt?: number;
  historicalKeys?: HistoricalPlatformKey[];
  rotations?: Array<SignedDocument<KeyRotationDocument>>;
  updatedAt: number;
  documentExpiresAt?: number;
}): SignedDocument<KeyHistoryDocument> {
  if (!Number.isSafeInteger(opts.activeValidFrom) || opts.activeValidFrom <= 0) {
    throw new Error("activeValidFrom must be a positive integer timestamp");
  }
  if (!Number.isSafeInteger(opts.updatedAt) || opts.updatedAt <= 0) {
    throw new Error("updatedAt must be a positive integer timestamp");
  }
  if (opts.activeExpiresAt !== undefined && (!Number.isSafeInteger(opts.activeExpiresAt) || opts.activeExpiresAt <= opts.activeValidFrom)) {
    throw new Error("activeExpiresAt must be an integer timestamp after activeValidFrom");
  }
  const activeKeyId = opts.activeKeyId ?? defaultPlatformKeyId(opts.activeKey.did);
  const seenDids = new Set<string>([opts.activeKey.did]);
  const seenKeyIds = new Set<string>([activeKeyId]);
  const collectedRotations: Array<SignedDocument<KeyRotationDocument>> = [...(opts.rotations ?? [])];

  const activeEntry: KeyHistoryEntry = {
    keyId: activeKeyId,
    did: opts.activeKey.did,
    publicKeyJwk: ed25519PublicJwkFromDidKey(opts.activeKey.did),
    status: "active",
    validFrom: opts.activeValidFrom,
    ...(opts.activeExpiresAt !== undefined ? { validUntil: opts.activeExpiresAt } : {}),
  };

  const historicalEntries: KeyHistoryEntry[] = (opts.historicalKeys ?? []).map((h) => {
    if (!isDidKey(h.did)) throw new Error(`historical key ${h.did} is not a valid Ed25519 did:key`);
    if (h.status !== "retired" && h.status !== "revoked") {
      throw new Error(`historical key ${h.did} status must be "retired" or "revoked"`);
    }
    if (!Number.isSafeInteger(h.validFrom) || h.validFrom <= 0) {
      throw new Error(`historical key ${h.did} validFrom must be a positive integer timestamp`);
    }
    if (h.validUntil !== undefined && (!Number.isSafeInteger(h.validUntil) || h.validUntil < h.validFrom)) {
      throw new Error(`historical key ${h.did} validUntil must be >= validFrom`);
    }
    if (h.revokedAt !== undefined && (!Number.isSafeInteger(h.revokedAt) || h.revokedAt <= 0)) {
      throw new Error(`historical key ${h.did} revokedAt must be a positive integer timestamp`);
    }
    if (h.compromisedAfter !== undefined && (!Number.isSafeInteger(h.compromisedAfter) || h.compromisedAfter <= 0)) {
      throw new Error(`historical key ${h.did} compromisedAfter must be a positive integer timestamp`);
    }
    const keyId = h.keyId ?? defaultPlatformKeyId(h.did);
    if (seenDids.has(h.did)) throw new Error(`duplicate platform key did in key history: ${h.did}`);
    if (seenKeyIds.has(keyId)) throw new Error(`duplicate platform keyId in key history: ${keyId}`);
    seenDids.add(h.did);
    seenKeyIds.add(keyId);
    if (h.rotationEndorsement) {
      collectedRotations.push(h.rotationEndorsement);
    }
    return {
      keyId,
      did: h.did,
      publicKeyJwk: ed25519PublicJwkFromDidKey(h.did),
      status: h.status,
      validFrom: h.validFrom,
      ...(h.validUntil !== undefined ? { validUntil: h.validUntil } : {}),
      ...(h.revokedAt !== undefined ? { revokedAt: h.revokedAt } : {}),
      ...(h.compromisedAfter !== undefined ? { compromisedAfter: h.compromisedAfter } : {}),
      ...(h.reason ? { reason: h.reason } : {}),
    };
  });

  historicalEntries.sort((a, b) => b.validFrom - a.validFrom);
  const platformDidWeb = didWebFromUrl(opts.baseUrl);
  const allEntries = [activeEntry, ...historicalEntries];
  const uniqueRotations: Array<SignedDocument<KeyRotationDocument>> = [];
  const seenFromDid = new Set<string>();
  for (const rot of collectedRotations) {
    const rdoc = rot?.document;
    if (!rdoc || rdoc.type !== KEY_ROTATION_TYPE) {
      throw new Error(`rotation endorsement type must be ${KEY_ROTATION_TYPE}`);
    }
    if (rdoc.platformDidWeb !== platformDidWeb) {
      throw new Error(`rotation endorsement platformDidWeb ${rdoc.platformDidWeb} does not match ${platformDidWeb}`);
    }
    if (!isDidKey(rdoc.fromDid) || !isDidKey(rdoc.toDid) || rdoc.fromDid === rdoc.toDid) {
      throw new Error("rotation endorsement must specify distinct valid Ed25519 fromDid and toDid");
    }
    if (seenFromDid.has(rdoc.fromDid)) {
      throw new Error(`duplicate rotation endorsement fromDid: ${rdoc.fromDid}`);
    }
    const fromEntry = allEntries.find((e) => e.did === rdoc.fromDid);
    if (!fromEntry || fromEntry.status !== "retired" || fromEntry.revokedAt !== undefined || fromEntry.compromisedAfter !== undefined) {
      throw new Error(`rotation endorsement fromDid ${rdoc.fromDid} must reference a non-revoked retired key entry`);
    }
    if (!allEntries.some((e) => e.did === rdoc.toDid)) {
      throw new Error(`rotation endorsement toDid ${rdoc.toDid} must reference a key entry in key history`);
    }
    if (!Number.isSafeInteger(rdoc.rotatedAt) || rdoc.rotatedAt < fromEntry.validFrom || rdoc.rotatedAt > opts.updatedAt) {
      throw new Error(`rotation endorsement rotatedAt for ${rdoc.fromDid} must lie within [${fromEntry.validFrom}, ${opts.updatedAt}]`);
    }
    if (rot.proof?.created !== rdoc.rotatedAt || !verifyDocument(rot, rdoc.fromDid, { expectedKeyId: fromEntry.keyId })) {
      throw new Error(`rotation endorsement signature for ${rdoc.fromDid} -> ${rdoc.toDid} is invalid`);
    }
    seenFromDid.add(rdoc.fromDid);
    uniqueRotations.push(rot);
  }
  uniqueRotations.sort((a, b) => a.document.rotatedAt - b.document.rotatedAt);

  const doc: KeyHistoryDocument = {
    type: KEY_HISTORY_TYPE,
    platformDidWeb,
    activeDid: opts.activeKey.did,
    activeKeyId,
    updatedAt: opts.updatedAt,
    keys: allEntries,
    ...(uniqueRotations.length > 0 ? { rotations: uniqueRotations } : {}),
  };

  return signDocument(doc, opts.activeKey, {
    keyId: activeKeyId,
    created: opts.updatedAt,
    expiresAt: opts.documentExpiresAt ?? opts.updatedAt + DEFAULT_KEY_HISTORY_TTL_MS,
  });
}

export type VerifiedKeyHistory =
  | { ok: true; activeKey: KeyHistoryEntry; rotatedFromDid?: string }
  | { ok: false; reason: string };

/**
 * Verify a signed `KeyHistoryDocument` (`/.well-known/key-history.json`) (`KEY-1`, `FS-M13`, `CR3-PROTO-M2`, `P1-1`).
 * Enforces `document.type === KEY_HISTORY_TYPE`, v2 `created` + `expectedKeyId === activeKeyId`,
 * `expectedActiveDid` pinning (accepting either `activeDid === expectedActiveDid` or an unbroken forward chain of
 * retired-key `agent-mediate/key-rotation/v1` endorsements from `expectedActiveDid` to `activeDid`), signature + expiry
 * check, optional `maxAgeMs` / monotonic `minUpdatedAt` anti-rollback bounds, and an active key entry in `keys`.
 */
export function verifyKeyHistory(
  keyHistory: SignedDocument<KeyHistoryDocument>,
  opts?: { expectedActiveDid?: string; now?: number; maxAgeMs?: number; minUpdatedAt?: number },
): VerifiedKeyHistory {
  if (!keyHistory || typeof keyHistory !== "object" || !keyHistory.document || keyHistory.document.type !== KEY_HISTORY_TYPE) {
    return { ok: false, reason: `key history document type must be ${KEY_HISTORY_TYPE}` };
  }
  const activeDid = keyHistory.document.activeDid;
  const activeKeyId = keyHistory.document.activeKeyId;
  if (typeof activeDid !== "string" || !isDidKey(activeDid) || typeof activeKeyId !== "string" || activeKeyId.length === 0) {
    return { ok: false, reason: "invalid key history activeDid/activeKeyId" };
  }
  if (opts?.expectedActiveDid !== undefined && (typeof opts.expectedActiveDid !== "string" || !isDidKey(opts.expectedActiveDid))) {
    return { ok: false, reason: "invalid expectedActiveDid" };
  }
  try {
    urlFromDidWeb(keyHistory.document.platformDidWeb);
  } catch {
    return { ok: false, reason: "invalid key history platformDidWeb" };
  }
  if (!Number.isSafeInteger(keyHistory.document.updatedAt) || keyHistory.document.updatedAt <= 0) {
    return { ok: false, reason: "invalid key history updatedAt" };
  }
  if (opts?.minUpdatedAt !== undefined) {
    if (!Number.isSafeInteger(opts.minUpdatedAt) || opts.minUpdatedAt <= 0) {
      return { ok: false, reason: "invalid minUpdatedAt" };
    }
    if (keyHistory.document.updatedAt < opts.minUpdatedAt) {
      return { ok: false, reason: "key history updatedAt precedes minUpdatedAt (rollback)" };
    }
  }
  if (opts?.maxAgeMs !== undefined) {
    if (!Number.isFinite(opts.maxAgeMs) || opts.maxAgeMs < 0) {
      return { ok: false, reason: "invalid maxAgeMs" };
    }
    if (opts.now === undefined || !Number.isFinite(opts.now) || opts.now <= 0) {
      return { ok: false, reason: "now is required when maxAgeMs is set" };
    }
    if (opts.now - keyHistory.document.updatedAt > opts.maxAgeMs) {
      return { ok: false, reason: "key history exceeds maxAgeMs" };
    }
  }
  if (keyHistory.proof?.created === undefined || !Number.isSafeInteger(keyHistory.proof.created) || keyHistory.proof.created <= 0) {
    return { ok: false, reason: "key history requires a v2 proof with created timestamp" };
  }
  if (
    !verifyDocument(keyHistory, activeDid, {
      ...(opts?.now !== undefined ? { now: opts.now } : {}),
      expectedKeyId: activeKeyId,
    })
  ) {
    return { ok: false, reason: "key history signature is invalid or expired" };
  }
  const keys = keyHistory.document.keys;
  if (!Array.isArray(keys)) {
    return { ok: false, reason: "key history keys missing" };
  }
  const seenDids = new Set<string>();
  const seenKeyIds = new Set<string>();
  const entryByDid = new Map<string, KeyHistoryEntry>();
  let activeCount = 0;
  for (const k of keys) {
    if (!k || typeof k !== "object" || typeof k.did !== "string" || !isDidKey(k.did) || typeof k.keyId !== "string" || k.keyId.length === 0) {
      return { ok: false, reason: "key history contains malformed key entry" };
    }
    if (k.status !== "active" && k.status !== "retired" && k.status !== "revoked") {
      return { ok: false, reason: "key history contains invalid key status" };
    }
    if (k.status === "active") activeCount++;
    if (seenDids.has(k.did) || seenKeyIds.has(k.keyId)) {
      return { ok: false, reason: "key history contains duplicate key did or keyId" };
    }
    seenDids.add(k.did);
    seenKeyIds.add(k.keyId);
    try {
      if (didKeyFromEd25519Jwk(k.publicKeyJwk) !== k.did) {
        return { ok: false, reason: `key history publicKeyJwk does not match ${k.did}` };
      }
    } catch {
      return { ok: false, reason: `key history publicKeyJwk is invalid for ${k.did}` };
    }
    entryByDid.set(k.did, k);
  }
  if (activeCount !== 1) {
    return { ok: false, reason: "key history must contain exactly one active key entry" };
  }
  const activeInList = keys.find(
    (k) => k && typeof k === "object" && k.did === activeDid && k.keyId === activeKeyId && k.status === "active",
  );
  if (!activeInList) {
    return { ok: false, reason: "key history missing active key entry" };
  }
  if (
    !Number.isSafeInteger(activeInList.validFrom) ||
    activeInList.validFrom <= 0 ||
    activeInList.compromisedAfter !== undefined ||
    activeInList.revokedAt !== undefined ||
    (activeInList.validUntil !== undefined && (!Number.isSafeInteger(activeInList.validUntil) || activeInList.validUntil < activeInList.validFrom)) ||
    keyHistory.proof.created < activeInList.validFrom
  ) {
    return { ok: false, reason: "key history active key entry is invalid" };
  }
  if (
    activeInList.validUntil !== undefined &&
    (keyHistory.proof.created > activeInList.validUntil || (opts?.now !== undefined && opts.now >= activeInList.validUntil))
  ) {
    return { ok: false, reason: "key history active key entry has expired" };
  }

  const rotations = keyHistory.document.rotations;
  const rotationByFromDid = new Map<string, KeyRotationDocument>();
  if (rotations !== undefined) {
    if (!Array.isArray(rotations) || rotations.length > MAX_KEY_ROTATION_HOPS * 2) {
      return { ok: false, reason: "key history rotations is malformed or exceeds maximum length" };
    }
    for (const rot of rotations) {
      const rdoc = rot?.document;
      if (
        !rot ||
        typeof rot !== "object" ||
        !rdoc ||
        typeof rdoc !== "object" ||
        rdoc.type !== KEY_ROTATION_TYPE ||
        rdoc.platformDidWeb !== keyHistory.document.platformDidWeb ||
        typeof rdoc.fromDid !== "string" ||
        !isDidKey(rdoc.fromDid) ||
        typeof rdoc.toDid !== "string" ||
        !isDidKey(rdoc.toDid) ||
        rdoc.fromDid === rdoc.toDid ||
        !Number.isSafeInteger(rdoc.rotatedAt) ||
        rdoc.rotatedAt <= 0 ||
        rdoc.rotatedAt > keyHistory.document.updatedAt
      ) {
        return { ok: false, reason: "key history contains malformed rotation endorsement" };
      }
      if (rotationByFromDid.has(rdoc.fromDid)) {
        return { ok: false, reason: "key history contains duplicate rotation endorsement fromDid" };
      }
      const fromEntry = entryByDid.get(rdoc.fromDid);
      const toEntry = entryByDid.get(rdoc.toDid);
      if (
        !fromEntry ||
        !toEntry ||
        fromEntry.status !== "retired" ||
        fromEntry.revokedAt !== undefined ||
        fromEntry.compromisedAfter !== undefined ||
        !Number.isSafeInteger(fromEntry.validFrom) ||
        fromEntry.validFrom <= 0 ||
        (fromEntry.validUntil !== undefined && (!Number.isSafeInteger(fromEntry.validUntil) || fromEntry.validUntil < fromEntry.validFrom)) ||
        rdoc.rotatedAt < fromEntry.validFrom
      ) {
        return { ok: false, reason: "key history rotation endorsement references non-retired or invalid key" };
      }
      if (
        rot.proof?.created !== rdoc.rotatedAt ||
        !verifyDocument(rot, rdoc.fromDid, {
          ...(opts?.now !== undefined ? { now: opts.now } : {}),
          expectedKeyId: fromEntry.keyId,
        })
      ) {
        return { ok: false, reason: "key history rotation endorsement signature is invalid" };
      }
      rotationByFromDid.set(rdoc.fromDid, rdoc);
    }
  }

  if (opts?.expectedActiveDid !== undefined && activeDid !== opts.expectedActiveDid) {
    let curr = opts.expectedActiveDid;
    let prevRotatedAt = 0;
    const visited = new Set<string>([curr]);
    let hops = 0;
    while (curr !== activeDid && hops < MAX_KEY_ROTATION_HOPS) {
      const step = rotationByFromDid.get(curr);
      if (!step || visited.has(step.toDid) || step.rotatedAt < prevRotatedAt) break;
      const targetEntry = entryByDid.get(step.toDid);
      if (!targetEntry || targetEntry.status === "revoked" || targetEntry.revokedAt !== undefined || targetEntry.compromisedAfter !== undefined) {
        break;
      }
      visited.add(step.toDid);
      prevRotatedAt = step.rotatedAt;
      curr = step.toDid;
      hops++;
    }
    if (curr !== activeDid) {
      return { ok: false, reason: "key history activeDid does not match pinned active platformDid" };
    }
    return { ok: true, activeKey: activeInList, rotatedFromDid: opts.expectedActiveDid };
  }
  return { ok: true, activeKey: activeInList };
}

export type VerifiedWithKeyHistory =
  | { ok: true; key: KeyHistoryEntry }
  | { ok: false; reason: string };

/**
 * Verify a platform-signed document against a signed `KeyHistoryDocument` (`/.well-known/key-history.json`).
 * - Verifies the `KeyHistoryDocument`'s own signature against `expectedActiveDid` (when pinned) or `activeDid`.
 * - Accepts `active` and `retired` keys within their `[validFrom, validUntil]` window.
 * - Rejects `revoked` or compromised keys unconditionally.
 */
export function verifyDocumentWithKeyHistory(
  signed: SignedDocument<object>,
  keyHistory: SignedDocument<KeyHistoryDocument>,
  opts: { expectedActiveDid: string; now?: number; maxAgeMs?: number; minUpdatedAt?: number },
): VerifiedWithKeyHistory {
  // CR-CORE-L3: without an out-of-band pin a key history is self-certifying (anyone can mint one listing any key),
  // so a document verified "against" it proves nothing. The pin is mandatory.
  if (!opts || typeof opts.expectedActiveDid !== "string" || !isDidKey(opts.expectedActiveDid)) {
    return { ok: false, reason: "expectedActiveDid (the out-of-band pinned platform did:key) is required" };
  }
  const verifiedHistory = verifyKeyHistory(keyHistory, opts);
  if (!verifiedHistory.ok) return verifiedHistory;
  const keys = keyHistory.document.keys;

  const signerDid = signed?.proof?.verificationMethod;
  if (typeof signerDid !== "string") return { ok: false, reason: "missing document proof.verificationMethod" };
  const entry = keys.find(
    (k) => k && typeof k === "object" && k.did === signerDid && (signed.proof.keyId === undefined || k.keyId === signed.proof.keyId),
  );
  if (!entry) return { ok: false, reason: "document signing key not present in key history" };
  if (entry.status === "revoked" || entry.revokedAt !== undefined) {
    return { ok: false, reason: `signing key ${entry.did} has been revoked` };
  }
  if (entry.compromisedAfter !== undefined) {
    return { ok: false, reason: `signing key ${entry.did} has a recorded compromise` };
  }
  if (entry.status !== "active" && entry.status !== "retired") {
    return { ok: false, reason: `unknown signing key status ${String(entry.status)}` };
  }
  if (!Number.isSafeInteger(entry.validFrom) || entry.validFrom <= 0) {
    return { ok: false, reason: "signing key validFrom is invalid" };
  }
  if (entry.validUntil !== undefined && (!Number.isSafeInteger(entry.validUntil) || entry.validUntil < entry.validFrom)) {
    return { ok: false, reason: "signing key validUntil is invalid" };
  }
  if (signed.proof.created === undefined || !Number.isSafeInteger(signed.proof.created) || signed.proof.created <= 0) {
    return { ok: false, reason: "key-history verification requires a v2 proof with created timestamp" };
  }
  if (!verifyDocument(signed, entry.did, opts?.now !== undefined ? { now: opts.now } : undefined)) {
    return { ok: false, reason: "document signature is invalid or expired" };
  }
  if (signed.proof.created < entry.validFrom) {
    return { ok: false, reason: "document proof.created precedes signing key validFrom" };
  }
  if (entry.validUntil !== undefined && signed.proof.created > entry.validUntil) {
    return { ok: false, reason: "document proof.created exceeds retired signing key validUntil" };
  }
  return { ok: true, key: entry };
}
