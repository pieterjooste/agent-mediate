/**
 * Hash-chained audit log.
 *
 * Each event commits to its data with sha256(salt + canonical(data)). The salt
 * is per dispute and never disclosed, so commitments can be published without
 * letting anyone brute-force low-entropy private values (a refund between 0 and
 * 1000 has only 1001 possibilities). Chain hashes cover seq, type, time,
 * visibility, the commitment and the previous hash.
 */
import { canonicalJson, sha256Hex } from "./canonical.ts";
import type { DomainEvent, Visibility } from "./types.ts";

export const GENESIS_HASH = "0".repeat(64);

export function commitData(salt: string, data: Record<string, unknown>): string {
  return sha256Hex(salt + canonicalJson(data));
}

export function chainHash(e: Pick<DomainEvent, "seq" | "type" | "at" | "visibility" | "dataCommitment" | "prevHash">): string {
  return sha256Hex(canonicalJson([e.seq, e.type, e.at, e.visibility, e.dataCommitment, e.prevHash]));
}

export function buildEvent(
  salt: string,
  prev: { seq: number; head: string },
  type: string,
  at: number,
  visibility: Visibility,
  data: Record<string, unknown>,
): DomainEvent {
  const seq = prev.seq + 1;
  const dataCommitment = commitData(salt, data);
  const prevHash = prev.head;
  const hash = chainHash({ seq, type, at, visibility, dataCommitment, prevHash });
  return { seq, type, at, visibility, data, dataCommitment, prevHash, hash };
}

const HEX64 = /^[0-9a-f]{64}$/;
const VISIBILITIES: ReadonlySet<string> = new Set(["both", "claimant", "respondent", "internal"]);

/**
 * Verify an ordered event list from genesis. With `salt`, data is also checked
 * against its commitment (operator-side verification); without it, only the
 * publishable chain is checked.
 */
export function verifyAuditChain(events: DomainEvent[], salt?: string): { ok: true; head: string } | { ok: false; atSeq: number; reason: string } {
  if (!Array.isArray(events)) return { ok: false, atSeq: 0, reason: "events must be an array" };
  let head = GENESIS_HASH;
  let seq = 0;
  for (const e of events) {
    if (!e || typeof e !== "object" || Array.isArray(e)) return { ok: false, atSeq: seq + 1, reason: "malformed event" };
    if (!Number.isSafeInteger(e.seq) || e.seq !== seq + 1) return { ok: false, atSeq: typeof e.seq === "number" ? e.seq : seq + 1, reason: "sequence gap" };
    if (
      typeof e.type !== "string" ||
      !Number.isSafeInteger(e.at) ||
      typeof e.visibility !== "string" ||
      !VISIBILITIES.has(e.visibility) ||
      typeof e.dataCommitment !== "string" ||
      !HEX64.test(e.dataCommitment) ||
      typeof e.prevHash !== "string" ||
      typeof e.hash !== "string" ||
      !HEX64.test(e.hash)
    ) {
      return { ok: false, atSeq: e.seq, reason: "malformed event fields" };
    }
    if (e.prevHash !== head) return { ok: false, atSeq: e.seq, reason: "prevHash mismatch" };
    if (salt !== undefined) {
      if (typeof salt !== "string" || !e.data || typeof e.data !== "object" || Array.isArray(e.data)) {
        return { ok: false, atSeq: e.seq, reason: "malformed event data" };
      }
      try {
        if (commitData(salt, e.data) !== e.dataCommitment) {
          return { ok: false, atSeq: e.seq, reason: "data does not match commitment" };
        }
      } catch {
        return { ok: false, atSeq: e.seq, reason: "malformed event data" };
      }
    }
    try {
      if (chainHash(e) !== e.hash) return { ok: false, atSeq: e.seq, reason: "hash mismatch" };
    } catch {
      return { ok: false, atSeq: e.seq, reason: "malformed event fields" };
    }
    head = e.hash;
    seq = e.seq;
  }
  return { ok: true, head };
}

/**
 * One entry of the publishable chain, as a given party sees it (security review L1).
 *
 * An event the party may not see (the counterparty's own events, `internal` records) is published as an
 * opaque link: only `seq`, `prevHash` and `hash`. Its type, time, visibility and data commitment are hidden,
 * so `/audit` no longer reveals, e.g., when the counterparty submitted a sealed offer or replaced its mandate.
 * The chain stays verifiable: every visible entry's hash is recomputed from its fields, every link is checked
 * (`prevHash` = previous `hash`), and the head is committed to by the platform-signed outcome. Changing a
 * hidden entry changes its hash and therefore every later `prevHash` and the head. The hidden fields can be
 * disclosed to an auditor later, who checks them against the published hash (`chainHash`). The hash does not
 * leak them: it also covers the salted data commitment, which the party never sees.
 *
 * Residual (documented): the position of an opaque link between visible entries is visible, so a party can
 * tell that some event it cannot see happened between two it can (e.g. the order of sealed submissions).
 */
export type PublicAuditEntry =
  | { seq: number; type: string; at: number; visibility: Visibility; dataCommitment: string; prevHash: string; hash: string }
  | { seq: number; redacted: true; prevHash: string; hash: string };

export function publicAuditEntry(
  e: Pick<DomainEvent, "seq" | "type" | "at" | "visibility" | "dataCommitment" | "prevHash" | "hash">,
  viewer: "claimant" | "respondent",
): PublicAuditEntry {
  if (e.visibility === "both" || e.visibility === viewer) {
    return { seq: e.seq, type: e.type, at: e.at, visibility: e.visibility, dataCommitment: e.dataCommitment, prevHash: e.prevHash, hash: e.hash };
  }
  return { seq: e.seq, redacted: true, prevHash: e.prevHash, hash: e.hash };
}

/**
 * Verify a party's view of the chain from genesis: sequence, links and every visible entry's hash.
 * Redacted entries are accepted as opaque links. Compare `head` with the outcome document's `auditRoot`.
 */
export function verifyPublicAuditChain(
  entries: PublicAuditEntry[],
): { ok: true; head: string; redacted: number } | { ok: false; atSeq: number; reason: string } {
  if (!Array.isArray(entries)) return { ok: false, atSeq: 0, reason: "entries must be an array" };
  let head = GENESIS_HASH;
  let seq = 0;
  let redacted = 0;
  for (const e of entries) {
    if (!e || typeof e !== "object" || Array.isArray(e)) return { ok: false, atSeq: seq + 1, reason: "malformed entry" };
    if (!Number.isSafeInteger(e.seq) || e.seq !== seq + 1) return { ok: false, atSeq: typeof e.seq === "number" ? e.seq : seq + 1, reason: "sequence gap" };
    if (typeof e.prevHash !== "string" || e.prevHash !== head) return { ok: false, atSeq: e.seq, reason: "prevHash mismatch" };
    if ("redacted" in e || Object.hasOwn(e, "redacted")) {
      if ((e as { redacted?: unknown }).redacted !== true) return { ok: false, atSeq: e.seq, reason: "invalid redacted flag" };
      if ("type" in e || "at" in e || "visibility" in e || "dataCommitment" in e) {
        return { ok: false, atSeq: e.seq, reason: "redacted entry carries unredacted fields" };
      }
      if (typeof e.hash !== "string" || !HEX64.test(e.hash)) return { ok: false, atSeq: e.seq, reason: "malformed hash" };
      redacted++;
    } else {
      if (
        typeof e.type !== "string" ||
        !Number.isSafeInteger(e.at) ||
        typeof e.visibility !== "string" ||
        !VISIBILITIES.has(e.visibility) ||
        typeof e.dataCommitment !== "string" ||
        !HEX64.test(e.dataCommitment) ||
        typeof e.hash !== "string" ||
        !HEX64.test(e.hash)
      ) {
        return { ok: false, atSeq: e.seq, reason: "malformed entry fields" };
      }
      if (chainHash(e) !== e.hash) {
        return { ok: false, atSeq: e.seq, reason: "hash mismatch" };
      }
    }
    head = e.hash;
    seq = e.seq;
  }
  return { ok: true, head, redacted };
}
