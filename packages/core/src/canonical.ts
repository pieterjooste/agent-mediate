import { createHash } from "node:crypto";

/** Published deterministic mechanism rules version embedded in outcomes and pre-dispute clauses. */
export const RULES_VERSION = "1.4.0";

/**
 * RFC 8785 (JCS) deterministic JSON: object keys sorted recursively by UTF-16 code units,
 * `-0` normalized to `0`, non-finite numbers rejected, `undefined` object fields omitted.
 * Used for every hash and signature so the same logical JSON value canonicalizes identically across languages.
 */
export function canonicalJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) throw new Error("Non-finite numbers cannot be canonicalized");
    return Object.is(value, -0) ? "0" : JSON.stringify(value);
  }
  if (typeof value === "string") return JSON.stringify(value);
  if (Array.isArray(value)) {
    const proto = Object.getPrototypeOf(value);
    if (proto !== Array.prototype) {
      throw new TypeError(`Non-plain array cannot be canonicalized: ${proto?.constructor?.name ?? "Array"}`);
    }
    const parts: string[] = [];
    for (let i = 0; i < value.length; i++) {
      const item = value[i];
      parts.push(item === undefined ? "null" : canonicalJson(item));
    }
    return `[${parts.join(",")}]`;
  }
  if (typeof value === "object") {
    const proto = Object.getPrototypeOf(value);
    if (proto !== null && proto !== Object.prototype) {
      throw new TypeError(`Non-plain object cannot be canonicalized: ${proto.constructor?.name ?? "Object"}`);
    }
    // Write the canonical string directly instead of passing a sorted object to JSON.stringify:
    // ECMAScript enumerates array-index keys ("0".."4294967294") in ascending numeric order ahead of
    // other keys, whereas RFC 8785 §3.2.3 requires UTF-16 code-unit order across all keys (review H7).
    const rec = value as Record<string, unknown>;
    const parts: string[] = [];
    for (const key of Object.keys(rec).sort()) {
      const v = rec[key];
      if (v !== undefined) parts.push(`${JSON.stringify(key)}:${canonicalJson(v)}`);
    }
    return `{${parts.join(",")}}`;
  }
  throw new TypeError(`Unsupported type in canonicalJson: ${typeof value}`);
}

export function sha256Hex(input: string): string {
  return createHash("sha256").update(input, "utf8").digest("hex");
}

/**
 * Standard contract commitment (DISC-3): lowercase hex SHA-256 of the RFC 8785 (JCS) canonical JSON
 * representation of `contract`, so two agents holding the same structured contract compute the same 64-hex hash.
 */
export function contractHash(contract: unknown): string {
  return sha256Hex(canonicalJson(contract));
}
