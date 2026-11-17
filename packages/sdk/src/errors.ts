export class AgentMediateError extends Error {
  readonly status: number;
  readonly code: string;
  readonly body: unknown;
  readonly hint: string | undefined;
  readonly docs: string | undefined;
  /**
   * The Idempotency-Key the failed request was sent with (CR-SDK-M1). Retry a mutating call with this exact key:
   * the server then replays (or safely resumes) the original request instead of charging a fresh fee.
   */
  readonly idempotencyKey: string | undefined;
  /** True if an x402 payment authorisation was attached before the failure (a fee may have been charged). */
  readonly paymentSent: boolean;
  constructor(status: number, code: string, message: string, body?: unknown, extra?: { idempotencyKey?: string; paymentSent?: boolean }) {
    super(message);
    this.name = "AgentMediateError";
    this.status = status;
    this.code = code;
    this.body = body;
    const obj = body !== null && typeof body === "object" ? (body as Record<string, unknown>) : undefined;
    this.hint = typeof obj?.hint === "string" ? obj.hint : undefined;
    this.docs = typeof obj?.docs === "string" ? obj?.docs : undefined;
    this.idempotencyKey = extra?.idempotencyKey;
    this.paymentSent = extra?.paymentSent ?? false;
  }
}
