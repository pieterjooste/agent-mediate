/**
 * Minimal RFC 9421 webhook receiver for Agent-Mediate notifications and dispute events.
 *
 * Verifies:
 *   1. 64 KiB request body cap enforced before buffering (`413 Payload Too Large`)
 *   2. Exact reconstructed request URL (`PUBLIC_WEBHOOK_ORIGIN` + `req.url`, plus path match when `PUBLIC_WEBHOOK_URL` is set)
 *   3. Platform Ed25519 signature (`tag="agent-mediate-webhook-v1"`) against pinned `PLATFORM_DID` and optional `AGENT_DID`
 *   4. Bounded 10-minute signature `nonce` replay cache + bounded `(disputeId, seq)` deduplication cache (FIFO eviction)
 *
 * Run:
 *   PLATFORM_DID=did:key:z6Mk... PUBLIC_WEBHOOK_URL=https://agent.example/webhooks/mediate node examples/webhook-receiver.ts
 *   PLATFORM_DID=did:key:z6Mk... PUBLIC_WEBHOOK_ORIGIN=https://agent.example node examples/webhook-receiver.ts
 */
import { createServer, type IncomingMessage, type RequestListener, type Server, type ServerResponse } from "node:http";
import { pathToFileURL } from "node:url";
import { AgentMediateClient, type WebhookEvent } from "@agent-mediate/sdk";

export const MAX_WEBHOOK_BODY_BYTES = 65_536;
export const DEFAULT_MAX_CACHE_ENTRIES = 10_000;
const NONCE_TTL_MS = 10 * 60_000;

export interface WebhookReceiverOptions {
  platformDid: string;
  publicWebhookUrl?: string;
  publicWebhookOrigin?: string;
  expectedAgentDid?: string;
  /** Accept unbound cold-start `DISPUTE_INVITE` webhooks alongside bound dispute/invite events (default `true`, `CR3-SDK-M2`). */
  allowUnboundInvite?: boolean;
  maxBodyBytes?: number;
  maxCacheEntries?: number;
  now?: () => number;
  onEvent?: (event: WebhookEvent & Record<string, unknown>) => void;
}

export function createWebhookReceiverHandler(opts: WebhookReceiverOptions): RequestListener {
  const maxBodyBytes = opts.maxBodyBytes ?? MAX_WEBHOOK_BODY_BYTES;
  const maxCacheEntries = opts.maxCacheEntries ?? DEFAULT_MAX_CACHE_ENTRIES;
  const nowFn = opts.now ?? Date.now;
  const parsedUrl = opts.publicWebhookUrl ? new URL(opts.publicWebhookUrl) : null;
  const origin = opts.publicWebhookOrigin
    ? new URL(opts.publicWebhookOrigin).origin
    : parsedUrl
      ? parsedUrl.origin
      : "http://localhost:9090";
  const expectedPath = parsedUrl ? `${parsedUrl.pathname}${parsedUrl.search}` : null;

  const seenNonces = new Map<string, number>();
  const processedEvents = new Set<string>();

  function pruneNonces(now: number): void {
    for (const [nonce, expiresAt] of seenNonces) {
      if (expiresAt <= now) seenNonces.delete(nonce);
    }
  }

  return (req: IncomingMessage, res: ServerResponse) => {
    if (req.method !== "POST") {
      res.writeHead(405, { allow: "POST" }).end();
      return;
    }

    const rawUrl = req.url ?? "";
    if (!rawUrl.startsWith("/") || rawUrl.startsWith("//")) {
      req.resume();
      res.writeHead(400, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, reason: "invalid request target" }));
      return;
    }
    if (expectedPath !== null && rawUrl !== expectedPath) {
      req.resume();
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: false, reason: "unexpected webhook path" }));
      return;
    }

    const clHeader = req.headers["content-length"];
    if (typeof clHeader === "string") {
      const declaredLen = Number(clHeader);
      if (!Number.isInteger(declaredLen) || declaredLen < 0 || declaredLen > maxBodyBytes) {
        req.destroy();
        res.writeHead(413, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, reason: "payload too large" }));
        return;
      }
    }

    const requestUrl = `${origin}${rawUrl}`;
    const chunks: Buffer[] = [];
    let totalBytes = 0;
    let aborted = false;

    req.on("data", (chunk: Buffer | string) => {
      if (aborted) return;
      const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk, "utf8");
      totalBytes += buf.length;
      if (totalBytes > maxBodyBytes) {
        aborted = true;
        req.destroy();
        if (!res.headersSent) {
          res.writeHead(413, { "content-type": "application/json" });
          res.end(JSON.stringify({ ok: false, reason: "payload too large" }));
        }
        return;
      }
      chunks.push(buf);
    });

    req.on("end", () => {
      if (aborted || res.writableEnded) return;
      const body = Buffer.concat(chunks).toString("utf8");
      const headers: Record<string, string> = {};
      for (const [k, v] of Object.entries(req.headers)) {
        if (typeof v === "string") headers[k.toLowerCase()] = v;
      }

      const now = nowFn();
      pruneNonces(now);

      const verified = AgentMediateClient.verifyWebhook(
        { url: requestUrl, headers, body },
        opts.platformDid,
        {
          now,
          allowUnboundInvite: opts.allowUnboundInvite ?? true,
          ...(opts.expectedAgentDid ? { agentId: opts.expectedAgentDid } : {}),
        },
      );

      if (!verified.ok) {
        res.writeHead(401, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, reason: verified.reason }));
        return;
      }

      if (seenNonces.has(verified.nonce)) {
        res.writeHead(409, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: false, reason: "replayed webhook nonce" }));
        return;
      }
      while (seenNonces.size >= maxCacheEntries) {
        const oldestNonce = seenNonces.keys().next().value;
        if (oldestNonce === undefined) break;
        seenNonces.delete(oldestNonce);
      }
      seenNonces.set(verified.nonce, now + NONCE_TTL_MS);

      const dedupeKey = `${verified.event.disputeId ?? verified.event.inviteId ?? "event"}:${verified.event.preCommit ? "pre:" : ""}${verified.event.seq ?? verified.event.type ?? verified.nonce}`;
      if (!processedEvents.has(dedupeKey)) {
        while (processedEvents.size >= maxCacheEntries) {
          const oldestEvent = processedEvents.values().next().value;
          if (oldestEvent === undefined) break;
          processedEvents.delete(oldestEvent);
        }
        processedEvents.add(dedupeKey);
        if (opts.onEvent) {
          opts.onEvent(verified.event as WebhookEvent & Record<string, unknown>);
        } else if (verified.event.preCommit) {
          // L-08: Pre-commit DISPUTE_NOTICE probe under requireDelivery=true: ack 200 immediately;
          // wait for follow-up DISPUTE_FILED before calling getDispute(disputeId).
          console.log("Verified pre-commit reachability probe:", JSON.stringify(verified.event));
        } else {
          console.log("Verified webhook event:", JSON.stringify(verified.event));
        }
      }

      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
  };
}

export function createWebhookReceiverServer(opts: WebhookReceiverOptions): Server {
  return createServer(createWebhookReceiverHandler(opts));
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const port = Number(process.env.PORT ?? 9090);
  const platformDid = process.env.PLATFORM_DID;
  const expectedAgentDid = process.env.AGENT_DID;
  const publicWebhookOrigin = process.env.PUBLIC_WEBHOOK_ORIGIN;
  const publicWebhookUrl =
    process.env.PUBLIC_WEBHOOK_URL ?? (publicWebhookOrigin ? undefined : `http://localhost:${port}/webhooks/mediate`);

  if (!platformDid) {
    console.error("Set PLATFORM_DID=did:key:z6Mk... (from GET /v1/platform or out-of-band pinning) before starting.");
    process.exit(1);
  }

  const server = createWebhookReceiverServer({
    platformDid,
    ...(publicWebhookUrl ? { publicWebhookUrl } : {}),
    ...(publicWebhookOrigin ? { publicWebhookOrigin } : {}),
    ...(expectedAgentDid ? { expectedAgentDid } : {}),
  });

  server.listen(port, () => {
    console.log(`Webhook receiver listening on port ${port} for ${publicWebhookUrl ?? publicWebhookOrigin}`);
  });
}
