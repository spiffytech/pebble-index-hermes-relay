#!/usr/bin/env bun
/**
 * Pebble Index 01 ring → Hermes webhook relay.
 *
 * Verifies the ring's HMAC-SHA256 signature, then forwards the request byte-for-byte
 * to Hermes (same method, raw body, Content-Type boundary and X-Index-* headers).
 * Hermes re-verifies the same bytes, so we never touch the body.
 *
 * Any webhook path is accepted and forwarded verbatim under the configured Hermes root:
 * `POST /webhooks/<route>` and `POST /p/<profile>/webhooks/<route>`.
 *
 * Durability: if Hermes is unreachable or transiently failing, the request is buffered
 * in SQLite and retried with backoff. Hermes rejects requests whose X-Index-Timestamp is
 * more than 300s old, so buffered retries are re-signed with a fresh timestamp — the raw
 * body bytes are never altered.
 */
import { Database } from "bun:sqlite";
import { createHmac, timingSafeEqual } from "crypto";
import { mkdirSync } from "fs";

const PORT = parseInt(process.env.PORT || "8655", 10);
// Origin of the Hermes webhook listener. The relay preserves the incoming path, so
// `POST /webhooks/<route>` becomes `<root>/webhooks/<route>`. A trailing `/webhooks`
// is tolerated so either `http://host:8644` or `http://host:8644/webhooks` works.
const HERMES_WEBHOOK_ROOT = (
  process.env.HERMES_WEBHOOK_ROOT || "http://127.0.0.1:8644"
)
  .replace(/\/+$/, "")
  .replace(/\/webhooks$/, "");
const DATA_DIR = process.env.DATA_DIR || "./data";
const WINDOW_SECONDS = parseInt(
  process.env.TIMESTAMP_WINDOW_SECONDS || "300",
  10,
);
const BACKOFF_SECONDS = [5, 30, 120, 600, 3600];
const INITIAL_RETRY_DELAYS_MS = [250, 500]; // short in-request retries

// Per-route secrets from the environment: `WEBHOOK_SECRET_<ROUTE>`, where the route is
// uppercased and every non-alphanumeric character becomes `_` (env names cannot hold `-`).
// `foo-bar` and `foo_bar` therefore share a variable; the path is always forwarded as
// received, and Hermes is the final judge of which routes exist. There is no fallback:
// a route with no configured secret is rejected.
const SECRET_ENV_PREFIX = "WEBHOOK_SECRET_";

function routeSecretEnvKey(route: string): string {
  return SECRET_ENV_PREFIX + route.toUpperCase().replace(/[^A-Z0-9]/g, "_");
}

function routeSecret(route: string): string | undefined {
  return process.env[routeSecretEnvKey(route)];
}

function configuredRoutes(): string {
  const routes = Object.keys(process.env)
    .filter((key) => key.startsWith(SECRET_ENV_PREFIX))
    .map((key) => key.slice(SECRET_ENV_PREFIX.length).toLowerCase())
    .sort();
  return routes.length ? routes.join(", ") : "(none)";
}

mkdirSync(DATA_DIR, { recursive: true });
const db = new Database(`${DATA_DIR}/relay.db`);
db.exec("PRAGMA journal_mode = WAL;");
db.exec(`
  CREATE TABLE IF NOT EXISTS deliveries (
    delivery_id     TEXT PRIMARY KEY,
    received_at     INTEGER NOT NULL,
    body            BLOB NOT NULL,
    headers         TEXT NOT NULL,
    path            TEXT NOT NULL DEFAULT '/webhooks/pebble-index',
    status          TEXT NOT NULL DEFAULT 'pending',
    attempts        INTEGER NOT NULL DEFAULT 0,
    next_attempt_at INTEGER NOT NULL DEFAULT 0,
    last_error      TEXT,
    forwarded_at    INTEGER
  );
`);
db.exec(
  "CREATE INDEX IF NOT EXISTS idx_deliveries_pending ON deliveries(status, next_attempt_at);",
);
// Migration for databases created before `path` existed.
const deliveryColumns = db
  .query("PRAGMA table_info(deliveries)")
  .all() as { name: string }[];
if (!deliveryColumns.some((c) => c.name === "path")) {
  db.exec(
    "ALTER TABLE deliveries ADD COLUMN path TEXT NOT NULL DEFAULT '/webhooks/pebble-index'",
  );
}

interface DeliveryRow {
  delivery_id: string;
  received_at: number;
  body: Uint8Array;
  headers: string;
  path: string;
  status: string;
  attempts: number;
  next_attempt_at: number;
  last_error: string | null;
  forwarded_at: number | null;
}

let lastForwardAt: string | null = null;
let lastForwardStatus: number | string | null = null;
let lastForwardError: string | null = null;

// ── Signing ─────────────────────────────────────────────────────────────────

function signIndex(
  secret: string,
  version: string,
  timestamp: string,
  deliveryId: string,
  trigger: string,
  isTest: boolean,
  body: Uint8Array,
): string {
  const prefix = `v${version}\n${timestamp}\n${deliveryId}\n${trigger}\n${isTest ? 1 : 0}\n`;
  const hmac = createHmac("sha256", secret);
  hmac.update(prefix); // utf-8
  hmac.update(body);
  return hmac.digest("hex");
}

function signatureMatches(expected: string, provided: string): boolean {
  const a = Buffer.from(expected, "utf8");
  const b = Buffer.from(provided, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

// Base Hermes does not understand the Index signature. It verifies the generic V2 scheme:
//   X-Webhook-Signature-V2 = hex HMAC-SHA256(secret, "<X-Webhook-Timestamp>.<body>")
// We add that (plus X-Request-ID so Hermes can dedupe) while still forwarding the original
// X-Index-* headers, so an Index-aware Hermes keeps working too. The body is never altered.
function v2Signature(secret: string, timestamp: string, body: Uint8Array): string {
  const hmac = createHmac("sha256", secret);
  hmac.update(`${timestamp}.`); // utf-8
  hmac.update(body);
  return hmac.digest("hex");
}

// Signs the body we actually forward, with a fresh timestamp. Both schemes are set: Index (so an
// Index-aware Hermes still works) and generic V2 (what the base image verifies).
function signForwardHeaders(
  headers: Headers,
  secret: string,
  body: Uint8Array,
  meta: { version: string; deliveryId: string; trigger: string; isTest: boolean },
  timestamp = Math.floor(Date.now() / 1000).toString(),
): void {
  headers.set("x-index-timestamp", timestamp);
  headers.set(
    "x-index-signature",
    signIndex(secret, meta.version, timestamp, meta.deliveryId, meta.trigger, meta.isTest, body),
  );
  headers.set("x-webhook-timestamp", timestamp);
  headers.set("x-webhook-signature-v2", v2Signature(secret, timestamp, body));
  headers.set("x-request-id", meta.deliveryId);
}

// ── Request helpers ─────────────────────────────────────────────────────────

const FORWARDED_PREFIXES = ["x-index-"];
const FORWARDED_EXACT = new Set(["x-audio-size"]);

function collectForwardHeaders(headers: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  const contentType = headers.get("content-type");
  if (contentType) out["content-type"] = contentType;
  for (const [key, value] of headers) {
    const lower = key.toLowerCase();
    if (
      FORWARDED_PREFIXES.some((p) => lower.startsWith(p)) ||
      FORWARDED_EXACT.has(lower)
    ) {
      out[lower] = value;
    }
  }
  return out;
}

function headersToHeadersObject(record: Record<string, string>): Headers {
  const h = new Headers();
  for (const [k, v] of Object.entries(record)) h.set(k, v);
  return h;
}

function lastIndexOfBytes(haystack: Uint8Array, needle: Uint8Array): number {
  outer: for (let i = haystack.length - needle.length; i >= 0; i--) {
    for (let j = 0; j < needle.length; j++) {
      if (haystack[i + j] !== needle[j]) continue outer;
    }
    return i;
  }
  return -1;
}

// Base Hermes does not surface X-Index-Trigger to the agent, but the route prompt expects a
// `trigger` payload field. Append it as one more multipart part: existing parts are untouched, we
// only insert before the closing delimiter. Returns the body unchanged when there is no trigger or
// the boundary cannot be located.
function injectTrigger(
  body: Uint8Array,
  contentType: string,
  trigger: string,
): Uint8Array {
  if (!trigger) return body;
  const boundary = /boundary="?([^";]+)"?/i.exec(contentType)?.[1];
  if (!boundary) return body;
  const closing = Buffer.from(`--${boundary}--`, "utf8");
  const at = lastIndexOfBytes(body, closing);
  if (at < 0) return body;
  const crlf =
    at >= 2 && body[at - 2] === 0x0d && body[at - 1] === 0x0a ? "" : "\r\n";
  const part = Buffer.from(
    `${crlf}--${boundary}\r\nContent-Disposition: form-data; name="trigger"\r\n\r\n${trigger}\r\n`,
    "utf8",
  );
  return Buffer.concat([body.subarray(0, at), part, body.subarray(at)]);
}

const WEBHOOK_PATH = /^\/webhooks\/.+/;
const PROFILED_WEBHOOK_PATH = /^\/p\/[^/]+\/webhooks\/.+/;

function isWebhookPath(pathname: string): boolean {
  return WEBHOOK_PATH.test(pathname) || PROFILED_WEBHOOK_PATH.test(pathname);
}

function routeFromPath(path: string): string {
  return path.replace(/^.*\/webhooks\//, "");
}

function targetUrl(path: string): string {
  return `${HERMES_WEBHOOK_ROOT}${path}`;
}

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

// Quick in-request retries: only genuinely transient transport/server statuses.
function isTransient(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
}

// Queue decision. Everything non-2xx is retried except statuses where resending the identical
// request cannot succeed (malformed or oversized body). 401/403/404 are retried on purpose:
// they reflect external state — secret, route enabled, route exists — that can change, and the
// relay is the ring's only retry mechanism.
const PERMANENT_STATUSES = new Set([400, 413, 415, 422]);
function isRetryable(status: number): boolean {
  return !PERMANENT_STATUSES.has(status);
}

function summarize(
  body: Uint8Array,
  headers: Headers,
): { transcriptionLength: number; audio: boolean } {
  // Logging only; never mutates the body.
  const text = Buffer.from(body).toString("latin1");
  let transcriptionLength = 0;
  const m =
    /name="transcription"\r\n(?:[^\r\n]*\r\n)*\r\n([\s\S]*?)\r\n--/.exec(text);
  if (m && m[1] !== undefined) {
    transcriptionLength = Buffer.byteLength(m[1], "latin1");
  }
  const audio = headers.has("x-audio-size") || /name="audio"/.test(text);
  return { transcriptionLength, audio };
}

function logRequest(fields: {
  route: string;
  delivery: string;
  trigger: string;
  test: boolean;
  transcriptionLength: number;
  audio: boolean;
  forward: string;
  latencyMs: number;
  upstreamError?: string;
}): void {
  const detail = fields.upstreamError
    ? ` upstream_error=${JSON.stringify(fields.upstreamError)}`
    : "";
  console.log(
    `route=${fields.route} delivery=${fields.delivery} trigger=${fields.trigger} test=${fields.test} ` +
      `transcription_len=${fields.transcriptionLength} audio=${fields.audio} ` +
      `forward=${fields.forward} latency_ms=${Math.round(fields.latencyMs)}${detail}`,
  );
}

// ── Forwarding ──────────────────────────────────────────────────────────────

async function forward(
  headers: Headers,
  body: Uint8Array,
  path: string,
): Promise<Response> {
  return fetch(targetUrl(path), { method: "POST", headers, body });
}

async function forwardNow(
  headers: Headers,
  body: Uint8Array,
  path: string,
): Promise<{ response: Response | null; error: unknown }> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt <= INITIAL_RETRY_DELAYS_MS.length; attempt++) {
    if (attempt > 0) await sleep(INITIAL_RETRY_DELAYS_MS[attempt - 1]!);
    try {
      const response = await forward(headers, body, path);
      if (response.ok || !isTransient(response.status)) {
        return { response, error: null };
      }
      lastError = new Error(`upstream ${response.status}`);
    } catch (error) {
      lastError = error;
    }
  }
  return { response: null, error: lastError };
}

async function upstreamDetail(response: Response | null, error: unknown): Promise<string> {
  if (response) {
    try {
      return (await response.text()).slice(0, 200);
    } catch {
      return "";
    }
  }
  return error instanceof Error ? error.message : String(error);
}

function setLastForward(status: Response | null, error: unknown): string {
  lastForwardAt = new Date().toISOString();
  if (status) {
    lastForwardStatus = status.status;
    return String(status.status);
  }
  lastForwardStatus = "error";
  return `error(${error instanceof Error ? error.message : String(error)})`;
}

// ── Queue ───────────────────────────────────────────────────────────────────

function enqueue(
  deliveryId: string,
  receivedAt: number,
  body: Uint8Array,
  headers: Record<string, string>,
  path: string,
): boolean {
  const res = db.run(
    `INSERT OR IGNORE INTO deliveries
       (delivery_id, received_at, body, headers, path, status, attempts, next_attempt_at)
     VALUES (?, ?, ?, ?, ?, 'pending', 0, 0)`,
    [deliveryId, receivedAt, body, JSON.stringify(headers), path],
  );
  return res.changes > 0;
}

function markForwarded(deliveryId: string): void {
  db.run(
    "UPDATE deliveries SET status='forwarded', forwarded_at=?, last_error=NULL WHERE delivery_id=?",
    [Date.now(), deliveryId],
  );
}

function markFailed(deliveryId: string, error: string): void {
  db.run(
    "UPDATE deliveries SET status='failed', last_error=? WHERE delivery_id=?",
    [error, deliveryId],
  );
}

function markPending(deliveryId: string, attempts: number, error: string): void {
  const delay = BACKOFF_SECONDS[Math.min(attempts - 1, BACKOFF_SECONDS.length - 1)]!;
  db.run(
    `UPDATE deliveries SET status='pending', attempts=?, next_attempt_at=?, last_error=? WHERE delivery_id=?`,
    [attempts, Date.now() + delay * 1000, error, deliveryId],
  );
}

function queueDepth(): number {
  const row = db
    .query("SELECT COUNT(*) AS n FROM deliveries WHERE status='pending'")
    .get() as { n: number };
  return row.n;
}

function failedCount(): number {
  const row = db
    .query("SELECT COUNT(*) AS n FROM deliveries WHERE status='failed'")
    .get() as { n: number };
  return row.n;
}

let draining = false;

async function drain(): Promise<void> {
  if (draining) return;
  draining = true;
  try {
    const rows = db
      .query(
        `SELECT * FROM deliveries
          WHERE status='pending' AND next_attempt_at <= ?
          ORDER BY received_at LIMIT 5`,
      )
      .all(Date.now()) as DeliveryRow[];
    for (const row of rows) {
      await retryOne(row);
    }
  } finally {
    draining = false;
  }
}

async function retryOne(row: DeliveryRow): Promise<void> {
  const headers = headersToHeadersObject(
    JSON.parse(row.headers) as Record<string, string>,
  );
  const version = headers.get("x-index-webhook-version") || "1";
  const trigger = headers.get("x-index-trigger") || "";
  const isTest =
    (headers.get("x-index-test") || "").trim().toLowerCase() === "true";
  const route = routeFromPath(row.path);
  const secret = routeSecret(route);
  if (!secret) {
    markFailed(row.delivery_id, "route no longer configured");
    console.warn(
      `route=${route} delivery=${row.delivery_id} outcome=unconfigured`,
    );
    return;
  }
  // Re-sign the stored body (already includes the injected trigger) with a fresh timestamp.
  signForwardHeaders(headers, secret, row.body, {
    version,
    deliveryId: row.delivery_id,
    trigger,
    isTest,
  });

  const started = performance.now();
  let response: Response | null = null;
  let error: unknown = null;
  try {
    response = await forward(headers, row.body, row.path);
  } catch (e) {
    error = e;
  }
  const forwardResult = setLastForward(response, error);
  const attempts = row.attempts + 1;

  if (response && response.ok) {
    lastForwardError = null;
    markForwarded(row.delivery_id);
    logRequest({
      route: routeFromPath(row.path),
      delivery: row.delivery_id,
      trigger,
      test: isTest,
      ...summarize(row.body, headers),
      forward: forwardResult,
      latencyMs: performance.now() - started,
    });
    return;
  }
  const detail = await upstreamDetail(response, error);
  lastForwardError = `${response ? response.status : "network"}: ${detail}`;
  if (response && !isRetryable(response.status)) {
    markFailed(row.delivery_id, lastForwardError);
    console.warn(
      `route=${routeFromPath(row.path)} delivery=${row.delivery_id} forward=${forwardResult} outcome=permanent-failure attempt=${attempts} upstream_error=${JSON.stringify(detail)}`,
    );
    return;
  }
  markPending(row.delivery_id, attempts, lastForwardError);
  console.log(
    `route=${routeFromPath(row.path)} delivery=${row.delivery_id} forward=${forwardResult} outcome=retry-scheduled attempt=${attempts} upstream_error=${JSON.stringify(detail)}`,
  );
}

// ── HTTP ────────────────────────────────────────────────────────────────────

function json(data: unknown, status = 200): Response {
  return new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json" },
  });
}

Bun.serve({
  port: PORT,
  maxRequestBodySize: 64 * 1024 * 1024,
  async fetch(req) {
    const url = new URL(req.url);

    if (url.pathname === "/health") {
      return json({
        ok: true,
        queue_depth: queueDepth(),
        failed_count: failedCount(),
        last_forward_at: lastForwardAt,
        last_forward_status: lastForwardStatus,
        last_forward_error: lastForwardError,
      });
    }

    if (!isWebhookPath(url.pathname) || req.method !== "POST") {
      return json({ error: "not found" }, 404);
    }

    const route = routeFromPath(url.pathname);
    const forwardPath = `${url.pathname}${url.search}`;
    const started = performance.now();
    const body = new Uint8Array(await req.arrayBuffer());

    const version = req.headers.get("x-index-webhook-version") || "";
    const timestamp = req.headers.get("x-index-timestamp") || "";
    const deliveryId = req.headers.get("x-index-delivery") || "";
    const trigger = req.headers.get("x-index-trigger") || "";
    const testHeader = req.headers.get("x-index-test") || "";
    const providedSignature = req.headers.get("x-index-signature") || "";
    const isTest = testHeader.trim().toLowerCase() === "true";

    if (version !== "1") {
      return json({ error: "unsupported webhook version" }, 400);
    }
    if (!deliveryId) {
      return json({ error: "missing X-Index-Delivery" }, 400);
    }
    if (!timestamp || Number.isNaN(Number(timestamp))) {
      return json({ error: "missing or invalid X-Index-Timestamp" }, 400);
    }
    const age = Math.abs(Math.floor(Date.now() / 1000) - Number(timestamp));
    if (age > WINDOW_SECONDS) {
      return json({ error: "timestamp outside replay window" }, 401);
    }
    const secret = routeSecret(route);
    if (!secret) {
      console.warn(
        `route=${route} outcome=unconfigured (no ${routeSecretEnvKey(route)})`,
      );
      return json({ error: "route not configured" }, 401);
    }
    const expected = signIndex(
      secret,
      version,
      timestamp,
      deliveryId,
      trigger,
      isTest,
      body,
    );
    if (!providedSignature || !signatureMatches(expected, providedSignature)) {
      return json({ error: "invalid signature" }, 401);
    }

    // Base Hermes won't show the gesture, so fold X-Index-Trigger into the body as a field.
    const forwardBody = injectTrigger(
      body,
      req.headers.get("content-type") || "",
      trigger,
    );
    const summary = summarize(forwardBody, req.headers);
    const forwardHeadersRecord = collectForwardHeaders(req.headers);

    // Reserve the delivery id first so a concurrent repeat cannot double-forward.
    if (!enqueue(deliveryId, Date.now(), forwardBody, forwardHeadersRecord, forwardPath)) {
      logRequest({
        route,
        delivery: deliveryId,
        trigger,
        test: isTest,
        ...summary,
        forward: "duplicate",
        latencyMs: performance.now() - started,
      });
      return json({ status: "duplicate", delivery_id: deliveryId }, 200);
    }

    const forwardHeaders = headersToHeadersObject(forwardHeadersRecord);
    signForwardHeaders(forwardHeaders, secret, forwardBody, {
      version,
      deliveryId,
      trigger,
      isTest,
    });
    const { response, error } = await forwardNow(
      forwardHeaders,
      forwardBody,
      forwardPath,
    );
    const forward = setLastForward(response, error);

    if (response && response.ok) {
      lastForwardError = null;
      markForwarded(deliveryId);
      logRequest({
        route,
        delivery: deliveryId,
        trigger,
        test: isTest,
        ...summary,
        forward,
        latencyMs: performance.now() - started,
      });
      return json(
        { status: "forwarded", delivery_id: deliveryId, upstream: response.status },
        202,
      );
    }

    const detail = await upstreamDetail(response, error);
    lastForwardError = `${response ? response.status : "network"}: ${detail}`;

    if (response && !isRetryable(response.status)) {
      // Malformed or oversized body: resending the same bytes cannot succeed.
      markFailed(deliveryId, lastForwardError);
      logRequest({
        route,
        delivery: deliveryId,
        trigger,
        test: isTest,
        ...summary,
        forward,
        latencyMs: performance.now() - started,
        upstreamError: detail,
      });
      return json(
        { status: "rejected", delivery_id: deliveryId, upstream: response.status },
        502,
      );
    }

    // Retryable: transient, or an external-state failure like 401/403/404. Buffer and retry.
    markPending(deliveryId, 1, lastForwardError);
    logRequest({
      route,
      delivery: deliveryId,
      trigger,
      test: isTest,
      ...summary,
      forward,
      latencyMs: performance.now() - started,
      upstreamError: detail,
    });
    return json({ status: "buffered", delivery_id: deliveryId }, 202);
  },
});

console.log(
  `pebble-hermes-relay listening on :${PORT} → ${HERMES_WEBHOOK_ROOT} ` +
    `(data ${DATA_DIR}; routes: ${configuredRoutes()})`,
);

setInterval(() => {
  void drain();
}, 5000);
void drain();
