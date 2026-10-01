#!/usr/bin/env bun
/**
 * Pebble Index 01 ring → Hermes webhook relay.
 *
 * Verifies the ring's HMAC-SHA256 signature over the original multipart body, then translates
 * that body into the JSON payload base Hermes expects: the multipart fields become JSON fields,
 * `event_type` is taken from X-Index-Trigger, and `test` becomes a boolean. Audio is not
 * forwarded (base Hermes has no audio storage for webhooks).
 *
 * The translated JSON is signed with Hermes's generic V2 HMAC and sent with X-Request-ID for
 * idempotency. Any webhook path is accepted and forwarded verbatim under the configured Hermes
 * root: `POST /webhooks/<route>` and `POST /p/<profile>/webhooks/<route>`.
 *
 * Durability: if Hermes is unreachable or transiently failing, the translated body is buffered in
 * SQLite and retried with backoff, re-signed with a fresh timestamp each attempt.
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

// Base Hermes verifies the generic V2 scheme:
//   X-Webhook-Signature-V2 = hex HMAC-SHA256(secret, "<X-Webhook-Timestamp>.<body>")
// X-Request-ID carries the delivery id for Hermes's idempotency. The ring's X-Index-* headers are
// not forwarded: base Hermes reads none of them, and the Index signature covers the multipart body
// we replace with JSON.
function v2Signature(secret: string, timestamp: string, body: Uint8Array): string {
  const hmac = createHmac("sha256", secret);
  hmac.update(`${timestamp}.`); // utf-8
  hmac.update(body);
  return hmac.digest("hex");
}

function signForwardHeaders(
  headers: Headers,
  secret: string,
  body: Uint8Array,
  deliveryId: string,
  timestamp = Math.floor(Date.now() / 1000).toString(),
): void {
  headers.set("x-webhook-timestamp", timestamp);
  headers.set("x-webhook-signature-v2", v2Signature(secret, timestamp, body));
  headers.set("x-request-id", deliveryId);
}

// ── Translation ─────────────────────────────────────────────────────────────

async function parseForm(body: Uint8Array, contentType: string) {
  try {
    return await new Request("http://relay.invalid/", {
      method: "POST",
      headers: { "content-type": contentType },
      body,
    }).formData();
  } catch {
    return null;
  }
}

// The ring posts multipart/form-data; base Hermes parses only JSON or form-encoded. Turn the
// multipart fields into a JSON payload, add `event_type` (from X-Index-Trigger) and a boolean
// `test`. Audio parts are dropped for now — base Hermes has no audio storage for webhooks.
async function translateToHermes(
  body: Uint8Array,
  contentType: string,
  trigger: string,
  isTest: boolean,
): Promise<
  { body: Uint8Array; transcriptionLength: number; audioDropped: boolean } | null
> {
  const form = await parseForm(body, contentType);
  if (!form) return null;
  const payload: Record<string, unknown> = {};
  let transcriptionLength = 0;
  let audioDropped = false;
  for (const [key, value] of form.entries()) {
    if (typeof value !== "string") {
      audioDropped = true;
      continue;
    }
    if (key === "test") continue; // derived from the signed X-Index-Test header
    if (key === "recordedAt" && /^\d+$/.test(value)) {
      payload[key] = Number(value);
    } else {
      payload[key] = value;
      if (key === "transcription") {
        transcriptionLength = Buffer.byteLength(value, "utf8");
      }
    }
  }
  payload.event_type = trigger;
  if (isTest) payload.test = true;
  return {
    body: Buffer.from(JSON.stringify(payload), "utf8"),
    transcriptionLength,
    audioDropped,
  };
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

// Recover log fields from a translated (stored) JSON body.
function jsonLogFields(body: Uint8Array): {
  trigger: string;
  test: boolean;
  transcriptionLength: number;
} {
  try {
    const p = JSON.parse(Buffer.from(body).toString("utf8")) as Record<
      string,
      unknown
    >;
    return {
      trigger: typeof p.event_type === "string" ? p.event_type : "",
      test: p.test === true,
      transcriptionLength:
        typeof p.transcription === "string"
          ? Buffer.byteLength(p.transcription, "utf8")
          : 0,
    };
  } catch {
    return { trigger: "", test: false, transcriptionLength: 0 };
  }
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
  const route = routeFromPath(row.path);
  const secret = routeSecret(route);
  if (!secret) {
    markFailed(row.delivery_id, "route no longer configured");
    console.warn(
      `route=${route} delivery=${row.delivery_id} outcome=unconfigured`,
    );
    return;
  }
  const fields = jsonLogFields(row.body);
  const headers = new Headers({ "content-type": "application/json" });
  signForwardHeaders(headers, secret, row.body, row.delivery_id);

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
      route,
      delivery: row.delivery_id,
      trigger: fields.trigger,
      test: fields.test,
      transcriptionLength: fields.transcriptionLength,
      audio: false,
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
      `route=${route} delivery=${row.delivery_id} forward=${forwardResult} outcome=permanent-failure attempt=${attempts} upstream_error=${JSON.stringify(detail)}`,
    );
    return;
  }
  markPending(row.delivery_id, attempts, lastForwardError);
  console.log(
    `route=${route} delivery=${row.delivery_id} forward=${forwardResult} outcome=retry-scheduled attempt=${attempts} upstream_error=${JSON.stringify(detail)}`,
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

    // Translate the ring's multipart body into the JSON payload base Hermes parses.
    const translated = await translateToHermes(
      body,
      req.headers.get("content-type") || "",
      trigger,
      isTest,
    );
    if (!translated) {
      console.warn(`route=${route} delivery=${deliveryId} outcome=unparseable-body`);
      return json({ error: "cannot parse body" }, 400);
    }
    const { body: forwardBody, transcriptionLength, audioDropped } = translated;
    const summary = { transcriptionLength, audio: audioDropped };
    if (audioDropped) {
      console.warn(
        `route=${route} delivery=${deliveryId} outcome=audio-dropped (audio is not forwarded)`,
      );
    }

    // Reserve the delivery id first so a concurrent repeat cannot double-forward.
    if (!enqueue(deliveryId, Date.now(), forwardBody, {}, forwardPath)) {
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

    const forwardHeaders = new Headers({ "content-type": "application/json" });
    signForwardHeaders(forwardHeaders, secret, forwardBody, deliveryId);
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
