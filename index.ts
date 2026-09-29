#!/usr/bin/env bun
/**
 * Pebble Index 01 ring → Hermes webhook relay.
 *
 * Verifies the ring's HMAC-SHA256 signature, then forwards the request byte-for-byte
 * to Hermes (same method, raw body, Content-Type boundary and X-Index-* headers).
 * Hermes re-verifies the same bytes, so we never touch the body.
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
const SECRET =
  process.env.PEBBLE_INDEX_WEBHOOK_SECRET ||
  process.env.pebbleIndexWebhookSecret ||
  "";
const HERMES_URL =
  process.env.HERMES_WEBHOOK_URL ||
  "http://127.0.0.1:8644/webhooks/pebble-index";
const DATA_DIR = process.env.DATA_DIR || "./data";
const WINDOW_SECONDS = parseInt(
  process.env.TIMESTAMP_WINDOW_SECONDS || "300",
  10,
);
const BACKOFF_SECONDS = [5, 30, 120, 600, 3600];
const INITIAL_RETRY_DELAYS_MS = [250, 500]; // short in-request retries

if (!SECRET) {
  console.error("FATAL: PEBBLE_INDEX_WEBHOOK_SECRET is not set");
  process.exit(1);
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

interface DeliveryRow {
  delivery_id: string;
  received_at: number;
  body: Uint8Array;
  headers: string;
  status: string;
  attempts: number;
  next_attempt_at: number;
  last_error: string | null;
  forwarded_at: number | null;
}

let lastForwardAt: string | null = null;
let lastForwardStatus: number | string | null = null;

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

function sleep(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function isTransient(status: number): boolean {
  return status === 408 || status === 425 || status === 429 || status >= 500;
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
  delivery: string;
  trigger: string;
  test: boolean;
  transcriptionLength: number;
  audio: boolean;
  forward: string;
  latencyMs: number;
}): void {
  console.log(
    `delivery=${fields.delivery} trigger=${fields.trigger} test=${fields.test} ` +
      `transcription_len=${fields.transcriptionLength} audio=${fields.audio} ` +
      `forward=${fields.forward} latency_ms=${Math.round(fields.latencyMs)}`,
  );
}

// ── Forwarding ──────────────────────────────────────────────────────────────

async function forward(
  headers: Headers,
  body: Uint8Array,
): Promise<Response> {
  return fetch(HERMES_URL, { method: "POST", headers, body });
}

async function forwardNow(
  headers: Headers,
  body: Uint8Array,
): Promise<{ response: Response | null; error: unknown }> {
  let lastError: unknown = null;
  for (let attempt = 0; attempt <= INITIAL_RETRY_DELAYS_MS.length; attempt++) {
    if (attempt > 0) await sleep(INITIAL_RETRY_DELAYS_MS[attempt - 1]!);
    try {
      const response = await forward(headers, body);
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
): boolean {
  const res = db.run(
    `INSERT OR IGNORE INTO deliveries
       (delivery_id, received_at, body, headers, status, attempts, next_attempt_at)
     VALUES (?, ?, ?, ?, 'pending', 0, 0)`,
    [deliveryId, receivedAt, body, JSON.stringify(headers)],
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
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const version = headers.get("x-index-webhook-version") || "1";
  const trigger = headers.get("x-index-trigger") || "";
  const isTest =
    (headers.get("x-index-test") || "").trim().toLowerCase() === "true";
  // Re-sign with a fresh timestamp; body bytes are unchanged.
  headers.set("x-index-timestamp", timestamp);
  headers.set(
    "x-index-signature",
    signIndex(SECRET, version, timestamp, row.delivery_id, trigger, isTest, row.body),
  );

  const started = performance.now();
  let response: Response | null = null;
  let error: unknown = null;
  try {
    response = await forward(headers, row.body);
  } catch (e) {
    error = e;
  }
  const forwardResult = setLastForward(response, error);
  const attempts = row.attempts + 1;

  if (response && response.ok) {
    markForwarded(row.delivery_id);
    logRequest({
      delivery: row.delivery_id,
      trigger,
      test: isTest,
      transcriptionLength: 0,
      audio: headers.has("x-audio-size"),
      forward: forwardResult,
      latencyMs: performance.now() - started,
    });
    return;
  }
  if (response && !isTransient(response.status)) {
    markFailed(row.delivery_id, `upstream ${response.status}`);
    console.warn(
      `delivery=${row.delivery_id} forward=${forwardResult} outcome=permanent-failure attempt=${attempts}`,
    );
    return;
  }
  markPending(row.delivery_id, attempts, error instanceof Error ? error.message : forwardResult);
  console.log(
    `delivery=${row.delivery_id} forward=${forwardResult} outcome=retry-scheduled attempt=${attempts}`,
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

    if (url.pathname === "/healthz") {
      return json({
        ok: true,
        queue_depth: queueDepth(),
        last_forward_at: lastForwardAt,
        last_forward_status: lastForwardStatus,
      });
    }

    if (url.pathname !== "/webhooks/pebble-index" || req.method !== "POST") {
      return json({ error: "not found" }, 404);
    }

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
    const expected = signIndex(
      SECRET,
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

    const summary = summarize(body, req.headers);
    const forwardHeadersRecord = collectForwardHeaders(req.headers);

    // Reserve the delivery id first so a concurrent repeat cannot double-forward.
    if (!enqueue(deliveryId, Date.now(), body, forwardHeadersRecord)) {
      logRequest({
        delivery: deliveryId,
        trigger,
        test: isTest,
        ...summary,
        forward: "duplicate",
        latencyMs: performance.now() - started,
      });
      return json({ status: "duplicate", delivery_id: deliveryId }, 200);
    }

    const { response, error } = await forwardNow(
      headersToHeadersObject(forwardHeadersRecord),
      body,
    );
    const forward = setLastForward(response, error);

    if (response && response.ok) {
      markForwarded(deliveryId);
      logRequest({
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

    if (response && !isTransient(response.status)) {
      // Permanent 4xx (bad route, body cap, auth mismatch). Retrying will not help.
      markFailed(deliveryId, `upstream ${response.status}`);
      logRequest({
        delivery: deliveryId,
        trigger,
        test: isTest,
        ...summary,
        forward,
        latencyMs: performance.now() - started,
      });
      return json(
        { status: "rejected", delivery_id: deliveryId, upstream: response.status },
        502,
      );
    }

    // Transient: buffered and retried in the background.
    markPending(deliveryId, 1, error instanceof Error ? error.message : forward);
    logRequest({
      delivery: deliveryId,
      trigger,
      test: isTest,
      ...summary,
      forward,
      latencyMs: performance.now() - started,
    });
    return json({ status: "buffered", delivery_id: deliveryId }, 202);
  },
});

console.log(
  `pebble-hermes-relay listening on :${PORT} → ${HERMES_URL} (data ${DATA_DIR})`,
);

setInterval(() => {
  void drain();
}, 5000);
void drain();
