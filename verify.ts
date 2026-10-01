#!/usr/bin/env bun
/**
 * Integration tests for the Pebble Index → Hermes relay.
 *
 *   RELAY_URL=http://127.0.0.1:8655 bun verify.ts happy
 *   bun verify.ts tamper
 *   bun verify.ts replay
 *   bun verify.ts translate      # spawns relay locally against an echo server
 *   bun verify.ts downtime        # spawns relay locally against a dead port, then restores
 *   bun verify.ts all             # happy+tamper+replay against RELAY_URL, then the two local tests
 *
 * The route secret is read from WEBHOOK_SECRET_PEBBLE_INDEX and is never printed.
 */
import { createHash, createHmac, randomUUID } from "crypto";
import { mkdtempSync, rmSync } from "fs";
import { tmpdir } from "os";
import { join } from "path";

const SECRET = process.env.WEBHOOK_SECRET_PEBBLE_INDEX || "";
const RELAY_URL = process.env.RELAY_URL || "http://127.0.0.1:8655";

if (!SECRET) {
  console.error("FATAL: WEBHOOK_SECRET_PEBBLE_INDEX is not set");
  process.exit(2);
}

// ── request synthesis ───────────────────────────────────────────────────────

interface Part {
  name: string;
  value?: string;
  filename?: string;
  contentType?: string;
  data?: Uint8Array;
}

function buildMultipart(parts: Part[]): { boundary: string; body: Uint8Array } {
  const boundary = "----pebble" + randomUUID().replace(/-/g, "");
  const chunks: Uint8Array[] = [];
  for (const p of parts) {
    let head = `--${boundary}\r\nContent-Disposition: form-data; name="${p.name}"`;
    if (p.filename) head += `; filename="${p.filename}"`;
    head += "\r\n";
    if (p.contentType) head += `Content-Type: ${p.contentType}\r\n`;
    head += "\r\n";
    chunks.push(Buffer.from(head, "utf8"));
    chunks.push(p.data ?? Buffer.from(p.value ?? "", "utf8"));
    chunks.push(Buffer.from("\r\n", "utf8"));
  }
  chunks.push(Buffer.from(`--${boundary}--\r\n`, "utf8"));
  return { boundary, body: Buffer.concat(chunks) };
}

function sign(
  version: string,
  timestamp: string,
  delivery: string,
  trigger: string,
  isTest: boolean,
  body: Uint8Array,
): string {
  const prefix = `v${version}\n${timestamp}\n${delivery}\n${trigger}\n${isTest ? 1 : 0}\n`;
  const hmac = createHmac("sha256", SECRET);
  hmac.update(prefix);
  hmac.update(body);
  return hmac.digest("hex");
}

function sha256(body: Uint8Array): string {
  return createHash("sha256").update(body).digest("hex");
}

function v2sig(timestamp: string, body: Uint8Array): string {
  const hmac = createHmac("sha256", SECRET);
  hmac.update(`${timestamp}.`);
  hmac.update(body);
  return hmac.digest("hex");
}

interface SignedRequest {
  body: Uint8Array;
  signature: string;
  delivery: string;
  timestamp: string;
  trigger: string;
  isTest: boolean;
  contentType: string;
}

function makeSigned(opts: {
  delivery?: string;
  trigger?: string;
  isTest?: boolean;
  transcription?: string;
} = {}): SignedRequest {
  const delivery = opts.delivery ?? randomUUID();
  const trigger = opts.trigger ?? "test-event";
  const isTest = opts.isTest ?? true;
  const parts: Part[] = [
    { name: "transcription", value: opts.transcription ?? "relay test" },
    { name: "recordedAt", value: String(Date.now()) },
    { name: "client", value: "ring" },
  ];
  if (isTest) parts.push({ name: "test", value: "true" });
  const { boundary, body } = buildMultipart(parts);
  const timestamp = Math.floor(Date.now() / 1000).toString();
  const signature = sign("1", timestamp, delivery, trigger, isTest, body);
  return {
    body,
    signature,
    delivery,
    timestamp,
    trigger,
    isTest,
    contentType: `multipart/form-data; boundary=${boundary}`,
  };
}

async function post(
  url: string,
  req: SignedRequest,
  override?: { body?: Uint8Array; signature?: string },
  path = "/webhooks/pebble-index",
): Promise<{ status: number; text: string }> {
  const res = await fetch(`${url}${path}`, {
    method: "POST",
    headers: {
      "content-type": req.contentType,
      "x-index-webhook-version": "1",
      "x-index-trigger": req.trigger,
      "x-index-timestamp": req.timestamp,
      "x-index-delivery": req.delivery,
      "x-index-signature": override?.signature ?? req.signature,
      ...(req.isTest ? { "x-index-test": "true" } : {}),
    },
    body: override?.body ?? req.body,
  });
  return { status: res.status, text: await res.text() };
}

async function checkHealth(url: string): Promise<any> {
  const res = await fetch(`${url}/health`);
  return res.json();
}

// ── remote tests ────────────────────────────────────────────────────────────

async function happy(): Promise<boolean> {
  const req = makeSigned({ transcription: "relay test" });
  const { status, text } = await post(RELAY_URL, req);
  const ok = status >= 200 && status < 300;
  console.log(`[happy] status=${status} ok=${ok} delivery=${req.delivery}`);
  console.log(`[happy] body=${text}`);
  console.log(
    `[happy] confirm on the Hermes side: gateway log entry for delivery=${req.delivery}`,
  );
  return ok;
}

async function tamper(): Promise<boolean> {
  const req = makeSigned({ transcription: "tamper test" });
  const tampered = new Uint8Array(req.body);
  const mid = Math.floor(tampered.length / 2);
  tampered[mid] = tampered[mid]! ^ 0x01;
  const { status, text } = await post(RELAY_URL, req, { body: tampered });
  const ok = status === 401;
  console.log(`[tamper] status=${status} expected=401 ok=${ok} body=${text}`);
  return ok;
}

async function replay(): Promise<boolean> {
  const req = makeSigned({ transcription: "replay test" });
  const first = await post(RELAY_URL, req);
  const second = await post(RELAY_URL, req);
  const ok =
    first.status >= 200 &&
    first.status < 300 &&
    second.status === 200 &&
    second.text.includes("duplicate");
  console.log(
    `[replay] first=${first.status} second=${second.status} ok=${ok} delivery=${req.delivery}`,
  );
  console.log(`[replay] first_body=${first.text}`);
  console.log(`[replay] second_body=${second.text}`);
  return ok;
}

// ── local harness ───────────────────────────────────────────────────────────

async function waitForHealth(url: string, timeoutMs = 15000): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${url}/health`);
      if (res.ok) return;
    } catch {
      // not up yet
    }
    await Bun.sleep(200);
  }
  throw new Error(`relay did not become healthy at ${url}`);
}

async function startRelay(
  port: number,
  hermesUrl: string,
  dataDir: string,
): Promise<ReturnType<typeof Bun.spawn>> {
  const proc = Bun.spawn(["bun", "index.ts"], {
    cwd: import.meta.dir,
    env: {
      ...process.env,
      PORT: String(port),
      HERMES_WEBHOOK_ROOT: hermesUrl,
      DATA_DIR: dataDir,
      // Route secrets for the routes the local tests exercise.
      WEBHOOK_SECRET_PEBBLE_INDEX: SECRET,
      WEBHOOK_SECRET_OTHER_ROUTE: SECRET,
      WEBHOOK_SECRET_ANOTHER: SECRET,
    },
    stdout: "inherit",
    stderr: "inherit",
  });
  await waitForHealth(`http://127.0.0.1:${port}`);
  return proc;
}

async function stopRelay(proc: ReturnType<typeof Bun.spawn>): Promise<void> {
  proc.kill();
  await Promise.race([proc.exited, Bun.sleep(3000)]);
}

interface Echo {
  path: string;
  contentType: string | null;
  sha256: string;
  signature: string | null;
  timestamp: string | null;
  webhookV2: string | null;
  webhookTs: string | null;
  delivery: string | null;
  body: Uint8Array;
}

function startEcho(): { server: ReturnType<typeof Bun.serve>; seen: Echo[]; url: string } {
  const seen: Echo[] = [];
  const server = Bun.serve({
    port: 0,
    async fetch(req) {
      const body = new Uint8Array(await req.arrayBuffer());
      seen.push({
        path: new URL(req.url).pathname,
        contentType: req.headers.get("content-type"),
        sha256: sha256(body),
        signature: req.headers.get("x-index-signature"),
        timestamp: req.headers.get("x-index-timestamp"),
        webhookV2: req.headers.get("x-webhook-signature-v2"),
        webhookTs: req.headers.get("x-webhook-timestamp"),
        delivery: req.headers.get("x-index-delivery"),
        body,
      });
      return new Response("OK", { status: 200 });
    },
  });
  return { server, seen, url: `http://127.0.0.1:${server.port}` };
}

let nextPort = 18655;

async function translate(): Promise<boolean> {
  const echo = startEcho();
  const dataDir = mkdtempSync(join(tmpdir(), "pebble-relay-"));
  const port = nextPort++;
  const proc = await startRelay(port, echo.url, dataDir);
  try {
    const req = makeSigned({ transcription: "translate test" });
    const { status } = await post(`http://127.0.0.1:${port}`, req);
    await Bun.sleep(300);
    const got = echo.seen[0];
    if (!got) {
      console.log(`[translate] status=${status} FAIL: echo received nothing`);
      return false;
    }
    const json = JSON.parse(Buffer.from(got.body).toString("utf8")) as Record<
      string,
      unknown
    >;
    const jsonType = (got.contentType ?? "").startsWith("application/json");
    const fieldsOk =
      json.transcription === "translate test" &&
      json.event_type === req.trigger &&
      json.test === true &&
      json.client === "ring" &&
      typeof json.recordedAt === "number";
    const v2Ok = !!got.webhookTs && got.webhookV2 === v2sig(got.webhookTs, got.body);
    const pathOk = got.path === "/webhooks/pebble-index";
    const ok = jsonType && fieldsOk && v2Ok && pathOk;
    console.log(
      `[translate] status=${status} json=${jsonType} fields_ok=${fieldsOk} v2_valid=${v2Ok} path_ok=${pathOk} ok=${ok}`,
    );
    console.log(
      `[translate] forwarded=${Buffer.from(got.body).toString("utf8").slice(0, 200)}`,
    );
    return ok;
  } finally {
    await stopRelay(proc);
    echo.server.stop(true);
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function downtime(): Promise<boolean> {
  const echo = startEcho();
  const dataDir = mkdtempSync(join(tmpdir(), "pebble-relay-"));
  const deadUrl = "http://127.0.0.1:1";
  const port = nextPort++;
  const req = makeSigned({ transcription: "downtime test" });

  let first = await startRelay(port, deadUrl, dataDir);
  try {
    const { status } = await post(`http://127.0.0.1:${port}`, req);
    const health = await checkHealth(`http://127.0.0.1:${port}`);
    const buffered = status >= 200 && status < 300 && health.queue_depth >= 1;
    console.log(
      `[downtime] buffered_status=${status} queue_depth=${health.queue_depth} ok=${buffered}`,
    );

    // Restore the target (restart proves persistence too).
    await stopRelay(first);
    first = await startRelay(port, echo.url, dataDir);

    const deadline = Date.now() + 20000;
    while (echo.seen.length === 0 && Date.now() < deadline) await Bun.sleep(250);

    const got = echo.seen[0];
    const forwardedOnce = echo.seen.length === 1;
    const json = got
      ? (JSON.parse(Buffer.from(got.body).toString("utf8")) as Record<string, unknown>)
      : null;
    const fieldsOk =
      !!json && json.transcription === "downtime test" && json.event_type === req.trigger;
    const v2Ok = !!got && !!got.webhookTs && got.webhookV2 === v2sig(got.webhookTs, got.body);
    const pathOk = !!got && got.path === "/webhooks/pebble-index";
    const ok = buffered && forwardedOnce && fieldsOk && v2Ok && pathOk;
    console.log(
      `[downtime] forwarded_count=${echo.seen.length} fields_ok=${fieldsOk} v2_valid=${v2Ok} ` +
        `path_ok=${pathOk} ok=${ok}`,
    );
    return ok;
  } finally {
    await stopRelay(first);
    echo.server.stop(true);
    rmSync(dataDir, { recursive: true, force: true });
  }
}

async function pathForwarding(): Promise<boolean> {
  const echo = startEcho();
  const dataDir = mkdtempSync(join(tmpdir(), "pebble-relay-"));
  const port = nextPort++;
  const proc = await startRelay(port, echo.url, dataDir);
  const wanted = ["/webhooks/other-route", "/p/default/webhooks/another"];
  try {
    for (const path of wanted) {
      const req = makeSigned({ transcription: "path test" });
      await post(`http://127.0.0.1:${port}`, req, undefined, path);
    }
    await Bun.sleep(300);
    const forwarded = echo.seen.map((e) => e.path);
    const ok = wanted.every((p) => forwarded.includes(p));
    console.log(`[paths] forwarded=${JSON.stringify(forwarded)} ok=${ok}`);
    return ok;
  } finally {
    await stopRelay(proc);
    echo.server.stop(true);
    rmSync(dataDir, { recursive: true, force: true });
  }
}

// ── main ────────────────────────────────────────────────────────────────────
const cmd = process.argv[2] || "all";
const results: Record<string, boolean> = {};

switch (cmd) {
  case "happy":
    results.happy = await happy();
    break;
  case "tamper":
    results.tamper = await tamper();
    break;
  case "replay":
    results.replay = await replay();
    break;
  case "translate":
    results.translate = await translate();
    break;
  case "downtime":
    results.downtime = await downtime();
    break;
  case "paths":
    results.paths = await pathForwarding();
    break;
  case "all":
  default:
    console.log(`# remote tests against ${RELAY_URL}`);
    results.happy = await happy();
    results.tamper = await tamper();
    results.replay = await replay();
    console.log("# local tests");
    results.translate = await translate();
    results.downtime = await downtime();
    results.paths = await pathForwarding();
    break;
}

console.log("\n# summary");
let allOk = true;
for (const [name, ok] of Object.entries(results)) {
  console.log(`  ${ok ? "PASS" : "FAIL"}  ${name}`);
  if (!ok) allOk = false;
}
process.exit(allOk ? 0 : 1);
