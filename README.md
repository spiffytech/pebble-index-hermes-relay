# pebble-hermes-relay

![MutuaL-1.2](https://img.shields.io/badge/License-MutuaL--1.2-af2e1a?style=flat&labelColor=110402&link=https%3A%2F%2Fcodeberg.org%2FMutualism%2FMutualist-License)

The Pebble Index 01 signs its webhook requests with HMAC-SHA256 using its own Index v1 protocol.
Hermes doesn't speak that protocol — its generic webhook receiver takes JSON. So this relay
verifies the ring's signature, translates the multipart body into Hermes's JSON shape, and signs
it with Hermes's generic V2 HMAC.

It store-and-forwards through SQLite: if Hermes is down when you use your Index, the capture is
buffered and retried with backoff instead of lost (the ring has no retry queue).

## Routes

- `POST /webhooks/*` — verify the ring's signature, translate to JSON, dedupe, forward. The path
  is preserved, so any Hermes webhook route works: `/webhooks/<route>` and
  `/p/<profile>/webhooks/<route>`.
- `GET /health` — `{ok, queue_depth, last_forward_at, last_forward_status}`.

Hermes' webhook listener serves `POST /webhooks/<route>` (bare, default profile) and
`POST /p/<profile>/webhooks/<route>` (profile-scoped). The relay forwards the incoming path
verbatim under `HERMES_WEBHOOK_ROOT`, so new routes need no relay change once a secret is
configured for them. Each route's secret comes from `WEBHOOK_SECRET_<ROUTE>` (see Env).
Verification is Index-only, so routes using a different auth scheme are not supported.

## Run

```sh
docker build -t pebble-hermes-relay .
docker run --rm -p 8655:8655 \
  -e WEBHOOK_SECRET_PEBBLE_INDEX=... \
  -e HERMES_WEBHOOK_ROOT=http://hermes:8644 \
  -v pebble-hermes-relay-data:/data \
  pebble-hermes-relay
```

Or directly with Bun:

```sh
WEBHOOK_SECRET_PEBBLE_INDEX=... bun run start
```

## Protocol (Index webhook v1)

Signed bytes: `UTF8("v1\n" + timestamp + "\n" + deliveryId + "\n" + trigger + "\n" +
("1" if isTest else "0") + "\n") || rawBody`. Header: `X-Index-Signature: <lowercase hex HMAC-SHA256>`.
Validation matches Hermes' Index v1 rules: version `1`; delivery required; timestamp
within ±300 s; constant-time signature compare.

## Behaviour

- The ring's `multipart/form-data` body is parsed and re-emitted as `application/json`:
  `transcription`, `recordedAt` (number, ms), `client`, `event_type` (from `X-Index-Trigger`), and
  `test: true` for test events.
- **Audio parts are not forwarded** — Hermes has no audio storage for webhooks. They are dropped
  and logged (`outcome=audio-dropped`).
- The JSON is signed with Hermes's generic V2 scheme
  (`X-Webhook-Signature-V2 = hex HMAC-SHA256(secret, "<X-Webhook-Timestamp>.<body>")`) and sent
  with `X-Request-ID: <delivery id>` for idempotency. The ring's `X-Index-*` headers are not
  forwarded.
- Idempotency: SQLite `deliveries` table keyed on `X-Index-Delivery`. A repeat returns 200
  without forwarding.
- Hermes 2xx → forwarded (202). Network error / 5xx / 429 / 408 / 425, and 401/403/404 → buffered
  in SQLite and retried with backoff (5 s, 30 s, 2 m, 10 m, 1 h, hourly). Permanent (400/413/415/422)
  → not buffered (502). Only a failure to persist returns 503.
- Buffered retries are re-signed with a fresh `X-Webhook-Timestamp`.

## Env

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8655` | |
| `WEBHOOK_SECRET_<ROUTE>` | — | HMAC secret per route, e.g. `WEBHOOK_SECRET_PEBBLE_INDEX` for `pebble-index`. Route names are uppercased and non-alphanumerics become `_`. No fallback: an unconfigured route is rejected. |
| `HERMES_WEBHOOK_ROOT` | `http://127.0.0.1:8644` | Hermes webhook listener origin; the relay appends the incoming path (a trailing `/webhooks` is tolerated) |
| `DATA_DIR` | `./data` | SQLite lives here |
| `TIMESTAMP_WINDOW_SECONDS` | `300` | |

## Tests

`verify.ts` is a standalone harness. The `translate` and `downtime` cases are self-contained —
they spawn their own relay and echo server on loopback:

```sh
WEBHOOK_SECRET_PEBBLE_INDEX=test bun verify.ts translate
WEBHOOK_SECRET_PEBBLE_INDEX=test bun verify.ts downtime
```

The `happy`, `tamper` and `replay` cases hit a running relay, so they need its URL and secret:

```sh
RELAY_URL=http://127.0.0.1:8655 WEBHOOK_SECRET_PEBBLE_INDEX=... bun verify.ts happy
RELAY_URL=http://127.0.0.1:8655 WEBHOOK_SECRET_PEBBLE_INDEX=... bun verify.ts tamper
RELAY_URL=http://127.0.0.1:8655 WEBHOOK_SECRET_PEBBLE_INDEX=... bun verify.ts replay
```

`bun verify.ts all` runs everything. The happy-path case forwards a test event to the configured
`HERMES_WEBHOOK_ROOT`; confirm the run on the receiving side via its log and reply channel.

## License

This project is licensed under the [Mutualist License v1.2](LICENSE.md).

### Mutualist License summary

**Permissions**

- Commercial use
- Private / internal use
- Modification
- Distribution (source and binaries)
- Network / SaaS use
- Patent use (from contributors, as described in the license)

**Conditions**

- Keep copyright and license notices
- Give appropriate credit (see "Credit" in the license)
- Share source for modified versions you distribute
- Share source for modified versions you let others use over a network
- License your changes under the Mutualist License too (same license)
- Don't add technical measures (like DRM) that stop users from exercising their rights
- Patent peace: you lose patent rights under this license if you start a patent attack over this software

**Limitations**

- No liability
- No warranty
- No trademark rights
- No implied endorsement
