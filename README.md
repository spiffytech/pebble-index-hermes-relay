# pebble-hermes-relay

![MutuaL-1.2](https://img.shields.io/badge/License-MutuaL--1.2-af2e1a?style=flat&labelColor=110402&link=https%3A%2F%2Fcodeberg.org%2FMutualism%2FMutualist-License)

The Pebble Index 01 supports HMAC signatures, an so does Hermes but they don't use the same headers etc.

This just relays Index events to Hermes, translating as appropriate. All substantive content is retransmitted verbatim.

Store-and-forwards messages in SQLite in case Hermes is down when you use your Index.

## Routes

- `POST /webhooks/pebble-index` — verify, dedupe, forward.
- `GET /healthz` — `{ok, queue_depth, last_forward_at, last_forward_status}`.

## Run

```sh
docker build -t pebble-hermes-relay .
docker run --rm -p 8655:8655 \
  -e PEBBLE_INDEX_WEBHOOK_SECRET=... \
  -e HERMES_WEBHOOK_URL=http://hermes:8644/webhooks/pebble-index \
  -v pebble-hermes-relay-data:/data \
  pebble-hermes-relay
```

Or directly with Bun:

```sh
PEBBLE_INDEX_WEBHOOK_SECRET=... bun run start
```

## Protocol (Index webhook v1)

Signed bytes: `UTF8("v1\n" + timestamp + "\n" + deliveryId + "\n" + trigger + "\n" +
("1" if isTest else "0") + "\n") || rawBody`. Header: `X-Index-Signature: <lowercase hex HMAC-SHA256>`.
Validation matches Hermes' Index v1 rules: version `1`; delivery required; timestamp
within ±300 s; constant-time signature compare.

## Behaviour

- Raw body is read into memory before anything else; it is never re-encoded.
- Forwarded headers: `Content-Type` (original boundary), `X-Index-*`, `X-Audio-Size`.
- Idempotency: SQLite `deliveries` table keyed on `X-Index-Delivery`. A repeat returns 200
  without forwarding.
- Hermes 2xx → forwarded (202). Network error / 5xx / 429 / 408 / 425 → buffered in SQLite and
  retried with backoff (5 s, 30 s, 2 m, 10 m, 1 h, hourly). Permanent 4xx → not buffered
  (502). Only a failure to persist returns 503.
- **Deferred retries are re-signed with a fresh `X-Index-Timestamp`.** Hermes rejects anything
  older than 300 s, so a raw replay of a buffered request would 401. The body bytes are
  unchanged; only the timestamp and signature headers are refreshed. Immediate forwards are
  never re-signed.

## Env

| Var | Default | Notes |
|---|---|---|
| `PORT` | `8655` | |
| `PEBBLE_INDEX_WEBHOOK_SECRET` | — | HMAC secret configured for the webhook route |
| `HERMES_WEBHOOK_URL` | `http://127.0.0.1:8644/webhooks/pebble-index` | target endpoint |
| `DATA_DIR` | `./data` | SQLite lives here |
| `TIMESTAMP_WINDOW_SECONDS` | `300` | |

## Tests

`verify.ts` is a standalone harness. The `byte-exact` and `downtime` cases are self-contained —
they spawn their own relay and echo server on loopback:

```sh
PEBBLE_INDEX_WEBHOOK_SECRET=test bun verify.ts byte-exact
PEBBLE_INDEX_WEBHOOK_SECRET=test bun verify.ts downtime
```

The `happy`, `tamper` and `replay` cases hit a running relay, so they need its URL and secret:

```sh
RELAY_URL=http://127.0.0.1:8655 PEBBLE_INDEX_WEBHOOK_SECRET=... bun verify.ts happy
RELAY_URL=http://127.0.0.1:8655 PEBBLE_INDEX_WEBHOOK_SECRET=... bun verify.ts tamper
RELAY_URL=http://127.0.0.1:8655 PEBBLE_INDEX_WEBHOOK_SECRET=... bun verify.ts replay
```

`bun verify.ts all` runs everything. The happy-path case forwards a test event to the configured
`HERMES_WEBHOOK_URL`; confirm the run on the receiving side via its log and reply channel.

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
