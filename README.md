# control704-proxy-system
Control704 IT Technician authentication and access proxy via Avrone Due’Krey and Control12-lattice-op. Proxy X, Y, Z data set code override functionality.

No runtime dependencies — Node.js 18+ built-ins only.

## Control12-lattice-op overview

| Layer | File | What it does |
|---|---|---|
| Auth provider | `src/auth/avroneProvider.js` | Avrone Due'Krey token provider. Verifies signed JWTs (HS256 shared secret, or RS256/ES256 public key). Checks signature, `alg` allowlist (no `none`, no alg confusion), `exp`, `nbf`, optional max age, `iss`, `aud`, `sub`. |
| Pluggable auth | `src/auth/index.js` | `createAuthenticator(provider)` — any provider with `{ name, verify(token) }` can be dropped in. Extracts `Authorization: Bearer <token>`, builds a principal (`sub`, `roles`, `scopes`). |
| Authorization | `src/access/authorize.js` | Role → scope mapping plus direct token scopes. |
| Audit | `src/access/audit.js` | JSON-lines audit log of auth failures, denials, authenticated requests, overrides and reverts. Tokens are never logged. |
| X/Y/Z datasets | `src/datasets/store.js` | X, Y, Z route profiles with validated overrides, override history and revert. |
| HTTP API | `src/server.js` | Routes, clean 401/403/400/404 JSON responses. |
| Entry / class API | `src/proxy.js` | `npm start`; `Control704Proxy` class (token-based `authenticate`, admin `overrideDataSet`). |

### How X, Y, Z are interpreted
The original `src/proxy.js` defined X, Y and Z as three proxy route profiles
(`/proxy/x` `token-override`, `/proxy/y` `dataset-code`, `/proxy/z` `lattice-op`).
These profiles are the "X, Y, Z data sets", and "data set code override" means an
admin-scoped, validated patch to a profile's config. Overridable fields:

- `endpoint` — must match `/proxy/<slug>` and not clash with another dataset
- `enabled` — boolean; disabled routes return `503`
- `upstream` — `http(s)` URL without embedded credentials, or `null`
- `rateLimitPerMinute` — integer 1–10000 (stored config; enforcement is up to the forwarding layer)
- `metadata` — flat object of short string/number/boolean values

The `auth` mode label is intentionally **not** overridable, so an override can never change how a route authenticates. Every override needs a `reason`, records `actor`, `before`, `after`, and can be reverted (newest-first per dataset).

> Note: the previous `authenticate(type)` granted access to anyone passing `'VIP'` or `'moderator'`. That bypass is removed; access now requires a valid signed Avrone Due'Krey token.

## Environment variables

| Var | Required | Description |
|---|---|---|
| `AVRONE_ISSUER` | yes | Expected `iss` claim of Avrone Due'Krey tokens; no leading/trailing whitespace (e.g. a stray CR) or invisible characters |
| `AVRONE_AUDIENCE` | yes | Expected `aud` claim (e.g. `control704-proxy`); same character rules as `AVRONE_ISSUER` |
| `AVRONE_JWT_SECRET` | one of | HS256 shared secret, ≥ 32 bytes, no leading/trailing whitespace, not low-variety |
| `AVRONE_JWT_PUBLIC_KEY` | one of | PEM public key for RS256 (RSA ≥ 2048) or ES256 (P-256); `\n` escapes and CRLF allowed; private keys are rejected |
| `AVRONE_CLOCK_SKEW_SEC` | no | Allowed clock skew, default `30`, integer 0–300 |
| `AVRONE_MAX_TOKEN_AGE_SEC` | no | Reject tokens whose `iat` is older than this; positive safe integer |
| `HOST` / `PORT` | no | Default `127.0.0.1:8704`; `PORT` must be an integer 0–65535, `HOST` must not contain whitespace or `/` |

Secrets come only from the environment. See `.env.example`; never commit real values.

### Startup, shutdown and restart
- **Invalid or missing env**: the process prints one line, `control704: startup failed: <reason>`, to stderr and exits `1`. The line names the variable, never includes secret or key values, and has no stack trace. A port already in use reports `Port <p> on <host> is already in use`.
- **Readiness**: `Control704 proxy listening on http://host:port` is printed only after the SIGTERM/SIGINT handlers are installed.
- **Graceful shutdown** (SIGTERM/SIGINT, or `close(graceMs)` from `startFromEnv()`):
  - New connections are refused immediately and idle keep-alive sockets are closed.
  - In-flight requests may finish.
  - Anything still open after `graceMs` (default 10 s) is force-closed.
  - Then the process exits `0`. `close()` is idempotent.
- **Restart semantics**: all state is in memory. Every start begins from the X/Y/Z defaults with an empty override history and an empty audit buffer, and old override ids are unknown (404). Auth is stateless, so tokens stay valid across restarts unless the secret or key is rotated.

## Wiring Avrone Due'Krey as the auth provider
Configure Avrone Due'Krey to issue JWTs with:

```json
{ "iss": "<AVRONE_ISSUER>", "aud": "control704-proxy", "sub": "tech-42",
  "exp": 1700000000, "iat": 1699999700,
  "roles": ["technician"], "scope": "proxy:read proxy:x" }
```

`roles` (array) and `scope` (space-separated) / `scp` (array) are both honoured.
Prefer RS256/ES256 with `AVRONE_JWT_PUBLIC_KEY` so the proxy never holds a signing secret.
To use a different identity provider, pass any `{ name, verify(token) }` object to `createApp({ provider })`.
Whatever `verify()` returns must be a plain object with a non-empty string `sub`, or the request is rejected (401).
`verify()` is cut off after `authTimeoutMs` (default 5000, `createApp({ provider, authTimeoutMs })`); a timeout returns `503 auth_unavailable` with `Retry-After: 5`, never access.

### Issuer contract (avrone-chat → proxy)
`src/auth/issuer.js` (`mintAvroneToken`) is the reference issuer: header `{"alg":"HS256","typ":"JWT"}`, claims `iss, aud, sub, roles, iat, exp, jti`, TTL ≤ 300 s. The avrone-chat app (`living-intermediate-control-plane/avrone-chat`, `lib/control704/avrone-jwt.ts`, `CONTROL704_PROXY_<T>_TOKEN_MODE=avrone-jwt`) mints exactly this layout; `test/fixtures/avrone-chat-tokens.json` holds golden tokens produced by that code with a TEST-ONLY secret, and `test/contract.test.js` checks both directions.

### Roles → scopes
| Role | Scopes |
|---|---|
| `viewer` | `proxy:read`, `datasets:read` |
| `technician` | viewer + `proxy:x`, `proxy:y`, `proxy:z` |
| `admin` | technician + `datasets:override`, `datasets:revert`, `audit:read` |

## API
| Method & path | Scope(s) |
|---|---|
| `GET /health` | public |
| `GET /proxy/{x,y,z}` | `proxy:read` + `proxy:<id>` |
| `GET /datasets`, `GET /datasets/{X,Y,Z}` | `datasets:read` |
| `POST /admin/datasets/{X,Y,Z}/overrides` | `datasets:override` |
| `GET /admin/datasets/{X,Y,Z}/overrides` | `audit:read` |
| `POST /admin/overrides/{overrideId}/revert` | `datasets:revert` |
| `GET /admin/audit` | `audit:read` |

Errors: `401` (missing/invalid/expired token or duplicate `Authorization` headers, with `WWW-Authenticate`), `403` (`insufficient_scope`, lists required scopes), `400` (validation / malformed JSON / non-object body / malformed request target), `404`, `405` (with `Allow`; includes `HEAD`/`OPTIONS`), `413` (body > 16 KiB), `415` (non-JSON content-type), `503` (route disabled, or `auth_unavailable` when the provider times out).

Token rules enforced: `alg` must exactly match the configured key type (`none`, case variants and HS/RS swaps rejected); `crit` headers rejected; `kid`/`jku`/`x5u`/`jwk` ignored (never used to pick keys); segments must be canonical base64url without padding; token ≤ 8 KiB; `exp` required and numeric; `nbf`/`iat` must be numeric if present and `iat` may not be in the future (beyond skew); `sub` 1–256 chars without control, zero-width, bidi or other format characters or lone surrogates; token JSON must be strict UTF-8; RSA keys ≥ 2048 bits; EC keys must be P-256. Tokens are only accepted from the `Authorization` header (never query strings).

### Usage
```bash
export AVRONE_ISSUER=https://avrone-due-krey.example.com AVRONE_AUDIENCE=control704-proxy
export AVRONE_JWT_SECRET="$(openssl rand -hex 32)"   # or AVRONE_JWT_PUBLIC_KEY
npm start

curl -H "Authorization: Bearer $TOKEN" localhost:8704/proxy/x

curl -X POST localhost:8704/admin/datasets/X/overrides \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'content-type: application/json' \
  -d '{"patch":{"enabled":false,"rateLimitPerMinute":10},"reason":"maintenance window"}'

curl -X POST -H "Authorization: Bearer $ADMIN_TOKEN" localhost:8704/admin/overrides/<id>/revert
```

## Tests
```bash
npm test               # fast suite (~4-5 s): unit, HTTP, edge cases, seeded fuzz, model-based, regressions
npm run test:slow      # + statistical timing check and long model sweep (minutes)
npm run test:fuzz      # longer fuzz + model runs
npm run test:mutation  # mutation check: breaks each guard in a throwaway copy and confirms tests fail
FUZZ_SEED=123 FUZZ_ITER=5000 node --test test/fuzz.test.js        # reproduce a fuzz seed
MODEL_SEEDS=42 MODEL_STEPS=2000 node --test test/model.test.js     # reproduce a model seed
```

| File | Covers |
|---|---|
| `auth`, `server` | Core happy paths and basic rejections |
| `jwt.edge` | Alg confusion, header tampering, odd/duplicate JSON keys, encoding, size limits, time-claim boundaries, aud/iss/sub types, config |
| `access.edge` | Role/scope matrix, unknown & prototype roles, escalation, case sensitivity, Bearer parsing, duplicate auth headers, audit redaction |
| `overrides.edge` | Validation boundaries, endpoint traversal/lookalikes/collisions, upstream schemes & credentials, prototype pollution, revert ordering, concurrency, 503 |
| `http.edge` | Malformed JSON, content types, body limits, unknown routes/methods, HEAD/OPTIONS, query strings, URL quirks |
| `fuzz` | Seeded randomized tests (default seed `704012`) |
| `model` (+ `model/harness.js`) | Stateful model-based testing: random auth/override/revert/read sequences vs an independent reference model after every step, with delta-debugging shrinking to a minimal repro (shrinker itself verified with injected bugs) |
| `time` | Fake clock: ms-precision exp/nbf/iat/max-age boundaries for several skews, clock jumps both ways, leap-second-like edges, broken clocks, token expiring mid-request |
| `sidechannel` | `timingSafeEqual` used (spy), no `Buffer#equals`, signature checked before claims, uniform 401 shapes/lengths, no message leaks, 500s expose only a requestId |
| `resources` | 300 concurrent requests, connection cap, slowloris headers/body (408), 431 for huge/many headers, endless bodies, audit & history growth bounds |
| `keys` | Malformed PEMs, unsupported key types/curves/sizes, wrong key for alg, PEM CRLF/whitespace, runtime env/config swaps, key rotation, empty/whitespace secrets |
| `unicode` | NFC/NFD, exhaustive `toUpperCase` scan for dataset ids, lookalike roles/scopes, bidi/zero-width chars, surrogates, overlong UTF-8, mixed-case percent-encoding |
| `ratelimit` | `rateLimitPerMinute` boundaries and per-route config (config only: **not enforced**) |
| `characterization` | Documents current behaviour for the open questions (scope-only admin actions, internal upstreams). **Not** an endorsement |
| `protocol` | HTTP/1.x edges, run over raw sockets: CL/TE smuggling, duplicate CL, obs-fold, bare CR/LF, chunk-size overflow and extensions, trailers carrying Authorization, keep-alive/pipelining auth isolation, HTTP/1.0, absolute-form targets, `Expect: 100-continue` gating, very long URLs, CRLF injection, x-request-id |
| `json` | JSON parser edges: big numbers, `-0`, `1e309`, deep arrays/objects, BOM, nested duplicate keys, nested `__proto__`/`constructor`, unsafe integers, control characters |
| `audit` | Audit integrity: frozen entries, system-owned `seq`/`ts`, strict ordering under concurrency, no newline forging, redaction, export under scope, ring cap boundary, sink failures |
| `lifecycle` | Startup failure for each env var (real child process), port in use, SIGTERM/SIGINT, graceful shutdown with in-flight/idle/stuck requests, restart semantics |
| `invariants` | Cross-dataset invariants under random concurrent interleavings (Promise races with chunked bodies, plus real sockets): endpoint uniqueness, state matches the last active record, LIFO chains, id uniqueness |
| `differential` | Production JWT verifier vs an independent reference built on different Node primitives: thousands of seeded HS256/RS256/ES256 tokens (valid, tampered, alg-confused, boundary claims) must get identical decisions and payloads |
| `regressions`, `regressions-r5` | One explicit test per previously fixed bug (R2-1..R2-8, R3-1..R3-12, R4-1..R4-11, R5-1..R5-5) |
| `contract` | Golden tokens from the avrone-chat issuer verify and map to the right principal; claim layout; expiry/max-age boundaries; tampering; byte-identical reference issuer |
| `e2e` | Full per-role journeys over a real socket via `startFromEnv` (anonymous, viewer, technician, admin override→audit→revert, multi-role, expired/foreign tokens, keep-alive identity isolation) |
| `chaos` | Failing/slow/non-Error audit sinks, broken clocks, providers that throw, return junk or hang, store faults, clients resetting mid-request and mid-response; asserts no unhandled rejections |
| `canonicalization` | Differential vs Node's WHATWG URL parser over random raw targets; admin-route spellings; Authorization header case/OWS/scheme/duplicate/folded variants |
| `config.fuzz` | Every env var fuzzed alone and in combination: sane config or an Error naming the variable, never echoing secrets, never hanging |
| `memory` (+ `memory-worker.js`) | `--expose-gc` child: mixed traffic must not grow the heap; caps and handles checked |
| `slow/` | Statistical HMAC timing check, long model sweep, 40k-request heap soak |

### Resource limits (defaults, `createApp().server(options)` to override)
| Limit | Default |
|---|---|
| Request body | 16 KiB (413); bodies are drained up to 1 MiB, then the connection is closed (lingering close) |
| Header size / count | 16 KiB (431) / 100 headers (431) |
| `requestTimeout` / `headersTimeout` / `keepAliveTimeout` | 15 s / 10 s / 5 s (408 on slow requests) |
| `maxConnections` | 1024 |
| Token size | 8 KiB |
| Audit ring buffer | 1000 entries in memory (`createAuditLogger({ maxEntries })`); the sink gets every event |
| Request id | Every response carries a server-generated `x-request-id` (UUID); caller-supplied values are ignored |
| HTTP version / Host | Only HTTP/1.x is served (others get 505); duplicate `Host` gets 400 |
| `Expect: 100-continue` | `100 Continue` is sent only after routing, authentication, authorisation and the content-type/length checks pass |
| Override history | 1000 records (`new DatasetStore(undefined, { maxHistory })`); older records are compacted and can no longer be reverted |

### Request targets (round 5)
- Origin-form targets (`/...`) are always treated as a path (RFC 9112): `//x/admin/audit` is the path `//x/admin/audit` (404), not host `x` + `/admin/audit`. Dot segments, `%2e` and `\` are normalised per WHATWG before routing and authorisation.

### Data rules (round 4)
- Metadata string values: ≤ 512 chars, no C0/C1 controls (including CR, LF, TAB), no bidi or zero-width characters, no lone surrogates. Numbers must be finite, and integers must be safe (≤ 2^53−1).
- Override reasons: 3–500 chars. LF and TAB are allowed; CR, bidi/zero-width characters and lone surrogates are not.
- Audit entries are deep-frozen. `seq` and `ts` are assigned by the logger, and each entry is one JSON line, so embedded newlines are escaped. `recent(n)` clamps `n`, and a failing sink is counted but never breaks a request.
- Reverts are LIFO per dataset and must never create an endpoint clash. As a result, a revert can be refused until a conflicting dataset moves. Uniqueness takes priority over revertibility; see `invariants` for a minimal example.

## Limitations / next steps
- Overrides and audit entries are in memory (lost on restart); swap in persistent storage for production.
- `rateLimitPerMinute` is stored and validated but **not enforced** yet.
- Auth is evaluated once at request start; a token that expires during a slow upload still completes that request (bounded by `requestTimeout`).
- `sub` values are compared exactly (no Unicode normalisation), per RFC 7519.
- JWKS URL fetching/rotation is not implemented; a single configured key is used.
- The proxy returns route profiles; actual upstream request forwarding is not implemented yet.
