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
| `AVRONE_ISSUER` | yes | Expected `iss` claim of Avrone Due'Krey tokens |
| `AVRONE_AUDIENCE` | yes | Expected `aud` claim (e.g. `control704-proxy`) |
| `AVRONE_JWT_SECRET` | one of | HS256 shared secret, ≥ 32 bytes |
| `AVRONE_JWT_PUBLIC_KEY` | one of | PEM public key for RS256 (RSA) or ES256 (P-256); `\n` escapes allowed |
| `AVRONE_CLOCK_SKEW_SEC` | no | Allowed clock skew, default `30` |
| `AVRONE_MAX_TOKEN_AGE_SEC` | no | Reject tokens whose `iat` is older than this |
| `HOST` / `PORT` | no | Default `127.0.0.1:8704` |

Secrets come only from the environment. See `.env.example`; never commit real values.

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

Errors: `401` (missing/invalid/expired token or duplicate `Authorization` headers, with `WWW-Authenticate`), `403` (`insufficient_scope`, lists required scopes), `400` (validation / malformed JSON / non-object body / malformed request target), `404`, `405` (with `Allow`; includes `HEAD`/`OPTIONS`), `413` (body > 16 KiB), `415` (non-JSON content-type), `503` (route disabled).

Token rules enforced: `alg` must exactly match the configured key type (`none`, case variants and HS/RS swaps rejected); `crit` headers rejected; `kid`/`jku`/`x5u`/`jwk` ignored (never used to pick keys); segments must be canonical base64url without padding; token ≤ 8 KiB; `exp` required and numeric; `nbf`/`iat` must be numeric if present and `iat` may not be in the future (beyond skew); `sub` 1–256 chars without control characters; RSA keys ≥ 2048 bits; EC keys must be P-256. Tokens are only accepted from the `Authorization` header (never query strings).

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
npm test                      # full suite (unit, HTTP, edge cases, seeded fuzz)
npm run test:fuzz             # longer fuzz run
FUZZ_SEED=123 FUZZ_ITER=5000 node --test test/fuzz.test.js   # reproduce a specific seed
```

| File | Covers |
|---|---|
| `test/auth.test.js`, `test/server.test.js` | Core happy paths and basic rejections |
| `test/jwt.edge.test.js` | Alg confusion, header tampering, odd/duplicate JSON keys, encoding, size limits, time-claim boundaries, aud/iss/sub types, config validation |
| `test/access.edge.test.js` | Role/scope matrix, unknown & prototype roles, scope escalation, case sensitivity, Bearer parsing, duplicate auth headers, audit redaction on every failure path |
| `test/overrides.edge.test.js` | Every validation boundary, endpoint traversal/lookalikes/collisions, upstream schemes & credentials, prototype pollution, revert ordering & collisions, concurrency, 503 |
| `test/http.edge.test.js` | Malformed JSON, content types, body limits (incl. chunked & lying Content-Length), unknown routes/methods, HEAD/OPTIONS, query strings, URL quirks |
| `test/fuzz.test.js` | Seeded randomized tests (Node built-ins only; default seed `704012`) |

## Limitations / next steps
- Overrides and audit entries are in memory (lost on restart); swap in persistent storage for production.
- JWKS URL fetching/rotation is not implemented; a single configured key is used.
- The proxy returns route profiles; actual upstream request forwarding is not implemented yet.
