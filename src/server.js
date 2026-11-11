'use strict';
// Control704 access proxy HTTP API (Control12-lattice-op).
// Uses only Node built-ins.

const http = require('http');
const crypto = require('crypto');
const { createAuthenticator, AuthError } = require('./auth');
const { hasScopes } = require('./access/authorize');
const { createAuditLogger } = require('./access/audit');
const { DatasetStore, ValidationError, NotFoundError } = require('./datasets/store');

const MAX_BODY = 16 * 1024;
// Bodies beyond MAX_BODY are drained (so a clean 413 can be sent) only up to MAX_DRAIN;
// past that the connection is closed to stop endless streams.
const MAX_DRAIN = 1024 * 1024;
const MAX_HEADERS = 100;
const LINGER_MS = 2000;

const SERVER_DEFAULTS = Object.freeze({
  requestTimeout: 15000, // whole request incl. body (slowloris bodies)
  headersTimeout: 10000, // slow headers
  keepAliveTimeout: 5000,
  maxHeaderSize: 16384, // bytes; Node returns 431 beyond this
  maxConnections: 1024,
  connectionsCheckingInterval: 1000,
});
const utf8 = new TextDecoder('utf-8', { fatal: true, ignoreBOM: false });

class HttpError extends Error {
  constructor(status, error, message) { super(message); this.status = status; this.error = error; }
}

function send(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    // Explicit length: writeHead() before end() would otherwise force chunked encoding.
    'content-length': Buffer.byteLength(payload),
    ...extraHeaders,
  });
  res.end(payload);
}

// The client went away before the request could be processed. Nothing can be sent; the
// request is audited as aborted and never reaches a handler's side effects.
class ClientGoneError extends Error {
  constructor() { super('Client disconnected'); this.name = 'ClientGoneError'; }
}
const clientGone = (req, res) => Boolean(req.destroyed || (res && res.destroyed) || (req.socket && req.socket.destroyed));

function readJson(req, res) {
  return new Promise((resolve, reject) => {
    // If the client disconnected earlier (e.g. while authentication was still running), the
    // request stream is already destroyed and will never emit 'end' or 'error'.
    if (clientGone(req, res) && !req.complete) { reject(new ClientGoneError()); return; }
    const ct = req.headers['content-type'] || '';
    if (!/^application\/json\s*(;.*)?$/i.test(ct)) {
      req.resume();
      reject(new HttpError(415, 'unsupported_media_type', 'content-type must be application/json'));
      return;
    }
    const declared = Number(req.headers['content-length']);
    if (Number.isFinite(declared) && declared > MAX_BODY) {
      req.resume();
      reject(new HttpError(413, 'payload_too_large', 'Request body too large'));
      return;
    }
    // Expect: 100-continue — only invite the body once auth, authz, content-type and the
    // declared length have all passed (Node's default would send 100 before any checks).
    if (req.expectsContinue && res && !res.headersSent) res.writeContinue();
    let size = 0;
    let tooBig = false;
    const chunks = [];
    // Drain (rather than destroy) oversized bodies so a clean 413 can still be sent.
    let settled = false;
    req.on('data', (c) => {
      size += c.length;
      if (size > MAX_DRAIN && !settled) {
        settled = true;
        const e = new HttpError(413, 'payload_too_large', 'Request body too large');
        e.closeConnection = true;
        reject(e);
        return;
      }
      if (tooBig) return;
      if (size > MAX_BODY) { tooBig = true; chunks.length = 0; return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (settled) return;
      if (tooBig) { reject(new HttpError(413, 'payload_too_large', 'Request body too large')); return; }
      let parsed;
      let text;
      // Strict UTF-8: invalid / overlong sequences are rejected instead of being silently
      // replaced with U+FFFD and stored.
      try { text = utf8.decode(Buffer.concat(chunks)); }
      catch { reject(new ValidationError('Request body is not valid UTF-8')); return; }
      try { parsed = JSON.parse(text || '{}'); }
      catch { reject(new ValidationError('Invalid JSON body')); return; }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        reject(new ValidationError('JSON body must be an object'));
        return;
      }
      resolve(parsed);
    });
    // Node reports a client disconnect mid-body as an 'aborted' stream error; classify it as
    // ClientGoneError so it is audited as request.aborted rather than as a server error.
    req.on('error', (err) => { settled = true; reject(clientGone(req, res) ? new ClientGoneError() : err); });
    // A disconnect mid-body emits 'close' without 'end'; settle instead of hanging forever.
    req.on('close', () => { if (!req.complete && !settled) { settled = true; reject(new ClientGoneError()); } });
  });
}

function createApp({ provider, store = new DatasetStore(), audit = createAuditLogger(), authTimeoutMs } = {}) {
  const authenticator = createAuthenticator(provider, authTimeoutMs === undefined ? {} : { timeoutMs: authTimeoutMs });

  // [method, regex, requiredScopes(params) | null (public), handler]
  const routes = [
    ['GET', /^\/health$/, null, () => [200, { status: 'ok' }]],
    ['GET', /^\/proxy\/([xyzXYZ])$/, (p) => ['proxy:read', `proxy:${p[0].toLowerCase()}`], (ctx) => {
      const profile = store.get(ctx.params[0]);
      if (!profile.enabled) return [503, { error: 'route_disabled', dataset: ctx.params[0].toUpperCase() }];
      return [200, { dataset: ctx.params[0].toUpperCase(), profile, principal: ctx.principal.sub }];
    }],
    ['GET', /^\/datasets$/, () => ['datasets:read'], () => [200, store.all()]],
    ['GET', /^\/datasets\/([^/]+)$/, () => ['datasets:read'], (ctx) => [200, store.get(ctx.params[0])]],
    ['POST', /^\/admin\/datasets\/([^/]+)\/overrides$/, () => ['datasets:override'], async (ctx) => {
      const body = await readJson(ctx.req, ctx.res);
      const rec = store.override(ctx.params[0], body.patch, { actor: ctx.principal.sub, reason: body.reason });
      audit.log({ type: 'dataset.override', requestId: ctx.requestId, actor: ctx.principal.sub,
        dataset: rec.dataset, overrideId: rec.id, patch: rec.patch, reason: rec.reason });
      return [201, rec];
    }],
    ['GET', /^\/admin\/datasets\/([^/]+)\/overrides$/, () => ['audit:read'], (ctx) => [200, store.listOverrides(ctx.params[0])]],
    ['POST', /^\/admin\/overrides\/([0-9a-f-]{36})\/revert$/, () => ['datasets:revert'], (ctx) => {
      const rec = store.revert(ctx.params[0], { actor: ctx.principal.sub });
      audit.log({ type: 'dataset.revert', requestId: ctx.requestId, actor: ctx.principal.sub,
        dataset: rec.dataset, overrideId: rec.id });
      return [200, rec];
    }],
    ['GET', /^\/admin\/audit$/, () => ['audit:read'], () => [200, audit.recent(200)]],
  ];

  async function handle(req, res) {
    const requestId = crypto.randomUUID();
    // Server-generated correlation id. Any caller-supplied X-Request-Id is ignored (never
    // echoed), so it cannot be used for header injection or audit-log confusion.
    if (typeof res.setHeader === 'function') res.setHeader('x-request-id', requestId);
    // RFC 9112 §3.2: more than one Host header MUST be rejected with 400 (an upstream proxy
    // might route on a different Host than the one Node keeps).
    if (Array.isArray(req.rawHeaders)) {
      let hosts = 0;
      for (let i = 0; i < req.rawHeaders.length; i += 2) if (String(req.rawHeaders[i]).toLowerCase() === 'host') hosts += 1;
      if (hosts > 1) return send(res, 400, { error: 'bad_request', message: 'Multiple Host headers' }, { connection: 'close' });
    }
    if (req.httpVersionMajor !== undefined && req.httpVersionMajor !== 1) {
      return send(res, 505, { error: 'http_version_not_supported' }, { connection: 'close' });
    }
    // Node silently truncates headers beyond maxHeadersCount, which could hide e.g. a
    // duplicate Authorization header. Reject instead of guessing.
    if (Array.isArray(req.rawHeaders) && req.rawHeaders.length / 2 >= MAX_HEADERS) {
      return send(res, 431, { error: 'too_many_headers' }, { connection: 'close' });
    }
    let url;
    try {
      // Fixed base; only the path is used. Malformed request targets get 400 instead of
      // an unhandled rejection that left the connection hanging.
      // An origin-form target ("/...") is always a path (RFC 9112 §3.2.1). Resolving it as a
      // relative reference would read "//host/rest" as scheme-relative and silently drop the
      // first segment, so "//x/admin/audit" would route as "/admin/audit" while a front proxy
      // sees a different path. Prefix the fixed origin instead so the whole target stays path.
      url = req.url.startsWith('/') ? new URL(`http://localhost${req.url}`) : new URL(req.url, 'http://localhost');
    } catch {
      return send(res, 400, { error: 'bad_request', message: 'Malformed request target' });
    }
    const base = { requestId, method: req.method, path: url.pathname.slice(0, 512) };
    let principal = null;
    try {
      const pathMatches = routes.filter(([, re]) => re.test(url.pathname));
      if (pathMatches.length === 0) return send(res, 404, { error: 'not_found' });
      const route = pathMatches.find(([m]) => m === req.method);
      if (!route) {
        const allow = [...new Set(pathMatches.map(([m]) => m))].join(', ');
        return send(res, 405, { error: 'method_not_allowed' }, { allow });
      }
      const [, re, scopeFn, handler] = route;
      const params = re.exec(url.pathname).slice(1);

      if (scopeFn) {
        try {
          principal = await authenticator.authenticate(req);
        } catch (err) {
          const code = err instanceof AuthError ? err.code : 'invalid_token';
          if (code === 'auth_unavailable') {
            // The provider did not answer in time: fail closed, but as a retryable 503, not a 401.
            audit.log({ ...base, type: 'auth.unavailable' });
            return send(res, 503, { error: 'auth_unavailable' }, { 'retry-after': '5' });
          }
          audit.log({ ...base, type: 'auth.failure', reason: code });
          return send(res, 401, { error: 'unauthorized', reason: code },
            { 'www-authenticate': `Bearer realm="control704", error="${code === 'missing_token' || code === 'invalid_request' ? 'invalid_request' : 'invalid_token'}"` });
        }
        const required = scopeFn(params);
        if (!hasScopes(principal, required)) {
          audit.log({ ...base, type: 'authz.denied', actor: principal.sub, required });
          return send(res, 403, { error: 'forbidden', required },
            { 'www-authenticate': `Bearer realm="control704", error="insufficient_scope", scope="${required.join(' ')}"` });
        }
      }

      // Authentication can be slow (pluggable providers); if the client left meanwhile, do not
      // run the handler (no side effects for a request nobody is waiting for).
      if (clientGone(req, res)) {
        audit.log({ ...base, type: 'request.aborted', actor: principal && principal.sub });
        return undefined;
      }
      const [status, body] = await handler({ req, res, params, principal, requestId });
      if (principal) audit.log({ ...base, type: 'request', actor: principal.sub, status });
      return send(res, status, body);
    } catch (err) {
      if (err instanceof ClientGoneError) {
        audit.log({ ...base, type: 'request.aborted', actor: principal && principal.sub });
        return undefined;
      }
      if (err instanceof HttpError) {
        if (err.closeConnection) {
          // "Lingering close": after the 413 is flushed, send FIN but keep discarding incoming
          // bytes for a short grace period. Destroying immediately while the peer is still
          // uploading triggers a TCP RST that can wipe the response before the client reads it.
          res.on('finish', () => {
            const sock = req.socket;
            if (!sock) return;
            req.on('data', () => {});
            req.resume();
            sock.end();
            setTimeout(() => sock.destroy(), LINGER_MS).unref();
          });
          return send(res, err.status, { error: err.error, message: err.message }, { connection: 'close' });
        }
        return send(res, err.status, { error: err.error, message: err.message });
      }
      if (err instanceof ValidationError) return send(res, 400, { error: 'validation_error', message: err.message, details: err.details || [] });
      if (err instanceof NotFoundError) return send(res, 404, { error: 'not_found', message: err.message });
      audit.log({ ...base, type: 'error', actor: principal && principal.sub, message: err.message });
      return send(res, 500, { error: 'internal_error', requestId });
    }
  }

  function server(options = {}) {
    const o = { ...SERVER_DEFAULTS, ...options };
    const srv = http.createServer({
      requestTimeout: o.requestTimeout,
      headersTimeout: o.headersTimeout,
      keepAliveTimeout: o.keepAliveTimeout,
      maxHeaderSize: o.maxHeaderSize,
      connectionsCheckingInterval: o.connectionsCheckingInterval,
    }, handle);
    srv.on('checkContinue', (req, res) => { req.expectsContinue = true; handle(req, res); });
    srv.maxConnections = o.maxConnections;
    // One above the cap so the handler can detect (and reject) truncation.
    srv.maxHeadersCount = MAX_HEADERS + 1;
    return srv;
  }

  return { handle, store, audit, server };
}

module.exports = { createApp, SERVER_DEFAULTS, MAX_BODY, MAX_DRAIN, MAX_HEADERS };
