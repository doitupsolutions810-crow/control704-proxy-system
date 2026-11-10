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

class HttpError extends Error {
  constructor(status, error, message) { super(message); this.status = status; this.error = error; }
}

function send(res, status, body, extraHeaders = {}) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff',
    ...extraHeaders,
  });
  res.end(payload);
}

function readJson(req) {
  return new Promise((resolve, reject) => {
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
    let size = 0;
    let tooBig = false;
    const chunks = [];
    // Drain (rather than destroy) oversized bodies so a clean 413 can still be sent.
    req.on('data', (c) => {
      if (tooBig) return;
      size += c.length;
      if (size > MAX_BODY) { tooBig = true; chunks.length = 0; return; }
      chunks.push(c);
    });
    req.on('end', () => {
      if (tooBig) { reject(new HttpError(413, 'payload_too_large', 'Request body too large')); return; }
      let parsed;
      try { parsed = JSON.parse(Buffer.concat(chunks).toString('utf8') || '{}'); }
      catch { reject(new ValidationError('Invalid JSON body')); return; }
      if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
        reject(new ValidationError('JSON body must be an object'));
        return;
      }
      resolve(parsed);
    });
    req.on('error', reject);
  });
}

function createApp({ provider, store = new DatasetStore(), audit = createAuditLogger() } = {}) {
  const authenticator = createAuthenticator(provider);

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
      const body = await readJson(ctx.req);
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
    let url;
    try {
      // Fixed base; only the path is used. Malformed request targets get 400 instead of
      // an unhandled rejection that left the connection hanging.
      url = new URL(req.url, 'http://localhost');
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

      const [status, body] = await handler({ req, params, principal, requestId });
      if (principal) audit.log({ ...base, type: 'request', actor: principal.sub, status });
      return send(res, status, body);
    } catch (err) {
      if (err instanceof HttpError) return send(res, err.status, { error: err.error, message: err.message });
      if (err instanceof ValidationError) return send(res, 400, { error: 'validation_error', message: err.message, details: err.details || [] });
      if (err instanceof NotFoundError) return send(res, 404, { error: 'not_found', message: err.message });
      audit.log({ ...base, type: 'error', actor: principal && principal.sub, message: err.message });
      return send(res, 500, { error: 'internal_error', requestId });
    }
  }

  return { handle, store, audit, server: () => http.createServer(handle) };
}

module.exports = { createApp };
