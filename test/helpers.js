'use strict';
const crypto = require('crypto');
const http = require('http');

const SECRET = crypto.randomBytes(48).toString('hex');
const ISSUER = 'https://avrone-due-krey.test';
const AUDIENCE = 'control704-proxy';

const b64 = (v) => Buffer.from(typeof v === 'string' ? v : JSON.stringify(v)).toString('base64url');
const hmac = (secret, input) => crypto.createHmac('sha256', secret).update(input).digest('base64url');

function sign(payload, { secret = SECRET, alg = 'HS256', header = {} } = {}) {
  const h = b64({ alg, typ: 'JWT', ...header });
  const p = b64(payload);
  const sig = /^none$/i.test(alg) ? '' : hmac(secret, `${h}.${p}`);
  return `${h}.${p}.${sig}`;
}

// Sign arbitrary raw header/payload JSON strings (for duplicate keys, odd JSON, etc.).
function signRaw(headerStr, payloadStr, secret = SECRET) {
  const h = b64(headerStr);
  const p = b64(payloadStr);
  return `${h}.${p}.${hmac(secret, `${h}.${p}`)}`;
}

function claims(extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: AUDIENCE, sub: 'user-1', iat: now, exp: now + 300, ...extra };
}

const config = { issuer: ISSUER, audience: AUDIENCE, secret: SECRET, publicKey: '', clockSkewSec: 0, maxTokenAgeSec: null };

// Deterministic PRNG (mulberry32) so randomized tests are reproducible.
function rng(seed) {
  let a = seed >>> 0;
  const next = () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let t = a;
    t = Math.imul(t ^ (t >>> 15), t | 1);
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
  next.int = (lo, hi) => lo + Math.floor(next() * (hi - lo + 1));
  next.pick = (arr) => arr[Math.floor(next() * arr.length)];
  next.str = (len, alphabet) => Array.from({ length: len }, () => next.pick(alphabet)).join('');
  return next;
}
const SEED = Number.parseInt(process.env.FUZZ_SEED || '704012', 10);

async function startServer(opts = {}) {
  const { createAvroneProvider } = require('../src/auth/avroneProvider');
  const { createApp } = require('../src/server');
  const { createAuditLogger } = require('../src/access/audit');
  const lines = [];
  const audit = createAuditLogger({ sink: (l) => lines.push(l), maxEntries: 100000 });
  const app = createApp({ provider: opts.provider || createAvroneProvider(config), audit, ...opts.app });
  const server = app.server();
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  const port = server.address().port;
  return { app, server, port, base: `http://127.0.0.1:${port}`, lines, close: () => new Promise((r) => server.close(r)) };
}

// Raw HTTP request (supports duplicate headers, odd methods, raw paths, raw bodies).
function raw(port, { method = 'GET', path = '/', headers = {}, body } = {}) {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method, path, headers, agent: false }, (res) => {
      const chunks = [];
      res.on('data', (c) => chunks.push(c));
      res.on('end', () => {
        const text = Buffer.concat(chunks).toString('utf8');
        let json = null;
        try { json = JSON.parse(text); } catch { /* not json */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

const bearer = (t) => ({ authorization: `Bearer ${t}` });
const jsonPost = (t, body) => ({
  method: 'POST',
  headers: { ...bearer(t), 'content-type': 'application/json' },
  body: typeof body === 'string' ? body : JSON.stringify(body),
});

module.exports = { SECRET, ISSUER, AUDIENCE, sign, signRaw, claims, config, b64, hmac, rng, SEED, startServer, raw, bearer, jsonPost };
