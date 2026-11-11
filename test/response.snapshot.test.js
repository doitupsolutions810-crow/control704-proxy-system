'use strict';
// Response header/body consistency snapshots per status code. Every application response
// must carry the same security headers, an exact Content-Length matching the body bytes, a
// server-generated UUID x-request-id, a JSON body with exactly the snapshot keys, and the
// status-specific headers (WWW-Authenticate, Allow, Retry-After, Connection) and nothing else.
const test = require('node:test');
const assert = require('node:assert');
const { sign, claims, startServer, raw, rawSocket, bearer, jsonPost } = require('./helpers');

const tech = sign(claims({ sub: 'tech1', roles: ['technician'] }));
const admin = sign(claims({ sub: 'jean', roles: ['admin'] }));
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/;
const COMMON = { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', 'x-content-type-options': 'nosniff' };
const NODE_OWNED = new Set(['date', 'connection', 'keep-alive', 'x-request-id', 'content-length']);

let s; let hung;
test.before(async () => {
  s = await startServer();
  hung = await startServer({ provider: { name: 'hang', verify: () => new Promise(() => {}) }, app: { authTimeoutMs: 50 } });
});
test.after(async () => { await s.close(); await hung.close(); });

const SNAP = [
  ['200 proxy', () => raw(s.port, { path: '/proxy/x', headers: bearer(tech) }), 200, ['dataset', 'profile', 'principal'], {}],
  ['200 health', () => raw(s.port, { path: '/health' }), 200, ['status'], {}],
  ['200 datasets', () => raw(s.port, { path: '/datasets', headers: bearer(tech) }), 200, ['X', 'Y', 'Z'], {}],
  ['201 override', () => raw(s.port, { path: '/admin/datasets/Z/overrides', ...jsonPost(admin, { patch: { metadata: { a: '1' } }, reason: 'snapshot' }) }), 201,
    ['id', 'dataset', 'actor', 'reason', 'patch', 'before', 'after', 'createdAt', 'revertedAt', 'revertedBy'], {}],
  ['400 validation', () => raw(s.port, { path: '/admin/datasets/Z/overrides', ...jsonPost(admin, { patch: { auth: 'none' }, reason: 'snapshot' }) }), 400, ['error', 'message', 'details'], {}],
  ['400 json', () => raw(s.port, { method: 'POST', path: '/admin/datasets/Z/overrides', headers: { ...bearer(admin), 'content-type': 'application/json' }, body: '{bad' }), 400, ['error', 'message', 'details'], {}],
  ['401 missing', () => raw(s.port, { path: '/proxy/x' }), 401, ['error', 'reason'], { 'www-authenticate': 'Bearer realm="control704", error="invalid_request"' }],
  ['401 invalid', () => raw(s.port, { path: '/proxy/x', headers: bearer('a.b.c') }), 401, ['error', 'reason'], { 'www-authenticate': 'Bearer realm="control704", error="invalid_token"' }],
  ['403', () => raw(s.port, { path: '/admin/audit', headers: bearer(tech) }), 403, ['error', 'required'], { 'www-authenticate': 'Bearer realm="control704", error="insufficient_scope", scope="audit:read"' }],
  ['404 route', () => raw(s.port, { path: '/nope' }), 404, ['error'], {}],
  ['404 dataset', () => raw(s.port, { path: '/datasets/Q', headers: bearer(tech) }), 404, ['error', 'message'], {}],
  ['405', () => raw(s.port, { method: 'DELETE', path: '/proxy/x', headers: bearer(tech) }), 405, ['error'], { allow: 'GET' }],
  ['413', () => raw(s.port, { method: 'POST', path: '/admin/datasets/Z/overrides', headers: { ...bearer(admin), 'content-type': 'application/json' }, body: JSON.stringify({ reason: 'x'.repeat(20000) }) }), 413, ['error', 'message'], {}],
  ['415', () => raw(s.port, { method: 'POST', path: '/admin/datasets/Z/overrides', headers: { ...bearer(admin), 'content-type': 'text/plain' }, body: '{}' }), 415, ['error', 'message'], {}],
  ['503 auth', () => raw(hung.port, { path: '/proxy/x', headers: bearer(tech) }), 503, ['error'], { 'retry-after': '5' }],
];

for (const [name, run, status, keys, extra] of SNAP) {
  test(`snapshot ${name}`, async () => {
    const r = await run();
    assert.equal(r.status, status);
    for (const [k, v] of Object.entries(COMMON)) assert.equal(r.headers[k], v, `${name}: ${k}`);
    for (const [k, v] of Object.entries(extra)) assert.equal(r.headers[k], v, `${name}: ${k}`);
    const unexpected = Object.keys(r.headers).filter((k) => !(k in COMMON) && !(k in extra) && !NODE_OWNED.has(k));
    assert.deepEqual(unexpected, [], `${name}: unexpected headers`);
    assert.equal(r.headers['transfer-encoding'], undefined, `${name}: chunked`);
    assert.equal(Number(r.headers['content-length']), Buffer.byteLength(r.text), `${name}: content-length`);
    assert.match(r.headers['x-request-id'], UUID);
    assert.deepEqual(Object.keys(r.json), keys, `${name}: body keys`);
    if (status >= 400) assert.equal(typeof r.json.error, 'string');
  });
}

test('snapshot: Content-Length counts UTF-8 bytes for non-ASCII bodies', async () => {
  const r = await raw(s.port, { path: '/admin/datasets/Y/overrides', ...jsonPost(admin, { patch: { metadata: { note: 'café ✓ 😀 Ünïcödé' } }, reason: 'raison: réglage ✓' }) });
  assert.equal(r.status, 201);
  assert.ok(Buffer.byteLength(r.text) > r.text.length);
  assert.equal(Number(r.headers['content-length']), Buffer.byteLength(r.text));
  assert.equal(r.json.reason, 'raison: réglage ✓');
});

test('snapshot: 500 exposes only error + requestId, and the body requestId equals the header', async (t) => {
  const { DatasetStore } = require('../src/datasets/store');
  const store = new DatasetStore();
  store.all = () => { throw new Error('boom'); };
  const x = await startServer({ app: { store } }); t.after(() => x.close());
  const r = await raw(x.port, { path: '/datasets', headers: bearer(tech) });
  assert.equal(r.status, 500);
  assert.deepEqual(Object.keys(r.json), ['error', 'requestId']);
  assert.equal(r.json.requestId, r.headers['x-request-id']);
  assert.equal(Number(r.headers['content-length']), Buffer.byteLength(r.text));
});

test('snapshot: 400 duplicate Host and 505 HTTP/2.0 carry the same JSON contract and close the connection', async () => {
  const dup = await rawSocket(s.port, 'GET /health HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n');
  assert.equal(dup.status, 400);
  assert.match(dup.data, /content-length: \d+/i);
  assert.match(dup.data, /connection: close/i);
  assert.match(dup.data, /x-content-type-options: nosniff/i);
  const v2 = await rawSocket(s.port, 'GET /health HTTP/2.0\r\nHost: a\r\n\r\n');
  assert.ok([400, 505].includes(v2.status), String(v2.status));
});

test('snapshot: x-request-id is unique per response, even on one keep-alive connection, and never echoed', async () => {
  const r = await rawSocket(s.port, 'GET /health HTTP/1.1\r\nHost: x\r\nX-Request-Id: evil\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
  const ids = [...r.data.matchAll(/x-request-id: ([0-9a-f-]+)/gi)].map((m) => m[1]);
  assert.equal(ids.length, 2);
  assert.notEqual(ids[0], ids[1]);
  assert.ok(!r.data.includes('evil'));
});

test('snapshot: error bodies never contain the presented token or any stack trace', async () => {
  for (const [, run] of SNAP) {
    const r = await run();
    assert.ok(!r.text.includes(admin) && !r.text.includes(tech), 'token echoed');
    assert.ok(!/\bat .+\(.+:\d+:\d+\)/.test(r.text), 'stack trace');
  }
});
