'use strict';
// Timing / information side channels.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { sign, claims, config, startServer, raw, bearer, b64 } = require('./helpers');

test('HS256 comparison goes through crypto.timingSafeEqual (spy)', async () => {
  const orig = crypto.timingSafeEqual;
  let calls = 0;
  crypto.timingSafeEqual = (a, b) => { calls++; return orig(a, b); };
  try {
    const p = createAvroneProvider(config);
    assert.ok(await p.verify(sign(claims())));
    await assert.rejects(p.verify(sign(claims(), { secret: 'x9'.repeat(20) + 'abcdefgh' })), /Invalid signature/);
    assert.equal(calls, 2, 'timingSafeEqual must be used for every same-length HMAC comparison');
  } finally { crypto.timingSafeEqual = orig; }
});
test('HS256 comparison never uses Buffer#equals / compare / string equality on the MAC', async () => {
  const origEq = Buffer.prototype.equals; const origCmp = Buffer.prototype.compare; const origCmpS = Buffer.compare;
  let bad = 0;
  Buffer.prototype.equals = function (...a) { bad++; return origEq.apply(this, a); };
  Buffer.prototype.compare = function (...a) { bad++; return origCmp.apply(this, a); };
  Buffer.compare = (...a) => { bad++; return origCmpS(...a); };
  try {
    const p = createAvroneProvider(config);
    await p.verify(sign(claims()));
    await assert.rejects(p.verify(sign(claims(), { secret: 'x9'.repeat(20) + 'abcdefgh' })));
  } finally { Buffer.prototype.equals = origEq; Buffer.prototype.compare = origCmp; Buffer.compare = origCmpS; }
  assert.equal(bad, 0);
});
test('static check: signature module has no ===/== comparisons on signatures or digests', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'src/auth/avroneProvider.js'), 'utf8');
  assert.ok(!/(expected|signature|digest)\s*[!=]==?\s*(expected|signature|digest)\b(?!\.length)/.test(src.replace(/expected\.length === signature\.length/g, '')));
  assert.match(src, /crypto\.timingSafeEqual\(expected, signature\)/);
});
test('wrong-length MAC short-circuits on length only (length is public: always 32 bytes for HS256)', async () => {
  const orig = crypto.timingSafeEqual; let calls = 0;
  crypto.timingSafeEqual = (a, b) => { calls++; return orig(a, b); };
  try {
    const p = createAvroneProvider(config);
    const [h, pl] = sign(claims()).split('.');
    await assert.rejects(p.verify(`${h}.${pl}.${crypto.randomBytes(16).toString('base64url')}`), /Invalid signature/);
    assert.equal(calls, 0);
  } finally { crypto.timingSafeEqual = orig; }
});
test('signature is verified BEFORE any claim is inspected (claims of forged tokens never influence errors)', async () => {
  const p = createAvroneProvider(config);
  const forged = (c) => sign(c, { secret: 'f0rged-secret-0123456789abcdefghijk' });
  for (const c of [claims({ exp: 1 }), claims({ iss: 'x' }), claims({ aud: 'x' }), claims({ sub: '' }), claims({ nbf: 9e15 }), {}]) {
    await assert.rejects(p.verify(forged(c)), /Invalid signature/);
  }
});

test('HTTP 401 response shape is identical for every invalid-token cause (only expired is distinguished, by design)', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const now = Math.floor(Date.now() / 1000);
  const cases = {
    'bad signature': sign(claims(), { secret: 'q1'.repeat(20) + 'abcdefgh' }),
    'alg none': sign(claims(), { alg: 'none' }),
    'wrong issuer': sign(claims({ iss: 'x' })),
    'wrong audience': sign(claims({ aud: 'x' })),
    'bad sub': sign(claims({ sub: '' })),
    'not yet valid': sign(claims({ nbf: now + 999 })),
    'future iat': sign(claims({ iat: now + 9999 })),
    'malformed': 'a.b.c',
    'two segments': 'abc.def',
    'crit header': sign(claims(), { header: { crit: ['x'] } }),
    'non-canonical': (() => { const [h, p] = sign(claims()).split('.'); return `${h}.${p}.A`; })(),
    'bad json': `${b64('{')}.${b64(claims())}.sig`,
  };
  const shapes = new Map();
  for (const [name, tok] of Object.entries(cases)) {
    const r = await raw(s.port, { path: '/admin/audit', headers: bearer(tok) });
    assert.equal(r.status, 401, name);
    const shape = JSON.stringify({ body: r.json, www: r.headers['www-authenticate'], keys: Object.keys(r.headers).filter((k) => !['date', 'content-length', 'connection', 'keep-alive'].includes(k)).sort() });
    shapes.set(shape, [...(shapes.get(shape) || []), name]);
  }
  assert.equal(shapes.size, 1, `distinguishable 401 shapes: ${JSON.stringify([...shapes.values()])}`);
  const [only] = shapes.keys();
  assert.deepEqual(JSON.parse(only).body, { error: 'unauthorized', reason: 'invalid_token' });
  // content-length is identical too
  const lens = new Set();
  for (const tok of Object.values(cases)) lens.add((await raw(s.port, { path: '/admin/audit', headers: bearer(tok) })).headers['content-length']);
  assert.equal(lens.size, 1);
  // expired is intentionally distinguishable (RFC 6750 lets clients refresh)
  const exp = await raw(s.port, { path: '/admin/audit', headers: bearer(sign(claims({ exp: now - 100 }))) });
  assert.deepEqual(exp.json, { error: 'unauthorized', reason: 'token_expired' });
});

test('HTTP: detailed AuthError messages never reach responses or the audit log', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const leaks = ['Invalid signature', 'Algorithm not allowed', 'Invalid issuer', 'Invalid audience', 'Non-canonical', 'Malformed', 'three segments'];
  for (const tok of [sign(claims(), { secret: 'q1'.repeat(20) + 'abcdefgh' }), sign(claims({ iss: 'x' })), 'a.b.c', 'x']) {
    const r = await raw(s.port, { path: '/datasets', headers: bearer(tok) });
    for (const l of leaks) assert.ok(!r.text.includes(l), `${l} leaked in response`);
  }
  for (const l of leaks) assert.ok(!s.lines.join('\n').includes(l), `${l} leaked in audit`);
});

test('HTTP: 404 vs 401 ordering — unknown dataset ids do not reveal existence to unauthenticated callers', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  for (const id of ['X', 'Q', '__proto__']) {
    const r = await raw(s.port, { path: `/datasets/${id}` });
    assert.equal(r.status, 401, id);
  }
});

test('HTTP: 403 for unknown vs known dataset is identical for under-privileged callers', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const tech = sign(claims({ roles: ['technician'] }));
  const body = JSON.stringify({ patch: { enabled: false }, reason: 'probe' });
  const a = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(tech), 'content-type': 'application/json' }, body });
  const b = await raw(s.port, { method: 'POST', path: '/admin/datasets/Q/overrides', headers: { ...bearer(tech), 'content-type': 'application/json' }, body });
  assert.equal(a.status, 403); assert.equal(b.status, 403);
  assert.deepEqual(a.json, b.json);
});

test('HTTP: 500 responses expose only a requestId (internal error message never leaks)', async () => {
  const { createApp } = require('../src/server');
  const { DatasetStore } = require('../src/datasets/store');
  const store = new DatasetStore();
  store.all = () => { throw new TypeError('db password is hunter2'); };
  const lines = [];
  const app = createApp({ provider: createAvroneProvider(config), store, audit: require('../src/access/audit').createAuditLogger({ sink: (l) => lines.push(l) }) });
  const srv = app.server();
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  try {
    const r = await raw(srv.address().port, { path: '/datasets', headers: bearer(sign(claims({ roles: ['viewer'] }))) });
    assert.equal(r.status, 500);
    assert.deepEqual(Object.keys(r.json).sort(), ['error', 'requestId']);
    assert.ok(!r.text.includes('hunter2'));
    // the operator-facing audit log does record it, keyed by the same requestId
    const e = lines.map((l) => JSON.parse(l)).find((x) => x.type === 'error');
    assert.equal(e.requestId, r.json.requestId);
  } finally { srv.close(); }
});
