'use strict';
// Chaos / fault injection: failing and slow audit sinks, broken clocks, misbehaving auth
// providers, store faults, partial requests, and sockets reset mid-request or mid-response.
// After every fault the server must keep answering correctly, never crash, never leak
// internals, and never leave an unhandled rejection behind.
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { createAuditLogger } = require('../src/access/audit');
const { DatasetStore } = require('../src/datasets/store');
const { sign, claims, config, startServer, raw, bearer, jsonPost } = require('./helpers');

const unhandled = [];
const onUnhandled = (e) => unhandled.push(e);
process.on('unhandledRejection', onUnhandled);
process.on('uncaughtException', onUnhandled);
test.after(() => {
  process.off('unhandledRejection', onUnhandled);
  process.off('uncaughtException', onUnhandled);
  assert.deepEqual(unhandled.map(String), [], 'no unhandled rejections / exceptions during chaos');
});

const admin = sign(claims({ sub: 'jean', roles: ['admin'] }));
const tech = sign(claims({ sub: 'tech1', roles: ['technician'] }));
const healthy = async (port) => {
  assert.equal((await raw(port, { path: '/health' })).status, 200);
  assert.equal((await raw(port, { path: '/proxy/x', headers: bearer(tech) })).status, 200);
};

// ---------- audit sink faults ----------
test('chaos: an audit sink failing every 3rd write under 200 concurrent requests', async (t) => {
  let n = 0; let reported = 0;
  const audit = createAuditLogger({ sink: () => { if (++n % 3 === 0) throw new Error('EIO'); }, onSinkError: () => { reported++; } });
  const s = await startServer({ audit }); t.after(() => s.close());
  const res = await Promise.all(Array.from({ length: 200 }, (_, i) => (i % 2
    ? raw(s.port, { path: '/proxy/y', headers: bearer(tech) })
    : raw(s.port, { path: '/admin/audit', headers: bearer(tech) }))));
  for (const [i, r] of res.entries()) assert.equal(r.status, i % 2 ? 200 : 403);
  assert.equal(audit.stats().sinkErrors, reported);
  assert.ok(reported > 0);
  await healthy(s.port);
});

test('chaos: sinks throwing non-Errors (string, undefined, null, objects with throwing getters)', async (t) => {
  const evil = { get message() { throw new Error('getter'); } };
  for (const thrown of ['boom', undefined, null, 42, evil]) {
    const audit = createAuditLogger({ sink: () => { throw thrown; }, onSinkError: () => { throw thrown; } });
    const s = await startServer({ audit });
    const r = await raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, { patch: { enabled: false }, reason: 'sink chaos' }) });
    assert.equal(r.status, 201, String(thrown));
    await s.close();
  }
  assert.ok(t);
});

test('chaos: a slow (synchronously blocking) sink delays but never breaks responses', async (t) => {
  const audit = createAuditLogger({ sink: () => { const end = Date.now() + 3; while (Date.now() < end); } });
  const s = await startServer({ audit }); t.after(() => s.close());
  const res = await Promise.all(Array.from({ length: 30 }, () => raw(s.port, { path: '/proxy/z', headers: bearer(tech) })));
  assert.ok(res.every((r) => r.status === 200));
});

// ---------- clock faults ----------
test('chaos: clocks that throw, return NaN/strings/BigInt/promises, or jump wildly -> 401, never 500 or a pass', async (t) => {
  const clocks = [() => { throw new Error('rtc'); }, () => NaN, () => '1800000000000', () => 1n, () => Promise.resolve(Date.now()),
    () => Infinity, () => -Infinity, () => undefined, () => null, () => ({ valueOf: () => Date.now() })];
  for (const now of clocks) {
    const s = await startServer({ provider: createAvroneProvider({ ...config, now }) });
    const r = await raw(s.port, { path: '/admin/audit', headers: bearer(admin) });
    assert.ok(r.status === 401 || (r.status === 200 && typeof now() === 'number'), `clock ${now}: ${r.status}`);
    assert.notEqual(r.status, 500);
    await s.close();
  }
  let flip = 0;
  const jumpy = createAvroneProvider({ ...config, now: () => (++flip % 2 ? Date.now() : Date.now() + 10 * 365 * 86400e3) });
  const s = await startServer({ provider: jumpy }); t.after(() => s.close());
  const st = [];
  for (let i = 0; i < 6; i++) st.push((await raw(s.port, { path: '/admin/audit', headers: bearer(admin) })).status);
  assert.deepEqual(st, [200, 401, 200, 401, 200, 401]);
});

// ---------- provider faults (pluggable providers, e.g. a future JWKS provider) ----------
const fakeProvider = (verify) => ({ name: 'chaos', verify });
test('chaos: provider throwing non-AuthErrors or rejecting with junk -> 401, no internals leaked', async () => {
  for (const verify of [async () => { throw new TypeError('secret-internal-detail'); }, async () => { throw 'str'; }, () => Promise.reject(null), () => { throw new RangeError('x'); }]) {
    const s = await startServer({ provider: fakeProvider(verify) });
    const r = await raw(s.port, { path: '/admin/audit', headers: bearer(admin) });
    assert.equal(r.status, 401);
    assert.ok(!r.text.includes('secret-internal-detail'));
    await s.close();
  }
});

test('chaos: provider resolving malformed claims (null, array, missing/blank/non-string sub) is never treated as authenticated', async () => {
  const bad = [null, undefined, [], 'claims', 7, {}, { roles: ['admin'] }, { sub: '', roles: ['admin'] }, { sub: 7, roles: ['admin'] },
    { sub: ['jean'], roles: ['admin'] }, { sub: { toString: () => 'jean' }, roles: ['admin'] }];
  for (const c of bad) {
    const s = await startServer({ provider: fakeProvider(async () => c) });
    const r = await raw(s.port, { path: '/admin/audit', headers: bearer(admin) });
    assert.equal(r.status, 401, `claims ${JSON.stringify(c)} -> ${r.status}`);
    await s.close();
  }
});

test('chaos: a provider that never settles is cut off (503 auth_unavailable), the socket is not held forever', async (t) => {
  const s = await startServer({ provider: fakeProvider(() => new Promise(() => {})), app: { authTimeoutMs: 200 } });
  t.after(() => s.close());
  const t0 = Date.now();
  const r = await raw(s.port, { path: '/admin/audit', headers: bearer(admin) });
  assert.equal(r.status, 503);
  assert.equal(r.json.error, 'auth_unavailable');
  assert.ok(Date.now() - t0 < 2000);
  assert.equal((await raw(s.port, { path: '/health' })).status, 200);
});

test('chaos: a slow-but-successful provider within the timeout still authenticates', async (t) => {
  const real = createAvroneProvider(config);
  const slow = fakeProvider(async (tk) => { await new Promise((r) => setTimeout(r, 50)); return real.verify(tk); });
  const s = await startServer({ provider: slow, app: { authTimeoutMs: 1000 } }); t.after(() => s.close());
  assert.equal((await raw(s.port, { path: '/admin/audit', headers: bearer(admin) })).status, 200);
});

// ---------- store faults ----------
test('chaos: store methods throwing unexpected errors -> 500 with only a requestId, then recovery', async (t) => {
  const store = new DatasetStore();
  const s = await startServer({ app: { store } }); t.after(() => s.close());
  const orig = store.all.bind(store);
  store.all = () => { throw new Error('disk on fire /etc/secret-path'); };
  const r = await raw(s.port, { path: '/datasets', headers: bearer(tech) });
  assert.equal(r.status, 500);
  assert.deepEqual(Object.keys(r.json).sort(), ['error', 'requestId']);
  assert.ok(!r.text.includes('secret-path'));
  store.all = orig;
  assert.equal((await raw(s.port, { path: '/datasets', headers: bearer(tech) })).status, 200);
});

// ---------- partial requests and resets ----------
function connect(port) {
  return new Promise((resolve) => { const sock = net.connect(port, '127.0.0.1', () => resolve(sock)); sock.on('error', () => {}); });
}
test('chaos: clients vanishing mid-headers, mid-body, right after the body, and with RST', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const body = JSON.stringify({ patch: { metadata: { k: 'v' } }, reason: 'reset chaos' });
  const head = `POST /admin/datasets/Z/overrides HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n`;
  const scripts = [
    (k) => { k.write(head.slice(0, 30)); k.end(); },
    (k) => { k.write(head.slice(0, 60)); k.destroy(); },
    (k) => { k.write(head + body.slice(0, 5)); k.end(); },
    (k) => { k.write(head + body.slice(0, 5)); k.resetAndDestroy(); },
    (k) => { k.write(head + body); k.resetAndDestroy(); },
  ];
  for (let round = 0; round < 4; round++) {
    for (const script of scripts) { const k = await connect(s.port); script(k); }
    await new Promise((r) => setTimeout(r, 30));
  }
  await new Promise((r) => setTimeout(r, 100));
  await healthy(s.port);
  const hist = s.app.store.listOverrides('Z');
  assert.ok(hist.length <= 4, 'only fully-sent bodies can have been applied');
  for (const h of hist) assert.equal(h.reason, 'reset chaos');
});

test('chaos: socket reset as soon as the first response byte arrives (large audit export)', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  for (let i = 0; i < 200; i++) await raw(s.port, { path: '/proxy/x', headers: bearer(tech) });
  for (let i = 0; i < 25; i++) {
    const k = await connect(s.port);
    k.write(`GET /admin/audit HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\n\r\n`);
    await new Promise((r) => k.once('data', r));
    k.resetAndDestroy();
  }
  await new Promise((r) => setTimeout(r, 50));
  await healthy(s.port);
  assert.equal((await raw(s.port, { path: '/admin/audit', headers: bearer(admin) })).json.length, 200);
});

test('chaos: 100 parallel connections reset at random points never wedge the server', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const payload = `GET /proxy/y HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${tech}\r\n\r\n`;
  await Promise.all(Array.from({ length: 100 }, async (_, i) => {
    const k = await connect(s.port);
    k.write(payload.slice(0, (i * 7) % payload.length));
    setTimeout(() => (i % 2 ? k.resetAndDestroy() : k.destroy()), i % 5);
  }));
  await new Promise((r) => setTimeout(r, 100));
  await healthy(s.port);
});
