'use strict';
// Resource exhaustion: concurrency, connection caps, slowloris, header limits, growth bounds.
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const { DatasetStore } = require('../src/datasets/store');
const { createAuditLogger } = require('../src/access/audit');
const { SERVER_DEFAULTS, MAX_HEADERS } = require('../src/server');
const { sign, claims, startServer, raw, bearer, jsonPost } = require('./helpers');

const admin = sign(claims({ roles: ['admin'] }));
const tech = sign(claims({ roles: ['technician'] }));

function rawSocket(port, payload, { waitMs = 3000 } = {}) {
  return new Promise((resolve) => {
    const sock = net.connect(port, '127.0.0.1', () => payload && sock.write(payload));
    let data = ''; const t0 = Date.now();
    const done = (why) => { clearTimeout(timer); sock.destroy(); resolve({ data, why, ms: Date.now() - t0, status: Number((data.match(/^HTTP\/1\.1 (\d{3})/) || [])[1]) || null }); };
    sock.on('data', (d) => { data += d; });
    sock.on('end', () => done('end'));
    sock.on('close', () => done('close'));
    sock.on('error', () => done('error'));
    const timer = setTimeout(() => done('timeout'), waitMs);
    resolve.sock = sock;
  });
}

test('defaults are sane and documented', () => {
  assert.ok(SERVER_DEFAULTS.requestTimeout <= 30000);
  assert.ok(SERVER_DEFAULTS.headersTimeout <= SERVER_DEFAULTS.requestTimeout);
  assert.ok(SERVER_DEFAULTS.maxConnections >= 64 && SERVER_DEFAULTS.maxConnections <= 65535);
  assert.equal(SERVER_DEFAULTS.maxHeaderSize, 16384);
  assert.equal(MAX_HEADERS, 100);
});

test('300 concurrent authenticated requests all succeed with correct, isolated responses', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const tokens = Array.from({ length: 300 }, (_, i) => sign(claims({ sub: `u${i}`, roles: ['technician'] })));
  const rs = await Promise.all(tokens.map((tk, i) => raw(s.port, { path: `/proxy/${'xyz'[i % 3]}`, headers: bearer(tk) })));
  rs.forEach((r, i) => { assert.equal(r.status, 200); assert.equal(r.json.principal, `u${i}`); });
});

test('mixed concurrent load (reads, writes, failures) never yields a 5xx', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const reqs = [];
  for (let i = 0; i < 200; i++) {
    const k = i % 5;
    if (k === 0) reqs.push(raw(s.port, { path: '/datasets', headers: bearer(tech) }));
    if (k === 1) reqs.push(raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, { patch: { rateLimitPerMinute: (i % 100) + 1 }, reason: `load ${i}` }) }));
    if (k === 2) reqs.push(raw(s.port, { path: '/admin/audit', headers: bearer('junk') }));
    if (k === 3) reqs.push(raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, '{bad') }));
    if (k === 4) reqs.push(raw(s.port, { path: '/nope' }));
  }
  const rs = await Promise.all(reqs);
  assert.ok(rs.every((r) => r.status < 500), [...new Set(rs.map((r) => r.status))].join());
});

test('maxConnections cap: connections beyond the cap are refused; capacity frees up when idle ones close', async (t) => {
  const s = await startServer({ serverOptions: { maxConnections: 5 } }); t.after(() => s.close());
  const idle = [];
  for (let i = 0; i < 5; i++) { const so = net.connect(s.port, '127.0.0.1'); await new Promise((r) => so.on('connect', r)); idle.push(so); }
  await new Promise((r) => setTimeout(r, 50));
  const over = await rawSocket(s.port, 'GET /health HTTP/1.1\r\nHost: x\r\n\r\n', { waitMs: 1000 });
  assert.equal(over.status, null, 'over-cap connection should be dropped without a response');
  idle.forEach((so) => so.destroy());
  await new Promise((r) => setTimeout(r, 100));
  assert.equal((await raw(s.port, { path: '/health' })).status, 200);
});

test('slowloris (headers): never-finished headers are cut off by headersTimeout', async (t) => {
  const s = await startServer({ serverOptions: { headersTimeout: 300, requestTimeout: 600, connectionsCheckingInterval: 50 } }); t.after(() => s.close());
  const sock = net.connect(s.port, '127.0.0.1');
  await new Promise((r) => sock.on('connect', r));
  let closedAt = null; let data = '';
  sock.on('data', (d) => { data += d; });
  const t0 = Date.now();
  const iv = setInterval(() => { try { sock.write('X-Slow: 1\r\n'); } catch { /* closed */ } }, 50);
  sock.write('GET /health HTTP/1.1\r\nHost: x\r\n');
  await new Promise((r) => { sock.on('close', () => { closedAt = Date.now(); r(); }); setTimeout(r, 3000); });
  clearInterval(iv); sock.destroy();
  assert.ok(closedAt, 'server never closed the slow-headers connection');
  assert.ok(closedAt - t0 < 2000, `took ${closedAt - t0}ms`);
  assert.ok(data === '' || /^HTTP\/1\.1 408/.test(data));
});

test('slowloris (body): a dribbled body is cut off by requestTimeout with 408', async (t) => {
  const s = await startServer({ serverOptions: { headersTimeout: 300, requestTimeout: 500, connectionsCheckingInterval: 50 } }); t.after(() => s.close());
  const sock = net.connect(s.port, '127.0.0.1');
  await new Promise((r) => sock.on('connect', r));
  let data = ''; let closed = false;
  sock.on('data', (d) => { data += d; });
  sock.on('close', () => { closed = true; });
  sock.on('error', () => {});
  sock.write(`POST /admin/datasets/X/overrides HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\nContent-Type: application/json\r\nContent-Length: 5000\r\n\r\n`);
  const t0 = Date.now();
  const iv = setInterval(() => { if (!closed) sock.write(' '); }, 40);
  await new Promise((r) => { const w = setInterval(() => { if (closed || data || Date.now() - t0 > 3000) { clearInterval(w); r(); } }, 20); });
  clearInterval(iv); sock.destroy();
  assert.ok(Date.now() - t0 < 2500);
  assert.match(data, /^HTTP\/1\.1 408/);
});

test('huge single header (> 16 KiB) -> 431', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await rawSocket(s.port, `GET /health HTTP/1.1\r\nHost: x\r\nX-Big: ${'a'.repeat(20000)}\r\n\r\n`);
  assert.equal(r.status, 431);
});
test('huge Authorization header (> 16 KiB) -> 431 (never reaches token parsing)', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await rawSocket(s.port, `GET /datasets HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${'a'.repeat(20000)}\r\n\r\n`);
  assert.equal(r.status, 431);
});
test('Authorization just under the header limit but over the 8 KiB token cap -> 401', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { path: '/datasets', headers: { authorization: `Bearer ${'a'.repeat(9000)}` } });
  assert.equal(r.status, 401);
});
test('header count: 90 headers OK, >= 100 -> 431', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const mk = (n) => { const h = { ...bearer(tech) }; for (let i = 0; i < n; i++) h[`x-h${i}`] = '1'; return h; };
  assert.equal((await raw(s.port, { path: '/proxy/x', headers: mk(90) })).status, 200);
  assert.equal((await raw(s.port, { path: '/proxy/x', headers: mk(98) })).status, 431);
  assert.equal((await raw(s.port, { path: '/proxy/x', headers: mk(500) })).status, 431);
});
test('endless streamed body: 413 then connection closed once past the drain cap; server stays healthy', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const sock = net.connect(s.port, '127.0.0.1');
  await new Promise((r) => sock.on('connect', r));
  let data = ''; let closed = false;
  sock.on('data', (d) => { data += d; });
  sock.on('close', () => { closed = true; });
  sock.on('error', () => {});
  sock.write(`POST /admin/datasets/X/overrides HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\n\r\n`);
  const chunk = 'x'.repeat(64 * 1024);
  let sent = 0;
  while (!closed && !data && sent < 8 * 1024 * 1024) {
    const ok = sock.write(`${chunk.length.toString(16)}\r\n${chunk}\r\n`);
    sent += chunk.length;
    // yield to the event loop like a real client so responses can be read while uploading
    await new Promise((r) => (ok ? setImmediate(r) : (sock.once('drain', r), setTimeout(r, 100))));
  }
  await new Promise((r) => { const w = setInterval(() => { if (closed) { clearInterval(w); r(); } }, 20); setTimeout(() => { clearInterval(w); r(); }, 2500); });
  sock.destroy();
  assert.match(data, /^HTTP\/1\.1 413/);
  assert.ok(closed, 'server did not close the connection');
  assert.ok(sent < 8 * 1024 * 1024, 'server kept reading an endless body');
  assert.equal((await raw(s.port, { path: '/health' })).status, 200);
});

test('audit log growth is bounded (in-memory ring buffer) and the API returns at most 200', async (t) => {
  const lines = [];
  const audit = createAuditLogger({ sink: (l) => lines.push(l), maxEntries: 50 });
  const s = await startServer({ audit }); t.after(() => s.close());
  for (let i = 0; i < 120; i++) await raw(s.port, { path: '/datasets', headers: bearer(i % 2 ? tech : 'junk') });
  assert.equal(audit.recent(10000).length, 50);
  const r = await raw(s.port, { path: '/admin/audit', headers: bearer(admin) });
  assert.ok(r.json.length <= 50);
  assert.ok(lines.length >= 120, 'sink still receives every event (persistence is the sink\'s job)');
  const big = createAuditLogger({ sink: () => {} });
  for (let i = 0; i < 5000; i++) big.log({ type: 'x', i });
  assert.equal(big.recent(100000).length, 1000);
});
test('audit entry size is bounded: path truncated to 512 chars', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  await raw(s.port, { path: `/datasets/${'a'.repeat(5000)}` });
  await raw(s.port, { path: `/datasets/${'a'.repeat(5000)}`, headers: bearer('junk') });
  for (const l of s.lines) assert.ok(JSON.parse(l).path.length <= 512);
});
test('audit logger rejects invalid caps', () => {
  for (const maxEntries of [0, -1, 1.5, NaN, Infinity]) assert.throws(() => createAuditLogger({ maxEntries }), /maxEntries/);
});

test('override history growth is bounded; compacted entries are no longer revertible; newest still are', async (t) => {
  const store = new DatasetStore(undefined, { maxHistory: 10 });
  const s = await startServer({ app: { store } }); t.after(() => s.close());
  const ids = [];
  for (let i = 0; i < 25; i++) {
    const r = await raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, { patch: { rateLimitPerMinute: i + 1 }, reason: `hist ${i}` }) });
    ids.push(r.json.id);
  }
  const list = (await raw(s.port, { path: '/admin/datasets/X/overrides', headers: bearer(admin) })).json;
  assert.equal(list.length, 10);
  assert.deepEqual(list.map((x) => x.id), ids.slice(-10));
  assert.equal((await raw(s.port, { method: 'POST', path: `/admin/overrides/${ids[0]}/revert`, headers: bearer(admin) })).status, 404);
  for (const id of ids.slice(-10).reverse()) {
    assert.equal((await raw(s.port, { method: 'POST', path: `/admin/overrides/${id}/revert`, headers: bearer(admin) })).status, 200);
  }
  // reverting all retained entries returns to the state before the oldest retained override
  assert.equal(store.get('X').rateLimitPerMinute, 15);
  assert.equal(store.compacted, 15);
});
test('history cap with many datasets: total across X/Y/Z is bounded', () => {
  const st = new DatasetStore(undefined, { maxHistory: 30 });
  for (let i = 0; i < 3000; i++) st.override('XYZ'[i % 3], { rateLimitPerMinute: (i % 50) + 1 }, { actor: 'a', reason: 'bulk' });
  assert.equal(st.listOverrides().length, 30);
  assert.equal(st.listOverrides('X').length, 10);
});
test('maxHistory must be a positive integer', () => {
  for (const maxHistory of [0, -1, 1.5, NaN, '10']) assert.throws(() => new DatasetStore(undefined, { maxHistory }), /maxHistory/);
});
test('maxHistory 1: only the latest override is revertible', () => {
  const st = new DatasetStore(undefined, { maxHistory: 1 });
  const a = st.override('X', { enabled: false }, { actor: 'a', reason: 'one' });
  const b = st.override('X', { enabled: true, rateLimitPerMinute: 5 }, { actor: 'a', reason: 'two' });
  assert.throws(() => st.revert(a.id, { actor: 'a' }), /Unknown override/);
  st.revert(b.id, { actor: 'a' });
  assert.equal(st.get('X').enabled, false);
});
