'use strict';
// Clients that disconnect while authentication (or the body read) is still running.
// R6-1: such requests used to leave the handler promise pending forever (readJson attached
// its listeners to an already-destroyed stream). Now they settle, are audited as
// request.aborted, and never reach a handler's side effects.
const test = require('node:test');
const assert = require('node:assert');
const http = require('http');
const net = require('net');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { createApp } = require('../src/server');
const { createAuditLogger } = require('../src/access/audit');
const { sign, claims, config, raw, bearer, jsonPost } = require('./helpers');

const real = createAvroneProvider(config);
const admin = sign(claims({ sub: 'jean', roles: ['admin'] }));
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function harness(delayMs = 150) {
  const slow = { name: 'slow', verify: async (t) => { await sleep(delayMs); return real.verify(t); } };
  const app = createApp({ provider: slow, authTimeoutMs: 5000, audit: createAuditLogger({ sink: () => {}, maxEntries: 10000 }) });
  const counts = { started: 0, settled: 0 };
  const srv = http.createServer((req, res) => { counts.started++; app.handle(req, res).finally(() => { counts.settled++; }); });
  await new Promise((r) => srv.listen(0, '127.0.0.1', r));
  return { app, counts, port: srv.address().port, close: () => new Promise((r) => { srv.close(r); srv.closeAllConnections(); }) };
}
function fire(port, payload, killAfterMs) {
  return new Promise((resolve) => {
    const k = net.connect(port, '127.0.0.1', () => { k.write(payload); setTimeout(() => { k.destroy(); resolve(); }, killAfterMs); });
    k.on('error', () => resolve());
  });
}
const post = (path, body) => `POST ${path} HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n`;

test('R6-1: disconnect mid-auth (full body, partial body, no body) -> every handler settles, nothing is applied', async (t) => {
  const h = await harness(); t.after(h.close);
  const body = JSON.stringify({ patch: { rateLimitPerMinute: 9 }, reason: 'gone mid auth' });
  await Promise.all([
    ...Array.from({ length: 10 }, () => fire(h.port, post('/admin/datasets/X/overrides', body) + body, 30)),
    ...Array.from({ length: 10 }, () => fire(h.port, post('/admin/datasets/Y/overrides', body) + body.slice(0, 7), 30)),
    ...Array.from({ length: 10 }, () => fire(h.port, post('/admin/datasets/Z/overrides', body), 30)),
    ...Array.from({ length: 10 }, () => fire(h.port, `GET /admin/audit HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\n\r\n`, 30)),
  ]);
  await sleep(400);
  assert.deepEqual(h.counts, { started: 40, settled: 40 });
  for (const id of ['X', 'Y', 'Z']) assert.equal(h.app.store.listOverrides(id).length, 0, id);
  const aborted = h.app.audit.recent(10000).filter((e) => e.type === 'request.aborted');
  assert.equal(aborted.length, 40);
  assert.ok(aborted.every((e) => e.actor === 'jean' && typeof e.requestId === 'string'));
});

test('R6-1: disconnect while the body is still being uploaded AFTER auth -> settles, nothing applied', async (t) => {
  const h = await harness(5); t.after(h.close);
  const body = JSON.stringify({ patch: { rateLimitPerMinute: 8 }, reason: 'slow upload' });
  await Promise.all(Array.from({ length: 10 }, () => fire(h.port, post('/admin/datasets/X/overrides', body) + body.slice(0, 5), 120)));
  await sleep(200);
  assert.deepEqual(h.counts, { started: 10, settled: 10 });
  assert.equal(h.app.store.listOverrides('X').length, 0);
  const log = h.app.audit.recent(10000);
  assert.equal(log.filter((e) => e.type === 'request.aborted').length, 10, 'mid-upload disconnects are audited as aborted');
  assert.equal(log.filter((e) => e.type === 'error').length, 0, 'and never as server errors');
});

test('R6-1: revert requests whose client vanished mid-auth do not revert', async (t) => {
  const h = await harness(100); t.after(h.close);
  const o = await raw(h.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, { patch: { enabled: false }, reason: 'keep me' }) });
  assert.equal(o.status, 201);
  await fire(h.port, `POST /admin/overrides/${o.json.id}/revert HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\nContent-Length: 0\r\n\r\n`, 20);
  await sleep(250);
  assert.equal(h.app.store.get('X').enabled, false, 'override still active');
  assert.equal((await raw(h.port, { method: 'POST', path: `/admin/overrides/${o.json.id}/revert`, headers: bearer(admin) })).status, 200);
});

test('R6-1: clients that stay connected are unaffected (control)', async (t) => {
  const h = await harness(50); t.after(h.close);
  const res = await Promise.all(Array.from({ length: 20 }, (_, i) => raw(h.port, { path: '/admin/datasets/Z/overrides', ...jsonPost(admin, { patch: { rateLimitPerMinute: 1 + i }, reason: `stay ${i}` }) })));
  assert.ok(res.every((r) => r.status === 201));
  assert.equal(h.app.store.listOverrides('Z').length, 20);
  assert.equal(h.app.audit.recent(10000).filter((e) => e.type === 'request.aborted').length, 0);
});
