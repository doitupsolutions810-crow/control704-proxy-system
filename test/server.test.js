'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { createApp } = require('../src/server');
const { createAuditLogger } = require('../src/access/audit');
const Control704Proxy = require('../src/proxy');
const { sign, claims, config } = require('./helpers');

function setup() {
  const lines = [];
  const app = createApp({ provider: createAvroneProvider(config), audit: createAuditLogger({ sink: (l) => lines.push(l) }) });
  const server = app.server();
  return new Promise((resolve) => server.listen(0, '127.0.0.1', () => {
    const base = `http://127.0.0.1:${server.address().port}`;
    resolve({ app, server, base, lines });
  }));
}

const tok = (extra) => sign(claims(extra));
const auth = (t) => ({ authorization: `Bearer ${t}` });
const json = (t, body) => ({ method: 'POST', headers: { ...auth(t), 'content-type': 'application/json' }, body: JSON.stringify(body) });

test('HTTP auth and access', async (t) => {
  const { server, base, lines } = await setup();
  t.after(() => server.close());

  await t.test('health is public', async () => {
    assert.equal((await fetch(`${base}/health`)).status, 200);
  });

  await t.test('401 without or with bad token, with WWW-Authenticate', async () => {
    const r = await fetch(`${base}/proxy/x`);
    assert.equal(r.status, 401);
    assert.match(r.headers.get('www-authenticate'), /Bearer/);
    assert.equal((await fetch(`${base}/proxy/x`, { headers: auth('a.b.c') })).status, 401);
  });

  await t.test('old VIP-type bypass is gone', async () => {
    const r = await fetch(`${base}/proxy/x`, { headers: { authorization: 'VIP' } });
    assert.equal(r.status, 401);
  });

  await t.test('viewer gets 403 on proxy X, technician gets 200', async () => {
    assert.equal((await fetch(`${base}/proxy/x`, { headers: auth(tok({ roles: ['viewer'] })) })).status, 403);
    const r = await fetch(`${base}/proxy/x`, { headers: auth(tok({ roles: ['technician'] })) });
    assert.equal(r.status, 200);
    assert.equal((await r.json()).profile.endpoint, '/proxy/x');
  });

  await t.test('direct scopes work (scope string)', async () => {
    const r = await fetch(`${base}/proxy/y`, { headers: auth(tok({ scope: 'proxy:read proxy:y' })) });
    assert.equal(r.status, 200);
  });

  await t.test('technician cannot override (403)', async () => {
    const r = await fetch(`${base}/admin/datasets/X/overrides`, json(tok({ roles: ['technician'] }), { patch: { enabled: false }, reason: 'test' }));
    assert.equal(r.status, 403);
  });

  await t.test('admin override -> applied -> revert', async () => {
    const admin = tok({ sub: 'admin-1', roles: ['admin'] });
    let r = await fetch(`${base}/admin/datasets/x/overrides`, json(admin, { patch: { rateLimitPerMinute: 5, enabled: false }, reason: 'maintenance window' }));
    assert.equal(r.status, 201);
    const rec = await r.json();
    assert.equal(rec.actor, 'admin-1');
    assert.equal(rec.before.rateLimitPerMinute, 60);

    r = await fetch(`${base}/proxy/x`, { headers: auth(tok({ roles: ['technician'] })) });
    assert.equal(r.status, 503);

    r = await fetch(`${base}/admin/datasets/X/overrides`, { headers: auth(admin) });
    assert.equal((await r.json()).length, 1);

    r = await fetch(`${base}/admin/overrides/${rec.id}/revert`, { method: 'POST', headers: auth(admin) });
    assert.equal(r.status, 200);
    r = await fetch(`${base}/datasets/X`, { headers: auth(admin) });
    const ds = await r.json();
    assert.equal(ds.enabled, true);
    assert.equal(ds.rateLimitPerMinute, 60);

    r = await fetch(`${base}/admin/overrides/${rec.id}/revert`, { method: 'POST', headers: auth(admin) });
    assert.equal(r.status, 400);
  });

  await t.test('override validation', async () => {
    const admin = tok({ roles: ['admin'] });
    const bad = [
      { patch: { auth: 'none' }, reason: 'try to change auth' },
      { patch: { endpoint: '/etc/passwd' }, reason: 'bad endpoint' },
      { patch: { endpoint: '/proxy/y' }, reason: 'clash with Y' },
      { patch: { upstream: 'ftp://x' }, reason: 'bad scheme' },
      { patch: { upstream: 'https://u:p@host' }, reason: 'creds in url' },
      { patch: { rateLimitPerMinute: 0 }, reason: 'too low' },
      { patch: {}, reason: 'empty' },
      { patch: { enabled: false } },
    ];
    for (const body of bad) {
      const r = await fetch(`${base}/admin/datasets/X/overrides`, json(admin, body));
      assert.equal(r.status, 400, JSON.stringify(body));
    }
    const r = await fetch(`${base}/admin/datasets/Q/overrides`, json(admin, { patch: { enabled: false }, reason: 'unknown ds' }));
    assert.equal(r.status, 404);
  });

  await t.test('audit log records requests and never contains tokens', async () => {
    const admin = tok({ roles: ['admin'] });
    const r = await fetch(`${base}/admin/audit`, { headers: auth(admin) });
    assert.equal(r.status, 200);
    const entries = await r.json();
    assert.ok(entries.some((e) => e.type === 'auth.failure'));
    assert.ok(entries.some((e) => e.type === 'authz.denied'));
    assert.ok(entries.some((e) => e.type === 'dataset.override'));
    assert.ok(entries.some((e) => e.type === 'dataset.revert'));
    const all = lines.join('\n');
    assert.ok(!all.includes(admin.split('.')[2]));
    assert.ok(!/eyJ/.test(all));
  });
});

test('store: only latest override can be reverted', () => {
  const { DatasetStore } = require('../src/datasets/store');
  const s = new DatasetStore();
  const a = s.override('Y', { rateLimitPerMinute: 10 }, { actor: 'a', reason: 'first' });
  const b = s.override('Y', { rateLimitPerMinute: 20 }, { actor: 'a', reason: 'second' });
  assert.throws(() => s.revert(a.id, { actor: 'a' }), /Revert newer/);
  s.revert(b.id, { actor: 'a' });
  assert.equal(s.get('Y').rateLimitPerMinute, 10);
  s.revert(a.id, { actor: 'a' });
  assert.equal(s.get('Y').rateLimitPerMinute, 60);
});

test('Control704Proxy class API requires signed tokens', async () => {
  const proxy = new Control704Proxy({ provider: createAvroneProvider(config) });
  assert.equal((await proxy.authenticate('VIP')).granted, false);
  assert.equal((await proxy.authenticate(tok({ roles: ['viewer'] }), 'Z')).granted, false);
  const ok = await proxy.authenticate(tok({ roles: ['technician'] }), 'Z');
  assert.equal(ok.granted, true);
  assert.equal(ok.proxy.endpoint, '/proxy/z');
  await assert.rejects(proxy.overrideDataSet(tok({ roles: ['technician'] }), 'Z', { enabled: false }, 'nope'), /Forbidden/);
  const rec = await proxy.overrideDataSet(tok({ roles: ['admin'] }), 'Z', { enabled: false }, 'maintenance');
  assert.equal(rec.after.enabled, false);
});
