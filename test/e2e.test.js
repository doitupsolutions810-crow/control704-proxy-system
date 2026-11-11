'use strict';
// End-to-end user journeys per role over a real socket. The proxy is started exactly as in
// production (startFromEnv) and tokens come from the reference Avrone issuer, so every layer
// (env config, HTTP parsing, auth, scopes, store, audit) is exercised together.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { startFromEnv } = require('../src/proxy');
const { mintAvroneToken } = require('../src/auth/issuer');
const { raw } = require('./helpers');

const ENV = { AVRONE_ISSUER: 'https://avrone-due-krey-chat.vercel.app', AVRONE_AUDIENCE: 'control704-proxy',
  AVRONE_JWT_SECRET: crypto.randomBytes(32).toString('hex'), AVRONE_MAX_TOKEN_AGE_SEC: '300', HOST: '127.0.0.1', PORT: '0' };
const tok = (sub, roles, extra = {}) => mintAvroneToken({ secret: ENV.AVRONE_JWT_SECRET, issuer: ENV.AVRONE_ISSUER, audience: ENV.AVRONE_AUDIENCE, sub, roles, ...extra }).token;

let inst; let port;
test.before(async () => { inst = await startFromEnv({ env: ENV }); port = inst.port; });
test.after(() => inst.close(500));

const req = (method, path, token, body) => raw(port, {
  method, path,
  headers: { ...(token ? { authorization: `Bearer ${token}` } : {}), ...(body !== undefined ? { 'content-type': 'application/json' } : {}) },
  body: body === undefined ? undefined : JSON.stringify(body),
});
const auditTypes = async (admin) => (await req('GET', '/admin/audit', admin)).json;

test('journey: anonymous caller sees only /health; everything else is 401 with a Bearer challenge', async () => {
  assert.equal((await req('GET', '/health')).status, 200);
  for (const [m, p] of [['GET', '/datasets'], ['GET', '/datasets/X'], ['GET', '/proxy/x'], ['GET', '/admin/audit'],
    ['POST', '/admin/datasets/X/overrides'], ['GET', '/admin/datasets/X/overrides']]) {
    const r = await req(m, p, undefined, m === 'POST' ? { patch: { enabled: false }, reason: 'anon try' } : undefined);
    assert.equal(r.status, 401, `${m} ${p}`);
    assert.match(r.headers['www-authenticate'], /^Bearer realm="control704"/);
  }
});

test('journey: viewer reads datasets and the proxy list, but cannot use X/Y/Z or any admin route', async () => {
  const v = tok('view1', ['viewer']);
  const all = await req('GET', '/datasets', v);
  assert.equal(all.status, 200);
  assert.deepEqual(Object.keys(all.json).sort(), ['X', 'Y', 'Z']);
  assert.equal((await req('GET', '/datasets/Y', v)).json.auth, 'dataset-code');
  for (const t of ['x', 'y', 'z']) assert.equal((await req('GET', `/proxy/${t}`, v)).status, 403, t);
  for (const [m, p] of [['GET', '/admin/audit'], ['GET', '/admin/datasets/X/overrides'], ['POST', '/admin/datasets/X/overrides']]) {
    const r = await req(m, p, v, m === 'POST' ? { patch: { enabled: false }, reason: 'viewer try' } : undefined);
    assert.equal(r.status, 403, `${m} ${p}`);
    assert.match(r.headers['www-authenticate'], /insufficient_scope/);
  }
});

test('journey: technician uses X, Y and Z (each with its own auth mode) but cannot override or read audit', async () => {
  const t = tok('tech1', ['technician']);
  const modes = {};
  for (const id of ['x', 'y', 'z', 'X']) {
    const r = await req('GET', `/proxy/${id}`, t);
    assert.equal(r.status, 200, id);
    assert.equal(r.json.dataset, id.toUpperCase());
    assert.equal(r.json.principal, 'tech1', 'principal is the token subject');
    modes[id.toLowerCase()] = r.json.profile.auth;
  }
  assert.deepEqual(modes, { x: 'token-override', y: 'dataset-code', z: 'lattice-op' });
  assert.equal((await req('POST', '/admin/datasets/Z/overrides', t, { patch: { enabled: false }, reason: 'tech try' })).status, 403);
  assert.equal((await req('GET', '/admin/audit', t)).status, 403);
});

test('journey: admin overrides X, the change is visible to a technician, audited, then reverted', async () => {
  const a = tok('jean', ['admin']);
  const t = tok('tech1', ['technician']);
  const before = (await req('GET', '/proxy/x', t)).json.profile;
  const ov = await req('POST', '/admin/datasets/X/overrides', a, { patch: { rateLimitPerMinute: 7, metadata: { ticket: 'C704-1' } }, reason: 'e2e maintenance' });
  assert.equal(ov.status, 201);
  assert.equal(ov.json.actor, 'jean');
  assert.equal((await req('GET', '/proxy/x', t)).json.profile.rateLimitPerMinute, 7);
  const hist = (await req('GET', '/admin/datasets/X/overrides', a)).json;
  assert.ok(hist.some((h) => h.id === ov.json.id && h.reason === 'e2e maintenance'));
  const rv = await req('POST', `/admin/overrides/${ov.json.id}/revert`, a);
  assert.equal(rv.status, 200);
  assert.deepEqual((await req('GET', '/proxy/x', t)).json.profile, before);
  const log = await auditTypes(a);
  const mine = log.filter((e) => e.actor === 'jean');
  assert.ok(mine.some((e) => e.type === 'dataset.override'));
  assert.ok(mine.some((e) => e.type === 'dataset.revert'));
  assert.ok(log.some((e) => e.type === 'authz.denied' && e.actor === 'tech1'), 'the technician\'s earlier denial was audited');
  assert.ok(!JSON.stringify(log).includes(a) && !JSON.stringify(log).includes(ENV.AVRONE_JWT_SECRET), 'no tokens or secrets in audit');
});

test('journey: admin cannot touch auth, cannot collide endpoints, and LIFO revert is enforced', async () => {
  const a = tok('jean', ['admin']);
  assert.equal((await req('POST', '/admin/datasets/Y/overrides', a, { patch: { auth: 'none' }, reason: 'try auth' })).status, 400);
  assert.equal((await req('POST', '/admin/datasets/Y/overrides', a, { patch: { endpoint: '/proxy/x' }, reason: 'collide' })).status, 400);
  const o1 = (await req('POST', '/admin/datasets/Y/overrides', a, { patch: { enabled: false }, reason: 'first one' })).json;
  const o2 = (await req('POST', '/admin/datasets/Y/overrides', a, { patch: { rateLimitPerMinute: 5 }, reason: 'second one' })).json;
  assert.equal((await req('POST', `/admin/overrides/${o1.id}/revert`, a)).status, 400, 'older revert refused');
  assert.equal((await req('POST', `/admin/overrides/${o2.id}/revert`, a)).status, 200);
  assert.equal((await req('POST', `/admin/overrides/${o1.id}/revert`, a)).status, 200);
  assert.equal((await req('POST', `/admin/overrides/${o1.id}/revert`, a)).status, 400, 'double revert refused');
  assert.equal((await req('GET', '/datasets/Y', a)).json.enabled, true);
});

test('journey: multi-role token gets the union of scopes; a token with no roles can only see /health', async () => {
  const both = tok('dual', ['viewer', 'technician']);
  assert.equal((await req('GET', '/proxy/z', both)).status, 200);
  assert.equal((await req('GET', '/admin/audit', both)).status, 403);
  const none = tok('nobody', []);
  assert.equal((await req('GET', '/datasets', none)).status, 403);
  assert.equal((await req('GET', '/health', none)).status, 200);
});

test('journey: tokens fail for expiry, wrong secret, wrong audience and age beyond AVRONE_MAX_TOKEN_AGE_SEC', async () => {
  const past = Date.now() - 400_000;
  const cases = {
    expired: tok('jean', ['admin'], { now: past, ttlSec: 60 }),
    tooOld: tok('jean', ['admin'], { now: Date.now() - 340_000, ttlSec: 300 }),
    wrongSecret: mintAvroneToken({ secret: crypto.randomBytes(32).toString('hex'), issuer: ENV.AVRONE_ISSUER, audience: ENV.AVRONE_AUDIENCE, sub: 'jean', roles: ['admin'] }).token,
    wrongAud: mintAvroneToken({ secret: ENV.AVRONE_JWT_SECRET, issuer: ENV.AVRONE_ISSUER, audience: 'something-else', sub: 'jean', roles: ['admin'] }).token,
  };
  for (const [name, t] of Object.entries(cases)) {
    const r = await req('GET', '/admin/audit', t);
    assert.equal(r.status, 401, name);
    assert.ok(!JSON.stringify(r.json).includes(t), `${name}: token not echoed`);
  }
});

test('journey: one keep-alive connection serving admin then anonymous requests never leaks identity', async () => {
  const net = require('net');
  const a = tok('jean', ['admin']);
  const sock = net.connect(port, '127.0.0.1');
  await new Promise((r) => sock.on('connect', r));
  let data = '';
  sock.on('data', (d) => { data += d; });
  sock.write(`GET /admin/audit HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${a}\r\n\r\nGET /admin/audit HTTP/1.1\r\nHost: x\r\n\r\nGET /datasets HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
  await new Promise((r) => sock.on('close', r));
  const statuses = [...data.matchAll(/HTTP\/1\.1 (\d{3}) /g)].map((m) => Number(m[1]));
  assert.deepEqual(statuses, [200, 401, 401]);
});
