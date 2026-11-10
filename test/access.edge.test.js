'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { ROLE_SCOPES, effectiveScopes, hasScopes } = require('../src/access/authorize');
const { toPrincipal, extractBearer, createAuthenticator } = require('../src/auth');
const { createAuditLogger } = require('../src/access/audit');
const { sign, claims, startServer, raw, bearer, jsonPost } = require('./helpers');

const P = (c) => toPrincipal({ sub: 's', ...c }, 'test');

// ---------- unit: role/scope resolution ----------
test('role table is frozen and admin is a superset of technician which is a superset of viewer', () => {
  assert.ok(Object.isFrozen(ROLE_SCOPES));
  for (const s of ROLE_SCOPES.viewer) assert.ok(ROLE_SCOPES.technician.includes(s));
  for (const s of ROLE_SCOPES.technician) assert.ok(ROLE_SCOPES.admin.includes(s));
});
test('no roles, no scopes => nothing', () => assert.equal(effectiveScopes(P({})).size, 0));
test('unknown roles grant nothing', () => {
  for (const r of ['root', 'superadmin', 'Admin', 'ADMIN', ' admin', 'admin ', 'admin\u0000', 'аdmin' /* cyrillic a */, '*', '']) {
    assert.equal(effectiveScopes(P({ roles: [r] })).size, 0, r);
  }
});
for (const r of ['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty', 'valueOf', '__defineGetter__']) {
  test(`prototype-pollution role "${r}" grants nothing and does not throw (500 before fix)`, () => {
    assert.doesNotThrow(() => effectiveScopes(P({ roles: [r] })));
    assert.equal(effectiveScopes(P({ roles: [r] })).size, 0);
    assert.equal(hasScopes(P({ roles: [r, 'viewer'] }), ['proxy:read']), true);
  });
}
test('roles of non-string types are ignored', () => {
  assert.equal(effectiveScopes(P({ roles: [1, null, {}, ['admin'], true] })).size, 0);
});
test('roles not an array (string "admin") is ignored', () => {
  assert.equal(effectiveScopes(P({ roles: 'admin' })).size, 0);
  assert.equal(effectiveScopes(P({ roles: { admin: true } })).size, 0);
});
test('scope string is split on any whitespace; empty pieces dropped', () => {
  const p = P({ scope: '  proxy:read\tproxy:x\n\nproxy:y  ' });
  assert.deepEqual([...p.scopes].sort(), ['proxy:read', 'proxy:x', 'proxy:y']);
});
test('scope matching is case-sensitive', () => {
  assert.equal(hasScopes(P({ scope: 'PROXY:READ proxy:X' }), ['proxy:read']), false);
  assert.equal(hasScopes(P({ scope: 'proxy:read proxy:X' }), ['proxy:read', 'proxy:x']), false);
});
test('scope escalation attempts: wildcards / prefixes / comma lists grant nothing extra', () => {
  for (const scope of ['*', 'datasets:*', 'datasets', 'datasets:override,datasets:revert', 'datasets:override:', ':override', 'datasets:overrides']) {
    assert.equal(hasScopes(P({ scope }), ['datasets:override']), false, scope);
  }
});
test('scp array honoured; non-string entries ignored', () => {
  const p = P({ scp: ['proxy:read', 7, null, { s: 1 }, 'proxy:z'] });
  assert.deepEqual([...p.scopes].sort(), ['proxy:read', 'proxy:z']);
});
test('scope as non-string / scp as non-array ignored', () => {
  assert.equal(P({ scope: ['datasets:override'], scp: 'datasets:override' }).scopes.size, 0);
});
test('role + scope combine (union)', () => {
  const p = P({ roles: ['viewer'], scope: 'proxy:x' });
  assert.ok(hasScopes(p, ['proxy:read', 'proxy:x']));
  assert.ok(!hasScopes(p, ['proxy:y']));
});
test('direct scope grants admin capability without admin role (documented behaviour)', () => {
  assert.ok(hasScopes(P({ scope: 'datasets:override' }), ['datasets:override']));
});
test('hasScopes with empty requirement is true; requires ALL listed', () => {
  assert.ok(hasScopes(P({}), []));
  assert.ok(!hasScopes(P({ roles: ['viewer'] }), ['proxy:read', 'proxy:x']));
});
test('duplicate roles are deduplicated', () => assert.deepEqual(P({ roles: ['viewer', 'viewer'] }).roles, ['viewer']));
test('custom role table: own-property lookup only', () => {
  const table = Object.create({ inherited: ['datasets:override'] });
  table.ops = ['proxy:x'];
  assert.ok(hasScopes(P({ roles: ['ops'] }), ['proxy:x'], table));
  assert.ok(!hasScopes(P({ roles: ['inherited'] }), ['datasets:override'], table));
  assert.ok(!hasScopes(P({ roles: ['bad'] }), ['x'], { bad: 'x' }));
});

// ---------- unit: bearer extraction ----------
const req = (authorization, rawHeaders) => ({ headers: authorization === undefined ? {} : { authorization }, rawHeaders });
test('extractBearer: valid forms', () => {
  assert.equal(extractBearer(req('Bearer abc.def.ghi')), 'abc.def.ghi');
  assert.equal(extractBearer(req('bearer abc')), 'abc');
  assert.equal(extractBearer(req('BEARER abc')), 'abc');
  assert.equal(extractBearer(req('  Bearer abc  ')), 'abc');
});
for (const h of ['', 'Bearer', 'Bearer ', 'Bearer  abc', 'Bearer\tabc', 'Basic YWRtaW46YWRtaW4=', 'Token abc', 'Bearerabc', 'Bearer a b', 'Bearer abc,Bearer def', 'Bearer "abc"', 'Bearer ab\u0000c', 'Bearer ä']) {
  test(`extractBearer rejects ${JSON.stringify(h)}`, () => assert.equal(extractBearer(req(h)), null));
}
test('extractBearer: missing header / non-string header => null', () => {
  assert.equal(extractBearer(req(undefined)), null);
  assert.equal(extractBearer({ headers: { authorization: ['Bearer a'] } }), null);
  assert.equal(extractBearer({}), null);
});
test('extractBearer: duplicate Authorization in rawHeaders throws invalid_request', () => {
  assert.throws(() => extractBearer(req('Bearer a', ['Authorization', 'Bearer a', 'authorization', 'Bearer b'])), (e) => e.code === 'invalid_request');
});
test('createAuthenticator requires a provider with verify()', () => {
  for (const p of [null, undefined, {}, { verify: 1 }]) assert.throws(() => createAuthenticator(p), /verify/);
});
test('pluggable provider: custom provider claims flow through', async () => {
  const a = createAuthenticator({ name: 'custom', verify: async (t) => ({ sub: `u-${t}`, roles: ['viewer'] }) });
  const p = await a.authenticate({ headers: { authorization: 'Bearer xyz' }, rawHeaders: ['Authorization', 'Bearer xyz'] });
  assert.equal(p.sub, 'u-xyz'); assert.equal(p.provider, 'custom');
});

// ---------- unit: audit logger ----------
test('audit logger strips token/authorization fields and caps entries', () => {
  const lines = [];
  const a = createAuditLogger({ sink: (l) => lines.push(l), maxEntries: 3 });
  a.log({ type: 't', token: 'SECRET1', authorization: 'Bearer SECRET2' });
  for (let i = 0; i < 5; i++) a.log({ type: `n${i}` });
  assert.ok(!lines.join().includes('SECRET'));
  assert.equal(a.recent().length, 3);
  assert.equal(a.recent(1)[0].type, 'n4');
  assert.match(a.recent(1)[0].ts, /^\d{4}-\d\d-\d\dT/);
});

// ---------- HTTP: access matrix ----------
test('HTTP access matrix and redaction', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const tok = (c) => sign(claims(c));
  const get = (path, token) => raw(s.port, { path, headers: token ? bearer(token) : {} });

  const matrix = [
    // [principal claims, path, expected status]
    [{ roles: ['viewer'] }, '/proxy/x', 403],
    [{ roles: ['viewer'] }, '/datasets', 200],
    [{ roles: ['viewer'] }, '/admin/audit', 403],
    [{ roles: ['technician'] }, '/proxy/x', 200],
    [{ roles: ['technician'] }, '/proxy/Y', 200],
    [{ roles: ['technician'] }, '/proxy/z', 200],
    [{ roles: ['technician'] }, '/admin/audit', 403],
    [{ roles: ['technician'] }, '/admin/datasets/X/overrides', 403],
    [{ roles: ['admin'] }, '/admin/audit', 200],
    [{ roles: ['admin'] }, '/admin/datasets/X/overrides', 200],
    [{ scope: 'proxy:x' }, '/proxy/x', 403], // missing proxy:read
    [{ scope: 'proxy:read' }, '/proxy/x', 403],
    [{ scope: 'proxy:read proxy:x' }, '/proxy/x', 200],
    [{ scope: 'proxy:read proxy:x' }, '/proxy/y', 403],
    [{ scope: 'audit:read' }, '/admin/audit', 200],
    [{ roles: ['__proto__'] }, '/proxy/x', 403],
    [{ roles: ['constructor'] }, '/datasets', 403],
    [{ roles: ['Admin'] }, '/admin/audit', 403],
    [{ roles: 'admin' }, '/admin/audit', 403],
    [{ scope: '*' }, '/admin/audit', 403],
    [{}, '/datasets', 403],
  ];
  for (const [c, path, status] of matrix) {
    await t.test(`${JSON.stringify(c)} GET ${path} -> ${status}`, async () => {
      const r = await get(path, tok(c));
      assert.equal(r.status, status, r.text);
      if (status === 403) {
        assert.equal(r.json.error, 'forbidden');
        assert.ok(Array.isArray(r.json.required));
        assert.match(r.headers['www-authenticate'], /insufficient_scope/);
      }
    });
  }

  await t.test('override POST matrix: only datasets:override may write', async () => {
    const body = { patch: { metadata: { k: 'v' } }, reason: 'matrix test' };
    for (const [c, status] of [[{ roles: ['viewer'] }, 403], [{ roles: ['technician'] }, 403], [{ scope: 'datasets:revert' }, 403], [{ scope: 'datasets:override' }, 201], [{ roles: ['admin'] }, 201]]) {
      const r = await raw(s.port, { path: '/admin/datasets/Y/overrides', ...jsonPost(tok(c), body) });
      assert.equal(r.status, status, JSON.stringify(c));
    }
  });

  await t.test('revert requires datasets:revert (override scope alone insufficient)', async () => {
    const r1 = await raw(s.port, { path: '/admin/datasets/Z/overrides', ...jsonPost(tok({ scope: 'datasets:override' }), { patch: { rateLimitPerMinute: 9 }, reason: 'need revert' }) });
    assert.equal(r1.status, 201);
    const r2 = await raw(s.port, { method: 'POST', path: `/admin/overrides/${r1.json.id}/revert`, headers: bearer(tok({ scope: 'datasets:override' })) });
    assert.equal(r2.status, 403);
    const r3 = await raw(s.port, { method: 'POST', path: `/admin/overrides/${r1.json.id}/revert`, headers: bearer(tok({ scope: 'datasets:revert' })) });
    assert.equal(r3.status, 200);
  });

  const failures = [
    ['no header', {}],
    ['empty header', { authorization: '' }],
    ['scheme only', { authorization: 'Bearer' }],
    ['basic', { authorization: 'Basic YWRtaW46YWRtaW4=' }],
    ['garbage token', { authorization: 'Bearer not-a-jwt' }],
    ['expired', { authorization: `Bearer ${tok({ exp: 1 })}` }],
    ['bad sig', { authorization: `Bearer ${sign(claims(), { secret: 'q'.repeat(40) })}` }],
    ['alg none', { authorization: `Bearer ${sign(claims(), { alg: 'none' })}` }],
    ['wrong aud', { authorization: `Bearer ${tok({ aud: 'x' })}` }],
    ['lowercase scheme valid token', { authorization: `bearer ${tok({ roles: ['admin'] })}` }, 200],
  ];
  for (const [name, headers, expected = 401] of failures) {
    await t.test(`auth failure path: ${name} -> ${expected}`, async () => {
      const r = await raw(s.port, { path: '/admin/audit', headers });
      assert.equal(r.status, expected, r.text);
      if (expected === 401) {
        assert.equal(r.json.error, 'unauthorized');
        assert.match(r.headers['www-authenticate'], /^Bearer realm="control704"/);
      }
    });
  }

  await t.test('multiple Authorization headers -> 401 invalid_request (even if first is valid admin)', async () => {
    const admin = tok({ roles: ['admin'] });
    for (const pair of [[`Bearer ${admin}`, 'Bearer junk'], ['Bearer junk', `Bearer ${admin}`], [`Bearer ${admin}`, `Bearer ${admin}`]]) {
      const r = await raw(s.port, { path: '/admin/audit', headers: { authorization: pair } });
      assert.equal(r.status, 401);
      assert.equal(r.json.reason, 'invalid_request');
      assert.match(r.headers['www-authenticate'], /invalid_request/);
    }
  });

  await t.test('token in query string is NOT accepted', async () => {
    const r = await get(`/admin/audit?access_token=${tok({ roles: ['admin'] })}`);
    assert.equal(r.status, 401);
  });

  await t.test('redaction: no token material in any audit line, response, or audit API across all failure paths', async () => {
    const all = s.lines.join('\n');
    assert.ok(!/eyJ[A-Za-z0-9_-]{5,}/.test(all), 'JWT header material in audit log');
    assert.ok(!/Bearer /i.test(all));
    assert.ok(!all.includes('YWRtaW46YWRtaW4'), 'basic creds in audit log');
    assert.ok(!all.includes('access_token'), 'query string leaked into audit path');
    const r = await get('/admin/audit', tok({ roles: ['admin'] }));
    assert.ok(!/eyJ[A-Za-z0-9_-]{5,}/.test(r.text));
    const types = new Set(r.json.map((e) => e.type));
    for (const ty of ['auth.failure', 'authz.denied', 'request', 'dataset.override', 'dataset.revert']) assert.ok(types.has(ty), ty);
    for (const e of r.json.filter((x) => x.type === 'auth.failure')) {
      assert.deepEqual(Object.keys(e).sort(), ['method', 'path', 'reason', 'requestId', 'ts', 'type']);
    }
  });
});
