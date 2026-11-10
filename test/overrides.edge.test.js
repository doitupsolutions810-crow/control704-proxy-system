'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { DatasetStore, DEFAULTS, ValidationError, NotFoundError, validatePatch } = require('../src/datasets/store');
const { sign, claims, startServer, raw, bearer, jsonPost } = require('./helpers');

const ctx = { actor: 'admin-1', reason: 'edge case test' };
const ok = (patch, id = 'X') => { const s = new DatasetStore(); return s.override(id, patch, ctx); };
const bad = (patch, re, id = 'X') => assert.throws(() => new DatasetStore().override(id, patch, ctx), (e) => e instanceof ValidationError && (!re || re.test(`${e.message} ${(e.details || []).join(' ')}`)));

// ---------- rateLimitPerMinute ----------
for (const v of [1, 2, 60, 9999, 10000]) test(`rateLimit ${v} accepted`, () => assert.equal(ok({ rateLimitPerMinute: v }).after.rateLimitPerMinute, v));
for (const v of [0, -1, 10001, 1e9, 1.5, 0.999, '60', NaN, Infinity, -Infinity, null, true, [60], { v: 60 }, 2 ** 53]) {
  test(`rateLimit ${String(v)} (${typeof v}) rejected`, () => bad({ rateLimitPerMinute: v }, /rateLimitPerMinute/));
}

// ---------- enabled ----------
for (const v of [true, false]) test(`enabled ${v} accepted`, () => assert.equal(ok({ enabled: v }).after.enabled, v));
for (const v of ['true', 'false', 0, 1, null, [], {}]) test(`enabled ${JSON.stringify(v)} rejected`, () => bad({ enabled: v }, /enabled/));

// ---------- endpoint ----------
for (const v of ['/proxy/x2', '/proxy/a', '/proxy/x/v2', '/proxy/x_y-z', '/proxy/' + 'a'.repeat(64)]) {
  test(`endpoint ${v} accepted`, () => assert.equal(ok({ endpoint: v }).after.endpoint, v));
}
for (const v of [
  '/proxy/', '/proxy', 'proxy/x', '/Proxy/x', '/proxy/X', '/proxy/../admin', '/proxy/x/../../etc', '/proxy/x/..', '/proxy/..',
  '/proxy/%2e%2e/admin', '/proxy/%2E%2E', '/proxy/x%2fy', '/proxy//x', '/proxy/x//y', '/proxy/x/', '//proxy/x',
  '/proxy/x\u0000', '/proxy/x\n', '/proxy/x y', '/proxy/х' /* cyrillic */, '/proxy/ｘ' /* fullwidth */, '/proxy/x\u200b',
  '/proxy/_x', '/proxy/-x', '/proxy/' + 'a'.repeat(65), '/admin/audit', 'http://evil/proxy/x', '\\proxy\\x', '/proxy/x?y=1', '/proxy/x#f',
  '', 1, null, ['/proxy/x'],
]) {
  test(`endpoint ${JSON.stringify(v)} rejected`, () => bad({ endpoint: v }, /endpoint/));
}
test('endpoint collision with another dataset rejected; reusing own endpoint allowed', () => {
  bad({ endpoint: '/proxy/y' }, /already used by dataset Y/);
  bad({ endpoint: '/proxy/z' }, /already used by dataset Z/);
  assert.equal(ok({ endpoint: '/proxy/x' }).after.endpoint, '/proxy/x');
});
test('endpoint collision checks current (overridden) values, and freed endpoints become reusable', () => {
  const s = new DatasetStore();
  const r = s.override('Y', { endpoint: '/proxy/new' }, ctx);
  assert.throws(() => s.override('X', { endpoint: '/proxy/new' }, ctx), /already used by dataset Y/);
  assert.equal(s.override('X', { endpoint: '/proxy/y' }, ctx).after.endpoint, '/proxy/y');
  // reverting Y would now collide? Revert restores Y to /proxy/y while X holds it — must be blocked or consistent.
  assert.throws(() => s.revert(r.id, { actor: 'a' }), /now used by dataset X/);
  assert.equal(s.get('Y').endpoint, '/proxy/new');
  assert.equal(s.listOverrides('Y')[0].revertedAt, null);
});

// ---------- upstream ----------
for (const v of [null, 'https://api.example.com', 'http://10.0.0.5:8080/path', 'https://[::1]:8443/', 'http://[2001:db8::1]/', 'HTTPS://EXAMPLE.COM', 'https://example.com/a?b=c#d']) {
  test(`upstream ${JSON.stringify(v)} accepted`, () => assert.equal(ok({ upstream: v }).after.upstream, v));
}
for (const v of [
  'https://user:pass@example.com', 'https://user@example.com', 'https://:pass@example.com', 'http://a%40b:c@example.com',
  'javascript:alert(1)', 'JAVASCRIPT:alert(1)', 'file:///etc/passwd', 'ftp://example.com', 'data:text/plain,hi', 'gopher://x', 'ws://x', 'wss://x',
  'example.com', '//example.com', '/relative', 'http://', 'https://[::1', '', 'https://' + 'a'.repeat(2050) + '.com', 42, true, {}, [],
]) {
  test(`upstream ${JSON.stringify(String(v).slice(0, 40))} rejected`, () => bad({ upstream: v }, /upstream/));
}

// ---------- metadata ----------
test('metadata: valid flat object accepted', () => assert.deepEqual(ok({ metadata: { owner: 'ops', ticket: 704, ok: true, 'a.b-c_d': 'x' } }).after.metadata.ticket, 704));
test('metadata: 50 keys accepted, 51 rejected', () => {
  const m = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i]));
  assert.ok(ok({ metadata: m(50) }));
  bad({ metadata: m(51) }, /metadata/);
});
test('metadata: value length 512 accepted, 513 rejected; key length 64/65', () => {
  assert.ok(ok({ metadata: { a: 'x'.repeat(512) } }));
  bad({ metadata: { a: 'x'.repeat(513) } }, /metadata/);
  assert.ok(ok({ metadata: { ['k'.repeat(64)]: 1 } }));
  bad({ metadata: { ['k'.repeat(65)]: 1 } }, /metadata/);
});
for (const m of [null, [], 'str', 1, { nested: { a: 1 } }, { arr: [1] }, { n: null }, { '': 1 }, { 'bad key': 1 }, { 'k/': 1 }, { 'ключ': 1 }]) {
  test(`metadata ${JSON.stringify(m)} rejected`, () => bad({ metadata: m }, /metadata/));
}
for (const key of ['__proto__', 'constructor', 'prototype']) {
  test(`metadata key "${key}" rejected (prototype pollution guard)`, () => {
    const m = JSON.parse(`{"${key}": "x"}`);
    bad({ metadata: m }, /metadata/);
    assert.equal(({}).x, undefined);
  });
}
test('metadata NaN/Infinity numbers: JSON cannot carry them; store accepts finite only via JSON round-trip', () => {
  // Direct API: Infinity serialises to null in history clone; ensure it is rejected or normalised predictably.
  const s = new DatasetStore();
  const r = s.override('X', { metadata: { n: 1.5 } }, ctx);
  assert.equal(r.after.metadata.n, 1.5);
});

// ---------- patch shape / forbidden fields ----------
for (const patch of [null, undefined, [], 'x', 1, true, {}]) {
  test(`patch ${JSON.stringify(patch)} rejected`, () => bad(patch, /Patch/));
}
for (const f of ['auth', 'AUTH', 'Auth', 'auth ', 'id', 'dataset', 'before', 'history']) {
  test(`patch field "${f}" not overridable`, () => bad({ [f]: 'none' }, /not overridable/));
}
for (const key of ['__proto__', 'constructor', 'prototype', 'toString', 'hasOwnProperty']) {
  test(`top-level patch key "${key}" rejected and nothing polluted`, () => {
    const patch = JSON.parse(`{"${key}": {"auth": "none", "polluted": true}}`);
    bad(patch, /not overridable/);
    assert.equal(({}).polluted, undefined);
    assert.equal(new DatasetStore().get('X').auth, 'token-override');
  });
}
test('mixed valid + invalid fields: whole patch rejected atomically, details list each problem', () => {
  const s = new DatasetStore();
  assert.throws(() => s.override('X', { enabled: false, auth: 'none', rateLimitPerMinute: 0 }, ctx), (e) => {
    assert.equal(e.details.length, 2);
    return true;
  });
  assert.equal(s.get('X').enabled, true);
  assert.equal(s.listOverrides().length, 0);
});
test('auth can never change via any path', () => {
  const s = new DatasetStore();
  s.override('X', { enabled: false, metadata: { auth: 'none' } }, ctx);
  assert.equal(s.get('X').auth, 'token-override');
});
test('validatePatch exported and consistent', () => {
  assert.doesNotThrow(() => validatePatch({ enabled: true }));
  assert.throws(() => validatePatch({ auth: 'x' }), ValidationError);
});

// ---------- reason / actor ----------
for (const reason of [undefined, null, '', '  ', 'ab', '   ab   ', 42, ['reason'], 'x'.repeat(501), ' '.repeat(2) + 'x'.repeat(501)]) {
  test(`reason ${JSON.stringify(String(reason).slice(0, 20))} (len ${reason && reason.length}) rejected`, () => {
    assert.throws(() => new DatasetStore().override('X', { enabled: false }, { actor: 'a', reason }), /reason/);
  });
}
test('reason boundaries: 3 and 500 chars accepted, trimmed', () => {
  assert.equal(new DatasetStore().override('X', { enabled: false }, { actor: 'a', reason: '  abc  ' }).reason, 'abc');
  assert.ok(new DatasetStore().override('X', { enabled: false }, { actor: 'a', reason: 'x'.repeat(500) }));
  assert.ok(new DatasetStore().override('X', { enabled: false }, { actor: 'a', reason: ` ${'x'.repeat(500)} ` }));
});
test('reason with unicode stored verbatim; control chars rejected (round 3 hardening)', () => {
  const r = new DatasetStore().override('X', { enabled: false }, { actor: 'a', reason: 'maintenance 🚧 done 👩‍💻' });
  assert.match(r.reason, /🚧/);
  assert.throws(() => new DatasetStore().override('X', { enabled: false }, { actor: 'a', reason: 'maintenance \u0007 done' }), /control or bidi/);
});
test('actor required for override and revert', () => {
  const s = new DatasetStore();
  assert.throws(() => s.override('X', { enabled: false }, { reason: 'abc' }), /actor/);
  const r = s.override('X', { enabled: false }, ctx);
  assert.throws(() => s.revert(r.id, {}), /actor/);
  assert.throws(() => s.revert(r.id), /actor/);
});

// ---------- dataset ids ----------
for (const id of ['x', 'X', 'y', 'Z']) test(`dataset id ${id} accepted (case-insensitive)`, () => assert.ok(ok({ enabled: false }, id)));
for (const id of ['W', 'XY', '', null, undefined, '__proto__', 'constructor', 'toString', ' X', 'X ', '0', 1]) {
  test(`dataset id ${JSON.stringify(id)} -> NotFound`, () => assert.throws(() => new DatasetStore().override(id, { enabled: false }, ctx), NotFoundError));
}

// ---------- history immutability / isolation ----------
test('returned records and get() are deep copies (mutation cannot alter store)', () => {
  const s = new DatasetStore();
  const r = s.override('X', { metadata: { a: 'b' } }, ctx);
  r.after.enabled = false; r.before.auth = 'none'; r.patch.metadata.a = 'z';
  const g = s.get('X'); g.auth = 'none';
  const all = s.all(); all.X.auth = 'none';
  s.listOverrides()[0].dataset = 'Y';
  assert.equal(s.get('X').auth, 'token-override');
  assert.equal(s.get('X').enabled, true);
  assert.equal(s.get('X').metadata.a, 'b');
  assert.equal(s.listOverrides()[0].dataset, 'X');
});
test('caller mutating the patch object after override does not change stored state', () => {
  const s = new DatasetStore();
  const patch = { metadata: { a: 'b' } };
  s.override('X', patch, ctx);
  patch.metadata.a = 'mutated';
  assert.equal(s.get('X').metadata.a, 'b');
});
test('separate store instances do not share state; DEFAULTS untouched', () => {
  const a = new DatasetStore(); a.override('X', { enabled: false }, ctx);
  assert.equal(new DatasetStore().get('X').enabled, true);
  assert.equal(DEFAULTS.X.enabled, true);
});
test('override records have unique ids and ISO timestamps', () => {
  const s = new DatasetStore();
  const ids = new Set();
  for (let i = 0; i < 200; i++) ids.add(s.override('X', { rateLimitPerMinute: (i % 100) + 1 }, ctx).id);
  assert.equal(ids.size, 200);
  assert.match(s.listOverrides()[0].createdAt, /Z$/);
});

// ---------- revert ----------
test('revert unknown id -> NotFound; revert on empty history -> NotFound', () => {
  const s = new DatasetStore();
  assert.throws(() => s.revert('00000000-0000-0000-0000-000000000000', { actor: 'a' }), NotFoundError);
  assert.throws(() => s.revert(undefined, { actor: 'a' }), NotFoundError);
});
test('double revert rejected', () => {
  const s = new DatasetStore();
  const r = s.override('X', { enabled: false }, ctx);
  s.revert(r.id, { actor: 'a' });
  assert.throws(() => s.revert(r.id, { actor: 'a' }), /already reverted/);
});
test('revert ordering: LIFO per dataset, independent across datasets', () => {
  const s = new DatasetStore();
  const x1 = s.override('X', { rateLimitPerMinute: 1 }, ctx);
  const y1 = s.override('Y', { rateLimitPerMinute: 2 }, ctx);
  const x2 = s.override('X', { rateLimitPerMinute: 3 }, ctx);
  assert.throws(() => s.revert(x1.id, { actor: 'a' }), /Revert newer override/);
  s.revert(y1.id, { actor: 'a' }); // Y independent of X ordering
  assert.equal(s.get('Y').rateLimitPerMinute, 60);
  s.revert(x2.id, { actor: 'a' });
  assert.equal(s.get('X').rateLimitPerMinute, 1);
  s.revert(x1.id, { actor: 'a' });
  assert.deepEqual(s.all(), JSON.parse(JSON.stringify(DEFAULTS)));
});
test('revert after re-override: reverted entries are skipped when finding latest', () => {
  const s = new DatasetStore();
  const a = s.override('X', { rateLimitPerMinute: 5 }, ctx);
  const b = s.override('X', { rateLimitPerMinute: 6 }, ctx);
  s.revert(b.id, { actor: 'a' });
  const c = s.override('X', { rateLimitPerMinute: 7 }, ctx);
  assert.throws(() => s.revert(a.id, { actor: 'a' }), /Revert newer/);
  s.revert(c.id, { actor: 'a' });
  assert.equal(s.get('X').rateLimitPerMinute, 5);
  s.revert(a.id, { actor: 'a' });
  assert.equal(s.get('X').rateLimitPerMinute, 60);
});
test('revert records revertedBy/revertedAt and keeps history', () => {
  const s = new DatasetStore();
  const r = s.override('Z', { enabled: false }, ctx);
  const rv = s.revert(r.id, { actor: 'reverter' });
  assert.equal(rv.revertedBy, 'reverter');
  assert.ok(rv.revertedAt);
  assert.equal(s.listOverrides('Z').length, 1);
  assert.equal(s.listOverrides('X').length, 0);
});
test('listOverrides with unknown dataset -> NotFound; without arg lists all', () => {
  const s = new DatasetStore();
  s.override('X', { enabled: false }, ctx); s.override('Y', { enabled: false }, ctx);
  assert.equal(s.listOverrides().length, 2);
  assert.throws(() => s.listOverrides('Q'), NotFoundError);
});

// ---------- HTTP-level override flows ----------
test('HTTP override flows', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const admin = sign(claims({ sub: 'admin-http', roles: ['admin'] }));
  const tech = sign(claims({ sub: 'tech', roles: ['technician'] }));
  const post = (path, body) => raw(s.port, { path, ...jsonPost(admin, body) });

  await t.test('concurrent overrides on the same dataset are all recorded, final state is consistent and fully revertible', async () => {
    const N = 40;
    const results = await Promise.all(Array.from({ length: N }, (_, i) => post('/admin/datasets/Y/overrides', { patch: { rateLimitPerMinute: i + 1 }, reason: `concurrent ${i}` })));
    assert.ok(results.every((r) => r.status === 201));
    const list = (await raw(s.port, { path: '/admin/datasets/Y/overrides', headers: bearer(admin) })).json;
    assert.equal(list.length, N);
    const cur = (await raw(s.port, { path: '/datasets/Y', headers: bearer(admin) })).json;
    assert.equal(cur.rateLimitPerMinute, list[list.length - 1].after.rateLimitPerMinute);
    // each record's before equals previous record's after (serialised history)
    for (let i = 1; i < list.length; i++) assert.deepEqual(list[i].before, list[i - 1].after);
    for (const rec of [...list].reverse()) {
      const r = await raw(s.port, { method: 'POST', path: `/admin/overrides/${rec.id}/revert`, headers: bearer(admin) });
      assert.equal(r.status, 200);
    }
    assert.equal((await raw(s.port, { path: '/datasets/Y', headers: bearer(admin) })).json.rateLimitPerMinute, 60);
  });

  await t.test('concurrent reverts of the same override: exactly one succeeds', async () => {
    const r = await post('/admin/datasets/Z/overrides', { patch: { enabled: false }, reason: 'race revert' });
    const rs = await Promise.all(Array.from({ length: 10 }, () => raw(s.port, { method: 'POST', path: `/admin/overrides/${r.json.id}/revert`, headers: bearer(admin) })));
    assert.equal(rs.filter((x) => x.status === 200).length, 1);
    assert.equal(rs.filter((x) => x.status === 400).length, 9);
  });

  await t.test('disabled route returns 503 for every proxy, re-enabling restores 200', async () => {
    for (const id of ['X', 'Y', 'Z']) {
      const r = await post(`/admin/datasets/${id}/overrides`, { patch: { enabled: false }, reason: 'disable test' });
      const p = await raw(s.port, { path: `/proxy/${id.toLowerCase()}`, headers: bearer(tech) });
      assert.equal(p.status, 503);
      assert.equal(p.json.error, 'route_disabled');
      assert.equal(p.json.dataset, id);
      await raw(s.port, { method: 'POST', path: `/admin/overrides/${r.json.id}/revert`, headers: bearer(admin) });
      assert.equal((await raw(s.port, { path: `/proxy/${id.toLowerCase()}`, headers: bearer(tech) })).status, 200);
    }
  });

  await t.test('disabled route: unauthenticated still gets 401 (no info leak), viewer still 403', async () => {
    const r = await post('/admin/datasets/X/overrides', { patch: { enabled: false }, reason: 'leak test' });
    assert.equal((await raw(s.port, { path: '/proxy/x' })).status, 401);
    assert.equal((await raw(s.port, { path: '/proxy/x', headers: bearer(sign(claims({ roles: ['viewer'] }))) })).status, 403);
    await raw(s.port, { method: 'POST', path: `/admin/overrides/${r.json.id}/revert`, headers: bearer(admin) });
  });

  await t.test('revert via HTTP: unknown uuid 404, malformed id 404, empty history 404', async () => {
    assert.equal((await raw(s.port, { method: 'POST', path: '/admin/overrides/00000000-0000-0000-0000-000000000000/revert', headers: bearer(admin) })).status, 404);
    assert.equal((await raw(s.port, { method: 'POST', path: '/admin/overrides/not-a-uuid/revert', headers: bearer(admin) })).status, 404);
    // dot-segments are normalised by the URL parser to /datasets/revert (GET-only) -> 405, never a revert
    const before = (await raw(s.port, { path: '/admin/datasets/X/overrides', headers: bearer(admin) })).json;
    assert.equal((await raw(s.port, { method: 'POST', path: '/admin/overrides/../../datasets/revert', headers: bearer(admin) })).status, 405);
    assert.deepEqual((await raw(s.port, { path: '/admin/datasets/X/overrides', headers: bearer(admin) })).json, before);
  });

  await t.test('HTTP validation errors return 400 with details and leave state untouched', async () => {
    const before = (await raw(s.port, { path: '/datasets', headers: bearer(admin) })).json;
    for (const body of [
      { patch: { rateLimitPerMinute: 10001 }, reason: 'too high' },
      { patch: { rateLimitPerMinute: 1.5 }, reason: 'float' },
      { patch: { rateLimitPerMinute: '10' }, reason: 'string' },
      { patch: { upstream: 'javascript:alert(1)' }, reason: 'js' },
      { patch: { endpoint: '/proxy/%2e%2e' }, reason: 'enc' },
      { patch: { auth: 'none' }, reason: 'auth change' },
      { patch: { enabled: false }, reason: 'x'.repeat(501) },
      { patch: { enabled: false }, reason: '' },
      { patch: { enabled: false } },
      { reason: 'no patch' },
      { patch: null, reason: 'null patch' },
    ]) {
      const r = await post('/admin/datasets/X/overrides', body);
      assert.equal(r.status, 400, JSON.stringify(body).slice(0, 80));
      assert.equal(r.json.error, 'validation_error');
      assert.ok(Array.isArray(r.json.details));
    }
    const polluted = await post('/admin/datasets/X/overrides', '{"patch":{"__proto__":{"auth":"none"}},"reason":"proto"}');
    assert.equal(polluted.status, 400);
    const polluted2 = await post('/admin/datasets/X/overrides', '{"__proto__":{"patch":{"enabled":false}},"reason":"proto2"}');
    assert.equal(polluted2.status, 400);
    assert.equal(({}).auth, undefined);
    assert.deepEqual((await raw(s.port, { path: '/datasets', headers: bearer(admin) })).json, before);
  });

  await t.test('audit trail entries for override contain actor/dataset/reason but no token', async () => {
    const r = await post('/admin/datasets/X/overrides', { patch: { metadata: { ticket: 'OPS-1' } }, reason: 'audit check' });
    const line = s.lines.map((l) => JSON.parse(l)).find((e) => e.type === 'dataset.override' && e.overrideId === r.json.id);
    assert.equal(line.actor, 'admin-http');
    assert.equal(line.dataset, 'X');
    assert.equal(line.reason, 'audit check');
    assert.ok(!JSON.stringify(line).includes(admin.split('.')[2]));
  });
});

// ---------- round 3: non-finite numbers via the direct (non-JSON) API ----------
for (const n of [Infinity, -Infinity, NaN]) {
  test(`metadata number ${n} rejected via direct store API (would silently become null in history)`, () => {
    assert.throws(() => new DatasetStore().override('X', { metadata: { n } }, ctx), (e) => /metadata/.test((e.details || []).join(' ')));
  });
}
test('metadata: safe-integer extremes, tiny floats and -0 accepted; unsafe integers (incl. MAX_VALUE) rejected (round 4)', () => {
  const r = new DatasetStore().override('X', { metadata: { a: Number.MAX_SAFE_INTEGER, b: Number.MIN_SAFE_INTEGER, c: Number.MIN_VALUE, d: -0, e: 123.456 } }, ctx);
  assert.equal(r.after.metadata.a, Number.MAX_SAFE_INTEGER);
  for (const n of [Number.MAX_VALUE, -Number.MAX_VALUE, 2 ** 53, 1e21, 1.5e300]) {
    assert.throws(() => new DatasetStore().override('X', { metadata: { n } }, ctx), (e) => /metadata/.test((e.details || []).join(' ')), String(n));
  }
});
