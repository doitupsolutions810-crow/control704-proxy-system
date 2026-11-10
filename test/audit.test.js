'use strict';
// Audit log integrity: immutability, system-owned seq/ts, ordering under concurrency,
// no log forging via newlines, scoped export, cap boundaries, failing sinks.
const test = require('node:test');
const assert = require('node:assert');
const { createAuditLogger } = require('../src/access/audit');
const { sign, claims, startServer, raw, bearer, jsonPost } = require('./helpers');

const mk = (o = {}) => { const lines = []; return { lines, a: createAuditLogger({ sink: (l) => lines.push(l), ...o }) }; };

// ---------- immutability ----------
test('entries returned by log() and recent() are deeply frozen', () => {
  const { a } = mk();
  const e = a.log({ type: 't', nested: { list: [1, { x: 1 }] } });
  assert.ok(Object.isFrozen(e) && Object.isFrozen(e.nested) && Object.isFrozen(e.nested.list) && Object.isFrozen(e.nested.list[1]));
  const r = a.recent(1)[0];
  assert.throws(() => { 'use strict'; r.type = 'forged'; }, TypeError);
  assert.throws(() => { 'use strict'; r.nested.list.push(2); }, TypeError);
  assert.throws(() => { 'use strict'; delete r.seq; }, TypeError);
  assert.equal(a.recent(1)[0].type, 't');
});
test('mutating the caller\'s event object after logging does not change the entry', () => {
  const { a, lines } = mk();
  const ev = { type: 'orig', patch: { enabled: false } };
  a.log(ev);
  ev.type = 'changed'; ev.patch.enabled = true; ev.extra = 1;
  const e = a.recent(1)[0];
  assert.equal(e.type, 'orig'); assert.equal(e.patch.enabled, false); assert.equal(e.extra, undefined);
  assert.equal(JSON.parse(lines[0]).type, 'orig');
});
test('the array returned by recent() is a copy: splicing it does not affect the log', () => {
  const { a } = mk();
  for (let i = 0; i < 5; i++) a.log({ type: `n${i}` });
  const arr = a.recent(5); arr.length = 0; arr.push({ type: 'forged' });
  assert.equal(a.recent(5).length, 5);
  assert.equal(a.recent(5)[0].type, 'n0');
});

// ---------- system-owned fields / forging ----------
test('callers cannot supply ts or seq (bug before round 4: ts was forgeable)', () => {
  const { a } = mk();
  const e = a.log({ type: 'x', ts: '1999-01-01T00:00:00.000Z', seq: -5 });
  assert.notEqual(e.ts, '1999-01-01T00:00:00.000Z');
  assert.equal(e.seq, 1);
  assert.ok(Math.abs(Date.parse(e.ts) - Date.now()) < 5000);
});
test('redacted keys are dropped at top level: token, authorization, secret, password', () => {
  const { a, lines } = mk();
  a.log({ type: 'x', token: 'T0K', authorization: 'Bearer AUTH', Authorization: 'Bearer AUTH2', secret: 'S3C', password: 'PW' });
  for (const v of ['T0K', 'AUTH', 'S3C', 'PW']) assert.ok(!lines[0].includes(v), v);
});
test('newlines / CR / U+2028 in values cannot forge extra log lines', () => {
  const { a, lines } = mk();
  a.log({ type: 'x', msg: 'a\n{"type":"forged","seq":999}\r\n', u: 'b\u2028c\u2029d' });
  assert.equal(lines.length, 1);
  assert.ok(!/[\r\n]/.test(lines[0]));
  assert.equal(JSON.parse(lines[0]).msg, 'a\n{"type":"forged","seq":999}\r\n');
});
test('non-object / array / cyclic / BigInt events are logged safely, never throw', () => {
  const { a } = mk();
  const cyc = { type: 'cyc' }; cyc.self = cyc;
  assert.equal(a.log(null).type, 'invalid_event');
  assert.equal(a.log('str').type, 'invalid_event');
  assert.equal(a.log([1, 2]).type, 'invalid_event');
  assert.equal(a.log(cyc).type, 'audit.unserializable');
  assert.equal(a.log({ type: 'big', n: 10n }).type, 'audit.unserializable');
  assert.equal(a.log({ type: 'fn', f: () => 1, u: undefined }).f, undefined);
  assert.deepEqual(a.recent(10).map((e) => e.seq), [1, 2, 3, 4, 5, 6]);
});
test('caller "type" strings are recorded verbatim but cannot impersonate system fields', () => {
  const { a } = mk();
  const e = a.log({ type: 'dataset.override', seq: 1e9, ts: 'x' });
  assert.equal(e.type, 'dataset.override');
  assert.equal(e.seq, 1);
});

// ---------- ordering ----------
test('seq is strictly increasing and gap-free; ts is ISO and non-decreasing in normal operation', () => {
  const { a } = mk({ maxEntries: 5000 });
  for (let i = 0; i < 3000; i++) a.log({ type: 'o', i });
  const all = a.recent(5000);
  all.forEach((e, i) => { assert.equal(e.seq, i + 1); assert.equal(e.i, i); });
  for (let i = 1; i < all.length; i++) assert.ok(all[i].ts >= all[i - 1].ts);
});
test('seq ordering survives a wall clock that jumps backwards', (t) => {
  const { a } = mk();
  const real = Date.now;
  let fake = real();
  t.mock.method(Date, 'now', () => fake);
  const RealDate = Date;
  a.log({ type: 'before' });
  fake -= 3600 * 1000;
  a.log({ type: 'after' });
  Date.now = real;
  const [x, y] = a.recent(2);
  assert.ok(y.seq > x.seq, 'seq is the ordering key even if ts goes backwards');
  assert.ok(RealDate);
});
test('HTTP: concurrent requests produce unique, gap-free seq values; sink order equals buffer order', async (t) => {
  const lines = [];
  const audit = createAuditLogger({ sink: (l) => lines.push(l), maxEntries: 5000 });
  const s = await startServer({ audit }); t.after(() => s.close());
  const tech = sign(claims({ roles: ['technician'] }));
  await Promise.all(Array.from({ length: 150 }, (_, i) => raw(s.port, { path: '/proxy/x', headers: bearer(i % 3 ? tech : 'junk') })));
  const seqs = audit.recent(5000).map((e) => e.seq);
  assert.equal(seqs.length, 150);
  assert.deepEqual(seqs, Array.from({ length: 150 }, (_, i) => i + 1));
  assert.deepEqual(lines.map((l) => JSON.parse(l).seq), seqs);
});
test('HTTP: override then revert of the same record appear in causal order', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const admin = sign(claims({ roles: ['admin'] }));
  for (let i = 0; i < 20; i++) {
    const r = await raw(s.port, { path: '/admin/datasets/Y/overrides', ...jsonPost(admin, { patch: { rateLimitPerMinute: i + 1 }, reason: `order ${i}` }) });
    await raw(s.port, { method: 'POST', path: `/admin/overrides/${r.json.id}/revert`, headers: bearer(admin) });
  }
  const ev = s.app.audit.recent(1000).filter((e) => e.type === 'dataset.override' || e.type === 'dataset.revert');
  const pos = new Map();
  ev.forEach((e) => { const k = `${e.type}:${e.overrideId}`; pos.set(k, e.seq); });
  for (const e of ev.filter((x) => x.type === 'dataset.revert')) assert.ok(pos.get(`dataset.override:${e.overrideId}`) < e.seq);
});

// ---------- cap boundaries ----------
for (const cap of [1, 2, 10, 1000]) {
  test(`cap boundary maxEntries=${cap}: exactly cap kept; cap+1 evicts the oldest; stats track evictions`, () => {
    const { a, lines } = mk({ maxEntries: cap });
    for (let i = 0; i < cap; i++) a.log({ type: 'f', i });
    assert.equal(a.recent(cap + 10).length, cap);
    assert.equal(a.recent(cap)[0].i, 0);
    assert.equal(a.stats().evicted, 0);
    a.log({ type: 'f', i: cap });
    const r = a.recent(cap + 10);
    assert.equal(r.length, cap);
    assert.equal(r[0].i, cap === 1 ? cap : 1);
    assert.equal(r[r.length - 1].i, cap);
    assert.deepEqual(a.stats(), { seq: cap + 1, size: cap, maxEntries: cap, evicted: 1, sinkErrors: 0 });
    assert.equal(lines.length, cap + 1, 'sink still receives evicted entries');
  });
}
test('recent(limit) clamping (recent(0) returned everything before round 4)', () => {
  const { a } = mk();
  for (let i = 0; i < 5; i++) a.log({ type: 'r', i });
  assert.equal(a.recent(0).length, 0);
  assert.equal(a.recent(-1).length, 0);
  assert.equal(a.recent(-100).length, 0);
  assert.equal(a.recent(2.9).length, 2);
  assert.equal(a.recent(3).map((e) => e.i).join(), '2,3,4');
  assert.equal(a.recent(1e9).length, 5);
  assert.equal(a.recent(Infinity).length, 5);
  assert.equal(a.recent(NaN).length, 5);
  assert.equal(a.recent().length, 5);
  assert.equal(a.recent('2').length, 5);
});

// ---------- failing sinks ----------
test('a throwing sink never throws out of log(); errors are counted and reported (hang/crash before round 4)', () => {
  const seen = [];
  const a = createAuditLogger({ sink: () => { throw new Error('disk full'); }, onSinkError: (err, entry) => seen.push([err.message, entry.seq]) });
  assert.doesNotThrow(() => a.log({ type: 'x' }));
  assert.doesNotThrow(() => a.log({ type: 'y' }));
  assert.deepEqual(seen, [['disk full', 1], ['disk full', 2]]);
  assert.equal(a.stats().sinkErrors, 2);
  assert.equal(a.recent(5).length, 2);
});
test('a throwing onSinkError handler is also contained', () => {
  const a = createAuditLogger({ sink: () => { throw new Error('a'); }, onSinkError: () => { throw new Error('b'); } });
  assert.doesNotThrow(() => a.log({ type: 'x' }));
});
test('HTTP with a throwing sink: every path still responds correctly (401, 403, 200, 201, 500)', async (t) => {
  const audit = createAuditLogger({ sink: () => { throw new Error('disk full'); } });
  const s = await startServer({ audit }); t.after(() => s.close());
  const admin = sign(claims({ roles: ['admin'] }));
  assert.equal((await raw(s.port, { path: '/admin/audit' })).status, 401);
  assert.equal((await raw(s.port, { path: '/admin/audit', headers: bearer(sign(claims({ roles: ['viewer'] }))) })).status, 403);
  assert.equal((await raw(s.port, { path: '/admin/audit', headers: bearer(admin) })).status, 200);
  assert.equal((await raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, { patch: { enabled: false }, reason: 'sink down' }) })).status, 201);
  const orig = s.app.store.all; s.app.store.all = () => { throw new Error('x'); };
  try { assert.equal((await raw(s.port, { path: '/datasets', headers: bearer(admin) })).status, 500); } finally { s.app.store.all = orig; }
  assert.ok(audit.stats().sinkErrors >= 5);
});
test('a slow (async) sink does not delay responses', async (t) => {
  const pending = [];
  const audit = createAuditLogger({ sink: (l) => pending.push(new Promise((r) => setTimeout(() => r(l), 500))) });
  const s = await startServer({ audit }); t.after(() => s.close());
  const t0 = Date.now();
  await raw(s.port, { path: '/datasets', headers: bearer(sign(claims({ roles: ['viewer'] }))) });
  assert.ok(Date.now() - t0 < 300);
});

// ---------- export under scope ----------
test('HTTP export: /admin/audit requires audit:read; returns <= 200 newest entries in seq order', async (t) => {
  const audit = createAuditLogger({ sink: () => {}, maxEntries: 1000 });
  const s = await startServer({ audit }); t.after(() => s.close());
  for (let i = 0; i < 260; i++) audit.log({ type: 'filler', i });
  for (const [c, st] of [[{ roles: ['viewer'] }, 403], [{ roles: ['technician'] }, 403], [{ scope: 'datasets:override' }, 403], [{ scope: 'audit:read' }, 200], [{ roles: ['admin'] }, 200]]) {
    assert.equal((await raw(s.port, { path: '/admin/audit', headers: bearer(sign(claims(c))) })).status, st, JSON.stringify(c));
  }
  const r = await raw(s.port, { path: '/admin/audit', headers: bearer(sign(claims({ roles: ['admin'] }))) });
  assert.equal(r.json.length, 200);
  for (let i = 1; i < r.json.length; i++) assert.equal(r.json[i].seq, r.json[i - 1].seq + 1);
  assert.equal(r.json[r.json.length - 1].seq, audit.stats().seq - 1, 'newest entries (the export request itself is logged after)');
});
test('HTTP export: denied export attempts are themselves audited', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  await raw(s.port, { path: '/admin/audit', headers: bearer(sign(claims({ sub: 'snoop', roles: ['viewer'] }))) });
  assert.ok(s.app.audit.recent(5).some((e) => e.type === 'authz.denied' && e.actor === 'snoop' && e.path === '/admin/audit'));
});
test('HTTP export: query parameters cannot widen the export', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  for (let i = 0; i < 300; i++) s.app.audit.log({ type: 'filler' });
  const r = await raw(s.port, { path: '/admin/audit?limit=100000&all=true', headers: bearer(sign(claims({ roles: ['admin'] }))) });
  assert.equal(r.json.length, 200);
});
