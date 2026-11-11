'use strict';
// Explicit regression locks: one test per bug fixed in rounds 2, 3 and 4.
// Round 2: R2-1..R2-8. Round 3: R3-1..R3-12. Round 4: R4-1..R4-11.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider, loadConfigFromEnv, AuthError } = require('../src/auth/avroneProvider');
const { effectiveScopes } = require('../src/access/authorize');
const { toPrincipal } = require('../src/auth');
const { DatasetStore } = require('../src/datasets/store');
const { sign, claims, config, SECRET, ISSUER, AUDIENCE, startServer, raw, bearer, fakeClock } = require('./helpers');

const nowS = () => Math.floor(Date.now() / 1000);

// ---------------- Round 2 ----------------
test('R2-1: NaN/invalid clock skew must never make expired tokens verify', async () => {
  assert.throws(() => createAvroneProvider({ ...config, clockSkewSec: NaN }), /CLOCK_SKEW/);
  const env = { AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_SECRET: SECRET };
  assert.equal(loadConfigFromEnv({ ...env, AVRONE_CLOCK_SKEW_SEC: '' }).clockSkewSec, 30); // unset -> default
  for (const v of ['abc', 'NaN', '  ', 'Infinity', '1e3']) {
    assert.throws(() => loadConfigFromEnv({ ...env, AVRONE_CLOCK_SKEW_SEC: v }), /AVRONE_CLOCK_SKEW_SEC/, v);
  }
  const p = createAvroneProvider({ ...config, clockSkewSec: 0 });
  await assert.rejects(p.verify(sign(claims({ exp: 1 }))), /expired/);
});
test('R2-2: future iat and non-numeric nbf/iat rejected', async () => {
  const p = createAvroneProvider(config);
  await assert.rejects(p.verify(sign(claims({ iat: nowS() + 3600 }))), /future/);
  await assert.rejects(p.verify(sign(claims({ nbf: 'later' }))), /nbf/);
  await assert.rejects(p.verify(sign(claims({ iat: 'now' }))), /iat/);
});
test('R2-3: prototype role names never crash authorization', () => {
  for (const r of ['__proto__', 'constructor', 'toString', 'valueOf', 'hasOwnProperty']) {
    assert.equal(effectiveScopes(toPrincipal({ sub: 's', roles: [r] }, 't')).size, 0);
  }
});
test('R2-3 (HTTP): prototype role -> 403 not 500', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { path: '/proxy/x', headers: bearer(sign(claims({ roles: ['__proto__'] }))) });
  assert.equal(r.status, 403);
});
test('R2-4: JSON body null -> 400 not 500', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(sign(claims({ roles: ['admin'] }))), 'content-type': 'application/json' }, body: 'null' });
  assert.equal(r.status, 400);
});
test('R2-5: oversized body -> clean 413 response (not connection reset)', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(sign(claims({ roles: ['admin'] }))), 'content-type': 'application/json' }, body: 'x'.repeat(100000) });
  assert.equal(r.status, 413);
  assert.equal(r.json.error, 'payload_too_large');
});
test('R2-6: malformed request target -> 400 and server keeps serving', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  assert.equal((await raw(s.port, { path: 'http://[' })).status, 400);
  assert.equal((await raw(s.port, { path: '/health' })).status, 200);
});
test('R2-7: revert cannot restore an endpoint now owned by another dataset', () => {
  const s = new DatasetStore();
  const r = s.override('Y', { endpoint: '/proxy/moved' }, { actor: 'a', reason: 'move y' });
  s.override('X', { endpoint: '/proxy/y' }, { actor: 'a', reason: 'x takes y' });
  assert.throws(() => s.revert(r.id, { actor: 'a' }), /now used by dataset X/);
  const eps = Object.values(s.all()).map((d) => d.endpoint);
  assert.equal(new Set(eps).size, 3);
});
test('R2-8: non-canonical base64url signature rejected (malleability)', async () => {
  const p = createAvroneProvider(config);
  const [h, pl, sg] = sign(claims()).split('.');
  const A = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const tweaked = sg.slice(0, -1) + A[A.indexOf(sg.at(-1)) ^ 1];
  await assert.rejects(p.verify(`${h}.${pl}.${tweaked}`), /Non-canonical/);
});

// ---------------- Round 3 ----------------
test('R3-1: blank / whitespace-only secret rejected', () => {
  for (const secret of [' '.repeat(40), '\t'.repeat(40), '\n'.repeat(64), ' \u00a0'.repeat(20)]) {
    assert.throws(() => createAvroneProvider({ ...config, secret }), /blank|whitespace|variety/);
  }
});
test('R3-2: secret with leading/trailing whitespace (copy-paste newline) rejected', () => {
  assert.throws(() => createAvroneProvider({ ...config, secret: `${SECRET}\n` }), /whitespace/);
  assert.throws(() => createAvroneProvider({ ...config, secret: ` ${SECRET}` }), /whitespace/);
});
test('R3-2b: low-variety secret ("aaaa...") rejected', () => {
  assert.throws(() => createAvroneProvider({ ...config, secret: 'a'.repeat(64) }), /variety/);
  assert.throws(() => createAvroneProvider({ ...config, secret: 'ab'.repeat(32) }), /variety/);
});
test('R3-3: PRIVATE key PEM in AVRONE_JWT_PUBLIC_KEY rejected', () => {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  for (const type of ['pkcs8', 'pkcs1']) {
    assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: privateKey.export({ type, format: 'pem' }) }), /PRIVATE key/);
  }
  const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).privateKey;
  assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: ec.export({ type: 'sec1', format: 'pem' }) }), /PRIVATE key/);
});
test('R3-4: malformed PEM gives a clear config error (not raw OpenSSL text)', () => {
  assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: '-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----' }), /not a valid PEM/);
});
test('R3-5: mutating the config object after creation cannot change trusted keys/issuer', async () => {
  const cfg = { ...config };
  const p = createAvroneProvider(cfg);
  const attacker = 'attacker-controlled-secret-0123456789abcdef';
  cfg.secret = attacker; cfg.issuer = 'evil'; cfg.audience = 'evil'; cfg.clockSkewSec = 300;
  await assert.rejects(p.verify(sign(claims(), { secret: attacker })), /Invalid signature/);
  await assert.rejects(p.verify(sign(claims({ iss: 'evil', aud: 'evil' }))), /issuer/);
  assert.ok(await p.verify(sign(claims())));
});
test('R3-6: fractional exp is enforced with sub-second precision', async () => {
  const clock = fakeClock(1_800_000_000_000);
  const p = createAvroneProvider({ ...config, now: clock.now });
  const tok = sign(claims({ iat: 1_799_999_990, exp: 1_800_000_000.5 }));
  clock.set(1_800_000_000_400); assert.ok(await p.verify(tok));
  clock.set(1_800_000_000_500); await assert.rejects(p.verify(tok), /expired/);
  clock.set(1_800_000_000_900); await assert.rejects(p.verify(tok), /expired/); // was accepted before fix
});
test('R3-7: zero-width / bidi / format chars in sub rejected', async () => {
  const p = createAvroneProvider(config);
  for (const sub of ['admin\u200b', 'evil\u202enimda', '\ufeffadmin', 'a\u2066b', 'a\u2028b', 'a\u00adb', 'a\u0085b']) {
    await assert.rejects(p.verify(sign(claims({ sub }))), /sub/, JSON.stringify(sub));
  }
});
test('R3-8: bidi/control chars in reason and metadata values rejected', () => {
  const s = new DatasetStore();
  assert.throws(() => s.override('X', { enabled: false }, { actor: 'a', reason: 'ok \u202e reversed' }), /control or bidi/);
  const metaErr = (e) => /Invalid value for metadata/.test((e.details || []).join(' '));
  assert.throws(() => s.override('X', { metadata: { a: 'x\u202ey' } }, { actor: 'a', reason: 'meta' }), metaErr);
  assert.throws(() => s.override('X', { metadata: { a: 'x\u0000y' } }, { actor: 'a', reason: 'meta' }), metaErr);
});
test('R3-9: override history is bounded (default 1000)', () => {
  const s = new DatasetStore();
  for (let i = 0; i < 2500; i++) s.override('X', { rateLimitPerMinute: (i % 100) + 1 }, { actor: 'a', reason: 'growth' });
  assert.equal(s.listOverrides().length, 1000);
  assert.equal(s.compacted, 1500);
});
test('R3-10: server has finite timeouts and a connection cap', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  assert.ok(s.server.requestTimeout > 0 && s.server.requestTimeout <= 30000);
  assert.ok(s.server.headersTimeout > 0 && s.server.headersTimeout <= s.server.requestTimeout);
  assert.ok(Number.isInteger(s.server.maxConnections) && s.server.maxConnections > 0);
});
test('R3-11: invalid / overlong UTF-8 body rejected instead of stored as U+FFFD', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const body = Buffer.concat([Buffer.from('{"patch":{"metadata":{"a":"'), Buffer.from([0xc0, 0xaf]), Buffer.from('"}},"reason":"overlong utf8"}')]);
  const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(sign(claims({ roles: ['admin'] }))), 'content-type': 'application/json' }, body });
  assert.equal(r.status, 400);
  assert.match(r.json.message, /UTF-8/);
});
test('R3-12: >100 headers (where Node would silently truncate) -> 431, so a hidden 2nd Authorization cannot slip through', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const headers = { authorization: `Bearer ${sign(claims({ roles: ['admin'] }))}` };
  for (let i = 0; i < 120; i++) headers[`x-p${i}`] = '1';
  const r = await raw(s.port, { path: '/admin/audit', headers });
  assert.equal(r.status, 431);
  assert.ok(AuthError);
});

// ---------------- Round 4 ----------------
const { createAuditLogger } = require('../src/access/audit');
const { rawSocket } = require('./helpers');
const { startFromEnv } = require('../src/proxy');
const { spawn } = require('child_process');

test('R4-1: Expect: 100-continue must not send "100 Continue" before authentication', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await rawSocket(s.port, 'POST /admin/datasets/X/overrides HTTP/1.1\r\nHost: x\r\nContent-Type: application/json\r\nContent-Length: 50\r\nExpect: 100-continue\r\n\r\n', { waitMs: 400 });
  assert.ok(!/HTTP\/1\.1 100/.test(r.data), r.data);
  assert.match(r.data, /HTTP\/1\.1 401/);
});

test('R4-2: a throwing audit sink must not crash the request or leave it unanswered', async (t) => {
  let errs = 0;
  const audit = createAuditLogger({ sink: () => { throw new Error('disk full'); }, onSinkError: () => { errs++; } });
  const s = await startServer({ audit }); t.after(() => s.close());
  const r = await raw(s.port, { path: '/proxy/x', headers: bearer(sign(claims({ roles: ['technician'] }))) });
  assert.equal(r.status, 200);
  assert.ok(errs > 0); assert.ok(audit.stats().sinkErrors > 0);
});

test('R4-3: audit entries returned by recent() are immutable', () => {
  const a = createAuditLogger({ sink: () => {} });
  a.log({ type: 't', nested: { x: 1 } });
  const [e] = a.recent();
  assert.throws(() => { 'use strict'; e.type = 'forged'; }, TypeError);
  assert.throws(() => { 'use strict'; e.nested.x = 2; }, TypeError);
  assert.equal(a.recent()[0].type, 't');
});

test('R4-4: callers cannot forge audit ts/seq', () => {
  const a = createAuditLogger({ sink: () => {} });
  a.log({ type: 't', ts: '1970-01-01T00:00:00.000Z', seq: 999 });
  const [e] = a.recent();
  assert.notEqual(e.ts, '1970-01-01T00:00:00.000Z'); assert.equal(e.seq, 1);
});

test('R4-5: recent(0) and recent(-1) return nothing (previously the whole log / all-but-one)', () => {
  const a = createAuditLogger({ sink: () => {} });
  for (let i = 0; i < 5; i++) a.log({ type: `t${i}` });
  assert.deepEqual(a.recent(0), []); assert.deepEqual(a.recent(-1), []);
  assert.deepEqual(a.recent(2).map((e) => e.type), ['t3', 't4']);
});

test('R4-6: metadata integers beyond 2^53 are rejected (they silently lost precision)', () => {
  const st = new DatasetStore();
  assert.throws(() => st.override('X', { metadata: { n: 9007199254740993 } }, { actor: 'a', reason: 'precision' }), /Invalid patch/);
  st.override('X', { metadata: { n: 9007199254740991, f: 1.5 } }, { actor: 'a', reason: 'precision ok' });
});

test('R4-7: HTTP/0.9-style and HTTP/2.0 request lines are not served as HTTP/1.1', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await rawSocket(s.port, 'GET /health HTTP/2.0\r\nHost: x\r\n\r\n', { waitMs: 400 });
  assert.ok(!/ 200 /.test(r.data.split('\r\n')[0] || ''), r.data);
});

test('R4-8: duplicate Host headers are rejected with 400 (RFC 9112 §3.2)', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await rawSocket(s.port, 'GET /health HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n', { waitMs: 400 });
  assert.match(r.data, /^HTTP\/1\.1 400/);
  for (const pair of ['Host: a\r\nhost: b', 'HOST: a\r\nHost: a', 'host: a\r\nhOsT: b']) {
    const r2 = await rawSocket(s.port, `GET /health HTTP/1.1\r\n${pair}\r\n\r\n`, { waitMs: 400 });
    assert.match(r2.data, /^HTTP\/1\.1 400/, `case-insensitive duplicate Host: ${JSON.stringify(pair)}`);
  }
});

test('R4-9: CR/LF/TAB in metadata values and CR in reasons are rejected (log-line forging)', () => {
  const st = new DatasetStore();
  for (const v of ['a\r\nb', 'a\nfake audit line', 'a\tb', 'a\rb']) {
    assert.throws(() => st.override('X', { metadata: { v } }, { actor: 'a', reason: 'ctl chars' }), /Invalid patch/, JSON.stringify(v));
  }
  assert.throws(() => st.override('X', { enabled: false }, { actor: 'a', reason: 'line1\r\nline2' }), /reason/);
  st.override('X', { enabled: false }, { actor: 'a', reason: 'multi\nline\treason ok' });
});

test('R4-10: signal handlers are installed before the "listening" line (instant SIGINT exits 0)', async () => {
  const env = { PATH: process.env.PATH, AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_SECRET: SECRET, PORT: '0' };
  const child = spawn(process.execPath, [require.resolve('../src/proxy.js')], { env, stdio: ['ignore', 'pipe', 'pipe'] });
  child.stdout.on('data', (d) => { if (/listening/.test(d)) child.kill('SIGINT'); });
  const code = await new Promise((r) => child.on('close', (c) => r(c)));
  assert.equal(code, 0);
});

test('R4-11 (hardening): every response carries a server-generated x-request-id; caller values are ignored', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const r = await raw(s.port, { path: '/nope', headers: { 'x-request-id': 'caller-chosen-id' } });
  assert.notEqual(r.headers['x-request-id'], 'caller-chosen-id');
  assert.match(r.headers['x-request-id'], /^[0-9a-f-]{36}$/);
  const r2 = await raw(s.port, { path: '/nope' });
  assert.notEqual(r2.headers['x-request-id'], r.headers['x-request-id'], 'unique per request');
  assert.ok(startFromEnv);
});
