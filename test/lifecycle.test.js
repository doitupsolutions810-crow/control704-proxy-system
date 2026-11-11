'use strict';
// Lifecycle: startup from env (each variable), port conflicts, graceful shutdown with
// in-flight requests, signals, and restart semantics for in-memory state.
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const path = require('path');
const crypto = require('crypto');
const { spawn } = require('child_process');
const { startFromEnv, parsePort, parseHost } = require('../src/proxy');
const { sign, claims, raw, bearer, jsonPost, rawSocket, SECRET, ISSUER, AUDIENCE } = require('./helpers');

const ENTRY = path.join(__dirname, '..', 'src', 'proxy.js');
const GOOD = { AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_SECRET: SECRET, HOST: '127.0.0.1', PORT: '0' };
const admin = sign(claims({ roles: ['admin'] }));

function runChild(env, { untilStdout, timeoutMs = 5000, signalAfterReady } = {}) {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, [ENTRY], { env: { PATH: process.env.PATH, ...env }, stdio: ['ignore', 'pipe', 'pipe'] });
    let stdout = ''; let stderr = '';
    const timer = setTimeout(() => child.kill('SIGKILL'), timeoutMs);
    child.stdout.on('data', (d) => {
      stdout += d;
      if (signalAfterReady && untilStdout && untilStdout.test(stdout) && !child.signalled) { child.signalled = true; child.kill(signalAfterReady); }
    });
    child.stderr.on('data', (d) => { stderr += d; });
    child.on('close', (code, signal) => { clearTimeout(timer); resolve({ code, signal, stdout, stderr }); });
  });
}

// ---------- parsing ----------
test('parsePort: defaults, valid values, invalid values', () => {
  assert.equal(parsePort(undefined), 8704); assert.equal(parsePort(''), 8704);
  for (const [v, n] of [['0', 0], ['80', 80], ['65535', 65535], [' 8080 ', 8080]]) assert.equal(parsePort(v), n);
  for (const v of ['abc', '-1', '65536', '70000', '1.5', '1e3', '0x50', '80 80', '999999']) assert.throws(() => parsePort(v), /PORT/, v);
});
test('parseHost: defaults, valid values, invalid values', () => {
  assert.equal(parseHost(undefined), '127.0.0.1');
  for (const v of ['0.0.0.0', '::1', 'localhost', 'example.internal']) assert.equal(parseHost(v), v);
  for (const v of ['bad host', 'a/b', '   ', 'x'.repeat(254)]) assert.throws(() => parseHost(v), /HOST/, v);
});

// ---------- startup failures, one variable at a time (real child process) ----------
const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const STARTUP_CASES = [
  ['AVRONE_ISSUER missing', { AVRONE_ISSUER: undefined }, /AVRONE_ISSUER/],
  ['AVRONE_ISSUER empty', { AVRONE_ISSUER: '' }, /AVRONE_ISSUER/],
  ['AVRONE_AUDIENCE missing', { AVRONE_AUDIENCE: undefined }, /AVRONE_AUDIENCE/],
  ['no secret and no public key', { AVRONE_JWT_SECRET: undefined }, /AVRONE_JWT_SECRET|AVRONE_JWT_PUBLIC_KEY/],
  ['AVRONE_JWT_SECRET too short', { AVRONE_JWT_SECRET: 'short-secret-1234' }, /32 bytes/],
  ['AVRONE_JWT_SECRET whitespace', { AVRONE_JWT_SECRET: ' '.repeat(48) }, /blank|whitespace/],
  ['AVRONE_JWT_SECRET low variety', { AVRONE_JWT_SECRET: 'a'.repeat(48) }, /variety/],
  ['AVRONE_JWT_PUBLIC_KEY garbage', { AVRONE_JWT_SECRET: undefined, AVRONE_JWT_PUBLIC_KEY: 'not a pem' }, /AVRONE_JWT_PUBLIC_KEY/],
  ['AVRONE_JWT_PUBLIC_KEY is a private key', { AVRONE_JWT_SECRET: undefined, AVRONE_JWT_PUBLIC_KEY: privateKey.export({ type: 'pkcs8', format: 'pem' }).replace(/\n/g, '\\n') }, /PRIVATE key/],
  ['AVRONE_CLOCK_SKEW_SEC not a number', { AVRONE_CLOCK_SKEW_SEC: 'abc' }, /AVRONE_CLOCK_SKEW_SEC/],
  ['AVRONE_CLOCK_SKEW_SEC out of range', { AVRONE_CLOCK_SKEW_SEC: '9999' }, /AVRONE_CLOCK_SKEW_SEC/],
  ['AVRONE_MAX_TOKEN_AGE_SEC invalid', { AVRONE_MAX_TOKEN_AGE_SEC: '-5' }, /AVRONE_MAX_TOKEN_AGE_SEC/],
  ['AVRONE_MAX_TOKEN_AGE_SEC zero', { AVRONE_MAX_TOKEN_AGE_SEC: '0' }, /AVRONE_MAX_TOKEN_AGE_SEC/],
  ['PORT not a number', { PORT: 'http' }, /PORT/],
  ['PORT out of range', { PORT: '70000' }, /PORT/],
  ['HOST invalid', { HOST: 'bad host' }, /HOST/],
  ['HOST not resolvable', { HOST: 'no-such-host.invalid' }, /HOST|listen/],
];
for (const [name, patch, re] of STARTUP_CASES) {
  test(`startup fails cleanly: ${name}`, async () => {
    const env = { ...GOOD, ...patch };
    for (const k of Object.keys(env)) if (env[k] === undefined) delete env[k];
    const r = await runChild(env);
    assert.equal(r.code, 1, `exit code (stderr: ${r.stderr})`);
    assert.match(r.stderr, /^control704: startup failed: /);
    assert.match(r.stderr, re);
    assert.ok(!/\n\s+at /.test(r.stderr), 'no stack trace');
    assert.ok(!r.stderr.includes(SECRET), 'secret value never printed');
    if (patch.AVRONE_JWT_SECRET) assert.ok(!r.stderr.includes(patch.AVRONE_JWT_SECRET.trim() || '\u0000'), 'bad secret value never printed');
    assert.ok(!r.stderr.includes('PRIVATE KEY-----\n'), 'key material never printed');
    assert.equal(r.stdout, '');
  });
}
test('startup succeeds with a valid env; SIGTERM shuts down gracefully with exit 0', async () => {
  const r = await runChild(GOOD, { untilStdout: /listening on/, signalAfterReady: 'SIGTERM' });
  assert.match(r.stdout, /Control704 proxy listening on http:\/\/127\.0\.0\.1:\d+/);
  assert.match(r.stdout, /Received SIGTERM, shutting down gracefully/);
  assert.equal(r.code, 0);
  assert.equal(r.stderr, '');
});
test('SIGINT is handled the same way', async () => {
  const r = await runChild(GOOD, { untilStdout: /listening on/, signalAfterReady: 'SIGINT' });
  assert.equal(r.code, 0);
  assert.match(r.stdout, /SIGINT/);
});

// ---------- port in use ----------
test('port in use: child exits 1 with a clear message; in-process start rejects', async () => {
  const blocker = net.createServer();
  await new Promise((r) => blocker.listen(0, '127.0.0.1', r));
  const port = String(blocker.address().port);
  try {
    const r = await runChild({ ...GOOD, PORT: port });
    assert.equal(r.code, 1);
    assert.match(r.stderr, new RegExp(`Port ${port} on 127\\.0\\.0\\.1 is already in use`));
    await assert.rejects(startFromEnv({ env: { ...GOOD, PORT: port } }), /already in use/);
  } finally { blocker.close(); }
});
test('two proxies cannot share a port; the first keeps serving', async () => {
  const a = await startFromEnv({ env: GOOD });
  try {
    await assert.rejects(startFromEnv({ env: { ...GOOD, PORT: String(a.port) } }), /already in use/);
    assert.equal((await raw(a.port, { path: '/health' })).status, 200);
  } finally { await a.close(500); }
});

// ---------- graceful shutdown ----------
test('graceful shutdown: in-flight request completes, new connections refused, close resolves', async () => {
  const inst = await startFromEnv({ env: GOOD });
  const body = JSON.stringify({ patch: { metadata: { inflight: 'yes' } }, reason: 'in flight' });
  const sock = net.connect(inst.port, '127.0.0.1');
  await new Promise((r) => sock.on('connect', r));
  let data = '';
  sock.on('data', (d) => { data += d; });
  sock.write(`POST /admin/datasets/X/overrides HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\n\r\n${body.slice(0, 10)}`);
  await new Promise((r) => setTimeout(r, 50));
  let closed = false;
  const closing = inst.close(3000).then(() => { closed = true; });
  await new Promise((r) => setTimeout(r, 50));
  await assert.rejects(raw(inst.port, { path: '/health' }), (e) => /ECONNREFUSED|ECONNRESET/.test(e.code || e.message));
  assert.equal(closed, false, 'must wait for the in-flight request');
  sock.write(body.slice(10));
  await closing;
  assert.match(data, /^HTTP\/1\.1 201/);
  assert.equal(inst.app.store.get('X').metadata.inflight, 'yes');
  sock.destroy();
});
test('graceful shutdown: idle keep-alive connections are closed immediately (close does not wait for them)', async () => {
  const inst = await startFromEnv({ env: GOOD });
  const sock = net.connect(inst.port, '127.0.0.1');
  await new Promise((r) => sock.on('connect', r));
  sock.write('GET /health HTTP/1.1\r\nHost: x\r\n\r\n');
  await new Promise((r) => sock.once('data', r));
  const t0 = Date.now();
  await inst.close(5000);
  assert.ok(Date.now() - t0 < 1000, `close took ${Date.now() - t0}ms`);
  sock.destroy();
});
test('graceful shutdown: a stuck request is force-closed after the grace period', async () => {
  const inst = await startFromEnv({ env: GOOD });
  const sock = net.connect(inst.port, '127.0.0.1');
  await new Promise((r) => sock.on('connect', r));
  let sockClosed = false;
  sock.on('close', () => { sockClosed = true; }); sock.on('error', () => {});
  sock.write(`POST /admin/datasets/X/overrides HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\nContent-Type: application/json\r\nContent-Length: 100\r\n\r\n{`);
  await new Promise((r) => setTimeout(r, 50));
  const t0 = Date.now();
  await inst.close(300);
  const took = Date.now() - t0;
  assert.ok(took >= 250 && took < 2000, `took ${took}ms`);
  await new Promise((r) => setTimeout(r, 50));
  assert.ok(sockClosed);
});
test('close() is idempotent (same promise, no throw on double close)', async () => {
  const inst = await startFromEnv({ env: GOOD });
  const a = inst.close(500); const b = inst.close(500);
  assert.equal(a, b);
  await a;
});

// ---------- restart semantics ----------
test('restart semantics (documented): in-memory overrides, history and audit do NOT survive a restart', async () => {
  const first = await startFromEnv({ env: GOOD });
  const r = await raw(first.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, { patch: { enabled: false, rateLimitPerMinute: 3 }, reason: 'pre restart' }) });
  assert.equal(r.status, 201);
  assert.ok(first.app.audit.stats().seq > 0);
  await first.close(500);
  const second = await startFromEnv({ env: GOOD });
  try {
    const ds = (await raw(second.port, { path: '/datasets/X', headers: bearer(admin) })).json;
    assert.equal(ds.enabled, true); assert.equal(ds.rateLimitPerMinute, 60);
    assert.equal((await raw(second.port, { path: '/admin/datasets/X/overrides', headers: bearer(admin) })).json.length, 0);
    assert.equal((await raw(second.port, { method: 'POST', path: `/admin/overrides/${r.json.id}/revert`, headers: bearer(admin) })).status, 404, 'old override ids are unknown after restart');
    const auditTypes = (await raw(second.port, { path: '/admin/audit', headers: bearer(admin) })).json.map((e) => e.type);
    assert.ok(!auditTypes.includes('dataset.override'));
  } finally { await second.close(500); }
});
test('restart semantics: tokens issued before a restart remain valid after it (stateless auth)', async () => {
  const tok = sign(claims({ roles: ['technician'] }));
  const a = await startFromEnv({ env: GOOD });
  assert.equal((await raw(a.port, { path: '/proxy/x', headers: bearer(tok) })).status, 200);
  await a.close(500);
  const b = await startFromEnv({ env: GOOD });
  try { assert.equal((await raw(b.port, { path: '/proxy/x', headers: bearer(tok) })).status, 200); } finally { await b.close(500); }
});
test('restart with a rotated secret invalidates old tokens', async () => {
  const tok = sign(claims({ roles: ['technician'] }));
  const b = await startFromEnv({ env: { ...GOOD, AVRONE_JWT_SECRET: crypto.randomBytes(32).toString('hex') } });
  try { assert.equal((await raw(b.port, { path: '/proxy/x', headers: bearer(tok) })).status, 401); } finally { await b.close(500); }
});
test('startFromEnv applies server option defaults (timeouts, caps) to the real listener', async () => {
  const inst = await startFromEnv({ env: GOOD });
  try {
    assert.equal(inst.server.requestTimeout, 15000);
    assert.equal(inst.server.maxConnections, 1024);
    assert.equal(inst.server.maxHeadersCount, 101, 'header parsing bounded just above the 431 threshold');
    assert.ok(rawSocket);
  } finally { await inst.close(500); }
});

const { describeListenError } = require('../src/proxy');
test('describeListenError: every listen() error code maps to a short, stack-free message', () => {
  const m = (code) => describeListenError(Object.assign(new Error(`listen ${code} secret-internal`), { code }), 'h', 1);
  assert.equal(m('EADDRINUSE'), 'Port 1 on h is already in use');
  assert.equal(m('EACCES'), 'Permission denied listening on h:1');
  for (const c of ['EADDRNOTAVAIL', 'ENOTFOUND', 'EAI_AGAIN']) assert.equal(m(c), 'Cannot listen on HOST h');
  assert.equal(m('EMFILE'), 'Failed to listen on h:1: EMFILE');
  assert.equal(describeListenError(new Error('boom'), 'h', 1), 'Failed to listen on h:1: boom');
  assert.equal(describeListenError(undefined, 'h', 1), 'Failed to listen on h:1: unknown error');
});
