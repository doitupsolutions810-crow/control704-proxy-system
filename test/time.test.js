'use strict';
// Fake-clock tests: expiry boundaries, clock jumps, leap-second-like edges, slow requests.
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { sign, claims, config, fakeClock, startServer, raw, bearer } = require('./helpers');

const T = 1_800_000_000; // fixed epoch seconds for deterministic tests
const mk = (clock, extra = {}) => createAvroneProvider({ ...config, now: clock.now, ...extra });
const tok = (c) => sign({ iss: config.issuer, aud: config.audience, sub: 'u', iat: T, exp: T + 60, ...c });
const ok = async (p, t) => assert.ok(await p.verify(t));
const no = (p, t, re) => assert.rejects(p.verify(t), re);

test('expiry boundary at millisecond resolution (skew 0)', async () => {
  const c = fakeClock(); const p = mk(c); const t = tok();
  c.set((T + 60) * 1000 - 1); await ok(p, t);
  c.set((T + 60) * 1000); await no(p, t, /expired/);
  c.set((T + 60) * 1000 + 1); await no(p, t, /expired/);
});
for (const skew of [1, 30, 300]) {
  test(`expiry boundary with clock skew ${skew}s`, async () => {
    const c = fakeClock(); const p = mk(c, { clockSkewSec: skew }); const t = tok();
    c.set((T + 60 + skew) * 1000 - 1); await ok(p, t);
    c.set((T + 60 + skew) * 1000); await no(p, t, /expired/);
  });
  test(`nbf boundary with clock skew ${skew}s`, async () => {
    const c = fakeClock(); const p = mk(c, { clockSkewSec: skew }); const t = tok({ nbf: T + 100, exp: T + 1000 });
    c.set((T + 100 - skew) * 1000 - 1); await no(p, t, /not yet valid/);
    c.set((T + 100 - skew) * 1000); await ok(p, t);
  });
  test(`iat-in-future boundary with clock skew ${skew}s`, async () => {
    const c = fakeClock(); const p = mk(c, { clockSkewSec: skew }); const t = tok({ iat: T + 100, exp: T + 1000 });
    c.set((T + 100 - skew) * 1000 - 1); await no(p, t, /future/);
    c.set((T + 100 - skew) * 1000); await ok(p, t);
  });
}
test('max token age boundary at ms resolution', async () => {
  const c = fakeClock(); const p = mk(c, { maxTokenAgeSec: 120 }); const t = tok({ exp: T + 10000 });
  c.set((T + 120) * 1000); await ok(p, t);
  c.set((T + 120) * 1000 + 1); await no(p, t, /too old/);
});
test('clock jumps forward past exp -> rejected; jumps back -> accepted again (stateless, documented)', async () => {
  const c = fakeClock(T * 1000); const p = mk(c); const t = tok();
  await ok(p, t);
  c.advance(3600 * 1000); await no(p, t, /expired/);
  c.advance(-3600 * 1000); await ok(p, t);
});
test('clock jumps backwards before iat -> "issued in the future" (beyond skew)', async () => {
  const c = fakeClock(T * 1000); const p = mk(c, { clockSkewSec: 30 }); const t = tok();
  c.advance(-29 * 1000); await ok(p, t);
  c.advance(-2 * 1000); await no(p, t, /future/);
});
test('clock jumps backwards before nbf -> not yet valid', async () => {
  const c = fakeClock(T * 1000); const p = mk(c); const t = tok({ nbf: T });
  await ok(p, t);
  c.advance(-1); await no(p, t, /not yet valid/);
});
test('large backwards jump (NTP correction of days) rejects freshly issued tokens', async () => {
  const c = fakeClock((T - 86400 * 3) * 1000); const p = mk(c, { clockSkewSec: 300 });
  await no(p, tok(), /future/);
});
test('leap-second-like boundary: last ms of 23:59:59 vs 00:00:00 (2016-12-31 leap second)', async () => {
  const MIDNIGHT = 1483228800; // 2017-01-01T00:00:00Z, the second after the 2016 leap second
  const c = fakeClock(); const p = mk(c);
  const t = sign({ iss: config.issuer, aud: config.audience, sub: 'u', iat: MIDNIGHT - 100, exp: MIDNIGHT });
  c.set(MIDNIGHT * 1000 - 1); await ok(p, t); // 23:59:59.999
  c.set(MIDNIGHT * 1000); await no(p, t, /expired/); // 00:00:00.000
});
test('leap-second smear / repeated second (clock steps back 1s at 23:59:60): token valid again during the repeat', async () => {
  const E = 1483228800;
  const c = fakeClock(); const p = mk(c);
  const t = sign({ iss: config.issuer, aud: config.audience, sub: 'u', iat: E - 100, exp: E + 0.5 });
  c.set(E * 1000 + 400); await ok(p, t);
  c.set(E * 1000 + 600); await no(p, t, /expired/);
  c.set(E * 1000 - 400); await ok(p, t); // the repeated second
});
test('fractional exp/nbf/iat honoured exactly', async () => {
  const c = fakeClock(); const p = mk(c);
  const t = tok({ iat: T + 0.25, nbf: T + 0.5, exp: T + 0.75 });
  c.set(T * 1000 + 499); await no(p, t, /not yet valid/);
  c.set(T * 1000 + 500); await ok(p, t);
  c.set(T * 1000 + 749); await ok(p, t);
  c.set(T * 1000 + 750); await no(p, t, /expired/);
});
test('extreme timestamps: year-2038, 2^53, negative and zero exp', async () => {
  const c = fakeClock(T * 1000); const p = mk(c);
  await ok(p, tok({ exp: 2147483647 }));
  await ok(p, tok({ exp: 2 ** 53 }));
  await no(p, tok({ exp: 0 }), /expired/);
  await no(p, tok({ exp: -1 }), /expired/);
  await no(p, tok({ exp: -1e308 }), /expired/);
  await ok(p, tok({ iat: 0 }));
  await no(p, tok({ nbf: 2 ** 53 }), /not yet valid/);
});
for (const bad of [() => NaN, () => Infinity, () => undefined, () => 'now']) {
  test(`broken clock (${bad()}) -> tokens rejected, never accepted`, async () => {
    const p = createAvroneProvider({ ...config, now: bad });
    await assert.rejects(p.verify(tok()), /Clock unavailable/);
  });
}
test('config.now must be a function', () => {
  assert.throws(() => createAvroneProvider({ ...config, now: 123 }), /now must be a function/);
});

test('HTTP: token expiring DURING a slow body upload — auth is evaluated once at request start (documented)', async (t) => {
  const c = fakeClock((T + 59) * 1000);
  const s = await startServer({ provider: mk(c) });
  t.after(() => s.close());
  const token = tok({ roles: ['admin'] });
  const body = JSON.stringify({ patch: { metadata: { slow: 'yes' } }, reason: 'slow upload' });
  const res = await new Promise((resolve, reject) => {
    const sock = net.connect(s.port, '127.0.0.1', () => {
      sock.write(`POST /admin/datasets/X/overrides HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${token}\r\nContent-Type: application/json\r\nContent-Length: ${body.length}\r\nConnection: close\r\n\r\n`);
      setTimeout(() => {
        c.advance(10 * 1000); // token now expired
        sock.write(body.slice(0, 10));
        setTimeout(() => sock.write(body.slice(10)), 30);
      }, 50);
    });
    let d = '';
    sock.on('data', (x) => { d += x; });
    sock.on('end', () => resolve(d));
    sock.on('error', reject);
  });
  assert.match(res, /^HTTP\/1\.1 201/);
  // ...but the next request with the same token is rejected
  assert.equal((await raw(s.port, { path: '/admin/audit', headers: bearer(token) })).status, 401);
});
test('HTTP: concurrent requests straddling expiry are decided individually', async (t) => {
  const c = fakeClock((T + 59) * 1000);
  const s = await startServer({ provider: mk(c) });
  t.after(() => s.close());
  const token = tok({ roles: ['viewer'] });
  const before = await Promise.all(Array.from({ length: 10 }, () => raw(s.port, { path: '/datasets', headers: bearer(token) })));
  c.advance(1000);
  const after = await Promise.all(Array.from({ length: 10 }, () => raw(s.port, { path: '/datasets', headers: bearer(token) })));
  assert.ok(before.every((r) => r.status === 200));
  assert.ok(after.every((r) => r.status === 401 && r.json.reason === 'token_expired'));
});
