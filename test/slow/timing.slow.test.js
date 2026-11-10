'use strict';
// SLOW / statistical: run via `npm run test:slow`. Not part of `npm test`.
// Coarse timing check that HMAC verification time does not depend on WHERE the forged MAC
// differs. Thresholds are deliberately loose (this is a smoke test, not a proof); the real
// guarantee is the use of crypto.timingSafeEqual, which test/sidechannel.test.js locks in.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider } = require('../../src/auth/avroneProvider');
const { sign, claims, config } = require('../helpers');

test('HS256 verify time: MAC differing in first vs last byte is statistically indistinguishable', async () => {
  const p = createAvroneProvider(config);
  const good = sign(claims());
  const [h, pl, s] = good.split('.');
  const mac = Buffer.from(s, 'base64url');
  const flip = (i) => { const m = Buffer.from(mac); m[i] ^= 1; return `${h}.${pl}.${m.toString('base64url')}`; };
  const first = flip(0); const last = flip(31);
  const N = Number(process.env.TIMING_N || 20000);
  const tFirst = []; const tLast = [];
  for (let i = 0; i < N; i++) {
    for (const [tok, arr] of i % 2 ? [[first, tFirst], [last, tLast]] : [[last, tLast], [first, tFirst]]) {
      const t0 = process.hrtime.bigint();
      try { await p.verify(tok); } catch { /* expected */ }
      arr.push(Number(process.hrtime.bigint() - t0));
    }
  }
  const median = (a) => { const b = [...a].sort((x, y) => x - y); return b[b.length >> 1]; };
  const mf = median(tFirst); const ml = median(tLast);
  const ratio = Math.max(mf, ml) / Math.min(mf, ml);
  console.log(`# median first-byte=${mf}ns last-byte=${ml}ns ratio=${ratio.toFixed(3)}`);
  assert.ok(ratio < 1.25, `timing ratio ${ratio}`);
  assert.ok(crypto.timingSafeEqual);
});
