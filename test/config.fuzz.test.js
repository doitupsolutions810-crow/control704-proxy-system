'use strict';
// Config fuzzing of every environment variable the proxy reads. For any value the startup
// path must either produce a sane config or throw a plain Error that names a variable, never
// echoes the secret/key, never throws a non-Error, and never hangs.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider, loadConfigFromEnv } = require('../src/auth/avroneProvider');
const { parsePort, parseHost, startFromEnv } = require('../src/proxy');

const SECRET = 'cfgfuzz-' + crypto.randomBytes(24).toString('hex');
const BASE = Object.freeze({ AVRONE_ISSUER: 'https://avrone-due-krey-chat.vercel.app', AVRONE_AUDIENCE: 'control704-proxy', AVRONE_JWT_SECRET: SECRET });
const VARS = ['AVRONE_ISSUER', 'AVRONE_AUDIENCE', 'AVRONE_JWT_SECRET', 'AVRONE_JWT_PUBLIC_KEY', 'AVRONE_CLOCK_SKEW_SEC', 'AVRONE_MAX_TOKEN_AGE_SEC', 'PORT', 'HOST'];
const NAMED = /AVRONE_[A-Z_]+|PORT|HOST/;

let seed = 0xC704;
const rnd = (n) => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % n; };
const ALPH = ['a', 'Z', '0', '9', '-', '.', ':', '/', ' ', '\t', '\r', '\n', '\u0000', '\u200b', '\u202e', '\ufeff', 'é', '😀', '\\n', '"', "'", '$', '{', '%', '+', 'e', '='];
const SPECIAL = ['', ' ', '0', '00', '-0', '-1', '1e3', '0x10', '1.5', 'NaN', 'Infinity', '9'.repeat(400), '9007199254740993', '65535', '65536',
  '300', '301', ' 30 ', '\t42\n', '٣٠', '３０', 'true', 'null', 'undefined', '__proto__', 'constructor', 'a'.repeat(100000),
  '-----BEGIN PUBLIC KEY-----\\nAAAA\\n-----END PUBLIC KEY-----', '-----BEGIN PRIVATE KEY-----\nMIIE\n-----END PRIVATE KEY-----', SECRET, ` ${SECRET}`];
const randomValue = () => (rnd(3) === 0 ? SPECIAL[rnd(SPECIAL.length)] : Array.from({ length: rnd(40) }, () => ALPH[rnd(ALPH.length)]).join(''));

function startup(env) {
  const cfg = loadConfigFromEnv(env);
  const provider = createAvroneProvider(cfg);
  return { cfg, provider, port: parsePort(env.PORT), host: parseHost(env.HOST) };
}

function check(env, label) {
  let out;
  try { out = startup(env); } catch (e) {
    assert.ok(e instanceof Error, `${label}: non-Error thrown`);
    assert.match(e.message, NAMED, `${label}: error does not name a variable: ${e.message}`);
    assert.ok(!e.message.includes(SECRET), `${label}: secret echoed`);
    if (env.AVRONE_JWT_PUBLIC_KEY && env.AVRONE_JWT_PUBLIC_KEY.length > 20) assert.ok(!e.message.includes(env.AVRONE_JWT_PUBLIC_KEY), `${label}: key echoed`);
    assert.ok(e.message.length < 200, `${label}: message too long`);
    return 'error';
  }
  const { cfg, port, host } = out;
  assert.ok(Number.isSafeInteger(cfg.clockSkewSec) && cfg.clockSkewSec >= 0 && cfg.clockSkewSec <= 300, label);
  assert.ok(cfg.maxTokenAgeSec === null || (Number.isSafeInteger(cfg.maxTokenAgeSec) && cfg.maxTokenAgeSec > 0), label);
  assert.ok(Number.isInteger(port) && port >= 0 && port <= 65535, label);
  assert.ok(typeof host === 'string' && host.length > 0 && host === host.trim() && !/[\s/]/.test(host), label);
  assert.equal(cfg.issuer, cfg.issuer.trim(), label);
  assert.equal(cfg.audience, cfg.audience.trim(), label);
  return 'ok';
}

test('config fuzz: every env var, 400 random values each, in isolation', () => {
  const tally = {};
  for (const name of VARS) {
    tally[name] = { ok: 0, error: 0 };
    for (let i = 0; i < 400; i++) {
      const v = randomValue();
      tally[name][check({ ...BASE, [name]: v }, `${name}=${JSON.stringify(v).slice(0, 60)}`)]++;
    }
  }
  for (const name of ['AVRONE_ISSUER', 'AVRONE_AUDIENCE', 'AVRONE_JWT_SECRET', 'AVRONE_CLOCK_SKEW_SEC', 'PORT', 'HOST']) {
    assert.ok(tally[name].error > 0, `${name} never rejected anything`);
  }
});

test('config fuzz: 2000 random combinations of all vars at once (including unset)', () => {
  for (let i = 0; i < 2000; i++) {
    const env = {};
    for (const name of VARS) if (rnd(3)) env[name] = rnd(4) ? randomValue() : BASE[name];
    check(env, `combo#${i}`);
  }
});

test('config fuzz: precise boundaries', () => {
  const expectOk = (env) => assert.equal(check({ ...BASE, ...env }, JSON.stringify(env)), 'ok', JSON.stringify(env));
  const expectErr = (env, re) => assert.throws(() => startup({ ...BASE, ...env }), re, JSON.stringify(env));
  expectOk({ AVRONE_CLOCK_SKEW_SEC: '0' }); expectOk({ AVRONE_CLOCK_SKEW_SEC: '300' }); expectOk({ AVRONE_CLOCK_SKEW_SEC: ' 30 ' });
  expectErr({ AVRONE_CLOCK_SKEW_SEC: '301' }, /AVRONE_CLOCK_SKEW_SEC/); expectErr({ AVRONE_CLOCK_SKEW_SEC: '-1' }, /AVRONE_CLOCK_SKEW_SEC/);
  expectErr({ AVRONE_CLOCK_SKEW_SEC: '３０' }, /AVRONE_CLOCK_SKEW_SEC/); expectErr({ AVRONE_CLOCK_SKEW_SEC: '1e2' }, /AVRONE_CLOCK_SKEW_SEC/);
  expectOk({ AVRONE_MAX_TOKEN_AGE_SEC: '1' }); expectOk({ AVRONE_MAX_TOKEN_AGE_SEC: String(Number.MAX_SAFE_INTEGER) });
  expectErr({ AVRONE_MAX_TOKEN_AGE_SEC: '0' }, /AVRONE_MAX_TOKEN_AGE_SEC/);
  expectErr({ AVRONE_MAX_TOKEN_AGE_SEC: '9007199254740993' }, /AVRONE_MAX_TOKEN_AGE_SEC is too large/);
  expectOk({ PORT: '0' }); expectOk({ PORT: '65535' }); expectErr({ PORT: '65536' }, /PORT/); expectErr({ PORT: '-1' }, /PORT/);
  expectErr({ HOST: 'a b' }, /HOST/); expectErr({ HOST: 'h'.repeat(254) }, /HOST/); expectOk({ HOST: 'h'.repeat(253) });
  expectErr({ AVRONE_JWT_SECRET: SECRET.slice(0, 31) }, /32 bytes/); expectErr({ AVRONE_JWT_SECRET: 'a'.repeat(64) }, /variety/);
  expectErr({ AVRONE_JWT_SECRET: '', AVRONE_JWT_PUBLIC_KEY: '' }, /AVRONE_JWT_SECRET|AVRONE_JWT_PUBLIC_KEY/);
});

test('R5-3 regression: issuer/audience with CR, padding or invisible characters are refused at startup', () => {
  for (const name of ['AVRONE_ISSUER', 'AVRONE_AUDIENCE']) {
    for (const bad of [`${BASE[name]}\r`, ` ${BASE[name]}`, `${BASE[name]}\n`, `${BASE[name]}\t`, `\ufeff${BASE[name]}`, `${BASE[name]}\u200b`, `a\u0000b`, `\u202eabc`]) {
      assert.throws(() => startup({ ...BASE, [name]: bad }), new RegExp(`${name} must not have`), JSON.stringify(bad));
    }
  }
});

test('R5-4 regression: integer env vars past 2^53 are refused instead of silently rounded', () => {
  for (const name of ['AVRONE_CLOCK_SKEW_SEC', 'AVRONE_MAX_TOKEN_AGE_SEC']) {
    assert.throws(() => startup({ ...BASE, [name]: '1'.repeat(25) }), new RegExp(name));
  }
});

test('config fuzz: startFromEnv fails fast (no listening socket left behind) for 50 random bad envs', async () => {
  let rejected = 0;
  for (let i = 0; i < 50; i++) {
    const env = { ...BASE, HOST: '127.0.0.1', PORT: '0', [VARS[i % VARS.length]]: SPECIAL[i % SPECIAL.length] };
    try {
      const inst = await startFromEnv({ env });
      await inst.close(100);
    } catch (e) {
      rejected++;
      // Listen-time failures (privileged/used port) name the host:port instead of a variable.
      assert.ok(e instanceof Error && (NAMED.test(e.message) || /127\.0\.0\.1:\d+/.test(e.message)), e.message);
      assert.ok(!e.message.includes(SECRET));
    }
  }
  assert.ok(rejected > 10);
});
