'use strict';
// Property / fuzz-style tests. Deterministic: seeded PRNG (override with FUZZ_SEED=<n>).
const test = require('node:test');
const assert = require('node:assert');
const { createAvroneProvider, AuthError } = require('../src/auth/avroneProvider');
const { toPrincipal } = require('../src/auth');
const { effectiveScopes, ROLE_SCOPES } = require('../src/access/authorize');
const { DatasetStore, ValidationError, NotFoundError, DEFAULTS } = require('../src/datasets/store');
const { sign, claims, config, rng, SEED, startServer, raw, bearer } = require('./helpers');

const B64URL = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const ANY = B64URL + '.+/=% \u0000é😀\n"{}[]:,';
const provider = createAvroneProvider(config);
const ITER = Number.parseInt(process.env.FUZZ_ITER || '400', 10);

test(`fuzz [seed ${SEED}]: random strings never verify and only ever throw AuthError`, async () => {
  const r = rng(SEED);
  for (let i = 0; i < ITER * 2; i++) {
    const t = r.str(r.int(0, 300), r() < 0.5 ? B64URL + '.' : ANY);
    await assert.rejects(provider.verify(t), (e) => e instanceof AuthError, `input #${i}: ${JSON.stringify(t).slice(0, 80)}`);
  }
});

test(`fuzz [seed ${SEED}]: single-character mutation of a valid token is always rejected`, async () => {
  const r = rng(SEED + 1);
  const valid = sign(claims({ roles: ['admin'], scope: 'datasets:override' }));
  let rejected = 0;
  for (let i = 0; i < ITER; i++) {
    const pos = r.int(0, valid.length - 1);
    let ch = r.pick(B64URL);
    if (ch === valid[pos]) ch = valid[pos] === 'A' ? 'B' : 'A';
    const mutated = valid.slice(0, pos) + ch + valid.slice(pos + 1);
    if (valid[pos] === '.') continue;
    await assert.rejects(provider.verify(mutated), (e) => e instanceof AuthError, `pos ${pos} -> ${ch}`);
    rejected++;
  }
  assert.ok(rejected > ITER * 0.9);
});

test(`fuzz [seed ${SEED}]: segment swaps / drops / duplications are rejected`, async () => {
  const r = rng(SEED + 2);
  const [h, p, s] = sign(claims()).split('.');
  const other = sign(claims({ sub: 'other' })).split('.');
  for (let i = 0; i < ITER / 4; i++) {
    const segs = [h, p, s, other[0], other[1], other[2], ''];
    const n = r.int(1, 5);
    const parts = Array.from({ length: n }, () => r.pick(segs));
    const t = parts.join('.');
    if (t === `${h}.${p}.${s}` || t === other.join('.')) continue;
    if (n === 3 && parts[0] === h && parts[1] === other[1] && parts[2] === other[2]) continue; // same header => valid other token
    if (n === 3 && parts[0] === other[0] && parts[1] === p && parts[2] === s) continue;
    await assert.rejects(provider.verify(t), AuthError, t);
  }
});

test(`fuzz [seed ${SEED}]: random claim sets — accepted iff all invariants hold`, async () => {
  const r = rng(SEED + 3);
  const now = Math.floor(Date.now() / 1000);
  const values = {
    iss: [config.issuer, 'evil', '', null, 1, [config.issuer]],
    aud: [config.audience, [config.audience], ['x', config.audience], 'x', [], null, 7],
    sub: ['u', 'a'.repeat(256), 'a'.repeat(257), '', null, 1, ['u'], 'a\u0000'],
    exp: [now + 100, now - 100, now, 'x', null, undefined],
    nbf: [undefined, now - 10, now + 100, 'x'],
    iat: [undefined, now - 10, now + 100, 'x'],
  };
  for (let i = 0; i < ITER; i++) {
    const c = {};
    for (const [k, opts] of Object.entries(values)) { const v = r.pick(opts); if (v !== undefined) c[k] = v; }
    const expectOk = c.iss === config.issuer
      && (c.aud === config.audience || (Array.isArray(c.aud) && c.aud.includes(config.audience)))
      && typeof c.sub === 'string' && c.sub.length > 0 && c.sub.length <= 256 && !/\u0000/.test(c.sub)
      && typeof c.exp === 'number' && c.exp > now + 1
      && (c.nbf === undefined || (typeof c.nbf === 'number' && c.nbf <= now))
      && (c.iat === undefined || (typeof c.iat === 'number' && c.iat <= now));
    const t = sign(c);
    if (expectOk) assert.equal((await provider.verify(t)).sub, c.sub, JSON.stringify(c));
    else await assert.rejects(provider.verify(t), AuthError, JSON.stringify(c));
  }
});

test(`fuzz [seed ${SEED}]: effective scopes are always a subset of (direct scopes ∪ known role scopes)`, () => {
  const r = rng(SEED + 4);
  const roleNames = [...Object.keys(ROLE_SCOPES), '__proto__', 'constructor', 'toString', 'root', 'Admin', '', 'valueOf'];
  const scopeNames = ['proxy:read', 'proxy:x', 'datasets:override', '*', 'datasets:*', 'PROXY:X', 'audit:read'];
  for (let i = 0; i < ITER; i++) {
    const roles = Array.from({ length: r.int(0, 4) }, () => (r() < 0.1 ? r.int(0, 9) : r.pick(roleNames)));
    const scopes = Array.from({ length: r.int(0, 4) }, () => r.pick(scopeNames));
    const p = toPrincipal({ sub: 's', roles, scope: scopes.join(' ') }, 't');
    const eff = effectiveScopes(p);
    const allowed = new Set(scopes);
    for (const role of roles) if (Object.prototype.hasOwnProperty.call(ROLE_SCOPES, role)) ROLE_SCOPES[role].forEach((x) => allowed.add(x));
    for (const s of eff) assert.ok(allowed.has(s), `${s} from ${JSON.stringify({ roles, scopes })}`);
    for (const s of allowed) assert.ok(eff.has(s));
  }
});

function randomValue(r, depth = 0) {
  const kind = r.int(0, depth > 2 ? 6 : 8);
  switch (kind) {
    case 0: return r.int(-20000, 20000);
    case 1: return r() * 1e5;
    case 2: return r.str(r.int(0, 30), ANY);
    case 3: return r() < 0.5;
    case 4: return null;
    case 5: return r.pick([NaN, Infinity, -Infinity, 0, 1, 10000, 10001, 2 ** 53]);
    case 6: return r.pick(['/proxy/a', '/proxy/x', '/proxy/y', '/proxy/../x', 'https://ok.example', 'javascript:x', 'https://u:p@h', '/proxy/a//b']);
    case 7: return Array.from({ length: r.int(0, 3) }, () => randomValue(r, depth + 1));
    default: {
      const o = {};
      for (let i = r.int(0, 4); i > 0; i--) o[r.pick(['a', 'b', '__proto__', 'constructor', 'k.1', 'bad key', r.str(3, B64URL)])] = randomValue(r, depth + 1);
      return o;
    }
  }
}

test(`fuzz [seed ${SEED}]: random patches — store invariants always hold`, () => {
  const r = rng(SEED + 5);
  const s = new DatasetStore();
  const fields = ['endpoint', 'enabled', 'upstream', 'rateLimitPerMinute', 'metadata', 'auth', '__proto__', 'constructor', 'junk'];
  let accepted = 0;
  for (let i = 0; i < ITER * 2; i++) {
    const id = r.pick(['X', 'Y', 'Z', 'x', 'W', '__proto__']);
    const patch = {};
    for (let k = r.int(0, 3); k > 0; k--) {
      const f = r.pick(fields);
      Object.defineProperty(patch, f, { value: randomValue(r), enumerable: true, configurable: true, writable: true });
    }
    const snapshot = JSON.stringify(s.all());
    const histLen = s.listOverrides().length;
    try {
      s.override(id, patch, { actor: 'fuzz', reason: `fuzz ${i}` });
      accepted++;
    } catch (e) {
      assert.ok(e instanceof ValidationError || e instanceof NotFoundError, `unexpected ${e.name}: ${e.message}`);
      assert.equal(JSON.stringify(s.all()), snapshot, 'failed override mutated state');
      assert.equal(s.listOverrides().length, histLen);
    }
    // invariants
    const all = s.all();
    const eps = Object.values(all).map((d) => d.endpoint);
    assert.equal(new Set(eps).size, 3, 'endpoint collision');
    for (const k of ['X', 'Y', 'Z']) {
      assert.equal(all[k].auth, DEFAULTS[k].auth, 'auth changed');
      assert.ok(Number.isInteger(all[k].rateLimitPerMinute) && all[k].rateLimitPerMinute >= 1 && all[k].rateLimitPerMinute <= 10000);
      assert.equal(typeof all[k].enabled, 'boolean');
      assert.match(all[k].endpoint, /^\/proxy\/[a-z0-9]/);
      assert.ok(!all[k].endpoint.includes('..') && !all[k].endpoint.includes('//'));
      assert.deepEqual(Object.keys(all[k]).sort(), Object.keys(DEFAULTS[k]).sort(), 'unexpected fields');
    }
    assert.equal(({}).auth, undefined);
  }
  // Fully reverting everything (newest first, skipping blocked) restores defaults.
  let progress = true;
  while (progress) {
    progress = false;
    for (const rec of [...s.listOverrides()].reverse()) {
      if (rec.revertedAt) continue;
      try { s.revert(rec.id, { actor: 'fuzz' }); progress = true; } catch (e) { assert.ok(e instanceof ValidationError); }
    }
  }
  assert.deepEqual(s.all(), JSON.parse(JSON.stringify(DEFAULTS)), `accepted=${accepted}`);
  assert.ok(accepted > 0, 'fuzzer produced no valid patches');
});

test(`fuzz [seed ${SEED}]: random override/revert interleavings — revert always restores the exact prior state`, () => {
  const r = rng(SEED + 6);
  const s = new DatasetStore();
  const stack = { X: [], Y: [], Z: [] };
  for (let i = 0; i < ITER; i++) {
    const id = r.pick(['X', 'Y', 'Z']);
    if (r() < 0.6 || stack[id].length === 0) {
      const before = s.get(id);
      const rec = s.override(id, { rateLimitPerMinute: r.int(1, 10000), enabled: r() < 0.5, metadata: { i } }, { actor: 'a', reason: 'interleave' });
      assert.deepEqual(rec.before, before);
      stack[id].push({ id: rec.id, before });
    } else {
      // reverting a non-top entry must fail
      if (stack[id].length > 1) assert.throws(() => s.revert(stack[id][0].id, { actor: 'a' }), /Revert newer/);
      const top = stack[id].pop();
      s.revert(top.id, { actor: 'a' });
      assert.deepEqual(s.get(id), top.before);
    }
  }
});

test(`fuzz [seed ${SEED}]: HTTP — random methods/paths/headers never produce 500 and server stays healthy`, async () => {
  const srv = await startServer();
  try {
    const r = rng(SEED + 7);
    const admin = sign(claims({ roles: ['admin'] }));
    const paths = ['/health', '/proxy/x', '/proxy/Y', '/datasets', '/datasets/Z', '/datasets/__proto__', '/admin/audit', '/admin/datasets/X/overrides', '/admin/overrides/00000000-0000-0000-0000-000000000000/revert', '/nope', '/proxy/../admin/audit', '/admin%2Faudit'];
    const methods = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];
    const auths = [undefined, '', `Bearer ${admin}`, `bearer ${admin}`, 'Bearer junk', 'Basic x', `Bearer ${admin}x`, `Bearer  ${admin}`];
    const cts = [undefined, 'application/json', 'text/plain', 'application/json; charset=utf-8'];
    const statuses = new Map();
    for (let i = 0; i < ITER / 2; i++) {
      const headers = {};
      const a = r.pick(auths); if (a !== undefined) headers.authorization = a;
      const ct = r.pick(cts); if (ct) headers['content-type'] = ct;
      const method = r.pick(methods);
      const path = r.pick(paths) + (r() < 0.2 ? `?q=${r.str(5, B64URL)}` : '');
      let body;
      if (method === 'POST' || method === 'PUT') body = r() < 0.5 ? JSON.stringify(randomValue(r)) ?? '' : r.str(r.int(0, 50), ANY);
      const res = await raw(srv.port, { method, path, headers, body });
      assert.ok(res.status < 500 || res.status === 503, `${method} ${path} -> ${res.status} ${res.text}`);
      statuses.set(res.status, (statuses.get(res.status) || 0) + 1);
    }
    assert.equal((await raw(srv.port, { path: '/health' })).status, 200);
    assert.ok(statuses.size >= 4, `low status diversity: ${[...statuses.keys()]}`);
    assert.ok(!/eyJ[A-Za-z0-9_-]{5,}/.test(srv.lines.join('\n')), 'token leaked into audit log');
  } finally { await srv.close(); }
});
