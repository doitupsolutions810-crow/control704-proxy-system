'use strict';
// Cross-dataset invariants under random concurrent interleavings.
// Requests are fired in Promise.all batches; bodies arrive in randomly delayed chunks so
// auth, body parsing and store mutations of different requests genuinely interleave.
// After every batch: endpoint uniqueness, state == last active record, ids unique, and
// history/status bookkeeping consistent. Global newest-first revert restores the defaults
// when no reverts were interleaved; otherwise it may be refused (endpoint clash) but never
// corrupts state.
const test = require('node:test');
const assert = require('node:assert');
const { Readable } = require('stream');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { createApp } = require('../src/server');
const { createAuditLogger } = require('../src/access/audit');
const { DatasetStore, DEFAULTS } = require('../src/datasets/store');
const { sign, claims, config, rng, SEED, startServer, raw, bearer, jsonPost } = require('./helpers');

const admin = sign(claims({ sub: 'inv-admin', roles: ['admin'] }));
const ENDPOINTS = ['/proxy/x', '/proxy/y', '/proxy/z', '/proxy/a', '/proxy/b'];

function call(app, { method, url, body }, r) {
  return new Promise((resolve, reject) => {
    const parts = [];
    if (body !== undefined) {
      const buf = Buffer.from(body);
      let i = 0;
      while (i < buf.length) { const n = r.int(1, Math.max(1, Math.ceil(buf.length / 3))); parts.push(buf.subarray(i, i + n)); i += n; }
    }
    async function* gen() { for (const p of parts) { await new Promise((res) => (r() < 0.5 ? setImmediate(res) : setTimeout(res, r.int(0, 3)))); yield p; } }
    const req = Readable.from(gen());
    const headers = { authorization: `Bearer ${admin}` };
    const rawHeaders = ['Authorization', headers.authorization];
    if (body !== undefined) { headers['content-type'] = 'application/json'; rawHeaders.push('Content-Type', 'application/json'); }
    Object.assign(req, { method, url, headers, rawHeaders, socket: null, httpVersionMajor: 1 });
    let status = null;
    const res = { writeHead(s) { status = s; }, setHeader() {}, end(p) { resolve({ status, json: JSON.parse(p) }); }, on() {} };
    Promise.resolve(app.handle(req, res)).catch(reject);
  });
}

function checkInvariants(store, created) {
  const all = store.all();
  const eps = ['X', 'Y', 'Z'].map((k) => all[k].endpoint);
  assert.equal(new Set(eps).size, 3, `endpoint collision: ${eps}`);
  const hist = store.listOverrides();
  assert.equal(new Set(hist.map((h) => h.id)).size, hist.length, 'duplicate override ids');
  assert.equal(hist.length, created.size, 'history length != number of 201 responses');
  for (const k of ['X', 'Y', 'Z']) {
    const active = hist.filter((h) => h.dataset === k && !h.revertedAt);
    const expected = active.length ? active[active.length - 1].after : DEFAULTS[k];
    assert.deepEqual(all[k], JSON.parse(JSON.stringify(expected)), `${k} state != last active record`);
    assert.equal(all[k].auth, DEFAULTS[k].auth);
    for (let i = 1; i < active.length; i++) assert.deepEqual(active[i].before, active[i - 1].after, `${k} active chain broken`);
  }
}

async function chaos(seed, { batches = 25, batchSize = 12 } = {}) {
  const r = rng(seed);
  const store = new DatasetStore(undefined, { maxHistory: 100000 });
  const app = createApp({ provider: createAvroneProvider(config), store, audit: createAuditLogger({ sink: () => {} }) });
  const created = new Set();
  const statuses = new Map();
  for (let b = 0; b < batches; b++) {
    const ops = Array.from({ length: batchSize }, () => {
      const ds = r.pick(['X', 'Y', 'Z']);
      const ids = [...created];
      if (r() < 0.35 && ids.length) return { method: 'POST', url: `/admin/overrides/${r.pick(ids)}/revert` };
      const patch = {};
      if (r() < 0.6) patch.endpoint = r.pick(ENDPOINTS);
      if (r() < 0.5) patch.enabled = r() < 0.5;
      if (r() < 0.5 || !Object.keys(patch).length) patch.rateLimitPerMinute = r.int(1, 10000);
      return { method: 'POST', url: `/admin/datasets/${ds}/overrides`, body: JSON.stringify({ patch, reason: `chaos ${seed}/${b}` }) };
    });
    const results = await Promise.all(ops.map((o) => call(app, o, r)));
    for (const res of results) {
      statuses.set(res.status, (statuses.get(res.status) || 0) + 1);
      assert.ok([200, 201, 400].includes(res.status), `unexpected ${res.status} ${JSON.stringify(res.json)}`);
      if (res.status === 201) created.add(res.json.id);
    }
    checkInvariants(store, created);
  }
  return { store, created, statuses };
}

const SEEDS = (process.env.INV_SEEDS || `${SEED},11,22,33,44`).split(',').map(Number);
for (const seed of SEEDS) {
  test(`concurrent chaos [seed ${seed}]: invariants hold after every Promise.all batch`, async () => {
    const { statuses } = await chaos(seed);
    assert.ok(statuses.get(201) > 10, 'too few successful overrides to be meaningful');
    assert.ok((statuses.get(400) || 0) > 0, 'expected some endpoint collisions / LIFO rejections');
  });
}

test('global newest-first revert after chaos: each step either succeeds or is refused ONLY for an endpoint clash, and a refusal changes nothing', async () => {
  // Note: "always restores the defaults" is NOT a valid invariant once reverts happened out of
  // order across datasets (see the characterisation test below) — uniqueness wins over revertibility.
  for (const seed of SEEDS.slice(0, 3)) {
    const { store, created } = await chaos(seed + 500);
    for (const rec of store.listOverrides().filter((h) => !h.revertedAt).reverse()) {
      const before = JSON.stringify(store.all());
      try { store.revert(rec.id, { actor: 'final' }); } catch (e) {
        assert.equal(e.name, 'ValidationError');
        assert.match(e.message, /endpoint .* is now used by dataset|Revert newer override/);
        assert.equal(JSON.stringify(store.all()), before, 'refused revert must not change state');
      }
      checkInvariants(store, created);
    }
  }
});

test('without interleaved reverts, global newest-first revert ALWAYS restores the defaults exactly', () => {
  for (let seed = 0; seed < 300; seed++) {
    const r = rng(SEED + seed);
    const store = new DatasetStore();
    for (let i = 0; i < 12; i++) {
      try { store.override(r.pick(['X', 'Y', 'Z']), { endpoint: r.pick(ENDPOINTS), rateLimitPerMinute: r.int(1, 99) }, { actor: 'a', reason: 'overrides only' }); } catch { /* clash: rejected, nothing recorded */ }
    }
    for (const rec of store.listOverrides().reverse()) store.revert(rec.id, { actor: 'final' });
    assert.deepEqual(store.all(), JSON.parse(JSON.stringify(DEFAULTS)), `seed ${seed}`);
  }
});

test('characterisation (found by the chaos test): a cross-dataset revert can permanently block another dataset\'s LIFO chain until the blocker moves', () => {
  const store = new DatasetStore();
  const opts = { actor: 'a', reason: 'characterise' };
  const z1 = store.override('Z', { endpoint: '/proxy/a' }, opts);        // Z: z -> a
  store.override('Y', { endpoint: '/proxy/z' }, opts);                    // Y: y -> z (free)
  const y2 = store.override('Y', { endpoint: '/proxy/y' }, opts);         // Y: z -> y
  store.revert(z1.id, opts);                                              // Z back on z
  assert.throws(() => store.revert(y2.id, opts), /endpoint \/proxy\/z is now used by dataset Z/);
  assert.equal(store.get('Y').endpoint, '/proxy/y');
  // Operator remedy: move the blocker with a new override, then the revert goes through.
  store.override('Z', { endpoint: '/proxy/b' }, opts);
  store.revert(y2.id, opts);
  assert.equal(store.get('Y').endpoint, '/proxy/z');
});

test('race: N concurrent requests all claiming the same free endpoint -> exactly one wins', async () => {
  for (let round = 0; round < 10; round++) {
    const r = rng(SEED + round);
    const store = new DatasetStore();
    const app = createApp({ provider: createAvroneProvider(config), store, audit: createAuditLogger({ sink: () => {} }) });
    const target = `/proxy/race${round}`;
    const res = await Promise.all(['X', 'Y', 'Z', 'X', 'Y', 'Z'].map((ds) => call(app, { method: 'POST', url: `/admin/datasets/${ds}/overrides`, body: JSON.stringify({ patch: { endpoint: target }, reason: 'race for endpoint' }) }, r)));
    const winners = res.filter((x) => x.status === 201);
    const winnerDs = new Set(winners.map((w) => w.json.dataset));
    assert.equal(winnerDs.size, 1, `round ${round}: ${winners.length} datasets won`);
    assert.equal(Object.values(store.all()).filter((d) => d.endpoint === target).length, 1);
  }
});

test('race: endpoint swap X<->Y attempted concurrently in both directions never ends with a collision', async () => {
  for (let round = 0; round < 20; round++) {
    const r = rng(SEED * 3 + round);
    const store = new DatasetStore();
    const app = createApp({ provider: createAvroneProvider(config), store, audit: createAuditLogger({ sink: () => {} }) });
    await Promise.all([
      call(app, { method: 'POST', url: '/admin/datasets/X/overrides', body: JSON.stringify({ patch: { endpoint: '/proxy/y' }, reason: 'swap x' }) }, r),
      call(app, { method: 'POST', url: '/admin/datasets/Y/overrides', body: JSON.stringify({ patch: { endpoint: '/proxy/x' }, reason: 'swap y' }) }, r),
    ]);
    const eps = Object.values(store.all()).map((d) => d.endpoint);
    assert.equal(new Set(eps).size, 3);
  }
});

test('race: concurrent revert + new override on the same dataset — LIFO is preserved', async () => {
  for (let round = 0; round < 20; round++) {
    const r = rng(SEED * 7 + round);
    const store = new DatasetStore();
    const app = createApp({ provider: createAvroneProvider(config), store, audit: createAuditLogger({ sink: () => {} }) });
    const first = await call(app, { method: 'POST', url: '/admin/datasets/Z/overrides', body: JSON.stringify({ patch: { rateLimitPerMinute: 1 }, reason: 'base one' }) }, r);
    const [rv, ov] = await Promise.all([
      call(app, { method: 'POST', url: `/admin/overrides/${first.json.id}/revert` }, r),
      call(app, { method: 'POST', url: '/admin/datasets/Z/overrides', body: JSON.stringify({ patch: { rateLimitPerMinute: 2 }, reason: 'racing two' }) }, r),
    ]);
    assert.equal(ov.status, 201);
    if (rv.status === 200) assert.equal(store.get('Z').rateLimitPerMinute, 2, 'revert ran first, then the new override');
    else { assert.equal(rv.status, 400); assert.equal(store.get('Z').rateLimitPerMinute, 2); }
    checkInvariants(store, new Set(store.listOverrides().map((h) => h.id)));
  }
});

test('over real sockets: 120 concurrent mixed overrides/reverts keep endpoints unique', async (t) => {
  const s = await startServer({ app: { store: new DatasetStore(undefined, { maxHistory: 100000 }) } });
  t.after(() => s.close());
  const r = rng(SEED + 99);
  const ids = [];
  for (let wave = 0; wave < 4; wave++) {
    const res = await Promise.all(Array.from({ length: 30 }, () => {
      if (ids.length && r() < 0.3) return raw(s.port, { method: 'POST', path: `/admin/overrides/${r.pick(ids)}/revert`, headers: bearer(admin) });
      return raw(s.port, { path: `/admin/datasets/${r.pick(['X', 'Y', 'Z'])}/overrides`, ...jsonPost(admin, { patch: { endpoint: r.pick(ENDPOINTS) }, reason: `wave ${wave}` }) });
    }));
    for (const x of res) { assert.ok(x.status < 500); if (x.status === 201) ids.push(x.json.id); }
    const eps = Object.values(s.app.store.all()).map((d) => d.endpoint);
    assert.equal(new Set(eps).size, 3, `wave ${wave}: ${eps}`);
  }
});
