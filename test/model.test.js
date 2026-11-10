'use strict';
// Stateful / model-based tests (see test/model/harness.js).
const test = require('node:test');
const assert = require('node:assert');
const { genOps, runSequence, shrink } = require('./model/harness');
const { DatasetStore } = require('../src/datasets/store');
const { SEED } = require('./helpers');

const STEPS = Number.parseInt(process.env.MODEL_STEPS || '300', 10);
const SEEDS = (process.env.MODEL_SEEDS || `${SEED},1,2,3,4,5,6,7`).split(',').map(Number);

for (const seed of SEEDS) {
  test(`model [seed ${seed}, ${STEPS} steps]: real app matches reference model after every step`, async () => {
    const ops = genOps(seed, STEPS);
    const r = await runSequence(ops);
    if (!r.ok) {
      const s = await shrink(ops);
      assert.fail(`diverged at step ${r.step} (${r.why}); minimal repro (${s.ops.length} ops): ${JSON.stringify(s.ops)}`);
    }
  });
}
for (const seed of SEEDS.slice(0, 3)) {
  test(`model [seed ${seed}] with small history cap (maxHistory=7): compaction matches model`, async () => {
    const ops = genOps(seed + 1000, STEPS);
    const r = await runSequence(ops, { maxHistory: 7 });
    if (!r.ok) {
      const s = await shrink(ops, { maxHistory: 7 });
      assert.fail(`diverged at step ${r.step} (${r.why}); minimal repro: ${JSON.stringify(s.ops)}`);
    }
  });
}
test('generator covers every op type, principal and status class', async () => {
  const ops = genOps(SEED, STEPS);
  const kinds = new Set(ops.map((o) => o.op));
  const whos = new Set(ops.map((o) => o.who));
  assert.deepEqual([...kinds].sort(), ['list', 'override', 'proxy', 'read', 'revert']);
  assert.equal(whos.size, 8);
});

// ---------- the shrinker itself ----------
class BuggyRevertStore extends DatasetStore {
  // Injected bug: revert "forgets" to restore rateLimitPerMinute.
  revert(id, opts) {
    const keep = (() => { const rec = this.history.find((h) => h.id === id); return rec && this.data[rec.dataset].rateLimitPerMinute; })();
    const out = super.revert(id, opts);
    if (keep !== undefined) this.data[out.dataset].rateLimitPerMinute = keep;
    return out;
  }
}
class BuggyBoundaryStore extends DatasetStore {
  // Injected bug: off-by-one rejects rateLimitPerMinute = 10000.
  override(id, patch, opts) {
    if (patch && patch.rateLimitPerMinute === 10000) { const { ValidationError } = require('../src/datasets/store'); throw new ValidationError('bug'); }
    return super.override(id, patch, opts);
  }
}
test('shrinker: an injected revert bug is detected and shrunk to a tiny repro (override + revert)', async () => {
  const storeFactory = (o) => new BuggyRevertStore(undefined, o);
  let found = null;
  for (let seed = 1; seed < 50 && !found; seed++) {
    const ops = genOps(seed, 200);
    const r = await runSequence(ops, { storeFactory });
    if (!r.ok) found = ops;
  }
  assert.ok(found, 'model failed to detect injected revert bug');
  const s = await shrink(found, { storeFactory });
  assert.equal(s.result.ok, false);
  assert.ok(s.ops.length <= 3, `repro not minimal: ${JSON.stringify(s.ops)}`);
  assert.ok(s.ops.some((o) => o.op === 'override') && s.ops.some((o) => o.op === 'revert'));
});
test('shrinker: an injected boundary bug shrinks to a single override with rateLimit 10000', async () => {
  const storeFactory = (o) => new BuggyBoundaryStore(undefined, o);
  let found = null;
  for (let seed = 1; seed < 80 && !found; seed++) {
    const ops = genOps(seed, 200);
    if (!(await runSequence(ops, { storeFactory })).ok) found = ops;
  }
  assert.ok(found, 'model failed to detect injected boundary bug');
  const s = await shrink(found, { storeFactory });
  assert.equal(s.ops.length, 1, JSON.stringify(s.ops));
  assert.equal(s.ops[0].patch.rateLimitPerMinute, 10000);
});
