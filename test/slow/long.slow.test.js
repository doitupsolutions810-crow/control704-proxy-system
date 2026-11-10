'use strict';
// SLOW: long model-based and fuzz runs. `npm run test:slow`.
const test = require('node:test');
const assert = require('node:assert');
const { genOps, runSequence, shrink } = require('../model/harness');

const SEEDS = Number(process.env.SLOW_MODEL_SEEDS || 150);
const STEPS = Number(process.env.SLOW_MODEL_STEPS || 1000);

test(`long model sweep: ${SEEDS} seeds x ${STEPS} steps x maxHistory {1000, 5, 1}`, async () => {
  for (let seed = 10000; seed < 10000 + SEEDS; seed++) {
    for (const maxHistory of [1000, 5, 1]) {
      const ops = genOps(seed, STEPS);
      const r = await runSequence(ops, { maxHistory });
      if (!r.ok) {
        const s = await shrink(ops, { maxHistory });
        assert.fail(`seed ${seed} maxHistory ${maxHistory}: ${r.why} at step ${r.step}; minimal repro: ${JSON.stringify(s.ops)}`);
      }
    }
  }
});
