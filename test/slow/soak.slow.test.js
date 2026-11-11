'use strict';
// Long soak (npm run test:slow): 40k mixed requests in a GC-instrumented child. Heap after the
// first and second halves must be flat (a leak shows up as linear growth between halves).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { execFileSync } = require('child_process');
const run = (n) => JSON.parse(execFileSync(process.execPath, ['--expose-gc', path.join(__dirname, '..', 'memory-worker.js'), String(n)], { encoding: 'utf8', timeout: 600000 }));

test('soak: 10k vs 40k requests -> heap flat (< 2 MB difference), caps hold, no leaked handles', () => {
  const short = run(10000);
  const long = run(40000);
  assert.ok(long.after - short.after < 2 * 1024 * 1024, `short ${short.after} long ${long.after}`);
  assert.ok(long.hist <= 1000);
  assert.equal(long.audit.evicted, long.audit.seq - 500);
  assert.deepEqual(long.handles, []);
});
