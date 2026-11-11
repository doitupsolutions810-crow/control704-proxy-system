'use strict';
// Heap-growth / leak check: a child process with --expose-gc drives mixed traffic (all roles,
// denials, override+revert cycles, malformed targets, mid-request resets) and measures heap
// after full GC. With the audit ring capped, steady-state traffic must not grow the heap.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { execFileSync } = require('child_process');

function run(n) {
  const out = execFileSync(process.execPath, ['--expose-gc', path.join(__dirname, 'memory-worker.js'), String(n)], { encoding: 'utf8', timeout: 120000 });
  return JSON.parse(out);
}

test('memory: 3000 mixed requests do not grow the heap beyond 3 MB; history and audit stay capped; no handles leak', () => {
  const r = run(3000);
  assert.ok(r.growth < 3 * 1024 * 1024, `heap grew ${r.growth} bytes`);
  assert.ok(r.hist <= 1000, `override history ${r.hist}`);
  assert.equal(r.audit.size, 500);
  assert.deepEqual(r.handles, [], `leftover handles: ${r.handles}`);
});
