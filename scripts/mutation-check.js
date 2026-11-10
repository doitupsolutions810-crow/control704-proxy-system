'use strict';
// Mutation-testing style check (Node built-ins only).
// For each mutation: copy the repo to a throwaway temp dir, apply ONE guard-breaking edit,
// run the test suite, and record whether the tests caught it ("killed") or not ("survived").
// The working tree is never modified.
//   node scripts/mutation-check.js [--only M01,M02] [--jobs 4]
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const ROOT = path.join(__dirname, '..');
const extra = fs.existsSync(path.join(__dirname, 'mutations.extra.js')) ? require('./mutations.extra.js') : [];
let mutations = [...require('./mutations.js'), ...extra];
const argv = process.argv.slice(2);
const onlyIdx = argv.indexOf('--only');
if (onlyIdx >= 0) { const set = new Set(argv[onlyIdx + 1].split(',')); mutations = mutations.filter((m) => set.has(m[0])); }
const jobsIdx = argv.indexOf('--jobs');
const JOBS = jobsIdx >= 0 ? Number(argv[jobsIdx + 1]) : Math.max(1, Math.min(4, os.cpus().length));

function copyTree(src, dst) {
  fs.mkdirSync(dst, { recursive: true });
  for (const e of fs.readdirSync(src, { withFileTypes: true })) {
    if (['.git', 'node_modules'].includes(e.name)) continue;
    const s = path.join(src, e.name); const d = path.join(dst, e.name);
    if (e.isDirectory()) copyTree(s, d); else fs.copyFileSync(s, d);
  }
}

function runTests(cwd) {
  return new Promise((resolve) => {
    const files = fs.readdirSync(path.join(cwd, 'test')).filter((f) => f.endsWith('.test.js')).map((f) => path.join('test', f));
    const child = spawn(process.execPath, ['--test', ...files], { cwd, env: { ...process.env, FUZZ_ITER: '150' }, stdio: ['ignore', 'pipe', 'pipe'] });
    let out = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { out += d; });
    const timer = setTimeout(() => child.kill('SIGKILL'), 120000);
    child.on('close', (code) => {
      clearTimeout(timer);
      const failed = (out.match(/^ℹ fail (\d+)/m) || [])[1];
      resolve({ code, failed: failed ? Number(failed) : null });
    });
  });
}

async function runOne([id, file, search, replace, desc, meta = {}]) {
  const src = fs.readFileSync(path.join(ROOT, file), 'utf8');
  if (!src.includes(search)) return { id, desc, status: 'NOT_APPLICABLE' };
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), `mut-${id}-`));
  try {
    copyTree(ROOT, dir);
    fs.writeFileSync(path.join(dir, file), src.replace(search, replace));
    const r = await runTests(dir);
    const survived = r.code === 0;
    return { id, desc, status: survived ? (meta.equivalent ? 'EQUIVALENT' : 'SURVIVED') : 'KILLED', failed: r.failed, note: meta.equivalent };
  } finally {
    fs.rmSync(dir, { recursive: true, force: true });
  }
}

(async () => {
  const base = await runTests(ROOT);
  if (base.code !== 0) { console.error('Baseline test run is failing; fix tests first.'); process.exit(2); }
  const results = [];
  const queue = [...mutations];
  await Promise.all(Array.from({ length: JOBS }, async () => {
    while (queue.length) {
      const m = queue.shift();
      const r = await runOne(m);
      results.push(r);
      console.log(`${r.id} ${r.status.padEnd(14)} ${r.failed != null ? `(${r.failed} failing)`.padEnd(14) : ''.padEnd(14)} ${r.desc}`);
    }
  }));
  results.sort((a, b) => a.id.localeCompare(b.id));
  const killed = results.filter((r) => r.status === 'KILLED').length;
  const survived = results.filter((r) => r.status === 'SURVIVED');
  const na = results.filter((r) => r.status === 'NOT_APPLICABLE');
  const eq = results.filter((r) => r.status === 'EQUIVALENT');
  console.log(`\nMutation score: ${killed}/${results.length - na.length - eq.length} killable mutants killed (${eq.length} equivalent, ${na.length} n/a)`);
  for (const e of eq) console.log(`EQUIVALENT ${e.id}: ${e.note}`);
  if (survived.length) console.log('SURVIVED:', survived.map((r) => `${r.id} (${r.desc})`).join('; '));
  if (na.length) console.log('NOT APPLICABLE (search string missing):', na.map((r) => r.id).join(', '));
  if (process.env.MUTATION_JSON) fs.writeFileSync(process.env.MUTATION_JSON, JSON.stringify(results, null, 2));
  process.exit(survived.length || na.length ? 1 : 0);
})();
