'use strict';
// Child-process worker for heap-growth checks (run with --expose-gc). Drives N mixed requests
// (all roles, denials, overrides+reverts, malformed targets, chaos resets) through a real
// server and reports heapUsed after warm-up and after the run, both measured after full GC.
const net = require('net');
const { sign, claims, startServer, raw, bearer, jsonPost } = require('./helpers');
const { createAuditLogger } = require('../src/access/audit');

const N = Number(process.argv[2] || 2000);
const tech = sign(claims({ sub: 'tech1', roles: ['technician'] }));
const admin = sign(claims({ sub: 'jean', roles: ['admin'] }));
const viewer = sign(claims({ sub: 'view1', roles: ['viewer'] }));
const gcHeap = async () => { for (let i = 0; i < 4; i++) { global.gc(); await new Promise((r) => setImmediate(r)); } return process.memoryUsage().heapUsed; };

async function step(port, i) {
  switch (i % 8) {
    case 0: return raw(port, { path: '/proxy/x', headers: bearer(tech) });
    case 1: return raw(port, { path: '/admin/audit', headers: bearer(viewer) });
    case 2: return raw(port, { path: '/datasets', headers: { authorization: 'Bearer garbage.' + i } });
    case 3: {
      const o = await raw(port, { path: '/admin/datasets/Y/overrides', ...jsonPost(admin, { patch: { rateLimitPerMinute: 1 + (i % 50), metadata: { i: String(i) } }, reason: `mem ${i}` }) });
      return raw(port, { method: 'POST', path: `/admin/overrides/${o.json.id}/revert`, headers: bearer(admin) });
    }
    case 4: return raw(port, { path: `/x/${'a'.repeat(i % 300)}/../proxy/z`, headers: bearer(tech) });
    case 5: return new Promise((resolve) => {
      const k = net.connect(port, '127.0.0.1', () => { k.write(`GET /proxy/y HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${tech}\r\n`); setImmediate(() => { k.resetAndDestroy(); resolve(); }); });
      k.on('error', () => resolve());
    });
    case 6: return raw(port, { path: '/admin/audit?limit=5', headers: bearer(admin) });
    default: return raw(port, { path: '/health' });
  }
}

(async () => {
  // Cap the audit ring so expected retention is bounded; anything else that grows is a leak.
  const s = await startServer({ audit: createAuditLogger({ sink: () => {}, maxEntries: 500 }) });
  for (let i = 0; i < 400; i++) await step(s.port, i);
  const warm = await gcHeap();
  for (let i = 0; i < N; i++) await step(s.port, i);
  const after = await gcHeap();
  const hist = s.app.store.listOverrides('Y').length;
  await s.close();
  await new Promise((r) => setTimeout(r, 50));
  const handles = process.getActiveResourcesInfo().filter((r) => r !== 'TTYWrap' && r !== 'PipeWrap'); // stdio to the parent, not ours
  process.stdout.write(JSON.stringify({ warm, after, growth: after - warm, n: N, hist, audit: s.app.audit.stats(), handles }));
})().catch((e) => { process.stderr.write(String(e && e.stack)); process.exit(1); });
