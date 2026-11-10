'use strict';
// Model-based (stateful) testing harness.
// A seeded random sequence of operations is run against the REAL app (createApp().handle,
// driven in-process with fake req/res objects, so no sockets) and against a small,
// independently written reference model. After every step the HTTP status, the full dataset
// state and the retained history are compared. On mismatch the failing sequence is shrunk
// (delta debugging) to a minimal reproduction.
const { Readable } = require('stream');
const crypto = require('crypto');
const { createAvroneProvider } = require('../../src/auth/avroneProvider');
const { createApp } = require('../../src/server');
const { createAuditLogger } = require('../../src/access/audit');
const { DatasetStore, DEFAULTS } = require('../../src/datasets/store');
const { sign, claims, config, rng } = require('../helpers');

const WHO = ['none', 'expired', 'forged', 'viewer', 'tech', 'admin', 'scopeOverride', 'scopeRevert'];
const TOKENS = {
  none: null,
  expired: sign(claims({ sub: 'expired', roles: ['admin'], exp: 1, iat: 0 })),
  forged: sign(claims({ sub: 'forged', roles: ['admin'] }), { secret: 'forged-secret-0123456789abcdefghijklm' }),
  viewer: sign(claims({ sub: 'viewer', roles: ['viewer'], exp: 4102444800 })),
  tech: sign(claims({ sub: 'tech', roles: ['technician'], exp: 4102444800 })),
  admin: sign(claims({ sub: 'admin', roles: ['admin'], exp: 4102444800 })),
  scopeOverride: sign(claims({ sub: 'svc-ov', scope: 'datasets:override', exp: 4102444800 })),
  scopeRevert: sign(claims({ sub: 'svc-rv', scope: 'datasets:revert', exp: 4102444800 })),
};
// Independent re-statement of the access policy (not imported from src).
const GRANTS = {
  viewer: ['proxy:read', 'datasets:read'],
  tech: ['proxy:read', 'proxy:x', 'proxy:y', 'proxy:z', 'datasets:read'],
  admin: ['proxy:read', 'proxy:x', 'proxy:y', 'proxy:z', 'datasets:read', 'datasets:override', 'datasets:revert', 'audit:read'],
  scopeOverride: ['datasets:override'],
  scopeRevert: ['datasets:revert'],
};
const ENDPOINTS = ['/proxy/x', '/proxy/y', '/proxy/z', '/proxy/a', '/proxy/b', '/proxy/../a', '/proxy//a', '/proxy/A'];
const RATES = [0, 1, 2, 60, 9999, 10000, 10001, 1.5, '5'];

function genOp(r) {
  const who = r.pick(WHO);
  const ds = r() < 0.9 ? r.pick(['X', 'Y', 'Z']) : r.pick(['Q', 'x']);
  const k = r();
  if (k < 0.2) return { op: 'read', who, ds };
  if (k < 0.35) return { op: 'proxy', who, ds };
  if (k < 0.45) return { op: 'list', who, ds };
  if (k < 0.75) {
    const patch = {};
    const n = r.int(1, 3);
    for (let i = 0; i < n; i++) {
      const f = r.pick(['endpoint', 'enabled', 'rateLimitPerMinute', 'metadata', 'auth']);
      if (f === 'endpoint') patch.endpoint = r.pick(ENDPOINTS);
      if (f === 'enabled') patch.enabled = r() < 0.5;
      if (f === 'rateLimitPerMinute') patch.rateLimitPerMinute = r.pick(RATES);
      if (f === 'metadata') patch.metadata = { step: r.int(0, 999) };
      if (f === 'auth') patch.auth = 'none';
    }
    return { op: 'override', who, ds, patch, reason: r() < 0.95 ? 'model step' : 'no' };
  }
  return { op: 'revert', who, target: r() < 0.85 ? r.int(0, 1e6) : -1 };
}
const genOps = (seed, n) => { const r = rng(seed); return Array.from({ length: n }, () => genOp(r)); };

// ---------- reference model ----------
function createModel({ maxHistory }) {
  const clone = (o) => JSON.parse(JSON.stringify(o));
  const m = { data: clone(DEFAULTS), history: [], createdIds: [], maxHistory };
  const can = (who, scopes) => (GRANTS[who] ? scopes.every((s) => GRANTS[who].includes(s)) : false);
  const authn = (who) => (['none', 'expired', 'forged'].includes(who) ? 401 : 0);
  const validPatch = (ds, p) => {
    for (const [k, v] of Object.entries(p)) {
      if (k === 'endpoint') { if (!/^\/proxy\/[a-z]$/.test(v)) return false; }
      else if (k === 'enabled') { if (typeof v !== 'boolean') return false; }
      else if (k === 'rateLimitPerMinute') { if (!Number.isInteger(v) || v < 1 || v > 10000) return false; }
      else if (k === 'metadata') { /* always valid in generator */ }
      else return false;
    }
    if (p.endpoint && ['X', 'Y', 'Z'].some((o) => o !== ds && m.data[o].endpoint === p.endpoint)) return false;
    return true;
  };
  m.step = (o) => {
    if (o.op === 'revert') {
      const a = authn(o.who); if (a) return a;
      if (!can(o.who, ['datasets:revert'])) return 403;
      const id = o.target < 0 || m.createdIds.length === 0 ? null : m.createdIds[o.target % m.createdIds.length];
      const rec = id && m.history.find((h) => h.id === id);
      if (!rec) return 404;
      if (rec.reverted) return 400;
      const latest = [...m.history].reverse().find((h) => h.ds === rec.ds && !h.reverted);
      if (latest !== rec) return 400;
      if (['X', 'Y', 'Z'].some((x) => x !== rec.ds && m.data[x].endpoint === rec.before.endpoint)) return 400;
      m.data[rec.ds] = clone(rec.before); rec.reverted = true;
      return 200;
    }
    // /proxy/<id> only has routes for x/y/z (any case): anything else is a router 404 before auth.
    if (o.op === 'proxy' && !/^[xyz]$/i.test(o.ds)) return 404;
    const a = authn(o.who); if (a) return a;
    const need = { read: ['datasets:read'], proxy: ['proxy:read', `proxy:${o.ds.toLowerCase()}`], list: ['audit:read'], override: ['datasets:override'] }[o.op];
    if (!can(o.who, need)) return 403;
    const ds = o.ds.toUpperCase();
    if (!['X', 'Y', 'Z'].includes(ds)) return 404;
    if (o.op === 'read' || o.op === 'list') return 200;
    if (o.op === 'proxy') return m.data[ds].enabled ? 200 : 503;
    if (o.reason.trim().length < 3) return 400;
    if (!validPatch(ds, o.patch)) return 400;
    return { ok: 201, apply: (id) => {
      const before = clone(m.data[ds]);
      m.data[ds] = { ...before, ...clone(o.patch) };
      m.history.push({ id, ds, before, reverted: false });
      if (m.history.length > m.maxHistory) m.history.splice(0, m.history.length - m.maxHistory);
    } };
  };
  return m;
}

// ---------- system under test, driven in-process ----------
function fakeCall(app, { method, url, token, body }) {
  return new Promise((resolve, reject) => {
    const headers = {}; const rawHeaders = [];
    if (token) { headers.authorization = `Bearer ${token}`; rawHeaders.push('Authorization', headers.authorization); }
    if (body !== undefined) { headers['content-type'] = 'application/json'; rawHeaders.push('Content-Type', 'application/json'); }
    const req = Readable.from(body !== undefined ? [Buffer.from(body)] : []);
    Object.assign(req, { method, url, headers, rawHeaders, socket: null });
    let status = null;
    const res = {
      writeHead(s) { status = s; },
      setHeader() {},
      end(payload) { let json = null; try { json = JSON.parse(payload); } catch { /* ignore */ } resolve({ status, json }); },
      on() {},
    };
    Promise.resolve(app.handle(req, res)).catch(reject);
  });
}

async function runSequence(ops, { maxHistory = 1000, storeFactory } = {}) {
  const store = storeFactory ? storeFactory({ maxHistory }) : new DatasetStore(undefined, { maxHistory });
  const app = createApp({ provider: createAvroneProvider(config), store, audit: createAuditLogger({ sink: () => {} }) });
  const model = createModel({ maxHistory });
  for (let i = 0; i < ops.length; i++) {
    const o = ops[i];
    const token = TOKENS[o.who];
    let req;
    if (o.op === 'read') req = { method: 'GET', url: `/datasets/${o.ds}` };
    if (o.op === 'proxy') req = { method: 'GET', url: `/proxy/${o.ds}` };
    if (o.op === 'list') req = { method: 'GET', url: `/admin/datasets/${o.ds}/overrides` };
    if (o.op === 'override') req = { method: 'POST', url: `/admin/datasets/${o.ds}/overrides`, body: JSON.stringify({ patch: o.patch, reason: o.reason }) };
    if (o.op === 'revert') {
      const id = o.target < 0 || model.createdIds.length === 0 ? crypto.randomUUID() : model.createdIds[o.target % model.createdIds.length];
      req = { method: 'POST', url: `/admin/overrides/${id}/revert` };
    }
    const real = await fakeCall(app, { ...req, token });
    let expected = model.step(o);
    if (typeof expected === 'object') {
      if (real.status === 201) { model.createdIds.push(real.json.id); expected.apply(real.json.id); }
      expected = expected.ok;
    }
    const fail = (why) => ({ ok: false, step: i, op: o, why, real: real.status, expected });
    if (real.status !== expected) return fail('status mismatch');
    // the proxy route regexp only matches x/y/z; model 404 for Q is the router's 404
    if (JSON.stringify(store.all()) !== JSON.stringify(model.data)) return fail('state mismatch');
    if (store.listOverrides().length !== model.history.length) return fail('history length mismatch');
    if (o.op === 'read' && real.status === 200 && JSON.stringify(real.json) !== JSON.stringify(model.data[o.ds.toUpperCase()])) return fail('read body mismatch');
  }
  return { ok: true };
}

// Delta-debugging shrinker: removes chunks, then single ops, while the run still fails.
async function shrink(ops, opts = {}) {
  let cur = ops.slice();
  let chunk = Math.max(1, Math.floor(cur.length / 2));
  let runs = 0;
  while (chunk >= 1) {
    let progressed = false;
    for (let i = 0; i < cur.length; i += chunk) {
      const cand = cur.slice(0, i).concat(cur.slice(i + chunk));
      if (cand.length === 0) continue;
      runs++;
      if (!(await runSequence(cand, opts)).ok) { cur = cand; progressed = true; i -= chunk; }
    }
    if (!progressed) chunk = Math.floor(chunk / 2);
  }
  return { ops: cur, runs, result: await runSequence(cur, opts) };
}

module.exports = { genOps, runSequence, shrink, createModel, TOKENS };
