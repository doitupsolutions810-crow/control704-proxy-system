'use strict';
// Log redaction under fuzzed inputs. Live bearer tokens, secrets and credential-looking
// strings are injected through every caller-controlled input (path, query, headers, reason,
// metadata keys/values at any depth, sub claims) and the audit sink + ring buffer are
// scanned. R6-2: nested sensitive keys and JWT/Bearer strings in values used to be logged.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAuditLogger, redactDeep } = require('../src/access/audit');
const { sign, claims, startServer, raw, bearer, jsonPost, SECRET } = require('./helpers');

const admin = sign(claims({ sub: 'jean', roles: ['admin'] }));
const tech = sign(claims({ sub: 'tech1', roles: ['technician'] }));
let seed = 0xBEEF;
const rnd = (n) => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % n; };
const pick = (a) => a[rnd(a.length)];

const SENSITIVE_KEYS = ['token', 'Token', 'TOKEN', 'access_token', 'accessToken', 'refresh-token', 'id_token', 'authorization', 'Authorization',
  'proxy-authorization', 'secret', 'client_secret', 'jwtSecret', 'password', 'passwd', 'apiKey', 'api_key', 'X-Api-Key', 'cookie', 'Set-Cookie', 'private_key', 'session', 'sessionId'];
const SAFE_KEYS = ['secretary', 'tokens_used', 'ticket', 'owner', 'passwordPolicy', 'keyboard', 'note'];

function scan(sinkLines, ringEntries, needles) {
  const all = sinkLines.join('\n') + JSON.stringify(ringEntries);
  for (const n of needles) assert.ok(!all.includes(n), `leaked: ${n.slice(0, 24)}...`);
}

test('R6-2: a live token pasted into a reason, and nested sensitive metadata keys, never reach the audit log', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const fake = 'eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.c2lnbmF0dXJl';
  const r = await raw(s.port, { path: '/admin/datasets/X/overrides', ...jsonPost(admin, {
    patch: { metadata: { token: 'tok-AAAA1111', note: `Authorization: Bearer opaque-ZZZZ9999`, apiKey: 'k-BBBB2222', ref: `see ${fake}` } },
    reason: `oops pasted ${admin}`,
  }) });
  assert.equal(r.status, 201);
  assert.equal(r.json.reason, `oops pasted ${admin}`, 'stored data and the API response are unchanged');
  scan(s.lines, s.app.audit.recent(1000), [admin, 'tok-AAAA1111', 'opaque-ZZZZ9999', 'k-BBBB2222', fake]);
  const entry = s.app.audit.recent(1000).find((e) => e.type === 'dataset.override');
  assert.equal(entry.patch.metadata.token, '[REDACTED]');
  assert.equal(entry.patch.metadata.note, 'Authorization: Bearer [REDACTED]');
  assert.equal(entry.patch.metadata.apiKey, '[REDACTED]');
  assert.equal(entry.patch.metadata.ref, 'see [REDACTED_JWT]');
  assert.match(entry.reason, /^oops pasted \[REDACTED_JWT\]$/);
});

test('redaction fuzz: 400 random overrides with secrets in keys, values and reasons at random depths', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const needles = [];
  let applied = 0;
  for (let i = 0; i < 400; i++) {
    const secretVal = `sv${i}-${crypto.randomBytes(6).toString('hex')}`;
    const jwt = sign(claims({ sub: `u${i}`, roles: ['viewer'] }));
    // Override metadata is flat (string/number/boolean values), so secrets go in keys and values.
    const meta = { [pick(SENSITIVE_KEYS)]: secretVal, [pick(SAFE_KEYS)]: pick([`text with ${jwt} inside`, `Bearer ${secretVal}x`, `basic ${secretVal}y`, 'plain']) };
    needles.push(secretVal, jwt);
    const reason = pick([`reason ${jwt}`, `Bearer ${secretVal}z ok`, `rotation ${i}`, `BEARER\t${secretVal}w`]);
    const r = await raw(s.port, { path: `/admin/datasets/${pick(['X', 'Y', 'Z'])}/overrides`, ...jsonPost(admin, { patch: { metadata: meta }, reason }) });
    assert.equal(r.status, 201, `override #${i} rejected: ${r.text}`);
    applied++;
    await raw(s.port, { method: 'POST', path: `/admin/overrides/${r.json.id}/revert`, headers: bearer(admin) });
  }
  assert.equal(applied, 400);
  scan(s.lines, s.app.audit.recent(100000), needles);
});

test('redaction fuzz: tokens in paths, queries, odd headers and failed auth attempts are never logged', async (t) => {
  const s = await startServer(); t.after(() => s.close());
  const needles = [admin, tech, SECRET];
  for (let i = 0; i < 150; i++) {
    const tk = pick([admin, tech, `${admin}x`, admin.split('.').slice(0, 2).join('.') + '.AAAA']);
    needles.push(tk);
    const where = i % 5;
    const opts = where === 0 ? { path: `/proxy/x?access_token=${tk}`, headers: bearer(tech) }
      : where === 1 ? { path: `/admin/${tk}` , headers: bearer(admin) }
        : where === 2 ? { path: '/proxy/x', headers: { authorization: `Bearer ${tk}`, 'x-forwarded-authorization': tk, 'user-agent': tk } }
          : where === 3 ? { path: '/admin/audit', headers: { authorization: `Basic ${Buffer.from(`u:${tk}`).toString('base64')}` } }
            : { path: '/proxy/x', headers: { authorization: `bearer ${tk}`, cookie: `session=${tk}` } };
    await raw(s.port, opts);
  }
  scan(s.lines, s.app.audit.recent(100000), needles);
});

test('redactDeep: safe look-alike keys are kept, values untouched unless credential-shaped, inputs not mutated', () => {
  const input = { a: { secretary: 'Ann', tokens_used: 7, passwordPolicy: 'strong', Token: 'x', 'X-Api-Key': 'y', arr: [{ cookie: 'c' }, 'Bearer abcd1234', 'no bearer here'] } };
  const snapshot = JSON.stringify(input);
  const out = redactDeep(input);
  assert.equal(JSON.stringify(input), snapshot);
  assert.deepEqual(out, { a: { secretary: 'Ann', tokens_used: 7, passwordPolicy: 'strong', Token: '[REDACTED]', 'X-Api-Key': '[REDACTED]',
    arr: [{ cookie: '[REDACTED]' }, 'Bearer [REDACTED]', 'no bearer here'] } });
});

test('redactDeep: very deep or wide entries stay bounded and never throw', () => {
  let deep = 'eyJhbGciOiJub25lIn0.eyJzIjoxfQ.sig1';
  for (let i = 0; i < 200; i++) deep = { n: deep };
  const out = redactDeep({ deep });
  assert.ok(!JSON.stringify(out).includes('eyJhbGciOiJub25lIn0'));
  let node = out.deep; let levels = 1;
  while (node && typeof node === 'object') { node = node.n; levels++; }
  assert.equal(node, '[REDACTED]', 'entries nested deeper than 64 levels are collapsed');
  assert.equal(levels, 65);
  const wide = Object.fromEntries(Array.from({ length: 5000 }, (_, i) => [`k${i}`, i % 2 ? `Bearer tok${i}xyz` : i]));
  const w = redactDeep({ wide }).wide;
  assert.equal(w.k1, 'Bearer [REDACTED]');
  assert.equal(w.k2, 2);
});

test('audit logger: sink receives the same redacted entry the ring buffer keeps', () => {
  const lines = [];
  const a = createAuditLogger({ sink: (l) => lines.push(l) });
  const e = a.log({ type: 't', detail: { password: 'p@ss-1234' }, message: `got Bearer ${admin}` });
  assert.equal(lines[0], JSON.stringify(e));
  assert.ok(!lines[0].includes('p@ss-1234') && !lines[0].includes(admin));
});
