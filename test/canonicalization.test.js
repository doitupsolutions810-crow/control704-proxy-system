'use strict';
// Header / URL canonicalization differential. The proxy routes and authorizes on the WHATWG
// canonical pathname, so for ANY raw request-target the response status must equal the status
// of its canonical form (new URL(raw, base).pathname + search). The only allowed divergence is
// Node's HTTP parser being stricter (a 400 for the raw form). Auth-header variants are checked
// the same way: every spelling Node normalizes must behave identically, and every
// non-canonical spelling must fail closed.
const test = require('node:test');
const assert = require('node:assert');
const { sign, claims, startServer, rawSocket } = require('./helpers');

const tech = sign(claims({ sub: 'tech1', roles: ['technician'] }));
const admin = sign(claims({ sub: 'jean', roles: ['admin'] }));
let s;
test.before(async () => { s = await startServer(); });
test.after(() => s.close());

const send = (target, headerLines) => rawSocket(s.port, `GET ${target} HTTP/1.1\r\nHost: x\r\n${headerLines}Connection: close\r\n\r\n`, { waitMs: 2000 });
// Origin-form targets are paths (RFC 9112), so "//a/b" is NOT scheme-relative.
const canonical = (target) => { const u = target.startsWith('/') ? new URL(`http://localhost${target}`) : new URL(target, 'http://localhost'); return u.pathname + u.search; };

let seed = 704;
const rnd = (n) => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % n; };
const SEGS = ['proxy', 'x', 'X', 'y', 'z', 'admin', 'audit', 'datasets', 'overrides', 'health', '.', '..', '%2e', '%2E%2e', '.%2e', '%2f', '%5c',
  '\\', '', 'X;a=b', 'x%00', '%78', '%41dmin', 'ADMIN', 'proxy%2Fx', '~', '%7e', 'x?', 'x#frag', '%3f', 'é', '%C3%A9', '..;', '%u0078', '*'];
function randomTarget() {
  const n = 1 + rnd(5);
  let p = '';
  for (let i = 0; i < n; i++) p += (rnd(6) === 0 ? '//' : '/') + SEGS[rnd(SEGS.length)];
  if (rnd(4) === 0) p += `?q=${SEGS[rnd(SEGS.length)]}`;
  return p;
}
// Only bytes that can legally appear in an HTTP/1.1 request-target on the wire.
const wireSafe = (t) => /^[\x21-\x7e]+$/.test(t);

test('canonicalization differential: 600 random raw targets x {technician, admin} match their canonical form', async () => {
  let compared = 0; let stricter = 0;
  for (let i = 0; i < 600; i++) {
    const target = randomTarget();
    if (!wireSafe(target)) continue;
    const canon = canonical(target);
    const tok = i % 2 ? tech : admin;
    const a = await send(target, `Authorization: Bearer ${tok}\r\n`);
    const b = await send(canon, `Authorization: Bearer ${tok}\r\n`);
    if (a.status === 400 && b.status !== 400) { stricter++; continue; }
    assert.equal(a.status, b.status, `raw ${target} -> ${a.status} but canonical ${canon} -> ${b.status}`);
    compared++;
  }
  assert.ok(compared > 400, `compared ${compared}`);
  assert.ok(stricter < 100);
});

test('canonicalization: no raw spelling of an admin route lets a technician in', async () => {
  const spellings = ['/admin/audit', '/admin//audit', '//admin/audit', '/admin/./audit', '/admin/x/../audit', '/admin/%2e/audit',
    '/proxy/../admin/audit', '/proxy/x/%2e%2e/%2e%2e/admin/audit', '/admin\\audit', '/./admin/audit?x=1', '/admin/audit#x',
    '/admin/audit/', '/ADMIN/audit', '/%61dmin/audit', '/admin%2faudit', '/admin/audit%00', '/admin/audit;jsessionid=1'];
  for (const sp of spellings) {
    const r = await send(sp, `Authorization: Bearer ${tech}\r\n`);
    assert.ok([400, 401, 403, 404].includes(r.status), `${sp} -> ${r.status}`);
    assert.notEqual(r.status, 200, sp);
  }
});

test('header canonicalization: equivalent Authorization spellings behave identically; others fail closed', async () => {
  const ok = [`Authorization: Bearer ${tech}`, `authorization: Bearer ${tech}`, `AUTHORIZATION: Bearer ${tech}`, `AuThOrIzAtIoN: Bearer ${tech}`,
    `Authorization:Bearer ${tech}`, `Authorization: \tBearer ${tech}`, `Authorization: Bearer ${tech}\t`, `Authorization: Bearer ${tech}   `];
  for (const h of ok) assert.equal((await send('/proxy/x', `${h}\r\n`)).status, 200, JSON.stringify(h));
  const caseScheme = await send('/proxy/x', `Authorization: bearer ${tech}\r\n`);
  const upperScheme = await send('/proxy/x', `Authorization: BEARER ${tech}\r\n`);
  assert.equal(caseScheme.status, upperScheme.status, 'scheme case handled consistently');
  const bad = [`Authorization: Bearer  ${tech}`, `Authorization: Bearer${tech}`, `Authorization: Basic ${tech}`, `Authorization: Bearer ${tech} extra`,
    `Authorization: Token ${tech}`, `X-Authorization: Bearer ${tech}`, `Authorization: Bearer "${tech}"`, `Authorization: Bearer ${tech},${tech}`];
  for (const h of bad) {
    const r = await send('/proxy/x', `${h}\r\n`);
    assert.ok([400, 401].includes(r.status), `${JSON.stringify(h)} -> ${r.status}`);
  }
});

test('header canonicalization: duplicate / folded / smuggled Authorization headers never authenticate', async () => {
  const variants = [
    `Authorization: Bearer ${tech}\r\nAuthorization: Bearer ${admin}\r\n`,
    `Authorization: Bearer ${tech}\r\nauthorization: Bearer ${tech}\r\n`,
    `Authorization: Bearer\r\n ${tech}\r\n`,
    `Authorization : Bearer ${tech}\r\n`,
    `Authorization: Bearer ${tech}\rX: y\r\n`,
  ];
  for (const v of variants) {
    const r = await send('/admin/audit', v);
    assert.ok([400, 401, 403].includes(r.status), `${JSON.stringify(v).slice(0, 60)} -> ${r.status}`);
  }
});

test('R5-5 regression: a leading "//seg" is part of the path, never an authority that gets dropped', async () => {
  for (const [target, want] of [['//x/admin/audit', 404], ['//evil/proxy/x', 404], ['//proxy/x', 404], ['//admin/audit', 404], ['///proxy/x', 404]]) {
    const r = await send(target, `Authorization: Bearer ${admin}\r\n`);
    assert.equal(r.status, want, target);
  }
  // the same request that was previously mis-routed as /admin/audit, now audited with its real path
  const log = s.app.audit.recent(100000);
  assert.ok(!log.some((e) => e.path === '/audit' || (e.type === 'request' && e.path === '/admin/audit' && e.actor === 'jean')));
});

test('canonicalization: absolute-form request-targets route on the path only, host is ignored', async () => {
  for (const [target, want] of [['http://evil.example/proxy/x', 200], ['http://localhost/admin/audit', 403], ['http://a/b/../proxy/y', 200]]) {
    const r = await send(target, `Authorization: Bearer ${tech}\r\n`);
    assert.equal(r.status, want, target);
  }
});
