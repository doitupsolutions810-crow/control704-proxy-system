'use strict';
// Property tests: URL canonicalization against WHATWG URL edge cases, over raw sockets.
//  P1 canonicalization is idempotent (canon(canon(t)) === canon(t)).
//  P2 the server's status for a raw target equals the status for its canonical form
//     (Node's HTTP parser may be stricter: 400 for the raw form only).
//  P3 an audited request records exactly the canonical pathname.
//  P4 no raw target ever produces a 500, and no technician ever reads an admin route.
const test = require('node:test');
const assert = require('node:assert');
const { sign, claims, startServer, rawSocket } = require('./helpers');

const tech = sign(claims({ sub: 'tech1', roles: ['technician'] }));
const admin = sign(claims({ sub: 'jean', roles: ['admin'] }));
let s;
test.before(async () => { s = await startServer(); });
test.after(() => s.close());

const canon = (t) => { const u = t.startsWith('/') ? new URL(`http://localhost${t}`) : new URL(t, 'http://localhost'); return u.pathname + u.search; };
const send = (target, tok) => rawSocket(s.port, Buffer.concat([Buffer.from('GET '), Buffer.isBuffer(target) ? target : Buffer.from(target, 'latin1'),
  Buffer.from(` HTTP/1.1\r\nHost: x\r\n${tok ? `Authorization: Bearer ${tok}\r\n` : ''}Connection: close\r\n\r\n`)]), { waitMs: 2000 });

// WHATWG path edge tokens: single/double-dot spellings, encoded separators, odd percent
// sequences, backslashes, empty segments, and characters the path percent-encode set touches.
const ATOMS = ['.', '..', '%2e', '%2E', '.%2e', '%2e.', '%2e%2e', '%2E%2e', '..%2f', '%2f', '%2F', '%5c', '\\', '', ';', ';x=1', '%', '%z', '%zz', '%%',
  '%25', '%252e', '%u002e', '%00', '%7f', '%c3%a9', '%C3%A9', '~', '%7E', "'", '"', '<', '>', '^', '`', '{', '}', '|', '[', ']', '@', ':', '!', '$', '&', '(', ')',
  '*', '+', ',', '=', 'proxy', 'x', 'X', 'y', 'z', 'admin', 'audit', 'datasets', 'health', 'overrides'];
let seed = 0x5EED;
const rnd = (n) => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % n; };
function target() {
  let p = '';
  const n = 1 + rnd(6);
  for (let i = 0; i < n; i++) p += (rnd(7) === 0 ? '\\' : '/') + ATOMS[rnd(ATOMS.length)] + (rnd(5) === 0 ? ATOMS[rnd(ATOMS.length)] : '');
  if (!p.startsWith('/')) p = `/${p}`;
  if (rnd(5) === 0) p += `?${ATOMS[rnd(ATOMS.length)]}=${ATOMS[rnd(ATOMS.length)]}`;
  if (rnd(9) === 0) p += `#${ATOMS[rnd(ATOMS.length)]}`;
  return p;
}
const isAdminRoute = (p) => /^\/admin\//.test(p);

test('P1: WHATWG canonicalization is idempotent for 5000 generated targets', () => {
  for (let i = 0; i < 5000; i++) {
    const t = target();
    const c = canon(t);
    assert.equal(canon(c), c, `${t} -> ${c} -> ${canon(c)}`);
    assert.ok(c.startsWith('/'));
    assert.ok(!/(^|\/)\.\.?(\/|$)/.test(c.split('?')[0]), `dot segment survived: ${c}`);
  }
});

test('P2+P4: 700 raw targets x {anon, technician, admin}: status(raw) == status(canonical), never 500, never a technician on admin', async () => {
  let compared = 0;
  for (let i = 0; i < 700; i++) {
    const t = target();
    const tok = [null, tech, admin][i % 3];
    const a = await send(t, tok);
    assert.notEqual(a.status, 500, t);
    assert.ok(a.status, `no response for ${t}`);
    if (tok === tech && a.status === 200) assert.ok(!isAdminRoute(canon(t)), `technician read ${t}`);
    const b = await send(canon(t).replace(/#.*/, ''), tok);
    if (a.status === 400 && b.status !== 400) continue;
    assert.equal(a.status, b.status, `raw ${JSON.stringify(t)} ${a.status} vs canonical ${JSON.stringify(canon(t))} ${b.status}`);
    compared++;
  }
  assert.ok(compared > 500, `compared ${compared}`);
});

test('P3: an authenticated request is audited with exactly the canonical pathname', async () => {
  const spellings = ['/proxy/x', '/proxy/./x', '/a/../proxy/x', '/proxy/%2e/x', '/proxy\\x', '/./proxy/x?z=1', '/b/%2e%2e/proxy/x', '/proxy/x#frag'];
  for (const sp of spellings) {
    const before = s.app.audit.stats().seq;
    const r = await send(sp, tech);
    assert.equal(r.status, 200, sp);
    const entries = s.app.audit.recent(10).filter((e) => e.seq > before && e.type === 'request');
    assert.equal(entries.length, 1, sp);
    assert.equal(entries[0].path, '/proxy/x', sp);
  }
});

test('raw non-ASCII bytes and control bytes in the request-target are rejected or treated like their encoding', async () => {
  for (const bytes of [Buffer.from('/proxy/\xc3\xa9', 'latin1'), Buffer.from('/proxy/x\x7f', 'latin1'), Buffer.from('/proxy/x\x00', 'latin1'), Buffer.from('/proxy/\xff', 'latin1')]) {
    const r = await send(bytes, tech);
    assert.ok([400, 404].includes(r.status), `${bytes.toString('hex')} -> ${r.status}`);
  }
});

test('WHATWG specifics: encoded slash and backslash are NOT separators once encoded; raw backslash IS', async () => {
  const cases = [['/proxy%2fx', 404], ['/proxy%5cx', 404], ['/proxy\\x', 200], ['/proxy/x%2f', 404], ['/proxy/%78', 404], ['/proxy/x;', 404], ['/proxy/x/', 404], ['/proxy/x/.', 404], ['/proxy/x/..', 404]];
  for (const [t, want] of cases) assert.equal((await send(t, tech)).status, want, t);
});
