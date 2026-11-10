'use strict';
// HTTP protocol edges: request smuggling, pipelining/keep-alive auth isolation, versions,
// absolute-form targets, Expect: 100-continue, long URLs, header injection, request ids.
const test = require('node:test');
const assert = require('node:assert');
const { sign, claims, startServer, rawSocket, raw, bearer } = require('./helpers');

const admin = sign(claims({ sub: 'admin-p', roles: ['admin'] }));
const tech = sign(claims({ sub: 'tech-p', roles: ['technician'] }));
const A = `Authorization: Bearer ${admin}\r\n`;
const BODY = '{"patch":{"metadata":{"p":"1"}},"reason":"protocol"}';
const OV = 'POST /admin/datasets/X/overrides HTTP/1.1\r\nHost: x\r\n';
const CT = 'Content-Type: application/json\r\n';

test('HTTP protocol edges', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const overrideCount = () => s.app.store.listOverrides('X').length;
  const send = (p, o) => rawSocket(s.port, p, o);

  // ---------- request smuggling ----------
  const smuggling = {
    'CL + TE (CL.TE)': `${OV}${A}${CT}Content-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin/audit HTTP/1.1\r\nHost: x\r\n\r\n`,
    'TE + CL (TE.CL ordering)': `${OV}${A}${CT}Transfer-Encoding: chunked\r\nContent-Length: 60\r\n\r\n0\r\n\r\nGET /admin/audit HTTP/1.1\r\nHost: x\r\n\r\n`,
    'duplicate Content-Length (different)': `${OV}${A}${CT}Content-Length: 5\r\nContent-Length: ${BODY.length}\r\n\r\n${BODY}`,
    'duplicate Content-Length (same)': `${OV}${A}${CT}Content-Length: ${BODY.length}\r\nContent-Length: ${BODY.length}\r\n\r\n${BODY}`,
    'Content-Length list "5, 5"': `${OV}${A}${CT}Content-Length: 5, 5\r\n\r\nhello`,
    'negative Content-Length': `${OV}${A}${CT}Content-Length: -1\r\n\r\n`,
    'Content-Length with plus sign': `${OV}${A}${CT}Content-Length: +${BODY.length}\r\n\r\n${BODY}`,
    'Content-Length hex': `${OV}${A}${CT}Content-Length: 0x10\r\n\r\n`,
    'Content-Length overflow': `${OV}${A}${CT}Content-Length: 99999999999999999999999\r\n\r\n`,
    'TE chunked, identity': `${OV}${A}${CT}Transfer-Encoding: chunked, identity\r\n\r\n0\r\n\r\n`,
    'TE xchunked': `${OV}${A}${CT}Transfer-Encoding: xchunked\r\n\r\n0\r\n\r\n`,
    'TE with leading space name': `${OV}${A}${CT} Transfer-Encoding: chunked\r\n\r\n0\r\n\r\n`,
    'TE header name with space before colon': `${OV}${A}${CT}Transfer-Encoding : chunked\r\n\r\n0\r\n\r\n`,
    'obs-fold continuation line': `GET /health HTTP/1.1\r\nHost: x\r\nX-A: a\r\n b\r\n\r\n`,
    'obs-fold on Authorization': `GET /admin/audit HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer\r\n ${admin}\r\n\r\n`,
    'bare LF line endings': 'GET /health HTTP/1.1\nHost: x\n\n',
    'bare CR inside header value': 'GET /health HTTP/1.1\r\nHost: x\r\nX-A: a\rb\r\n\r\n',
    'NUL in header value': 'GET /health HTTP/1.1\r\nHost: x\r\nX-A: a\u0000b\r\n\r\n',
    'chunk size overflow': `${OV}${A}${CT}Transfer-Encoding: chunked\r\n\r\nFFFFFFFFFFFFFFFFFF\r\nabc\r\n0\r\n\r\n`,
    'chunk size not hex': `${OV}${A}${CT}Transfer-Encoding: chunked\r\n\r\nzz\r\nabc\r\n0\r\n\r\n`,
    'chunk data longer than size': `${OV}${A}${CT}Transfer-Encoding: chunked\r\n\r\n2\r\nabcdef\r\n0\r\n\r\n`,
    'missing Host on HTTP/1.1': 'GET /health HTTP/1.1\r\n\r\n',
    'duplicate Host': 'GET /health HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n',
    'space in request target': 'GET /hea lth HTTP/1.1\r\nHost: x\r\n\r\n',
    'NUL in request target': 'GET /hea\u0000lth HTTP/1.1\r\nHost: x\r\n\r\n',
    'invalid method token': 'G\u00e9T /health HTTP/1.1\r\nHost: x\r\n\r\n',
  };
  for (const [name, payload] of Object.entries(smuggling)) {
    await t.test(`smuggling: ${name} -> rejected with 400, no smuggled second request`, async () => {
      const before = overrideCount();
      const r = await send(payload);
      assert.deepEqual(r.statuses, [400], `${name}: got ${JSON.stringify(r.statuses)}`);
      assert.equal(overrideCount(), before, 'no override may be applied');
    });
  }
  await t.test('TE.CL desync attempt cannot smuggle an admin request onto an anonymous socket', async () => {
    const r = await send(`GET /health HTTP/1.1\r\nHost: x\r\nContent-Length: 70\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin/audit HTTP/1.1\r\nHost: x\r\n${A}\r\n`);
    assert.ok(!r.statuses.includes(200) || r.statuses.length === 1, JSON.stringify(r.statuses));
    assert.ok(!/"type":"auth\./.test(r.data));
  });

  // ---------- chunked bodies, extensions, trailers ----------
  await t.test('chunk extensions are tolerated (valid chunked body succeeds)', async () => {
    const r = await send(`${OV}${A}${CT}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n${BODY.length.toString(16)};ext=1;name="v"\r\n${BODY}\r\n0\r\n\r\n`);
    assert.equal(r.status, 201);
  });
  await t.test('uppercase hex chunk sizes and multiple chunks reassemble correctly', async () => {
    const a = BODY.slice(0, 20); const b = BODY.slice(20);
    const r = await send(`${OV}${A}${CT}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n${a.length.toString(16).toUpperCase()}\r\n${a}\r\n${b.length.toString(16).toUpperCase()}\r\n${b}\r\n0\r\n\r\n`);
    assert.equal(r.status, 201);
  });
  await t.test('Authorization in trailers is ignored (anonymous request stays 401)', async () => {
    const before = overrideCount();
    const r = await send(`${OV}${CT}Transfer-Encoding: chunked\r\nTrailer: Authorization\r\nConnection: close\r\n\r\n${BODY.length.toString(16)}\r\n${BODY}\r\n0\r\n${A}\r\n`);
    assert.equal(r.status, 401);
    assert.equal(overrideCount(), before);
  });
  await t.test('a second Authorization in trailers does not change the authenticated principal', async () => {
    const r = await send(`${OV}Authorization: Bearer ${tech}\r\n${CT}Transfer-Encoding: chunked\r\nConnection: close\r\n\r\n${BODY.length.toString(16)}\r\n${BODY}\r\n0\r\n${A}\r\n`);
    assert.equal(r.status, 403, 'still the technician (not admin from trailer)');
  });

  // ---------- keep-alive & pipelining: no auth state leaks across requests ----------
  await t.test('pipelined admin -> anonymous on one socket: second request is 401', async () => {
    const r = await send(`GET /admin/audit HTTP/1.1\r\nHost: x\r\n${A}\r\nGET /admin/audit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
    assert.deepEqual(r.statuses, [200, 401]);
  });
  await t.test('pipelined admin -> technician -> invalid -> admin: each request judged on its own token', async () => {
    const r = await send([
      `GET /admin/audit HTTP/1.1\r\nHost: x\r\n${A}\r\n`,
      `GET /admin/audit HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${tech}\r\n\r\n`,
      'GET /admin/audit HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer junk\r\n\r\n',
      `GET /admin/audit HTTP/1.1\r\nHost: x\r\n${A}Connection: close\r\n\r\n`,
    ].join(''));
    assert.deepEqual(r.statuses, [200, 403, 401, 200]);
  });
  await t.test('keep-alive with delays between requests: no principal carried over', async () => {
    const r = await rawSocket(s.port, undefined, { chunks: [
      [0, `GET /proxy/x HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${tech}\r\n\r\n`],
      [80, 'GET /proxy/x HTTP/1.1\r\nHost: x\r\n\r\n'],
      [80, `GET /proxy/x HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${tech}\r\nConnection: close\r\n\r\n`],
    ] });
    assert.deepEqual(r.statuses, [200, 401, 200]);
  });
  await t.test('pipelined POST whose body is short does not swallow the next request', async () => {
    const r = await send(`${OV}${A}${CT}Content-Length: ${BODY.length}\r\n\r\n${BODY}GET /admin/audit HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`);
    assert.deepEqual(r.statuses, [201, 401]);
  });
  await t.test('pipelined responses carry distinct x-request-ids, in order', async () => {
    const r = await send('GET /health HTTP/1.1\r\nHost: x\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\n\r\nGET /health HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n');
    const ids = [...r.data.matchAll(/x-request-id: ([0-9a-f-]{36})/gi)].map((m) => m[1]);
    assert.equal(ids.length, 3);
    assert.equal(new Set(ids).size, 3);
  });

  // ---------- versions & request targets ----------
  await t.test('HTTP/1.0 request works (no Host required) and the connection closes', async () => {
    const r = await send('GET /health HTTP/1.0\r\n\r\n');
    assert.equal(r.status, 200);
    assert.equal(r.why, 'close');
  });
  await t.test('HTTP/1.0 with keep-alive header and auth', async () => {
    const r = await send(`GET /proxy/x HTTP/1.0\r\nAuthorization: Bearer ${tech}\r\n\r\n`);
    assert.equal(r.status, 200);
  });
  for (const line of ['GET /health', 'GET /health HTTP/0.9', 'GET /health HTTP/2.0']) {
    await t.test(`non-HTTP/1.x request line "${line}" -> 505 (was served as 200 before round 4)`, async () => {
      const r = await send(`${line}\r\nHost: x\r\n\r\n`);
      assert.equal(r.status, 505);
    });
  }
  for (const line of ['GET /health HTTP/1.2', 'GET /health HTTP/9.9', 'GET /health HTTP/1', 'GET /health HTTPS/1.1', 'GET /health http/1.1']) {
    await t.test(`malformed version "${line}" -> 400`, async () => {
      assert.equal((await send(`${line}\r\nHost: x\r\n\r\n`)).status, 400);
    });
  }
  await t.test('absolute-form target: routed by path only, Host/authority ignored for authz', async () => {
    assert.equal((await send(`GET http://evil.example/admin/audit HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${tech}\r\nConnection: close\r\n\r\n`)).status, 403);
    assert.equal((await send(`GET http://evil.example/admin/audit HTTP/1.1\r\nHost: x\r\n${A}Connection: close\r\n\r\n`)).status, 200);
    assert.equal((await send('GET https://x/health?x=1 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')).status, 200);
  });
  await t.test('CONNECT (authority-form) is not tunnelled: socket closed with no response', async () => {
    const r = await send('CONNECT evil.example:443 HTTP/1.1\r\nHost: evil.example:443\r\n\r\n');
    assert.deepEqual(r.statuses, []);
    assert.equal(r.why, 'close');
  });
  await t.test('OPTIONS * (asterisk-form) -> 404, never routed', async () => {
    assert.equal((await send('OPTIONS * HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n')).status, 404);
  });
  await t.test('very long URLs: 8 KiB -> 404; 20 KiB -> 431; never 500', async () => {
    assert.equal((await send(`GET /${'a'.repeat(8000)} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`)).status, 404);
    assert.equal((await send(`GET /${'a'.repeat(20000)} HTTP/1.1\r\nHost: x\r\n\r\n`)).status, 431);
    assert.equal((await send(`GET /health?${'q=1&'.repeat(3000)} HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n`)).status, 200);
  });

  // ---------- Expect: 100-continue ----------
  await t.test('Expect: 100-continue from an anonymous client -> 401 and NO 100 Continue (bug before round 4)', async () => {
    const r = await send(`${OV}${CT}Content-Length: 1000\r\nExpect: 100-continue\r\n\r\n`);
    assert.deepEqual(r.statuses, [401]);
  });
  await t.test('Expect: 100-continue from an under-privileged client -> 403, no 100', async () => {
    const r = await send(`${OV}Authorization: Bearer ${tech}\r\n${CT}Content-Length: 1000\r\nExpect: 100-continue\r\n\r\n`);
    assert.deepEqual(r.statuses, [403]);
  });
  await t.test('Expect: 100-continue with an oversized Content-Length -> 413, no 100', async () => {
    const r = await send(`${OV}${A}${CT}Content-Length: 999999\r\nExpect: 100-continue\r\n\r\n`);
    assert.deepEqual(r.statuses, [413]);
  });
  await t.test('Expect: 100-continue with wrong content-type -> 415, no 100', async () => {
    const r = await send(`${OV}${A}Content-Type: text/plain\r\nContent-Length: 10\r\nExpect: 100-continue\r\n\r\n`);
    assert.deepEqual(r.statuses, [415]);
  });
  await t.test('Expect: 100-continue for a valid admin request -> 100 then 201 once the body arrives', async () => {
    const r = await rawSocket(s.port, undefined, { chunks: [
      [0, `${OV}${A}${CT}Content-Length: ${BODY.length}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n`],
      [100, BODY],
    ] });
    assert.deepEqual(r.statuses, [100, 201]);
  });
  await t.test('Expect: 100-continue on a GET (no body route) -> served normally', async () => {
    const r = await send(`GET /proxy/x HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${tech}\r\nExpect: 100-continue\r\nConnection: close\r\n\r\n`);
    assert.equal(r.status, 200);
  });
  await t.test('unknown Expect values -> 417', async () => {
    for (const v of ['200-ok', 'x', 'continue']) {
      assert.equal((await send(`GET /health HTTP/1.1\r\nHost: x\r\nExpect: ${v}\r\nConnection: close\r\n\r\n`)).status, 417, v);
    }
  });
  await t.test('Expect "100-continue, foo" is treated by Node as 100-continue (documented); still auth-gated', async () => {
    assert.equal((await send('GET /health HTTP/1.1\r\nHost: x\r\nExpect: 100-continue, foo\r\nConnection: close\r\n\r\n')).status, 200);
    assert.deepEqual((await send(`${OV}${CT}Content-Length: 100\r\nExpect: 100-continue, foo\r\n\r\n`)).statuses, [401]);
  });

  // ---------- header injection & request ids ----------
  await t.test('every response has a server-generated UUID x-request-id', async () => {
    for (const [path, h] of [['/health', {}], ['/nope', {}], ['/datasets', {}], ['/datasets', bearer(tech)], ['/proxy/x', bearer(tech)]]) {
      const r = await raw(s.port, { path, headers: h });
      assert.match(r.headers['x-request-id'], /^[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/);
    }
  });
  await t.test('caller-supplied X-Request-Id is ignored, never echoed (headers or body)', async () => {
    const r = await raw(s.port, { path: '/nope', headers: { 'x-request-id': 'attacker-chosen-id' } });
    assert.notEqual(r.headers['x-request-id'], 'attacker-chosen-id');
    assert.ok(!r.text.includes('attacker-chosen-id'));
  });
  await t.test('500 body requestId matches the x-request-id header and the audit entry', async () => {
    const orig = s.app.store.all;
    s.app.store.all = () => { throw new Error('boom'); };
    try {
      const r = await raw(s.port, { path: '/datasets', headers: bearer(tech) });
      assert.equal(r.status, 500);
      assert.equal(r.json.requestId, r.headers['x-request-id']);
      assert.ok(s.app.audit.recent(5).some((e) => e.type === 'error' && e.requestId === r.json.requestId));
    } finally { s.app.store.all = orig; }
  });
  await t.test('CRLF / encoded CRLF in path, query and ids is never reflected into response headers', async () => {
    for (const p of ['/datasets/X%0d%0aSet-Cookie:%20a=b', '/proxy/x%0d%0aX-Evil:%201', '/admin/overrides/%0d%0aX-Evil:1/revert', '/health?%0d%0aX-Evil:1', '/admin/datasets/X%0D%0AX-Evil:%201/overrides']) {
      const r = await raw(s.port, { path: p, headers: bearer(admin) });
      assert.ok(r.status < 500, `${p} -> ${r.status}`);
      assert.ok(!('set-cookie' in r.headers) && !('x-evil' in r.headers), p);
      for (const v of Object.values(r.headers)) assert.ok(!/[\r\n]/.test(String(v)));
    }
  });
  await t.test('Allow and WWW-Authenticate headers are built only from static route data', async () => {
    const r = await raw(s.port, { method: 'DELETE', path: '/admin/datasets/X%0d%0aX-Evil:1/overrides' });
    assert.ok(!('x-evil' in r.headers));
    const r2 = await raw(s.port, { method: 'DELETE', path: '/proxy/x' });
    assert.equal(r2.headers.allow, 'GET');
    const r3 = await raw(s.port, { path: '/proxy/y', headers: bearer(sign(claims({ roles: ['viewer'] }))) });
    assert.equal(r3.headers['www-authenticate'], 'Bearer realm="control704", error="insufficient_scope", scope="proxy:read proxy:y"');
  });
  await t.test('error messages echoing ids are JSON-encoded in the body only', async () => {
    const r = await raw(s.port, { path: '/datasets/Q%0d%0aX', headers: bearer(admin) });
    assert.equal(r.status, 404);
    assert.ok(!/[\r\n]/.test(r.text));
  });
});
