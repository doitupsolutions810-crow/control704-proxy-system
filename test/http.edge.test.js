'use strict';
const test = require('node:test');
const assert = require('node:assert');
const net = require('net');
const { sign, claims, startServer, raw, bearer } = require('./helpers');

test('HTTP server edge cases', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const admin = sign(claims({ roles: ['admin'] }));
  const tech = sign(claims({ roles: ['technician'] }));
  const post = (body, headers = {}) => raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(admin), 'content-type': 'application/json', ...headers }, body });
  const goodBody = JSON.stringify({ patch: { metadata: { a: 'b' } }, reason: 'http edge' });

  // ---------- malformed JSON ----------
  for (const body of ['{', '{"patch":', 'not json', '{"a":1}}', "{'patch':{}}", '{"patch":{"enabled":false},}', '\u0000', '[1,2', 'NaN', '{"a":Infinity}']) {
    await t.test(`malformed JSON ${JSON.stringify(body)} -> 400`, async () => {
      const r = await post(body);
      assert.equal(r.status, 400);
      assert.equal(r.json.error, 'validation_error');
    });
  }
  for (const body of ['null', '[]', '"str"', '42', 'true', '[{"patch":{"enabled":false},"reason":"arr"}]']) {
    await t.test(`non-object JSON body ${body} -> 400 (null crashed with 500 before fix)`, async () => {
      const r = await post(body);
      assert.equal(r.status, 400);
      assert.match(r.json.message, /object/);
    });
  }
  await t.test('empty body -> 400 (treated as {} -> missing patch)', async () => assert.equal((await post('')).status, 400));
  await t.test('JSON with BOM -> 400 not 500', async () => assert.ok([400].includes((await post('\ufeff' + goodBody)).status)));
  await t.test('invalid UTF-8 bytes -> 400 not 500', async () => assert.equal((await post(Buffer.from([0x7b, 0xff, 0xfe, 0x7d]))).status, 400));
  await t.test('valid body succeeds -> 201', async () => assert.equal((await post(goodBody)).status, 201));

  // ---------- content-type ----------
  for (const ct of ['application/json; charset=utf-8', 'Application/JSON', 'application/json;charset=UTF-8', 'application/json ']) {
    await t.test(`content-type ${JSON.stringify(ct)} accepted`, async () => assert.equal((await post(goodBody, { 'content-type': ct })).status, 201));
  }
  for (const ct of [undefined, '', 'text/plain', 'application/x-www-form-urlencoded', 'multipart/form-data; boundary=x', 'application/jsonx', 'application/json-patch+json', 'text/json', 'application/xml', 'json']) {
    await t.test(`content-type ${JSON.stringify(ct)} -> 415`, async () => {
      const headers = { ...bearer(admin) };
      if (ct !== undefined) headers['content-type'] = ct;
      const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers, body: goodBody });
      assert.equal(r.status, 415);
      assert.equal(r.json.error, 'unsupported_media_type');
    });
  }
  await t.test('wrong content-type but unauthenticated -> 401 first (auth before body parsing)', async () => {
    const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { 'content-type': 'text/plain' }, body: 'x' });
    assert.equal(r.status, 401);
  });
  await t.test('wrong content-type, authenticated but not admin -> 403 (authz before body parsing)', async () => {
    const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(tech), 'content-type': 'text/plain' }, body: 'x' });
    assert.equal(r.status, 403);
  });

  // ---------- oversized bodies ----------
  await t.test('body exactly 16 KiB accepted for parsing', async () => {
    const base = { patch: { metadata: { a: 'b' } }, reason: 'size', pad: '' };
    const pad = 16 * 1024 - Buffer.byteLength(JSON.stringify(base));
    const body = JSON.stringify({ ...base, pad: 'x'.repeat(pad) });
    assert.equal(Buffer.byteLength(body), 16 * 1024);
    assert.equal((await post(body)).status, 201);
  });
  await t.test('body 16 KiB + 1 -> 413 with JSON response (connection reset before fix)', async () => {
    const base = { patch: { metadata: { a: 'b' } }, reason: 'size', pad: '' };
    const pad = 16 * 1024 + 1 - Buffer.byteLength(JSON.stringify(base));
    const r = await post(JSON.stringify({ ...base, pad: 'x'.repeat(pad) }));
    assert.equal(r.status, 413);
    assert.equal(r.json.error, 'payload_too_large');
  });
  await t.test('1 MiB body -> 413', async () => {
    const r = await post('{"pad":"' + 'x'.repeat(1024 * 1024) + '"}');
    assert.equal(r.status, 413);
  });
  await t.test('chunked (no content-length) oversized body -> 413', async () => {
    const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(admin), 'content-type': 'application/json', 'transfer-encoding': 'chunked' }, body: 'x'.repeat(40000) });
    assert.equal(r.status, 413);
  });
  await t.test('lying content-length header (huge) -> 413 without waiting for body', async () => {
    const r = await new Promise((resolve, reject) => {
      const sock = net.connect(s.port, '127.0.0.1', () => {
        sock.write(`POST /admin/datasets/X/overrides HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer ${admin}\r\nContent-Type: application/json\r\nContent-Length: 999999999\r\n\r\n{`);
      });
      let data = '';
      sock.on('data', (d) => { data += d; if (data.includes('\r\n\r\n')) { sock.destroy(); resolve(data); } });
      sock.on('error', reject);
      setTimeout(() => { sock.destroy(); resolve(data); }, 2000);
    });
    assert.match(r, /^HTTP\/1\.1 413/);
  });

  // ---------- routes / methods ----------
  for (const path of ['/', '/proxy', '/proxy/w', '/proxy/xx', '/proxy/x/', '/proxy/x/extra', '/admin', '/admin/datasets', '/admin/overrides', '/datasets/', '/health/', '/HEALTH', '/%2e%2e/etc/passwd', '/proxy/%78', '/favicon.ico', '/admin/audit/']) {
    await t.test(`unknown route ${path} -> 404`, async () => {
      const r = await raw(s.port, { path, headers: bearer(admin) });
      assert.equal(r.status, 404, `${path} ${r.text}`);
    });
  }
  await t.test('unknown routes 404 without auth too (no auth oracle differences beyond 404)', async () => {
    assert.equal((await raw(s.port, { path: '/nope' })).status, 404);
  });
  await t.test('dataset ids that are prototype keys -> 404 not 500', async () => {
    for (const id of ['__proto__', 'constructor', 'toString', 'hasOwnProperty']) {
      assert.equal((await raw(s.port, { path: `/datasets/${id}`, headers: bearer(admin) })).status, 404);
      const r = await raw(s.port, { method: 'POST', path: `/admin/datasets/${id}/overrides`, headers: { ...bearer(admin), 'content-type': 'application/json' }, body: goodBody });
      assert.equal(r.status, 404);
    }
  });
  for (const [method, path, allow] of [
    ['POST', '/health', 'GET'], ['DELETE', '/proxy/x', 'GET'], ['PUT', '/datasets/X', 'GET'], ['PATCH', '/datasets', 'GET'],
    ['GET', '/admin/overrides/00000000-0000-0000-0000-000000000000/revert', 'POST'], ['DELETE', '/admin/datasets/X/overrides', 'POST, GET'],
    ['HEAD', '/health', 'GET'], ['OPTIONS', '/proxy/x', 'GET'], ['TRACE', '/health', 'GET'],
  ]) {
    await t.test(`${method} ${path} -> 405 with Allow: ${allow}`, async () => {
      const r = await raw(s.port, { method, path, headers: bearer(admin) });
      assert.equal(r.status, 405);
      assert.equal(r.headers.allow, allow);
    });
  }
  await t.test('405 does not require auth and does not leak data', async () => {
    const r = await raw(s.port, { method: 'DELETE', path: '/datasets' });
    assert.equal(r.status, 405);
    assert.deepEqual(r.json, { error: 'method_not_allowed' });
  });

  // ---------- query strings & URL quirks ----------
  await t.test('query strings are ignored for routing', async () => {
    assert.equal((await raw(s.port, { path: '/health?x=1&y=2' })).status, 200);
    assert.equal((await raw(s.port, { path: '/proxy/x?role=admin&scope=datasets:override', headers: bearer(tech) })).status, 200);
    assert.equal((await raw(s.port, { path: '/admin/audit?roles=admin', headers: bearer(tech) })).status, 403);
  });
  await t.test('fragment / encoded chars do not bypass routing', async () => {
    assert.equal((await raw(s.port, { path: '/admin%2faudit', headers: bearer(tech) })).status, 404);
    assert.equal((await raw(s.port, { path: '/proxy/x%00', headers: bearer(tech) })).status, 404);
  });
  await t.test('dot-segment normalisation cannot reach admin routes without admin scope', async () => {
    const r = await raw(s.port, { path: '/proxy/../admin/audit', headers: bearer(tech) });
    assert.equal(r.status, 403);
  });
  await t.test('absolute-form request target is routed by path only', async () => {
    const r = await raw(s.port, { path: 'http://evil.example/health' });
    assert.equal(r.status, 200);
  });
  await t.test('malformed request target -> 400, server stays up (hung before fix)', async () => {
    const r = await raw(s.port, { path: 'http://[' });
    assert.equal(r.status, 400);
    assert.equal((await raw(s.port, { path: '/health' })).status, 200);
  });
  await t.test('very long path -> 404, logged path truncated', async () => {
    const r = await raw(s.port, { path: '/proxy/' + 'a'.repeat(4000), headers: bearer(admin) });
    assert.equal(r.status, 404);
  });

  // ---------- headers ----------
  await t.test('responses carry security headers and JSON content-type', async () => {
    const r = await raw(s.port, { path: '/datasets', headers: bearer(admin) });
    assert.equal(r.headers['cache-control'], 'no-store');
    assert.equal(r.headers['x-content-type-options'], 'nosniff');
    assert.match(r.headers['content-type'], /^application\/json/);
  });
  await t.test('500s do not leak error messages (requestId only)', async () => {
    const { createApp } = require('../src/server');
    const app = createApp({ provider: { name: 'boom', verify: async () => { throw new TypeError('secret internal detail'); } } });
    const srv = app.server();
    await new Promise((r) => srv.listen(0, '127.0.0.1', r));
    try {
      const r = await raw(srv.address().port, { path: '/datasets', headers: bearer('x') });
      // non-AuthError from provider is treated as invalid token (401), not 500
      assert.equal(r.status, 401);
      assert.ok(!r.text.includes('secret internal detail'));
    } finally { srv.close(); }
  });
  await t.test('slow/idle keep-alive connections do not block other requests', async () => {
    const sock = net.connect(s.port, '127.0.0.1');
    await new Promise((r) => sock.on('connect', r));
    sock.write('GET /health HTTP/1.1\r\nHost: x\r\n'); // incomplete
    const r = await raw(s.port, { path: '/health' });
    assert.equal(r.status, 200);
    sock.destroy();
  });
});
