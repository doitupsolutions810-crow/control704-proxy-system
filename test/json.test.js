'use strict';
// JSON parser edges in request bodies: number precision, -0, 1e309, deep nesting, BOM,
// duplicate keys at every level, and __proto__/constructor at nested levels.
const test = require('node:test');
const assert = require('node:assert');
const { sign, claims, startServer, raw, bearer } = require('./helpers');

test('JSON body edge cases', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const admin = sign(claims({ roles: ['admin'] }));
  const post = (body, ds = 'X') => raw(s.port, { method: 'POST', path: `/admin/datasets/${ds}/overrides`, headers: { ...bearer(admin), 'content-type': 'application/json' }, body });
  const wrap = (patchJson, reason = '"json edge"') => `{"patch":${patchJson},"reason":${reason}}`;
  const ok = async (body, check) => { const r = await post(body); assert.equal(r.status, 201, `${body.slice(0, 80)} -> ${r.status} ${r.text.slice(0, 120)}`); if (check) check(r.json); return r; };
  const bad = async (body, status = 400) => { const r = await post(body); assert.equal(r.status, status, `${body.slice(0, 80)} -> ${r.status} ${r.text.slice(0, 120)}`); return r; };
  const before = () => s.app.store.get('X');

  // ---------- numbers ----------
  await t.test('1e309 (Infinity after parse) rejected in every numeric field', async () => {
    await bad(wrap('{"rateLimitPerMinute":1e309}'));
    await bad(wrap('{"rateLimitPerMinute":-1e309}'));
    await bad(wrap('{"metadata":{"n":1e309}}'));
    await bad(wrap('{"metadata":{"n":-1e309}}'));
  });
  await t.test('integers beyond 2^53 in metadata rejected (would silently lose precision)', async () => {
    for (const n of ['9007199254740993', '9007199254740992', '-9007199254740993', '1e21', '123456789012345678901234567890']) await bad(wrap(`{"metadata":{"n":${n}}}`));
  });
  await t.test('MAX_SAFE_INTEGER and MIN_SAFE_INTEGER round-trip exactly', async () => {
    await ok(wrap('{"metadata":{"a":9007199254740991,"b":-9007199254740991}}'), (j) => {
      assert.equal(j.after.metadata.a, Number.MAX_SAFE_INTEGER);
      assert.equal(j.after.metadata.b, Number.MIN_SAFE_INTEGER);
    });
  });
  await t.test('rateLimit 10000.0000000000001 parses to exactly 10000 -> accepted (JSON number semantics, documented)', async () => {
    await ok(wrap('{"rateLimitPerMinute":10000.0000000000001}'), (j) => assert.equal(j.after.rateLimitPerMinute, 10000));
  });
  await t.test('rateLimit 10000.000000001 (representable fraction) rejected', async () => {
    await bad(wrap('{"rateLimitPerMinute":10000.000000001}'));
  });
  await t.test('rateLimit as 1.0 / 1e2 / 1E2 / 100e0 accepted as integers', async () => {
    for (const v of ['1.0', '1e2', '1E2', '100e0', '1.00e+2']) await ok(wrap(`{"rateLimitPerMinute":${v}}`));
  });
  await t.test('rateLimit -0 rejected (< 1); metadata -0 stored as 0', async () => {
    await bad(wrap('{"rateLimitPerMinute":-0}'));
    await ok(wrap('{"metadata":{"z":-0}}'), (j) => assert.ok(Object.is(j.after.metadata.z, 0)));
  });
  await t.test('denormals, 5e-324 and tiny negatives accepted as metadata', async () => {
    await ok(wrap('{"metadata":{"a":5e-324,"b":-5e-324,"c":2.2250738585072014e-308}}'));
  });
  await t.test('non-JSON number syntaxes rejected: NaN, Infinity, hex, leading zeros, +1, .5, 1., trailing e', async () => {
    for (const v of ['NaN', 'Infinity', '-Infinity', '0x10', '010', '+1', '.5', '1.', '1e', '1e+', '--1', '1_000']) await bad(wrap(`{"rateLimitPerMinute":${v}}`));
  });
  await t.test('number strings are not coerced', async () => {
    for (const v of ['"60"', '"1e2"', '" 60"', '"0x3c"']) await bad(wrap(`{"rateLimitPerMinute":${v}}`));
  });

  // ---------- deep nesting ----------
  await t.test('deeply nested arrays/objects as body -> 400 (not a crash), within the 16 KiB cap', async () => {
    await bad('['.repeat(8000) + ']'.repeat(8000));
    await bad('{"a":'.repeat(2500) + '1' + '}'.repeat(2500).replace(/^/, '') );
  });
  await t.test('deep nesting inside patch.metadata -> 400', async () => {
    await bad(wrap(`{"metadata":{"a":${'['.repeat(3000)}${']'.repeat(3000)}}}`));
    await bad(wrap(`{"metadata":${'{"a":'.repeat(1000)}1${'}'.repeat(1000)}}`));
  });
  await t.test('deep nesting inside an ignored top-level key is harmless (only patch/reason are read)', async () => {
    await ok(`{"extra":${'['.repeat(3000)}${']'.repeat(3000)},"patch":{"metadata":{"e":1}},"reason":"extra key"}`);
  });
  await t.test('server survives and stays correct after many deep-nesting bodies', async () => {
    await Promise.all(Array.from({ length: 20 }, () => post('['.repeat(7000) + ']'.repeat(7000))));
    assert.equal((await raw(s.port, { path: '/health' })).status, 200);
  });

  // ---------- BOM / whitespace ----------
  await t.test('UTF-8 BOM prefix tolerated; UTF-16 BOM / double BOM rejected', async () => {
    await ok(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(wrap('{"metadata":{"bom":1}}'))]));
    await bad(Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf]), Buffer.from(wrap('{"enabled":true}'))]));
    await bad(Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from(wrap('{"enabled":true}'), 'utf16le')]));
  });
  await t.test('BOM inside a string value is rejected as a format character', async () => {
    await bad(wrap('{"metadata":{"k":"a\\ufeffb"}}'));
    await bad(wrap('{"enabled":true}', '"reason \\ufeff x"'));
  });
  await t.test('insignificant whitespace (tabs, CR, LF) around tokens is fine', async () => {
    await ok(`\r\n\t {\n"patch"\t:\r{ "metadata" : { "ws" : 1 } } ,\n "reason" : "whitespace" }\n\n`);
  });
  await t.test('trailing garbage / multiple JSON values rejected', async () => {
    await bad(`${wrap('{"enabled":true}')} x`);
    await bad(`${wrap('{"enabled":true}')}${wrap('{"enabled":false}')}`);
    await bad(`${wrap('{"enabled":true}')}\u0000`);
  });

  // ---------- duplicate keys ----------
  await t.test('duplicate keys: last one wins at every level, and the audit trail records exactly what was applied', async () => {
    const r = await ok('{"patch":{"enabled":true,"enabled":false,"metadata":{"k":"first","k":"second"}},"reason":"first reason","reason":"dup keys"}');
    assert.equal(r.json.after.enabled, false);
    assert.equal(r.json.after.metadata.k, 'second');
    assert.equal(r.json.reason, 'dup keys');
    const entry = s.app.audit.recent(20).reverse().find((e) => e.type === 'dataset.override' && e.overrideId === r.json.id);
    assert.deepEqual(entry.patch, r.json.patch);
    assert.equal(entry.reason, 'dup keys');
  });
  await t.test('duplicate "patch" keys: last wins (documented)', async () => {
    await ok('{"patch":{"auth":"none"},"patch":{"metadata":{"dp":1}},"reason":"dup patch"}', (j) => assert.equal(j.after.auth, 'token-override'));
  });
  await t.test('duplicate key where the LAST value is invalid -> rejected (no "first valid" bypass)', async () => {
    await bad('{"patch":{"rateLimitPerMinute":5,"rateLimitPerMinute":0},"reason":"dup invalid"}');
    await bad('{"patch":{"metadata":{"ok":1}},"patch":{"auth":"none"},"reason":"dup invalid patch"}');
  });

  // ---------- prototype pollution at nested levels ----------
  const POLLUTERS = [
    ['patch.__proto__', '{"patch":{"__proto__":{"auth":"none","enabled":false}},"reason":"proto1"}'],
    ['patch.constructor.prototype', '{"patch":{"constructor":{"prototype":{"auth":"none"}}},"reason":"proto2"}'],
    ['patch.metadata.__proto__', '{"patch":{"metadata":{"__proto__":{"polluted":"yes"}}},"reason":"proto3"}'],
    ['patch.metadata.__proto__ (string)', '{"patch":{"metadata":{"__proto__":"x"}},"reason":"proto4"}'],
    ['patch.metadata.constructor', '{"patch":{"metadata":{"constructor":"x"}},"reason":"proto5"}'],
    ['patch.metadata.prototype', '{"patch":{"metadata":{"prototype":1}},"reason":"proto6"}'],
    ['patch.endpoint.__proto__', '{"patch":{"endpoint":{"__proto__":"/proxy/q"}},"reason":"proto7"}'],
    ['patch with __proto__ AND valid field', '{"patch":{"enabled":false,"__proto__":{"auth":"none"}},"reason":"proto8"}'],
    ['top-level __proto__ carrying patch', '{"__proto__":{"patch":{"enabled":false},"reason":"inherited"}}'],
    ['top-level constructor', '{"constructor":{"prototype":{"patch":{"enabled":false}}},"reason":"proto10"}'],
    ['escaped "\\u005f_proto__" key', '{"patch":{"\\u005f_proto__":{"auth":"none"}},"reason":"proto11"}'],
  ];
  for (const [name, body] of POLLUTERS) {
    await t.test(`prototype pollution via ${name} -> 400, nothing polluted, state untouched`, async () => {
      const b = before();
      await bad(body);
      assert.deepEqual(before(), b);
      assert.equal(({}).polluted, undefined);
      assert.equal(({}).auth, undefined);
      assert.equal(({}).patch, undefined);
      assert.equal(Object.prototype.enabled, undefined);
    });
  }
  await t.test('after all pollution attempts, every dataset auth mode is unchanged', async () => {
    const all = (await raw(s.port, { path: '/datasets', headers: bearer(admin) })).json;
    assert.deepEqual([all.X.auth, all.Y.auth, all.Z.auth], ['token-override', 'dataset-code', 'lattice-op']);
  });

  // ---------- strings ----------
  await t.test('all JSON escapes decode correctly; escaped control chars still rejected', async () => {
    await ok(wrap('{"metadata":{"e":"\\"\\\\\\/ \\u00e9 \\ud83d\\ude80"}}'), (j) => assert.equal(j.after.metadata.e, '"\\/ é 🚀'));
    for (const esc of ['\\n', '\\r', '\\t', '\\b', '\\f', '\\u0000', '\\u001b', '\\u007f', '\\u0085']) await bad(wrap(`{"metadata":{"e":"a${esc}b"}}`));
    // reason: TAB and LF allowed (multi-line reasons), CR rejected
    await ok(wrap('{"metadata":{"r":1}}', '"line one\\nline two\\tend"'));
    await bad(wrap('{"metadata":{"r":2}}', '"overwrite\\rspoof"'));
  });
  await t.test('invalid escapes and raw control characters in strings rejected by the parser', async () => {
    for (const v of ['"\\x41"', '"\\u12"', '"\\uZZZZ"', '"a\u0001b"', '"a\nb"', "'single'"]) await bad(wrap(`{"metadata":{"e":${v}}}`));
  });
});
