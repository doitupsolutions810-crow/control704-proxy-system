'use strict';
// Unicode / encoding: NFC/NFD, RTL & zero-width, overlong UTF-8, mixed-case percent-encoding, surrogates.
const test = require('node:test');
const assert = require('node:assert');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { toPrincipal } = require('../src/auth');
const { hasScopes } = require('../src/access/authorize');
const { DatasetStore, ValidationError, NotFoundError } = require('../src/datasets/store');
const { sign, claims, config, b64, hmac, SECRET, startServer, raw, bearer } = require('./helpers');

const provider = createAvroneProvider(config);
const ctx = { actor: 'a', reason: 'unicode test' };
const detailsMatch = (re) => (e) => e instanceof ValidationError && re.test(`${e.message} ${(e.details || []).join(' ')}`);

// ---------- NFC / NFD ----------
test('sub NFC vs NFD: both accepted, NOT normalised (sub is an opaque, exact-match identifier per RFC 7519)', async () => {
  const nfc = 'jos\u00e9'; const nfd = 'jose\u0301';
  assert.notEqual(nfc, nfd); assert.equal(nfc.normalize('NFC'), nfd.normalize('NFC'));
  assert.equal((await provider.verify(sign(claims({ sub: nfc })))).sub, nfc);
  assert.equal((await provider.verify(sign(claims({ sub: nfd })))).sub, nfd);
});
test('endpoint NFC/NFD/compatibility forms all rejected (ASCII-only endpoints)', () => {
  for (const ep of ['/proxy/caf\u00e9', '/proxy/cafe\u0301', '/proxy/\uff58', '/proxy/x\u0307', '/proxy/\u2170', '/proxy/\ufb01le' /* ﬁ ligature */]) {
    assert.throws(() => new DatasetStore().override('X', { endpoint: ep }, ctx), detailsMatch(/endpoint/), ep);
  }
});
test('dataset ids: only ASCII x/y/z (any case) map to X/Y/Z — exhaustive BMP + astral scan of toUpperCase', () => {
  const hits = [];
  for (let cp = 0; cp <= 0x10ffff; cp++) {
    if (cp >= 0xd800 && cp <= 0xdfff) continue;
    const ch = String.fromCodePoint(cp);
    const up = ch.toUpperCase();
    if (up === 'X' || up === 'Y' || up === 'Z') hits.push(ch);
  }
  assert.deepEqual(hits.sort(), ['X', 'Y', 'Z', 'x', 'y', 'z'].sort());
  for (const id of ['\uff38', 'Χ' /* Greek chi */, 'Х' /* Cyrillic */, 'x\u200b', '\u202eX']) {
    assert.throws(() => new DatasetStore().get(id), NotFoundError, id);
  }
});
test('roles & scopes are exact code-point matches (no case folding, no normalisation, no lookalikes)', () => {
  const P = (c) => toPrincipal({ sub: 's', ...c }, 't');
  for (const role of ['adm\u0131n' /* dotless i */, '\u0430dmin' /* Cyrillic a */, 'ADMIN', 'admin\u200b', 'ad\u00admin', '\uff41dmin']) {
    assert.ok(!hasScopes(P({ roles: [role] }), ['audit:read']), role);
  }
  for (const scope of ['datasets:overr\u0456de', 'datasets\uff1aoverride', 'datasets:override\u200b', 'DATASETS:OVERRIDE']) {
    assert.ok(!hasScopes(P({ scope }), ['datasets:override']), scope);
  }
});

// ---------- RTL / zero-width ----------
const INVIS = ['\u200b', '\u200c', '\u200e', '\u200f', '\u202a', '\u202b', '\u202c', '\u202d', '\u202e', '\u2066', '\u2067', '\u2068', '\u2069', '\u2060', '\ufeff', '\u061c'];
for (const ch of INVIS) {
  const cp = `U+${ch.codePointAt(0).toString(16).toUpperCase().padStart(4, '0')}`;
  test(`${cp} rejected in sub, reason, metadata value and endpoint`, async () => {
    await assert.rejects(provider.verify(sign(claims({ sub: `ad${ch}min` }))), /sub/);
    assert.throws(() => new DatasetStore().override('X', { enabled: false }, { actor: 'a', reason: `fix ${ch} it` }), /control or bidi/);
    assert.throws(() => new DatasetStore().override('X', { metadata: { k: `v${ch}` } }, ctx), detailsMatch(/metadata/));
    assert.throws(() => new DatasetStore().override('X', { endpoint: `/proxy/a${ch}b` }, ctx), detailsMatch(/endpoint/));
  });
}
test('ZWJ emoji sequences and RTL *letters* (Arabic/Hebrew text) are allowed in reason', () => {
  const s = new DatasetStore();
  assert.ok(s.override('X', { enabled: false }, { actor: 'a', reason: 'deploy 👩‍💻 by ops' }));
  assert.ok(s.override('X', { enabled: true }, { actor: 'a', reason: 'صيانة مجدولة' }));
  assert.ok(s.override('X', { enabled: false }, { actor: 'a', reason: 'תחזוקה מתוכננת' }));
});
test('RTL letters in sub allowed (they are not format controls)', async () => {
  assert.equal((await provider.verify(sign(claims({ sub: 'مستخدم-1' })))).sub, 'مستخدم-1');
});

// ---------- surrogates ----------
for (const [name, str] of [['lone high', 'a\ud800b'], ['lone low', 'a\udc00b'], ['reversed pair', 'a\udc00\ud800b'], ['trailing high', 'abc\ud83d']]) {
  test(`${name} surrogate rejected in reason/metadata/sub`, async () => {
    assert.throws(() => new DatasetStore().override('X', { enabled: false }, { actor: 'a', reason: `r ${str}` }), /control or bidi/);
    assert.throws(() => new DatasetStore().override('X', { metadata: { k: str } }, ctx), detailsMatch(/metadata/));
    // JSON.stringify escapes lone surrogates (well-formed JSON.stringify), so the token is valid JSON
    await assert.rejects(provider.verify(sign(claims({ sub: str }))), /sub/);
  });
}
test('valid astral characters (surrogate pairs) allowed', () => {
  assert.ok(new DatasetStore().override('X', { metadata: { k: '𝔘𝔫𝔦𝔠𝔬𝔡𝔢 🚀' } }, ctx));
});

// ---------- overlong / invalid UTF-8 in tokens ----------
const signBytes = (headerObj, payloadBytes) => {
  const h = b64(headerObj); const p = Buffer.from(payloadBytes).toString('base64url');
  return `${h}.${p}.${hmac(SECRET, `${h}.${p}`)}`;
};
for (const [name, bytes] of [
  ['overlong "/" (C0 AF)', [0xc0, 0xaf]], ['overlong NUL (C0 80)', [0xc0, 0x80]], ['3-byte overlong (E0 80 AF)', [0xe0, 0x80, 0xaf]],
  ['UTF-16 surrogate encoded in UTF-8 (ED A0 80)', [0xed, 0xa0, 0x80]], ['truncated sequence (E2 82)', [0xe2, 0x82]], ['invalid byte FF', [0xff]],
  ['code point > U+10FFFF (F4 90 80 80)', [0xf4, 0x90, 0x80, 0x80]],
]) {
  test(`token payload with ${name} rejected (strict UTF-8)`, async () => {
    const c = JSON.stringify(claims());
    const payload = Buffer.concat([Buffer.from(c.slice(0, -1) + ',"x":"'), Buffer.from(bytes), Buffer.from('"}')]);
    await assert.rejects(provider.verify(signBytes({ alg: 'HS256' }, payload)), /Malformed/);
  });
}
test('token header with invalid UTF-8 rejected', async () => {
  const h = Buffer.concat([Buffer.from('{"alg":"HS256","k":"'), Buffer.from([0xc0, 0xaf]), Buffer.from('"}')]).toString('base64url');
  const p = b64(claims());
  await assert.rejects(provider.verify(`${h}.${p}.${hmac(SECRET, `${h}.${p}`)}`), /Malformed/);
});
test('UTF-8 BOM before token JSON is rejected (RFC 8259: BOM MUST NOT be added to network JSON)', async () => {
  const payload = Buffer.concat([Buffer.from([0xef, 0xbb, 0xbf]), Buffer.from(JSON.stringify(claims()))]);
  await assert.rejects(provider.verify(signBytes({ alg: 'HS256' }, payload)), /Malformed/);
});

// ---------- HTTP: percent-encoding & encodings ----------
test('HTTP percent-encoding and body encodings', async (t) => {
  const s = await startServer();
  t.after(() => s.close());
  const admin = sign(claims({ roles: ['admin'] }));
  const tech = sign(claims({ roles: ['technician'] }));

  await t.test('mixed-case encoded dot-segments are normalised by the URL parser and still authorised by the final path', async () => {
    for (const p of ['/proxy/%2e%2e/admin/audit', '/proxy/%2E%2e/admin/audit', '/proxy/%2e%2E/admin/audit', '/proxy/%2E%2E/admin/audit', '/proxy/.%2e/admin/audit']) {
      const r = await raw(s.port, { path: p, headers: bearer(tech) });
      assert.equal(r.status, 403, p); // reaches /admin/audit, which technicians may not read
      assert.equal((await raw(s.port, { path: p, headers: bearer(admin) })).status, 200, p);
    }
  });
  await t.test('percent-encoded route characters are NOT decoded (no alternate spellings of routes)', async () => {
    for (const p of ['/proxy/%78', '/proxy/%58', '/%70roxy/x', '/admin%2Faudit', '/admin%2faudit', '/admin/%61udit', '/datasets%2FX', '/proxy/x%2F', '/proxy/x%00', '/proxy/x%20', '/proxy/x%E2%80%8B']) {
      assert.equal((await raw(s.port, { path: p, headers: bearer(admin) })).status, 404, p);
    }
  });
  await t.test('raw non-ASCII bytes in path -> 404 or 400, never 500', async () => {
    for (const p of ['/proxy/\u00e9', '/datasets/\uff38']) {
      let r;
      try { r = await raw(s.port, { path: encodeURI(p), headers: bearer(admin) }); } catch { continue; }
      assert.ok([400, 404].includes(r.status), `${p} ${r.status}`);
    }
  });
  await t.test('JSON \\u-escaped bidi / zero-width / lone surrogate in body are rejected after decoding', async () => {
    for (const reason of ['\\u202e evil', 'ok \\u200b ok', 'bad \\ud800 x']) {
      const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(admin), 'content-type': 'application/json' }, body: `{"patch":{"enabled":false},"reason":"${reason}"}` });
      assert.equal(r.status, 400, reason);
    }
  });
  await t.test('UTF-16 encoded body (with charset param) is rejected as invalid UTF-8/JSON, not misparsed', async () => {
    const body = Buffer.from('\ufeff{"patch":{"enabled":false},"reason":"utf16 body"}', 'utf16le');
    const r = await raw(s.port, { method: 'POST', path: '/admin/datasets/X/overrides', headers: { ...bearer(admin), 'content-type': 'application/json; charset=utf-16' }, body });
    assert.equal(r.status, 400);
  });
  await t.test('audit log entries are valid JSON and ASCII-safe for unicode actors', async () => {
    const t2 = sign(claims({ sub: 'jos\u00e9-\u05d0', roles: ['viewer'] }));
    await raw(s.port, { path: '/datasets', headers: bearer(t2) });
    const line = s.lines.map((l) => JSON.parse(l)).reverse().find((e) => e.type === 'request');
    assert.equal(line.actor, 'jos\u00e9-\u05d0');
    assert.ok(s.lines.every((l) => !/[\u2028\u2029]/.test(l) || JSON.parse(l)));
  });
});
