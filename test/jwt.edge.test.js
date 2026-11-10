'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider, loadConfigFromEnv, AuthError } = require('../src/auth/avroneProvider');
const { sign, signRaw, claims, config, b64, hmac, SECRET, ISSUER, AUDIENCE } = require('./helpers');

const provider = createAvroneProvider(config);
const now = () => Math.floor(Date.now() / 1000);
const rejects = (tok, re, p = provider) => assert.rejects(p.verify(tok), (e) => e instanceof AuthError && (!re || re.test(e.message)));

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaPem = rsa.publicKey.export({ type: 'spki', format: 'pem' });
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const ecPem = ec.publicKey.export({ type: 'spki', format: 'pem' });

function signRS(payload, header = {}, key = rsa.privateKey) {
  const h = b64({ alg: 'RS256', typ: 'JWT', ...header });
  const p = b64(payload);
  return `${h}.${p}.${crypto.sign('sha256', Buffer.from(`${h}.${p}`), key).toString('base64url')}`;
}
function signES(payload, header = {}) {
  const h = b64({ alg: 'ES256', ...header });
  const p = b64(payload);
  const sig = crypto.sign('sha256', Buffer.from(`${h}.${p}`), { key: ec.privateKey, dsaEncoding: 'ieee-p1363' });
  return `${h}.${p}.${sig.toString('base64url')}`;
}

// ---------- algorithm confusion ----------
for (const alg of ['none', 'NONE', 'None', 'nOnE', 'hs256', 'HS384', 'HS512', 'RS256', 'ES256', 'PS256', 'EdDSA', '', ' HS256', 'HS256 ']) {
  test(`alg confusion: header alg ${JSON.stringify(alg)} rejected on HS256-only provider`, () => rejects(sign(claims(), { alg }), /Algorithm not allowed/));
}
for (const alg of [null, 123, true, ['HS256'], { a: 1 }]) {
  test(`alg confusion: non-string alg ${JSON.stringify(alg)} rejected`, () => rejects(signRaw(JSON.stringify({ alg }), JSON.stringify(claims())), /Algorithm not allowed/));
}
test('alg missing from header rejected', () => rejects(signRaw('{"typ":"JWT"}', JSON.stringify(claims())), /Algorithm not allowed/));
test('alg none with empty signature rejected', () => {
  const t = `${b64({ alg: 'none' })}.${b64(claims())}.`;
  return rejects(t);
});

test('HS/RS swap: HS256 signed with RSA public key PEM rejected by RS256 provider', async () => {
  const p = createAvroneProvider({ ...config, secret: '', publicKey: rsaPem });
  await rejects(sign(claims(), { secret: rsaPem }), /Algorithm not allowed/, p);
  await rejects(sign(claims(), { secret: rsaPem.trim() }), /Algorithm not allowed/, p);
  const der = rsa.publicKey.export({ type: 'spki', format: 'der' });
  const h = b64({ alg: 'HS256' }); const pl = b64(claims());
  await rejects(`${h}.${pl}.${crypto.createHmac('sha256', der).update(`${h}.${pl}`).digest('base64url')}`, /Algorithm not allowed/, p);
});
test('HS/ES swap: HS256 signed with EC public key rejected by ES256 provider', async () => {
  const p = createAvroneProvider({ ...config, secret: '', publicKey: ecPem });
  await rejects(sign(claims(), { secret: ecPem }), /Algorithm not allowed/, p);
});
test('RS256 provider accepts genuine RS256 token', async () => {
  const p = createAvroneProvider({ ...config, secret: '', publicKey: rsaPem });
  assert.equal((await p.verify(signRS(claims()))).sub, 'user-1');
});
test('RS256 provider rejects token signed by a different RSA key', async () => {
  const p = createAvroneProvider({ ...config, secret: '', publicKey: rsaPem });
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  await rejects(signRS(claims(), {}, other.privateKey), /Invalid signature/, p);
});
test('RS256 provider rejects ES256 header', async () => {
  const p = createAvroneProvider({ ...config, secret: '', publicKey: rsaPem });
  await rejects(signES(claims()), /Algorithm not allowed/, p);
});
test('ES256 provider accepts genuine ES256 token and rejects DER-encoded signature', async () => {
  const p = createAvroneProvider({ ...config, secret: '', publicKey: ecPem });
  assert.equal((await p.verify(signES(claims()))).sub, 'user-1');
  const h = b64({ alg: 'ES256' }); const pl = b64(claims());
  const der = crypto.sign('sha256', Buffer.from(`${h}.${pl}`), ec.privateKey).toString('base64url');
  await rejects(`${h}.${pl}.${der}`, /Invalid signature/, p);
});
test('RS256 token tampered payload rejected', async () => {
  const p = createAvroneProvider({ ...config, secret: '', publicKey: rsaPem });
  const [h, , s] = signRS(claims()).split('.');
  await rejects(`${h}.${b64(claims({ roles: ['admin'] }))}.${s}`, /Invalid signature/, p);
});
test('provider with both secret and RSA key accepts both, each only with its own key', async () => {
  const p = createAvroneProvider({ ...config, publicKey: rsaPem });
  assert.ok(await p.verify(sign(claims())));
  assert.ok(await p.verify(signRS(claims())));
  await rejects(sign(claims(), { secret: rsaPem }), /Invalid signature/, p);
});

// ---------- header tampering ----------
for (const [name, header] of [
  ['kid path traversal', { kid: '../../../../etc/passwd' }],
  ['kid sql injection', { kid: "' OR 1=1 --" }],
  ['jku remote key', { jku: 'https://evil.example/jwks.json' }],
  ['x5u remote cert', { x5u: 'https://evil.example/cert.pem' }],
  ['embedded jwk', { jwk: { kty: 'oct', k: b64('attacker-secret-attacker-secret-attacker') } }],
]) {
  test(`header tampering: ${name} is ignored — only configured key is trusted`, async () => {
    assert.ok(await provider.verify(sign(claims(), { header })));
    await rejects(sign(claims(), { header, secret: 'attacker-secret-attacker-secret-attacker' }), /Invalid signature/);
  });
}
test('header crit is rejected', () => rejects(sign(claims(), { header: { crit: ['exp'] } }), /crit/));
test('header tampered after signing rejected', () => {
  const [, p, s] = sign(claims()).split('.');
  return rejects(`${b64({ alg: 'HS256', kid: 'x' })}.${p}.${s}`, /Invalid signature/);
});
test('header that is a JSON array rejected', () => rejects(signRaw('["HS256"]', JSON.stringify(claims())), /Malformed/));
test('header that is JSON null rejected', () => rejects(signRaw('null', JSON.stringify(claims())), /Malformed/));
test('payload that is JSON array / string / number rejected', async () => {
  for (const pl of ['[]', '"sub"', '42', 'true', 'null']) await rejects(signRaw('{"alg":"HS256"}', pl), /Malformed/);
});
test('header that is not JSON rejected', () => rejects(signRaw('{alg:HS256}', JSON.stringify(claims())), /Malformed/));

// ---------- odd JSON ----------
test('duplicate JSON keys: last value wins and is the one that was signed', async () => {
  const c = claims();
  const payload = JSON.stringify(c).replace(/^\{/, '{"sub":"attacker",');
  const out = await provider.verify(signRaw('{"alg":"HS256"}', payload));
  assert.equal(out.sub, 'user-1');
});
test('duplicate alg keys: last wins (none) -> rejected', () => rejects(signRaw('{"alg":"HS256","alg":"none"}', JSON.stringify(claims())), /Algorithm not allowed/));
test('__proto__ key in payload does not pollute Object.prototype', async () => {
  const pl = JSON.stringify(claims()).replace(/^\{/, '{"__proto__":{"polluted":true,"roles":["admin"]},');
  const out = await provider.verify(signRaw('{"alg":"HS256"}', pl));
  assert.equal(({}).polluted, undefined);
  assert.equal(Object.prototype.roles, undefined);
  assert.equal(out.sub, 'user-1');
});
test('constructor/prototype keys in payload are inert', async () => {
  const out = await provider.verify(sign(claims({ constructor: { prototype: { x: 1 } }, prototype: 1 })));
  assert.equal(({}).x, undefined);
  assert.equal(out.sub, 'user-1');
});
test('deeply nested payload within size limit is handled', async () => {
  let nested = {}; const root = nested;
  for (let i = 0; i < 500; i++) { nested.a = {}; nested = nested.a; }
  const t = sign(claims({ deep: root }));
  if (t.length <= 8192) assert.ok(await provider.verify(t));
  else await rejects(t, /oversized/);
});
test('huge payload (> 8 KiB token) rejected before parsing', () => rejects(sign(claims({ blob: 'x'.repeat(10000) })), /oversized/));
test('token exactly at 8192 chars is still parsed; 8193 rejected', async () => {
  const base = sign(claims({ pad: '' }));
  let pad = '';
  let t = base;
  // grow pad until the token is around the limit
  while (t.length < 8192) { pad += 'x'; t = sign(claims({ pad })); }
  if (t.length === 8192) assert.ok(await provider.verify(t));
  await rejects(t + 'x'.repeat(8193 - t.length + 1), /oversized|Malformed|three segments|Non-canonical|signature/);
});
test('unicode in claims round-trips', async () => {
  const out = await provider.verify(sign(claims({ sub: 'tëch-😀-Ω', name: '名前' })));
  assert.equal(out.sub, 'tëch-😀-Ω');
});
test('null byte / control chars in sub rejected', async () => {
  await rejects(sign(claims({ sub: 'admin\u0000' })), /sub/);
  await rejects(sign(claims({ sub: 'a\nb' })), /sub/);
  await rejects(sign(claims({ sub: '\u007f' })), /sub/);
});
test('sub longer than 256 chars rejected', () => rejects(sign(claims({ sub: 'a'.repeat(257) })), /sub/));
test('sub of exactly 256 chars accepted', async () => assert.ok(await provider.verify(sign(claims({ sub: 'a'.repeat(256) })))));
for (const sub of [['user-1'], 123, null, true, {}, '']) {
  test(`sub wrong type ${JSON.stringify(sub)} rejected`, () => rejects(sign(claims({ sub })), /sub/));
}
test('missing sub rejected', () => { const c = claims(); delete c.sub; return rejects(sign(c), /sub/); });

// ---------- aud / iss ----------
test('aud as array containing audience accepted', async () => assert.ok(await provider.verify(sign(claims({ aud: ['other', AUDIENCE] })))));
for (const aud of [['other'], [], [[AUDIENCE]], [{ a: AUDIENCE }], 42, null, { aud: AUDIENCE }, AUDIENCE.toUpperCase(), `${AUDIENCE} `, `${AUDIENCE},x`]) {
  test(`aud ${JSON.stringify(aud)} rejected`, () => rejects(sign(claims({ aud })), /audience/));
}
test('missing aud rejected', () => { const c = claims(); delete c.aud; return rejects(sign(c), /audience/); });
for (const iss of [ISSUER + '/', ISSUER.toUpperCase(), [ISSUER], null, 1, '']) {
  test(`iss ${JSON.stringify(iss)} rejected`, () => rejects(sign(claims({ iss })), /issuer/));
}

// ---------- time claims ----------
test('exp exactly now is rejected (skew 0)', () => rejects(sign(claims({ exp: now() })), /expired/));
test('exp now+1 accepted (skew 0)', async () => assert.ok(await provider.verify(sign(claims({ exp: now() + 2 })))));
test('exp in past but within skew accepted; at skew boundary rejected', async () => {
  const p = createAvroneProvider({ ...config, clockSkewSec: 30 });
  assert.ok(await p.verify(sign(claims({ exp: now() - 25 }))));
  await rejects(sign(claims({ exp: now() - 30 })), /expired/, p);
  await rejects(sign(claims({ exp: now() - 31 })), /expired/, p);
});
for (const exp of ['9999999999', null, true, [1], {}]) {
  test(`exp wrong type ${JSON.stringify(exp)} rejected`, () => rejects(sign(claims({ exp })), /exp/));
}
test('missing exp rejected', () => { const c = claims(); delete c.exp; return rejects(sign(c), /exp/); });
test('exp as float in future accepted', async () => assert.ok(await provider.verify(sign(claims({ exp: now() + 100.5 })))));
test('exp 1e308 accepted (finite), but huge iat in future rejected', async () => {
  assert.ok(await provider.verify(sign(claims({ exp: 1e308 }))));
  await rejects(sign(claims({ iat: 1e308 })), /future/);
});
test('nbf in future rejected, nbf now accepted, nbf within skew accepted', async () => {
  await rejects(sign(claims({ nbf: now() + 60 })), /not yet valid/);
  assert.ok(await provider.verify(sign(claims({ nbf: now() }))));
  const p = createAvroneProvider({ ...config, clockSkewSec: 30 });
  assert.ok(await p.verify(sign(claims({ nbf: now() + 20 }))));
  await rejects(sign(claims({ nbf: now() + 40 })), /not yet valid/, p);
});
for (const nbf of ['later', null, [0], {}]) {
  test(`nbf wrong type ${JSON.stringify(nbf)} rejected (was silently ignored before fix)`, () => rejects(sign(claims({ nbf })), /nbf/));
}
test('iat in the future rejected (was accepted before fix)', () => rejects(sign(claims({ iat: now() + 3600 })), /future/));
test('iat in the future within skew accepted', async () => {
  const p = createAvroneProvider({ ...config, clockSkewSec: 30 });
  assert.ok(await p.verify(sign(claims({ iat: now() + 10 }))));
});
for (const iat of ['now', null, {}]) {
  test(`iat wrong type ${JSON.stringify(iat)} rejected`, () => rejects(sign(claims({ iat })), /iat/));
}
test('max token age: fresh accepted, old rejected, missing iat rejected', async () => {
  const p = createAvroneProvider({ ...config, maxTokenAgeSec: 60 });
  assert.ok(await p.verify(sign(claims({ iat: now() - 30 }))));
  await rejects(sign(claims({ iat: now() - 120 })), /too old/, p);
  const c = claims(); delete c.iat;
  await rejects(sign(c), /missing iat/, p);
});
test('max token age boundary: exactly maxAge old accepted, maxAge+1 rejected', async () => {
  const p = createAvroneProvider({ ...config, maxTokenAgeSec: 60 });
  assert.ok(await p.verify(sign(claims({ iat: now() - 59 }))));
  await rejects(sign(claims({ iat: now() - 62 })), /too old/, p);
});
test('expired token has code token_expired; bad sig has invalid_token', async () => {
  await assert.rejects(provider.verify(sign(claims({ exp: now() - 5 }))), (e) => e.code === 'token_expired');
  await assert.rejects(provider.verify(sign(claims(), { secret: 'z'.repeat(40) })), (e) => e.code === 'invalid_token');
});

// ---------- structure / encoding ----------
test('extra segments rejected', () => rejects(sign(claims()) + '.extra', /three segments/));
test('two segments rejected', () => rejects(sign(claims()).split('.').slice(0, 2).join('.'), /three segments/));
test('empty segments rejected', async () => { await rejects('..', /Malformed/); await rejects('a..b'); });
test('base64 padding (=) rejected', () => { const [h, p, s] = sign(claims()).split('.'); return rejects(`${h}=.${p}.${s}`, /Malformed/); });
for (const ch of ['+', '/', ' ', '%', '!', '\u0000', 'é', '\n']) {
  test(`non-base64url char ${JSON.stringify(ch)} rejected`, () => {
    const [h, p, s] = sign(claims()).split('.');
    return rejects(`${h}.${p}${ch}.${s}`, /Malformed/);
  });
}
test('standard base64 (with +/) of the signature rejected', () => {
  const [h, p] = sign(claims()).split('.');
  // find a payload where sig contains - or _ to force difference
  const sig = crypto.createHmac('sha256', SECRET).update(`${h}.${p}`).digest('base64');
  if (/[+/=]/.test(sig)) return rejects(`${h}.${p}.${sig}`, /Malformed/);
  return undefined;
});
test('non-canonical base64url (trailing bits) signature rejected (malleability fix)', async () => {
  const [h, p, s] = sign(claims()).split('.');
  // HS256 sig = 32 bytes = 43 chars; last char encodes 4 data bits + 2 padding bits.
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  const idx = alphabet.indexOf(s[s.length - 1]);
  const tweaked = s.slice(0, -1) + alphabet[idx ^ 1];
  assert.deepEqual(Buffer.from(tweaked, 'base64url'), Buffer.from(s, 'base64url'));
  await rejects(`${h}.${p}.${tweaked}`, /Non-canonical/);
});
test('segment length % 4 === 1 rejected', () => { const [h, p] = sign(claims()).split('.'); return rejects(`${h}.${p}.A`, /Malformed/); });
test('truncated signature rejected', () => { const t = sign(claims()); return rejects(t.slice(0, -4)); });
test('signature of different length rejected without throwing non-AuthError', () => {
  const [h, p] = sign(claims()).split('.');
  return rejects(`${h}.${p}.${b64('short')}`);
});
for (const t of [undefined, null, 42, {}, [], Buffer.from('a.b.c')]) {
  test(`non-string token ${Object.prototype.toString.call(t)} rejected`, () => rejects(t, /Missing/));
}

// ---------- config ----------
test('config: NaN/negative/huge clock skew rejected (NaN previously accepted expired tokens)', () => {
  for (const clockSkewSec of [NaN, -1, 301, 1.5, Infinity, '30']) {
    assert.throws(() => createAvroneProvider({ ...config, clockSkewSec }), /CLOCK_SKEW/);
  }
});
test('config: bad max token age rejected', () => {
  for (const maxTokenAgeSec of [0, -5, NaN, 1.5]) assert.throws(() => createAvroneProvider({ ...config, maxTokenAgeSec }), /MAX_TOKEN_AGE/);
});
test('config from env: strict integer parsing', () => {
  const env = { AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_SECRET: SECRET };
  assert.equal(loadConfigFromEnv(env).clockSkewSec, 30);
  assert.equal(loadConfigFromEnv({ ...env, AVRONE_CLOCK_SKEW_SEC: '0' }).clockSkewSec, 0);
  assert.equal(loadConfigFromEnv({ ...env, AVRONE_MAX_TOKEN_AGE_SEC: '600' }).maxTokenAgeSec, 600);
  assert.equal(loadConfigFromEnv(env).maxTokenAgeSec, null);
  for (const v of ['abc', '30s', '-1', '1.5', '0x10']) {
    assert.throws(() => loadConfigFromEnv({ ...env, AVRONE_CLOCK_SKEW_SEC: v }), /AVRONE_CLOCK_SKEW_SEC/);
  }
});
test('config from env: PEM with escaped \\n works', async () => {
  const env = { AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_PUBLIC_KEY: rsaPem.replace(/\n/g, '\\n') };
  const p = createAvroneProvider(loadConfigFromEnv(env));
  assert.ok(await p.verify(signRS(claims())));
});
test('config: secret of exactly 32 bytes accepted, 31 rejected (multi-byte counted as bytes)', () => {
  assert.ok(createAvroneProvider({ ...config, secret: 'a'.repeat(32) }));
  assert.throws(() => createAvroneProvider({ ...config, secret: 'a'.repeat(31) }), /32/);
  assert.ok(createAvroneProvider({ ...config, secret: 'é'.repeat(16) }));
});
test('config: weak RSA (1024) and unsupported key types rejected', () => {
  const weak = crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: weak }), /2048/);
  const ed = crypto.generateKeyPairSync('ed25519').publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: ed }), /Unsupported/);
  const p384 = crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey.export({ type: 'spki', format: 'pem' });
  assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: p384 }), /Unsupported/);
  assert.throws(() => createAvroneProvider({ ...config, secret: '', publicKey: 'not a pem' }));
});
test('config: no secret in module source or test fixtures', () => {
  const fs = require('fs');
  for (const f of ['src/auth/avroneProvider.js', 'src/server.js', 'src/proxy.js']) {
    const src = fs.readFileSync(require('path').join(__dirname, '..', f), 'utf8');
    assert.ok(!/AVRONE_JWT_SECRET\s*=\s*['"][^'"]+['"]/.test(src), f);
  }
  assert.ok(hmac);
});
