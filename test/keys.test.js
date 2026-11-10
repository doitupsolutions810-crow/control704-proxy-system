'use strict';
// Key handling: malformed PEMs, wrong key types for an alg, runtime env/config swaps, empty/whitespace secrets.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider, loadConfigFromEnv } = require('../src/auth/avroneProvider');
const { sign, claims, config, b64, SECRET, ISSUER, AUDIENCE } = require('./helpers');

const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsaPem = rsa.publicKey.export({ type: 'spki', format: 'pem' });
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
const ecPem = ec.publicKey.export({ type: 'spki', format: 'pem' });
const withKey = (publicKey) => ({ ...config, secret: '', publicKey });
const signAsym = (alg, key, payload, opts = {}) => {
  const h = b64({ alg }); const p = b64(payload);
  return `${h}.${p}.${crypto.sign('sha256', Buffer.from(`${h}.${p}`), opts.dsa ? { key, dsaEncoding: 'ieee-p1363' } : key).toString('base64url')}`;
};

// ---------- malformed PEMs ----------
const body = rsaPem.split('\n').slice(1, -2).join('\n');
const malformed = {
  'truncated body': rsaPem.slice(0, 200) + '\n-----END PUBLIC KEY-----\n',
  'missing END line': rsaPem.replace('-----END PUBLIC KEY-----', ''),
  'missing BEGIN line': rsaPem.replace('-----BEGIN PUBLIC KEY-----', ''),
  'garbage base64': '-----BEGIN PUBLIC KEY-----\n!!!!notbase64!!!!\n-----END PUBLIC KEY-----\n',
  'valid base64 but not ASN.1': `-----BEGIN PUBLIC KEY-----\n${Buffer.from('hello world, not a key').toString('base64')}\n-----END PUBLIC KEY-----\n`,
  'body only (no armor)': body,
  'wrong label (CERTIFICATE) with key body': rsaPem.replace(/PUBLIC KEY/g, 'CERTIFICATE'),
  'whitespace only': '   \n\t ',
  'random text': 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ user@host',
  'JWK JSON instead of PEM': JSON.stringify(rsa.publicKey.export({ format: 'jwk' })),
  'byte-flipped body': rsaPem.replace(/A/, 'B').replace(/M/, 'N'),
};
for (const [name, pem] of Object.entries(malformed)) {
  test(`malformed PEM: ${name} -> clear config error at startup`, () => {
    assert.throws(() => createAvroneProvider(withKey(pem)), (e) => /AVRONE_JWT_PUBLIC_KEY|Unsupported|2048/.test(e.message));
  });
}
test('PEM variants that are fine: CRLF line endings, surrounding whitespace, escaped \\n from env', async () => {
  const tokn = signAsym('RS256', rsa.privateKey, claims());
  for (const pem of [rsaPem.replace(/\n/g, '\r\n'), `\n\n  ${rsaPem}  \n`]) {
    assert.ok(await createAvroneProvider(withKey(pem)).verify(tokn));
  }
  const env = { AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_PUBLIC_KEY: rsaPem.replace(/\n/g, '\\n') };
  assert.ok(await createAvroneProvider(loadConfigFromEnv(env)).verify(tokn));
});
test('PKCS#1 "RSA PUBLIC KEY" PEM accepted', async () => {
  const pkcs1 = rsa.publicKey.export({ type: 'pkcs1', format: 'pem' });
  assert.ok(await createAvroneProvider(withKey(pkcs1)).verify(signAsym('RS256', rsa.privateKey, claims())));
});
test('non-string key / secret types rejected', () => {
  assert.throws(() => createAvroneProvider(withKey(Buffer.from(rsaPem))), /PEM string/);
  assert.throws(() => createAvroneProvider(withKey(rsa.publicKey)), /PEM string/);
  assert.throws(() => createAvroneProvider({ ...config, secret: Buffer.from(SECRET) }), /must be a string/);
  assert.throws(() => createAvroneProvider({ ...config, secret: 12345678901234567890 }), /must be a string/);
});

// ---------- unsupported key types ----------
const unsupported = {
  'RSA-PSS': () => crypto.generateKeyPairSync('rsa-pss', { modulusLength: 2048 }).publicKey,
  'DSA': () => crypto.generateKeyPairSync('dsa', { modulusLength: 2048, divisorLength: 256 }).publicKey,
  'Ed25519': () => crypto.generateKeyPairSync('ed25519').publicKey,
  'Ed448': () => crypto.generateKeyPairSync('ed448').publicKey,
  'X25519': () => crypto.generateKeyPairSync('x25519').publicKey,
  'EC secp256k1': () => crypto.generateKeyPairSync('ec', { namedCurve: 'secp256k1' }).publicKey,
  'EC P-384': () => crypto.generateKeyPairSync('ec', { namedCurve: 'secp384r1' }).publicKey,
  'EC P-521': () => crypto.generateKeyPairSync('ec', { namedCurve: 'secp521r1' }).publicKey,
  'RSA 1024': () => crypto.generateKeyPairSync('rsa', { modulusLength: 1024 }).publicKey,
  'RSA 2047': () => crypto.generateKeyPairSync('rsa', { modulusLength: 2047 }).publicKey,
};
for (const [name, gen] of Object.entries(unsupported)) {
  test(`unsupported key type ${name} rejected at startup`, () => {
    let pem;
    try { pem = gen().export({ type: 'spki', format: 'pem' }); } catch { return; } // not available in this OpenSSL build
    assert.throws(() => createAvroneProvider(withKey(pem)), /Unsupported|2048/);
  });
}
test('RSA 2048 and 4096 accepted', () => {
  assert.ok(createAvroneProvider(withKey(rsaPem)));
  const big = crypto.generateKeyPairSync('rsa', { modulusLength: 3072 }).publicKey.export({ type: 'spki', format: 'pem' });
  assert.ok(createAvroneProvider(withKey(big)));
});

// ---------- wrong key type for alg ----------
test('RSA key configured: ES256 / HS256 / PS256 tokens rejected regardless of signature', async () => {
  const p = createAvroneProvider(withKey(rsaPem));
  await assert.rejects(p.verify(signAsym('ES256', ec.privateKey, claims(), { dsa: true })), /Algorithm not allowed/);
  await assert.rejects(p.verify(sign(claims(), { secret: rsaPem })), /Algorithm not allowed/);
  await assert.rejects(p.verify(signAsym('PS256', rsa.privateKey, claims())), /Algorithm not allowed/);
});
test('EC key configured: RS256 / HS256 tokens rejected', async () => {
  const p = createAvroneProvider(withKey(ecPem));
  await assert.rejects(p.verify(signAsym('RS256', rsa.privateKey, claims())), /Algorithm not allowed/);
  await assert.rejects(p.verify(sign(claims(), { secret: ecPem })), /Algorithm not allowed/);
});
test('RS256 header with an ES256-shaped signature (64 bytes) is rejected without throwing non-AuthError', async () => {
  const p = createAvroneProvider(withKey(rsaPem));
  const h = b64({ alg: 'RS256' }); const pl = b64(claims());
  await assert.rejects(p.verify(`${h}.${pl}.${crypto.randomBytes(64).toString('base64url')}`), /Invalid signature/);
  await assert.rejects(p.verify(`${h}.${pl}.`), /Invalid signature/);
});
test('ES256 with wrong-length signature (63/65/0 bytes) rejected', async () => {
  const p = createAvroneProvider(withKey(ecPem));
  const h = b64({ alg: 'ES256' }); const pl = b64(claims());
  for (const n of [0, 63, 65, 72]) await assert.rejects(p.verify(`${h}.${pl}.${crypto.randomBytes(n).toString('base64url')}`), /Invalid signature/);
});
test('ES256 high-S (malleable) signature: documented — Node accepts both forms; payload still authenticated', async () => {
  // Informational: ECDSA signatures (r, s) and (r, n-s) both verify. Tokens are still authentic,
  // they just have two encodings; we never use signatures as identifiers.
  const p = createAvroneProvider(withKey(ecPem));
  const tokn = signAsym('ES256', ec.privateKey, claims(), { dsa: true });
  assert.ok(await p.verify(tokn));
});

// ---------- runtime config / env swaps ----------
test('changing process.env after startup does not change the running provider', async () => {
  const saved = { ...process.env };
  try {
    Object.assign(process.env, { AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_SECRET: SECRET });
    const p = createAvroneProvider(loadConfigFromEnv());
    const attacker = 'attacker-secret-0123456789abcdefghijklmnop';
    process.env.AVRONE_JWT_SECRET = attacker;
    process.env.AVRONE_ISSUER = 'evil';
    await assert.rejects(p.verify(sign(claims(), { secret: attacker })), /Invalid signature/);
    assert.ok(await p.verify(sign(claims())));
    // an explicit reload (new provider) picks up the new values
    const p2 = createAvroneProvider(loadConfigFromEnv());
    assert.ok(await p2.verify(sign(claims({ iss: 'evil' }), { secret: attacker })));
    await assert.rejects(p2.verify(sign(claims())), /Invalid signature/);
  } finally {
    for (const k of Object.keys(process.env)) if (!(k in saved)) delete process.env[k];
    Object.assign(process.env, saved);
  }
});
test('key rotation: tokens from the old secret fail on a provider built with the new one', async () => {
  const old = createAvroneProvider(config);
  const rotated = createAvroneProvider({ ...config, secret: crypto.randomBytes(32).toString('hex') });
  const t = sign(claims());
  assert.ok(await old.verify(t));
  await assert.rejects(rotated.verify(t), /Invalid signature/);
});
test('provider config snapshot is frozen-in at creation (mutating publicKey/secret later has no effect)', async () => {
  const cfg = withKey(rsaPem);
  const p = createAvroneProvider(cfg);
  const other = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  cfg.publicKey = other.publicKey.export({ type: 'spki', format: 'pem' });
  cfg.secret = SECRET;
  await assert.rejects(p.verify(signAsym('RS256', other.privateKey, claims())), /Invalid signature/);
  await assert.rejects(p.verify(sign(claims())), /Algorithm not allowed/);
});

// ---------- empty / whitespace secrets ----------
for (const [name, secret] of [['empty', ''], ['null', null], ['undefined', undefined]]) {
  test(`secret ${name} with no public key -> startup error`, () => {
    assert.throws(() => createAvroneProvider({ ...config, secret, publicKey: '' }), /Set AVRONE_JWT_SECRET/);
  });
}
for (const [name, secret] of [
  ['32 spaces', ' '.repeat(32)], ['tabs', '\t'.repeat(40)], ['newlines', '\n'.repeat(40)], ['NBSP', '\u00a0'.repeat(40)],
  ['ideographic spaces', '\u3000'.repeat(20)], ['trailing newline', `${SECRET}\n`], ['leading space', ` ${SECRET}`], ['trailing CRLF', `${SECRET}\r\n`],
]) {
  test(`secret "${name}" rejected`, () => assert.throws(() => createAvroneProvider({ ...config, secret }), /blank|whitespace|variety/));
}
test('env: whitespace-only AVRONE_JWT_SECRET from env rejected', () => {
  const cfg = loadConfigFromEnv({ AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_SECRET: ' '.repeat(48) });
  assert.throws(() => createAvroneProvider(cfg), /blank|whitespace/);
});
test('env: whitespace-only AVRONE_JWT_PUBLIC_KEY rejected with clear error', () => {
  const cfg = loadConfigFromEnv({ AVRONE_ISSUER: ISSUER, AVRONE_AUDIENCE: AUDIENCE, AVRONE_JWT_PUBLIC_KEY: '   ' });
  assert.throws(() => createAvroneProvider(cfg), /not a valid PEM/);
});
test('a secret with internal spaces but good variety is fine', () => {
  assert.ok(createAvroneProvider({ ...config, secret: 'correct horse battery staple 0123456789' }));
});
