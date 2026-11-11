'use strict';
// Cross-repo contract: avrone-chat's real minting helper (living-intermediate-control-plane,
// avrone-chat/lib/control704/avrone-jwt.ts) against this proxy's verifier, with freshly
// generated keys. Runs when AVRONE_CHAT_DIR points at an avrone-chat checkout (or the sibling
// checkout ../living-intermediate-control-plane/avrone-chat exists); skipped otherwise.
// The TypeScript is loaded with Node's built-in type stripping (no TypeScript dependency).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { pathToFileURL } = require('url');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { toPrincipal } = require('../src/auth');

const candidates = [process.env.AVRONE_CHAT_DIR, path.join(__dirname, '..', '..', 'repos', 'living-intermediate-control-plane', 'avrone-chat'),
  path.join(__dirname, '..', '..', 'living-intermediate-control-plane', 'avrone-chat')].filter(Boolean);
const dir = candidates.find((d) => fs.existsSync(path.join(d, 'lib', 'control704', 'avrone-jwt.ts')));
const [major] = process.versions.node.split('.').map(Number);
const skip = !dir ? 'avrone-chat checkout not found (set AVRONE_CHAT_DIR)' : major < 23 ? 'needs Node >= 23 type stripping' : false;

let helper;
async function load() {
  if (helper) return helper;
  const src = path.join(dir, 'lib', 'control704');
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'c704-chat-'));
  for (const f of ['avrone-jwt.ts', 'roles.ts']) {
    fs.writeFileSync(path.join(tmp, f), fs.readFileSync(path.join(src, f), 'utf8').replace(/from '\.\/roles'/g, "from './roles.ts'"));
  }
  const prev = process.emitWarning; process.emitWarning = () => {};
  try { helper = await import(pathToFileURL(path.join(tmp, 'avrone-jwt.ts')).href); } finally { process.emitWarning = prev; }
  return helper;
}

let seed = 0xA7;
const rnd = (n) => { seed = (seed * 1103515245 + 12345) >>> 0; return seed % n; };
const genSecret = (i) => {
  switch (i % 4) {
    case 0: return crypto.randomBytes(32).toString('hex');
    case 1: return crypto.randomBytes(24 + rnd(40)).toString('base64url');
    case 2: return crypto.generateKeySync('hmac', { length: 256 + 8 * rnd(32) }).export().toString('base64');
    default: return `ключ-${crypto.randomBytes(16).toString('hex')}-秘密`;
  }
};
const ISS = 'https://avrone-due-krey-chat.vercel.app';
const AUD = 'control704-proxy';

test('cross-repo: 200 generated secrets x random subjects/roles/TTLs minted by avrone-chat verify in the proxy', { skip }, async () => {
  const m = await load();
  for (let i = 0; i < 200; i++) {
    const secret = genSecret(i);
    const ttl = [30, 60, 120, 299, 300][i % 5];
    const cfg = m.proxyJwtConfig({ AVRONE_ISSUER: ISS, AVRONE_AUDIENCE: AUD, AVRONE_JWT_SECRET: secret, CONTROL704_PROXY_JWT_TTL_S: String(ttl) });
    assert.ok(cfg, `config #${i}`);
    const sub = ['tech1', 'jean', 'ops.tech-2', 'Ünïcödé', 'a'.repeat(256), `u${i}@example`][i % 6];
    const role = m.ROLES ? m.ROLES[i % 3] : ['viewer', 'technician', 'admin'][i % 3];
    const now = Date.now();
    const { token, claims } = await m.mintProxyToken(sub, role, { config: cfg, now });
    const provider = createAvroneProvider({ issuer: ISS, audience: AUD, clockSkewSec: 30, secret, maxTokenAgeSec: 300, now: () => now });
    const verified = await provider.verify(token);
    assert.deepEqual(verified, claims);
    const p = toPrincipal(verified, 'avrone');
    assert.equal(p.sub, sub);
    assert.deepEqual(p.roles, [role]);
    assert.equal(verified.exp - verified.iat, ttl);
    const other = createAvroneProvider({ issuer: ISS, audience: AUD, clockSkewSec: 30, secret: genSecret(i + 1) + 'x', now: () => now });
    await assert.rejects(other.verify(token), `foreign secret #${i}`);
  }
});

test('cross-repo: secret acceptance rules agree (avrone-chat secretProblem vs proxy startup)', { skip }, async () => {
  const m = await load();
  const cases = ['', 'short', 'a'.repeat(32), 'ab'.repeat(16), '0123456'.repeat(5), '01234567'.repeat(4), ` ${genSecret(0)}`, `${genSecret(0)}\n`,
    genSecret(0), genSecret(1), genSecret(2), genSecret(3), 'é'.repeat(8) + 'abcdefgh' + 'x'.repeat(4), '😀'.repeat(8) + '1234567'];
  for (let i = 0; i < 200; i++) cases.push(Array.from({ length: rnd(50) }, () => String.fromCharCode(32 + rnd(95))).join(''));
  for (const s of cases) {
    const chatOk = m.secretProblem(s) === null;
    let proxyOk = true;
    try { createAvroneProvider({ issuer: ISS, audience: AUD, clockSkewSec: 30, secret: s }); } catch { proxyOk = false; }
    if (s === '') { assert.equal(proxyOk, false); continue; }
    assert.equal(chatOk, proxyOk, `secret ${JSON.stringify(s).slice(0, 40)} chat=${chatOk} proxy=${proxyOk}`);
  }
});

test('cross-repo: subject acceptance agrees (avrone-chat isValidSub vs proxy verification)', { skip }, async () => {
  const m = await load();
  const { mintAvroneToken } = require('../src/auth/issuer');
  const secret = genSecret(0);
  const provider = createAvroneProvider({ issuer: ISS, audience: AUD, clockSkewSec: 30, secret });
  const subs = ['ok', 'a'.repeat(256), 'a'.repeat(257), 'tab\there', 'nl\n', 'zw\u200bsp', 'bidi\u202e', 'bom\ufeff', 'lone\ud800', 'pair\ud83d\ude00', 'nbsp\u00a0x', 'del\u007f', 'c1\u0085', 'ls\u2028'];
  for (const sub of subs) {
    const chatOk = m.isValidSub(sub);
    let proxyOk;
    if (sub.length > 256) proxyOk = false;
    else {
      const { token } = mintAvroneToken({ secret, issuer: ISS, audience: AUD, sub, roles: ['viewer'] });
      proxyOk = await provider.verify(token).then(() => true, () => false);
    }
    assert.equal(chatOk, proxyOk, `sub ${JSON.stringify(sub)} chat=${chatOk} proxy=${proxyOk}`);
  }
});

test('cross-repo: tokens are byte-compatible with the reference issuer given the same jti and clock', { skip }, async () => {
  const m = await load();
  const { mintAvroneToken } = require('../src/auth/issuer');
  for (let i = 0; i < 25; i++) {
    const secret = genSecret(i);
    const cfg = m.proxyJwtConfig({ AVRONE_ISSUER: ISS, AVRONE_AUDIENCE: AUD, AVRONE_JWT_SECRET: secret });
    const now = Date.now() - i * 1000;
    const { token, claims } = await m.mintProxyToken('tech1', 'technician', { config: cfg, now });
    const ref = mintAvroneToken({ secret, issuer: ISS, audience: AUD, sub: 'tech1', roles: ['technician'], ttlSec: claims.exp - claims.iat, now, jti: claims.jti });
    assert.equal(ref.token, token);
  }
});
