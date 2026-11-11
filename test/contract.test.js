'use strict';
// Contract tests: the Avrone Due'Krey issuer (avrone-chat, living-intermediate-control-plane)
// <-> this proxy's verifier. test/fixtures/avrone-chat-tokens.json holds golden tokens minted
// by avrone-chat's real issuer with a TEST-ONLY secret at a fixed clock.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { toPrincipal } = require('../src/auth');
const { effectiveScopes, ROLE_SCOPES } = require('../src/access/authorize');
const { mintAvroneToken, MAX_TTL_SEC } = require('../src/auth/issuer');
const G = require('./fixtures/avrone-chat-tokens.json');

const provider = (over = {}) => createAvroneProvider({ issuer: G.issuer, audience: G.audience, secret: G.secret, clockSkewSec: 30, maxTokenAgeSec: MAX_TTL_SEC, now: () => G.nowMs, ...over });
const decode = (seg) => JSON.parse(Buffer.from(seg, 'base64url').toString('utf8'));

test('golden vectors: every avrone-chat token verifies and maps to the right principal and scopes', async () => {
  const p = provider();
  for (const v of G.vectors) {
    const claims = await p.verify(v.token);
    assert.deepStrictEqual(claims, v.claims);
    const principal = toPrincipal(claims, 'avrone-due-krey');
    assert.equal(principal.sub, v.sub);
    assert.deepEqual(principal.roles, [v.role]);
    assert.deepEqual([...effectiveScopes(principal)].sort(), [...ROLE_SCOPES[v.role]].sort());
  }
});

test('golden vectors: header and claim layout are exactly the contract', () => {
  for (const v of G.vectors) {
    const [h, p] = v.token.split('.');
    assert.equal(Buffer.from(h, 'base64url').toString(), '{"alg":"HS256","typ":"JWT"}');
    assert.deepEqual(Object.keys(decode(p)), ['iss', 'aud', 'sub', 'roles', 'iat', 'exp', 'jti']);
    assert.ok(v.claims.exp - v.claims.iat <= MAX_TTL_SEC);
    assert.equal(v.claims.iat, Math.floor(G.nowMs / 1000));
  }
});

test('golden vectors: expiry boundary with the proxy default skew (30 s)', async () => {
  for (const v of G.vectors) {
    const at = (s) => provider({ now: () => s * 1000 }).verify(v.token);
    await at(v.claims.exp + 29.999);
    await assert.rejects(at(v.claims.exp + 30), /expired/);
    await assert.rejects(at(v.claims.iat - 31), /future/);
  }
});

test('golden vectors: max token age (300 s) and the 300 s ttl cap agree', async () => {
  const long = G.vectors.find((v) => v.ttl === 300);
  await provider({ now: () => (long.claims.iat + 300 + 29) * 1000 }).verify(long.token);
  await assert.rejects(provider({ now: () => (long.claims.iat + 300 + 31) * 1000, clockSkewSec: 30 }).verify(long.token));
});

test('golden vectors: rejected with a different secret, issuer or audience', async () => {
  const v = G.vectors[0];
  await assert.rejects(provider({ secret: `${G.secret}-other` }).verify(v.token), /signature/);
  await assert.rejects(provider({ issuer: 'https://evil.example' }).verify(v.token), /issuer/);
  await assert.rejects(provider({ audience: 'other-service' }).verify(v.token), /audience/);
});

test('golden vectors: any single-character change to any segment is rejected', async () => {
  const p = provider();
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
  for (const v of G.vectors) {
    for (let i = 0; i < v.token.length; i += 3) {
      if (v.token[i] === '.') continue;
      const c = alphabet[(alphabet.indexOf(v.token[i]) + 1) % 64];
      await assert.rejects(p.verify(v.token.slice(0, i) + c + v.token.slice(i + 1)), undefined, `pos ${i}`);
    }
  }
});

test('golden vectors: role escalation by re-encoding claims without the secret fails', async () => {
  const p = provider();
  const v = G.vectors.find((x) => x.role === 'viewer');
  const [h, , s] = v.token.split('.');
  const forged = Buffer.from(JSON.stringify({ ...v.claims, roles: ['admin'] })).toString('base64url');
  await assert.rejects(p.verify(`${h}.${forged}.${s}`), /signature/);
});

test('reference issuer reproduces the avrone-chat layout byte for byte (same jti, same clock)', () => {
  for (const v of G.vectors) {
    const { token } = mintAvroneToken({ secret: G.secret, issuer: G.issuer, audience: G.audience, sub: v.sub, roles: [v.role],
      ttlSec: v.claims.exp - v.claims.iat, now: G.nowMs, jti: v.claims.jti });
    assert.equal(token, v.token, `${v.sub}/${v.role}`);
  }
});

test('reference issuer: tokens round-trip for random subjects, roles and ttls', async () => {
  const p = provider({ now: Date.now });
  for (let i = 0; i < 100; i++) {
    const roles = ['viewer', 'technician', 'admin'].filter(() => Math.random() < 0.5);
    const sub = `u-${crypto.randomBytes(4).toString('hex')}`;
    const { token, claims } = mintAvroneToken({ secret: G.secret, issuer: G.issuer, audience: G.audience, sub, roles, ttlSec: 1 + (i % MAX_TTL_SEC) });
    assert.deepStrictEqual(await p.verify(token), claims);
  }
});

test('reference issuer: refuses weak or malformed input', () => {
  const ok = { secret: G.secret, issuer: G.issuer, audience: G.audience, sub: 's', roles: [] };
  for (const bad of [{ secret: 'short' }, { issuer: '' }, { audience: '' }, { sub: '' }, { sub: 'x'.repeat(257) }, { roles: 'admin' }, { roles: [1] }, { ttlSec: 0 }, { ttlSec: 301 }, { ttlSec: 1.5 }]) {
    assert.throws(() => mintAvroneToken({ ...ok, ...bad }), Error, JSON.stringify(bad));
  }
});
