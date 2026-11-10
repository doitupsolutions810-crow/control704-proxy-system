'use strict';
// Differential testing: the production verifier vs. an independent reference verifier
// written from RFC 7515/7519 using different Node primitives (hand-written base64url codec,
// crypto.createVerify instead of crypto.verify, Unicode general categories instead of the
// provider's hand-written ranges). Thousands of seeded random tokens (valid and invalid,
// HS256/RS256/ES256, alg confusion, encoding damage, claim edge values) must get the same
// accept/reject decision and, on accept, the same payload.
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { createAvroneProvider } = require('../src/auth/avroneProvider');
const { rng, SEED, ISSUER, AUDIENCE } = require('./helpers');

const ITER = Number(process.env.FUZZ_ITER || 400);
const NOW_MS = 1_800_000_000_123;
const NOW = NOW_MS / 1000;

// ---------- independent base64url ----------
const ALPHA = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
const IDX = new Map([...ALPHA].map((c, i) => [c, i]));
function encB64u(bytes) {
  let out = '';
  for (let i = 0; i < bytes.length; i += 3) {
    const n = (bytes[i] << 16) | ((bytes[i + 1] ?? 0) << 8) | (bytes[i + 2] ?? 0);
    const chars = [n >> 18, (n >> 12) & 63, (n >> 6) & 63, n & 63].map((x) => ALPHA[x]);
    out += chars.slice(0, Math.min(4, bytes.length - i + 1)).join('');
  }
  return out;
}
function decB64u(s) { // returns null when invalid or non-canonical
  if (s.length % 4 === 1) return null;
  const bytes = [];
  let acc = 0; let bits = 0;
  for (const c of s) {
    const v = IDX.get(c);
    if (v === undefined) return null;
    acc = (acc << 6) | v; bits += 6;
    if (bits >= 8) { bits -= 8; bytes.push((acc >> bits) & 255); }
  }
  if (bits > 0 && (acc & ((1 << bits) - 1)) !== 0) return null; // non-zero padding bits
  return Uint8Array.from(bytes);
}
const enc = (o) => encB64u(new TextEncoder().encode(typeof o === 'string' ? o : JSON.stringify(o)));

// ---------- reference verifier ----------
function subOk(sub) {
  if (typeof sub !== 'string' || sub.length === 0 || sub.length > 256 || !sub.isWellFormed()) return false;
  for (const ch of sub) if (/^[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]$/u.test(ch)) return false;
  return true;
}
function refVerify(token, cfg) {
  if (typeof token !== 'string' || token.length === 0 || token.length > 8192) return null;
  const segs = token.split('.');
  if (segs.length !== 3) return null;
  const raw = segs.map(decB64u);
  if (raw.some((x) => x === null)) return null;
  let header; let payload;
  try {
    const td = new TextDecoder('utf-8', { fatal: true, ignoreBOM: true });
    header = JSON.parse(td.decode(raw[0])); payload = JSON.parse(td.decode(raw[1]));
  } catch { return null; }
  for (const o of [header, payload]) if (o === null || typeof o !== 'object' || Array.isArray(o)) return null;
  const algs = [];
  if (cfg.secret) algs.push('HS256');
  if (cfg.rsaPem) algs.push('RS256');
  if (cfg.ecPem) algs.push('ES256');
  if (!algs.includes(header.alg)) return null;
  if (Object.keys(header).includes('crit')) return null;
  const input = `${segs[0]}.${segs[1]}`;
  const sig = Buffer.from(raw[2]);
  let ok = false;
  if (header.alg === 'HS256') {
    const mac = crypto.createHmac('sha256', cfg.secret).update(input).digest();
    ok = mac.length === sig.length && crypto.timingSafeEqual(mac, sig);
  } else if (header.alg === 'RS256') {
    ok = crypto.createVerify('RSA-SHA256').update(input).verify(cfg.rsaPem, sig);
  } else {
    // createVerify THROWS on a wrong-length P1363 signature (crypto.verify returns false);
    // either way the token is rejected.
    try { ok = crypto.createVerify('SHA256').update(input).verify({ key: cfg.ecPem, dsaEncoding: 'ieee-p1363' }, sig); } catch { ok = false; }
  }
  if (!ok) return null;
  const num = (v) => typeof v === 'number' && Number.isFinite(v);
  const skew = cfg.clockSkewSec;
  if (!num(payload.exp) || !(NOW - skew < payload.exp)) return null;
  if (Object.keys(payload).includes('nbf') && (!num(payload.nbf) || payload.nbf > NOW + skew)) return null;
  if (Object.keys(payload).includes('iat') && (!num(payload.iat) || payload.iat > NOW + skew)) return null;
  if (cfg.maxTokenAgeSec && (!num(payload.iat) || NOW - payload.iat > cfg.maxTokenAgeSec + skew)) return null;
  if (payload.iss !== ISSUER) return null;
  const auds = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
  if (!auds.includes(AUDIENCE)) return null;
  if (!subOk(payload.sub)) return null;
  return payload;
}

// ---------- keys & configs ----------
const SECRET_A = 'differential-secret-A-0123456789abcdefXYZ';
const SECRET_B = 'differential-secret-B-0123456789abcdefXYZ';
const rsa = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const rsa2 = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
const ec = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const ec2 = crypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
const pem = (k) => k.publicKey.export({ type: 'spki', format: 'pem' });

const CONFIGS = [
  { name: 'HS256 skew0', secret: SECRET_A, clockSkewSec: 0, maxTokenAgeSec: null },
  { name: 'HS256 skew30 maxAge600', secret: SECRET_A, clockSkewSec: 30, maxTokenAgeSec: 600 },
  { name: 'RS256 + HS256 (alg confusion surface)', secret: SECRET_A, rsaPem: pem(rsa), clockSkewSec: 5, maxTokenAgeSec: null },
  { name: 'ES256 skew60', ecPem: pem(ec), clockSkewSec: 60, maxTokenAgeSec: 3600 },
];
function providerFor(c) {
  return createAvroneProvider({ issuer: ISSUER, audience: AUDIENCE, secret: c.secret || '', publicKey: c.rsaPem || c.ecPem || '',
    clockSkewSec: c.clockSkewSec, maxTokenAgeSec: c.maxTokenAgeSec, now: () => NOW_MS });
}

// ---------- token generator ----------
function genToken(r, c) {
  const pick = (a) => a[Math.floor(r() * a.length)];
  const algsAvail = [c.secret && 'HS256', c.rsaPem && 'RS256', c.ecPem && 'ES256'].filter(Boolean);
  const header = { alg: r() < 0.88 ? pick(algsAvail) : pick(['none', 'HS384', 'RS256', 'ES256', 'HS256', 'hs256', '', null, 1]), typ: 'JWT' };
  if (r() < 0.04) header.crit = ['exp'];
  if (r() < 0.1) header.kid = `k${r.int(0, 9)}`;
  const t = Math.floor(NOW);
  const p = { iss: ISSUER, aud: AUDIENCE, sub: 'diff-user', iat: t - r.int(0, 100), exp: t + r.int(1, 900) };
  const mut = (k, vals) => { if (r() < 0.12) { const v = pick(vals); if (v === undefined) delete p[k]; else p[k] = v; } };
  const edge = (base) => [base - 1, base, base + 1, base - 0.001, base + 0.001, base - 0.5];
  mut('exp', [undefined, String(t + 100), null, true, [t + 100], ...edge(NOW - c.clockSkewSec), t - 10_000, 1e15]);
  mut('nbf', [undefined, ...edge(NOW + c.clockSkewSec), 'soon', null, 0]);
  mut('iat', [undefined, ...edge(NOW + c.clockSkewSec), ...(c.maxTokenAgeSec ? edge(NOW - c.maxTokenAgeSec - c.clockSkewSec) : []), 'x', null, -1]);
  mut('iss', [undefined, `${ISSUER}/`, ISSUER.toUpperCase(), [ISSUER], 7, '']);
  mut('aud', [undefined, [AUDIENCE], ['x', AUDIENCE], ['x'], `${AUDIENCE} `, [[AUDIENCE]], null, {}]);
  mut('sub', [undefined, '', 'a'.repeat(256), 'a'.repeat(257), 'tab\there', 'zw\u200bj', 'bidi\u202e', 'ok-ünïcødé', '\ud83d\ude00emoji', 'lone\ud83d', 'ls\u2028', 'del\u007f', 'nbsp\u00a0ok', 'soft\u00adhy', 7, null]);
  let payloadText = JSON.stringify(p);
  if (r() < 0.03) payloadText = payloadText.replace(/"exp":[^,}]+/, '"exp":1e309');
  if (r() < 0.03) payloadText = payloadText.replace(/^\{/, `{"exp":${t + 100},`); // duplicate key (last wins)
  if (r() < 0.02) payloadText = `\ufeff${payloadText}`;
  if (r() < 0.02) payloadText = `[${payloadText}]`;
  if (r() < 0.01) p.sub = 'x'.repeat(256) + 'y'.repeat(r.int(0, 1)) , payloadText = JSON.stringify({ ...p, pad: 'z'.repeat(6200) });

  const h = enc(header); const pl = enc(payloadText);
  const input = `${h}.${pl}`;
  const keyChoice = r();
  let sigBytes;
  const sa = typeof header.alg === 'string' ? header.alg.toUpperCase() : 'HS256';
  if (sa.startsWith('HS') || sa === 'NONE' || sa === '') {
    const secret = keyChoice < 0.8 ? (c.secret || SECRET_A) : keyChoice < 0.9 ? SECRET_B : (c.rsaPem || pem(rsa));
    sigBytes = header.alg === 'none' && r() < 0.5 ? Buffer.alloc(0) : crypto.createHmac('sha256', secret).update(input).digest();
  } else if (sa === 'RS256') {
    sigBytes = crypto.sign('sha256', Buffer.from(input), keyChoice < 0.85 ? rsa.privateKey : rsa2.privateKey);
  } else {
    sigBytes = crypto.sign('sha256', Buffer.from(input), { key: keyChoice < 0.85 ? ec.privateKey : ec2.privateKey, dsaEncoding: r() < 0.9 ? 'ieee-p1363' : 'der' });
  }
  let tok = `${input}.${encB64u(sigBytes)}`;
  // encoding damage
  const d = r();
  if (d < 0.03) { const i = r.int(0, tok.length - 1); tok = tok.slice(0, i) + pick([...ALPHA, '.', '=', '+', '/', ' ']) + tok.slice(i + 1); }
  else if (d < 0.05) tok += '=';
  else if (d < 0.06) tok += '.';
  else if (d < 0.08) { const last = tok[tok.length - 1]; const i = IDX.get(last); if (i !== undefined) tok = tok.slice(0, -1) + ALPHA[i ^ 1]; }
  else if (d < 0.09) tok = tok.slice(0, -r.int(1, 8));
  else if (d < 0.10) tok = `${tok.split('.')[0]}.${tok.split('.')[1]}.`;
  return tok;
}

// ---------- codec self-check vs Buffer ----------
test('reference base64url codec agrees with Buffer on random bytes, and on canonicality', () => {
  const r = rng(SEED);
  for (let i = 0; i < 3000; i++) {
    const bytes = crypto.randomBytes(r.int(0, 70));
    const e = encB64u(bytes);
    assert.equal(e, bytes.toString('base64url'));
    assert.deepEqual(Buffer.from(decB64u(e)), bytes);
    if (e.length) {
      const j = IDX.get(e[e.length - 1]) ^ 1; const bad = e.slice(0, -1) + ALPHA[j];
      const canonical = Buffer.from(bad, 'base64url').toString('base64url') === bad;
      assert.equal(decB64u(bad) !== null, canonical, bad);
    }
  }
});

for (const [ci, c] of CONFIGS.entries()) {
  test(`differential [${c.name}]: ${ITER} random tokens, identical decisions and payloads`, async () => {
    const provider = providerFor(c);
    const r = rng(SEED + ci * 1000);
    let accepted = 0; let rejected = 0;
    for (let i = 0; i < ITER; i++) {
      const tok = genToken(r, c);
      const ref = refVerify(tok, c);
      let got = null;
      try { got = await provider.verify(tok); } catch (e) { assert.equal(e.name, 'AuthError', `non-AuthError thrown: ${e.stack}`); }
      if ((ref === null) !== (got === null)) {
        assert.fail(`DIVERGENCE (seed ${SEED + ci * 1000}, i=${i}): ref=${ref ? 'accept' : 'reject'} prod=${got ? 'accept' : 'reject'}\n${tok}`);
      }
      if (got) { assert.deepEqual(got, ref); accepted++; } else rejected++;
    }
    assert.ok(accepted > ITER * 0.15, `accepted only ${accepted}/${ITER} — generator too destructive`);
    assert.ok(rejected > ITER * 0.15, `rejected only ${rejected}/${ITER} — generator too gentle`);
  });
}

test('differential: exact boundary sweep (exp/nbf/iat at now±skew, ms resolution) matches the reference', async () => {
  for (const c of CONFIGS) {
    const provider = providerFor(c);
    const t = NOW;
    for (const field of ['exp', 'nbf', 'iat']) {
      const base = field === 'exp' ? t - c.clockSkewSec : t + c.clockSkewSec;
      for (let dms = -3; dms <= 3; dms++) {
        const p = { iss: ISSUER, aud: AUDIENCE, sub: 's', iat: Math.floor(t) - 1, exp: Math.floor(t) + 100, [field]: base + dms / 1000 };
        const alg = c.secret ? 'HS256' : 'ES256';
        const input = `${enc({ alg })}.${enc(p)}`;
        const sig = alg === 'HS256' ? crypto.createHmac('sha256', c.secret).update(input).digest()
          : crypto.sign('sha256', Buffer.from(input), { key: ec.privateKey, dsaEncoding: 'ieee-p1363' });
        const tok = `${input}.${encB64u(sig)}`;
        const ref = refVerify(tok, c) !== null;
        const got = await provider.verify(tok).then(() => true, () => false);
        assert.equal(got, ref, `${c.name} ${field} ${dms}ms`);
      }
    }
  }
});
