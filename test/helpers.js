'use strict';
const crypto = require('crypto');

const SECRET = crypto.randomBytes(48).toString('hex');
const ISSUER = 'https://avrone-due-krey.test';
const AUDIENCE = 'control704-proxy';

function sign(payload, { secret = SECRET, alg = 'HS256', header = {} } = {}) {
  const h = Buffer.from(JSON.stringify({ alg, typ: 'JWT', ...header })).toString('base64url');
  const p = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = alg === 'none' ? '' : crypto.createHmac('sha256', secret).update(`${h}.${p}`).digest('base64url');
  return `${h}.${p}.${sig}`;
}

function claims(extra = {}) {
  const now = Math.floor(Date.now() / 1000);
  return { iss: ISSUER, aud: AUDIENCE, sub: 'user-1', iat: now, exp: now + 300, ...extra };
}

const config = { issuer: ISSUER, audience: AUDIENCE, secret: SECRET, publicKey: '', clockSkewSec: 0, maxTokenAgeSec: null };

module.exports = { SECRET, ISSUER, AUDIENCE, sign, claims, config };
