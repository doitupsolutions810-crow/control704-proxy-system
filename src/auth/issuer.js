'use strict';
// Reference Avrone Due'Krey token issuer (Node built-ins only).
//
// Produces exactly the token format that avrone-chat's lib/control704/avrone-jwt.ts mints
// and that ./avroneProvider.js verifies: header {"alg":"HS256","typ":"JWT"}, claims in the
// order iss, aud, sub, roles, iat, exp, jti. Used by tests and local tooling; production
// tokens come from the Avrone Due'Krey service. The secret is always passed in (from env).

const crypto = require('crypto');

const MAX_TTL_SEC = 300;
const b64 = (obj) => Buffer.from(JSON.stringify(obj)).toString('base64url');

function mintAvroneToken({ secret, issuer, audience, sub, roles = [], ttlSec = 120, now = Date.now(), jti } = {}) {
  if (typeof secret !== 'string' || Buffer.byteLength(secret) < 32) throw new Error('secret must be at least 32 bytes');
  if (typeof issuer !== 'string' || !issuer || typeof audience !== 'string' || !audience) throw new Error('issuer and audience are required');
  if (typeof sub !== 'string' || !sub || sub.length > 256) throw new Error('sub must be a non-empty string of at most 256 chars');
  if (!Array.isArray(roles) || !roles.every((r) => typeof r === 'string')) throw new Error('roles must be an array of strings');
  if (!Number.isInteger(ttlSec) || ttlSec < 1 || ttlSec > MAX_TTL_SEC) throw new Error(`ttlSec must be an integer 1-${MAX_TTL_SEC}`);
  const iat = Math.floor(now / 1000);
  const claims = { iss: issuer, aud: audience, sub, roles: [...roles], iat, exp: iat + ttlSec, jti: jti || crypto.randomBytes(12).toString('base64url') };
  const input = `${b64({ alg: 'HS256', typ: 'JWT' })}.${b64(claims)}`;
  const sig = crypto.createHmac('sha256', secret).update(input).digest('base64url');
  return { token: `${input}.${sig}`, claims };
}

module.exports = { mintAvroneToken, MAX_TTL_SEC };
