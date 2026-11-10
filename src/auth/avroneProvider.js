'use strict';
// Avrone Due'Krey identity/token provider.
// Verifies compact JWS (JWT) tokens issued by Avrone Due'Krey.
// Supported algorithms: HS256 (shared secret) and RS256 / ES256 (PEM public key).
// Secrets and keys are read from environment variables only.

const crypto = require('crypto');

class AuthError extends Error {
  constructor(message, code = 'invalid_token') {
    super(message);
    this.name = 'AuthError';
    this.code = code;
  }
}

function b64urlDecode(str) {
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str)) {
    throw new AuthError('Malformed token segment');
  }
  return Buffer.from(str, 'base64url');
}

function parseJson(buf) {
  try {
    const v = JSON.parse(buf.toString('utf8'));
    if (!v || typeof v !== 'object' || Array.isArray(v)) throw new Error('not object');
    return v;
  } catch {
    throw new AuthError('Malformed token JSON');
  }
}

function loadConfigFromEnv(env = process.env) {
  const secret = env.AVRONE_JWT_SECRET || '';
  const publicKey = env.AVRONE_JWT_PUBLIC_KEY ? env.AVRONE_JWT_PUBLIC_KEY.replace(/\\n/g, '\n') : '';
  return {
    issuer: env.AVRONE_ISSUER || '',
    audience: env.AVRONE_AUDIENCE || '',
    secret,
    publicKey,
    clockSkewSec: Number.parseInt(env.AVRONE_CLOCK_SKEW_SEC || '30', 10),
    maxTokenAgeSec: env.AVRONE_MAX_TOKEN_AGE_SEC ? Number.parseInt(env.AVRONE_MAX_TOKEN_AGE_SEC, 10) : null,
  };
}

function validateConfig(cfg) {
  if (!cfg.issuer) throw new Error('AVRONE_ISSUER is required');
  if (!cfg.audience) throw new Error('AVRONE_AUDIENCE is required');
  if (!cfg.secret && !cfg.publicKey) {
    throw new Error('Set AVRONE_JWT_SECRET (HS256) or AVRONE_JWT_PUBLIC_KEY (RS256/ES256)');
  }
  if (cfg.secret && Buffer.byteLength(cfg.secret) < 32) {
    throw new Error('AVRONE_JWT_SECRET must be at least 32 bytes');
  }
}

function createAvroneProvider(config = loadConfigFromEnv()) {
  validateConfig(config);
  const allowedAlgs = new Set();
  let keyObject = null;
  if (config.secret) allowedAlgs.add('HS256');
  if (config.publicKey) {
    keyObject = crypto.createPublicKey(config.publicKey);
    allowedAlgs.add(keyObject.asymmetricKeyType === 'ec' ? 'ES256' : 'RS256');
  }

  function verifySignature(alg, signingInput, signature) {
    if (alg === 'HS256') {
      const expected = crypto.createHmac('sha256', config.secret).update(signingInput).digest();
      return expected.length === signature.length && crypto.timingSafeEqual(expected, signature);
    }
    if (alg === 'RS256') {
      return crypto.verify('sha256', Buffer.from(signingInput), keyObject, signature);
    }
    if (alg === 'ES256') {
      return crypto.verify('sha256', Buffer.from(signingInput),
        { key: keyObject, dsaEncoding: 'ieee-p1363' }, signature);
    }
    return false;
  }

  return {
    name: 'avrone-due-krey',
    async verify(token) {
      if (typeof token !== 'string' || token.length === 0 || token.length > 8192) {
        throw new AuthError('Missing or oversized token', 'missing_token');
      }
      const parts = token.split('.');
      if (parts.length !== 3) throw new AuthError('Token must have three segments');
      const [h, p, s] = parts;
      const header = parseJson(b64urlDecode(h));
      const payload = parseJson(b64urlDecode(p));
      const signature = b64urlDecode(s);

      if (!allowedAlgs.has(header.alg)) {
        throw new AuthError(`Algorithm not allowed: ${header.alg}`);
      }
      if (!verifySignature(header.alg, `${h}.${p}`, signature)) {
        throw new AuthError('Invalid signature');
      }

      const now = Math.floor(Date.now() / 1000);
      const skew = config.clockSkewSec;
      if (typeof payload.exp !== 'number') throw new AuthError('Token missing exp');
      if (now - skew >= payload.exp) throw new AuthError('Token expired', 'token_expired');
      if (typeof payload.nbf === 'number' && now + skew < payload.nbf) {
        throw new AuthError('Token not yet valid');
      }
      if (config.maxTokenAgeSec && typeof payload.iat === 'number' && now - payload.iat > config.maxTokenAgeSec + skew) {
        throw new AuthError('Token too old', 'token_expired');
      }
      if (payload.iss !== config.issuer) throw new AuthError('Invalid issuer');
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.includes(config.audience)) throw new AuthError('Invalid audience');
      if (typeof payload.sub !== 'string' || !payload.sub) throw new AuthError('Token missing sub');

      return payload;
    },
  };
}

module.exports = { createAvroneProvider, loadConfigFromEnv, AuthError };
