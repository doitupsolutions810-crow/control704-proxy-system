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
  if (typeof str !== 'string' || !/^[A-Za-z0-9_-]*$/.test(str) || str.length % 4 === 1) {
    throw new AuthError('Malformed token segment');
  }
  const buf = Buffer.from(str, 'base64url');
  // Reject non-canonical encodings (e.g. non-zero trailing bits) to prevent token malleability.
  if (buf.toString('base64url') !== str) throw new AuthError('Non-canonical base64url segment');
  return buf;
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

function parseIntStrict(v, name) {
  if (v === undefined || v === null || v === '') return undefined;
  if (!/^\d+$/.test(String(v).trim())) throw new Error(`${name} must be a non-negative integer`);
  return Number.parseInt(String(v).trim(), 10);
}

function loadConfigFromEnv(env = process.env) {
  const secret = env.AVRONE_JWT_SECRET || '';
  const publicKey = env.AVRONE_JWT_PUBLIC_KEY ? env.AVRONE_JWT_PUBLIC_KEY.replace(/\\n/g, '\n') : '';
  return {
    issuer: env.AVRONE_ISSUER || '',
    audience: env.AVRONE_AUDIENCE || '',
    secret,
    publicKey,
    clockSkewSec: parseIntStrict(env.AVRONE_CLOCK_SKEW_SEC, 'AVRONE_CLOCK_SKEW_SEC') ?? 30,
    maxTokenAgeSec: parseIntStrict(env.AVRONE_MAX_TOKEN_AGE_SEC, 'AVRONE_MAX_TOKEN_AGE_SEC') ?? null,
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
  if (!Number.isInteger(cfg.clockSkewSec) || cfg.clockSkewSec < 0 || cfg.clockSkewSec > 300) {
    throw new Error('AVRONE_CLOCK_SKEW_SEC must be an integer between 0 and 300');
  }
  if (cfg.maxTokenAgeSec !== null && cfg.maxTokenAgeSec !== undefined
    && (!Number.isInteger(cfg.maxTokenAgeSec) || cfg.maxTokenAgeSec <= 0)) {
    throw new Error('AVRONE_MAX_TOKEN_AGE_SEC must be a positive integer');
  }
}

const isNumericDate = (v) => typeof v === 'number' && Number.isFinite(v);

function createAvroneProvider(config = loadConfigFromEnv()) {
  validateConfig(config);
  const allowedAlgs = new Set();
  let keyObject = null;
  if (config.secret) allowedAlgs.add('HS256');
  if (config.publicKey) {
    keyObject = crypto.createPublicKey(config.publicKey);
    const t = keyObject.asymmetricKeyType;
    if (t === 'rsa') {
      if (keyObject.asymmetricKeyDetails.modulusLength < 2048) throw new Error('RSA key must be >= 2048 bits');
      allowedAlgs.add('RS256');
    } else if (t === 'ec' && keyObject.asymmetricKeyDetails.namedCurve === 'prime256v1') {
      allowedAlgs.add('ES256');
    } else {
      throw new Error(`Unsupported public key type for AVRONE_JWT_PUBLIC_KEY: ${t}`);
    }
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

      if (typeof header.alg !== 'string' || !allowedAlgs.has(header.alg)) {
        throw new AuthError(`Algorithm not allowed: ${String(header.alg).slice(0, 20)}`);
      }
      // We understand no critical header extensions, so any `crit` must be rejected (RFC 7515 4.1.11).
      if (Object.prototype.hasOwnProperty.call(header, 'crit')) throw new AuthError('Unsupported crit header');
      if (!verifySignature(header.alg, `${h}.${p}`, signature)) {
        throw new AuthError('Invalid signature');
      }

      const now = Math.floor(Date.now() / 1000);
      const skew = config.clockSkewSec;
      if (!isNumericDate(payload.exp)) throw new AuthError('Token missing exp');
      if (now - skew >= payload.exp) throw new AuthError('Token expired', 'token_expired');
      if ('nbf' in payload) {
        if (!isNumericDate(payload.nbf)) throw new AuthError('Invalid nbf');
        if (now + skew < payload.nbf) throw new AuthError('Token not yet valid');
      }
      if ('iat' in payload) {
        if (!isNumericDate(payload.iat)) throw new AuthError('Invalid iat');
        if (payload.iat > now + skew) throw new AuthError('Token issued in the future');
      }
      if (config.maxTokenAgeSec) {
        if (!isNumericDate(payload.iat)) throw new AuthError('Token missing iat');
        if (now - payload.iat > config.maxTokenAgeSec + skew) throw new AuthError('Token too old', 'token_expired');
      }
      if (typeof payload.iss !== 'string' || payload.iss !== config.issuer) throw new AuthError('Invalid issuer');
      const aud = Array.isArray(payload.aud) ? payload.aud : [payload.aud];
      if (!aud.some((a) => typeof a === 'string' && a === config.audience)) throw new AuthError('Invalid audience');
      if (typeof payload.sub !== 'string' || !payload.sub || payload.sub.length > 256
        || /[\u0000-\u001f\u007f]/.test(payload.sub)) throw new AuthError('Invalid sub');

      return payload;
    },
  };
}

module.exports = { createAvroneProvider, loadConfigFromEnv, AuthError };
