'use strict';
// Pluggable authentication layer.
// A provider is any object: { name: string, verify(token): Promise<claims> }.
// verify() must throw (ideally an AuthError) for any invalid token.

const { AuthError } = require('./avroneProvider');

function countAuthHeaders(req) {
  const raw = req.rawHeaders;
  if (!Array.isArray(raw)) return req.headers && req.headers.authorization ? 1 : 0;
  let n = 0;
  for (let i = 0; i < raw.length; i += 2) if (String(raw[i]).toLowerCase() === 'authorization') n += 1;
  return n;
}

function extractBearer(req) {
  // Node keeps only the first of duplicate Authorization headers; treat duplicates as
  // ambiguous and reject rather than silently picking one.
  if (countAuthHeaders(req) > 1) throw new AuthError('Multiple Authorization headers', 'invalid_request');
  const header = req.headers && req.headers.authorization;
  if (!header || typeof header !== 'string') return null;
  // RFC 6750: scheme is case-insensitive, single space-separated credential.
  const m = /^Bearer ([A-Za-z0-9._~+/=-]+)$/i.exec(header.trim());
  return m ? m[1] : null;
}

function toPrincipal(claims, providerName) {
  const scopes = new Set();
  if (typeof claims.scope === 'string') claims.scope.split(/\s+/).filter(Boolean).forEach((s) => scopes.add(s));
  if (Array.isArray(claims.scp)) claims.scp.filter((s) => typeof s === 'string').forEach((s) => scopes.add(s));
  const roles = Array.isArray(claims.roles) ? [...new Set(claims.roles.filter((r) => typeof r === 'string'))] : [];
  return { sub: claims.sub, provider: providerName, roles, scopes, claims };
}

function createAuthenticator(provider) {
  if (!provider || typeof provider.verify !== 'function') {
    throw new Error('Auth provider must implement verify(token)');
  }
  return {
    provider,
    async authenticate(req) {
      const token = extractBearer(req);
      if (!token) throw new AuthError('Missing bearer token', 'missing_token');
      const claims = await provider.verify(token);
      return toPrincipal(claims, provider.name);
    },
  };
}

module.exports = { createAuthenticator, extractBearer, toPrincipal, AuthError };
