'use strict';
// Role/scope-based authorization.
// Effective scopes = scopes granted directly in the token + scopes implied by roles.

const ROLE_SCOPES = Object.freeze({
  viewer: ['proxy:read', 'datasets:read'],
  technician: ['proxy:read', 'proxy:x', 'proxy:y', 'proxy:z', 'datasets:read'],
  admin: ['proxy:read', 'proxy:x', 'proxy:y', 'proxy:z', 'datasets:read',
    'datasets:override', 'datasets:revert', 'audit:read'],
});

function effectiveScopes(principal, roleScopes = ROLE_SCOPES) {
  const out = new Set(principal.scopes || []);
  for (const role of principal.roles || []) {
    for (const s of roleScopes[role] || []) out.add(s);
  }
  return out;
}

function hasScopes(principal, required, roleScopes = ROLE_SCOPES) {
  const eff = effectiveScopes(principal, roleScopes);
  return required.every((s) => eff.has(s));
}

module.exports = { ROLE_SCOPES, effectiveScopes, hasScopes };
