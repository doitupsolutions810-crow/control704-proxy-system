'use strict';
// Control704 Access Proxy System — Control12-lattice-op
// Authentication is delegated to the Avrone Due'Krey token provider (see src/auth).
// X, Y, Z route profiles live in a DatasetStore with validated, audited, revertible overrides.

const { createAvroneProvider, loadConfigFromEnv } = require('./auth/avroneProvider');
const { createAuthenticator, toPrincipal } = require('./auth');
const { hasScopes } = require('./access/authorize');
const { DatasetStore } = require('./datasets/store');
const { createApp } = require('./server');

class Control704Proxy {
  constructor({ provider, store = new DatasetStore() } = {}) {
    this.provider = provider || createAvroneProvider(loadConfigFromEnv());
    this.authenticator = createAuthenticator(this.provider);
    this.store = store;
  }

  get proxies() { return this.store.all(); }

  // Previously granted access to anyone claiming type 'VIP'/'moderator'. Now requires a
  // signed Avrone Due'Krey token whose roles/scopes allow the requested proxy.
  async authenticate(token, proxyId = 'X') {
    try {
      const claims = await this.provider.verify(token);
      const principal = toPrincipal(claims, this.provider.name);
      const id = String(proxyId).toUpperCase();
      if (!hasScopes(principal, ['proxy:read', `proxy:${id.toLowerCase()}`])) {
        return { granted: false, reason: 'insufficient_scope' };
      }
      return { granted: true, principal: principal.sub, proxy: this.store.get(id) };
    } catch (err) {
      return { granted: false, reason: err.code || 'invalid_token' };
    }
  }

  // Admin-only dataset override (requires datasets:override).
  async overrideDataSet(token, datasetId, patch, reason) {
    const claims = await this.provider.verify(token);
    const principal = toPrincipal(claims, this.provider.name);
    if (!hasScopes(principal, ['datasets:override'])) {
      const e = new Error('Forbidden: datasets:override scope required');
      e.code = 'forbidden';
      throw e;
    }
    return this.store.override(datasetId, patch, { actor: principal.sub, reason });
  }
}

if (require.main === module) {
  const provider = createAvroneProvider(loadConfigFromEnv());
  const app = createApp({ provider });
  const port = Number.parseInt(process.env.PORT || '8704', 10);
  const host = process.env.HOST || '127.0.0.1';
  app.server().listen(port, host, () => {
    process.stdout.write(`Control704 proxy listening on http://${host}:${port}\n`);
  });
}

module.exports = Control704Proxy;
module.exports.Control704Proxy = Control704Proxy;
