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

function parsePort(v) {
  if (v === undefined || v === '') return 8704;
  if (!/^\d{1,5}$/.test(String(v).trim())) throw new Error('PORT must be an integer between 0 and 65535');
  const n = Number(String(v).trim());
  if (n > 65535) throw new Error('PORT must be an integer between 0 and 65535');
  return n;
}

function parseHost(v) {
  if (v === undefined || v === '') return '127.0.0.1';
  const h = String(v).trim();
  if (!h || /[\s/]/.test(h) || h.length > 253) throw new Error('HOST must be a hostname or IP address');
  return h;
}

// Maps listen() errors to short operator-facing messages (no stack, no internals).
function describeListenError(err, host, port) {
  const code = err && err.code;
  if (code === 'EADDRINUSE') return `Port ${port} on ${host} is already in use`;
  if (code === 'EACCES') return `Permission denied listening on ${host}:${port}`;
  if (code === 'EADDRNOTAVAIL' || code === 'ENOTFOUND' || code === 'EAI_AGAIN') return `Cannot listen on HOST ${host}`;
  return `Failed to listen on ${host}:${port}: ${code || (err && err.message) || 'unknown error'}`;
}

// Starts the proxy from environment variables. Resolves once listening.
// In-memory state (dataset overrides, override history, audit ring buffer) lives only in
// this process: every start begins from the X/Y/Z defaults with empty history and audit.
async function startFromEnv({ env = process.env, serverOptions } = {}) {
  const port = parsePort(env.PORT);
  const host = parseHost(env.HOST);
  const provider = createAvroneProvider(loadConfigFromEnv(env));
  const app = createApp({ provider });
  const server = app.server(serverOptions);
  await new Promise((resolve, reject) => {
    const onError = (err) => {
      server.removeListener('listening', onListening);
      reject(new Error(describeListenError(err, host, port)));
    };
    const onListening = () => { server.removeListener('error', onError); resolve(); };
    server.once('error', onError);
    server.once('listening', onListening);
    server.listen(port, host);
  });
  let closing = null;
  // Graceful shutdown: stop accepting, let in-flight requests finish, close idle keep-alive
  // sockets immediately, and force-close whatever remains after `graceMs`.
  function close(graceMs = 10000) {
    if (closing) return closing;
    closing = new Promise((resolve) => {
      const force = setTimeout(() => server.closeAllConnections(), graceMs);
      force.unref();
      server.close(() => { clearTimeout(force); resolve(); });
      server.closeIdleConnections();
    });
    return closing;
  }
  return { app, server, port: server.address().port, host, close };
}

if (require.main === module) {
  startFromEnv().then((inst) => {
    const stop = (sig) => {
      process.stdout.write(`Received ${sig}, shutting down gracefully\n`);
      inst.close(10000).then(() => process.exit(0));
    };
    // Install signal handlers BEFORE announcing readiness: a supervisor may signal as soon
    // as it sees the "listening" line (previously that raced the default kill handler).
    process.once('SIGTERM', () => stop('SIGTERM'));
    process.once('SIGINT', () => stop('SIGINT'));
    process.stdout.write(`Control704 proxy listening on http://${inst.host}:${inst.port}\n`);
  }).catch((err) => {
    // Message only: config errors never include secret values, and no stack trace is printed.
    process.stderr.write(`control704: startup failed: ${err.message}\n`);
    process.exit(1);
  });
}

module.exports = Control704Proxy;
module.exports.Control704Proxy = Control704Proxy;
module.exports.startFromEnv = startFromEnv;
module.exports.parsePort = parsePort;
module.exports.parseHost = parseHost;
module.exports.describeListenError = describeListenError;
