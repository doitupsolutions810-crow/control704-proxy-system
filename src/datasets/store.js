'use strict';
// X / Y / Z dataset store with validated overrides, audit trail and revert.
// The X, Y, Z datasets are the proxy route profiles defined in src/proxy.js.

const crypto = require('crypto');

const DATASET_IDS = ['X', 'Y', 'Z'];

const DEFAULTS = Object.freeze({
  X: { endpoint: '/proxy/x', auth: 'token-override', enabled: true, upstream: null, rateLimitPerMinute: 60, metadata: {} },
  Y: { endpoint: '/proxy/y', auth: 'dataset-code', enabled: true, upstream: null, rateLimitPerMinute: 60, metadata: {} },
  Z: { endpoint: '/proxy/z', auth: 'lattice-op', enabled: true, upstream: null, rateLimitPerMinute: 60, metadata: {} },
});

// Only these fields may be overridden. `auth` is deliberately immutable via override
// so an override can never change how a route authenticates.
const VALIDATORS = {
  endpoint: (v) => typeof v === 'string' && /^\/proxy\/[a-z0-9][a-z0-9/_-]{0,63}$/.test(v) && !v.includes('..'),
  enabled: (v) => typeof v === 'boolean',
  upstream: (v) => {
    if (v === null) return true;
    if (typeof v !== 'string' || v.length > 2048) return false;
    try {
      const u = new URL(v);
      return (u.protocol === 'https:' || u.protocol === 'http:') && !u.username && !u.password;
    } catch { return false; }
  },
  rateLimitPerMinute: (v) => Number.isInteger(v) && v >= 1 && v <= 10000,
  metadata: (v) => v !== null && typeof v === 'object' && !Array.isArray(v)
    && Object.keys(v).length <= 50
    && Object.entries(v).every(([k, val]) => /^[A-Za-z0-9_.-]{1,64}$/.test(k)
      && (typeof val === 'string' ? val.length <= 512 : (typeof val === 'number' || typeof val === 'boolean'))),
};

class ValidationError extends Error {
  constructor(message, details = []) {
    super(message);
    this.name = 'ValidationError';
    this.details = details;
  }
}

class NotFoundError extends Error {
  constructor(message) { super(message); this.name = 'NotFoundError'; }
}

const clone = (o) => JSON.parse(JSON.stringify(o));

function normalizeId(id) {
  const up = String(id || '').toUpperCase();
  if (!DATASET_IDS.includes(up)) throw new NotFoundError(`Unknown dataset: ${id}`);
  return up;
}

function validatePatch(patch) {
  if (!patch || typeof patch !== 'object' || Array.isArray(patch)) {
    throw new ValidationError('Patch must be a JSON object');
  }
  const keys = Object.keys(patch);
  if (keys.length === 0) throw new ValidationError('Patch must not be empty');
  const errors = [];
  for (const k of keys) {
    if (!Object.prototype.hasOwnProperty.call(VALIDATORS, k)) {
      errors.push(`Field not overridable: ${k}`);
    } else if (!VALIDATORS[k](patch[k])) {
      errors.push(`Invalid value for ${k}`);
    }
  }
  if (errors.length) throw new ValidationError('Invalid patch', errors);
}

class DatasetStore {
  constructor(initial = DEFAULTS) {
    this.data = clone(initial);
    this.history = []; // override records
  }

  get(id) { return clone(this.data[normalizeId(id)]); }

  all() { return clone(this.data); }

  override(id, patch, { actor, reason } = {}) {
    const ds = normalizeId(id);
    if (!actor) throw new ValidationError('actor is required');
    if (typeof reason !== 'string' || reason.trim().length < 3 || reason.length > 500) {
      throw new ValidationError('reason is required (3-500 chars)');
    }
    validatePatch(patch);
    if (patch.endpoint) {
      const clash = DATASET_IDS.find((o) => o !== ds && this.data[o].endpoint === patch.endpoint);
      if (clash) throw new ValidationError(`endpoint already used by dataset ${clash}`);
    }
    const before = clone(this.data[ds]);
    const after = { ...before, ...clone(patch) };
    this.data[ds] = after;
    const record = {
      id: crypto.randomUUID(),
      dataset: ds,
      actor,
      reason: reason.trim(),
      patch: clone(patch),
      before,
      after: clone(after),
      createdAt: new Date().toISOString(),
      revertedAt: null,
      revertedBy: null,
    };
    this.history.push(record);
    return clone(record);
  }

  listOverrides(id) {
    const ds = id ? normalizeId(id) : null;
    return clone(this.history.filter((r) => !ds || r.dataset === ds));
  }

  // Reverts a single override. Only the most recent active override on a dataset can be
  // reverted, so reverts never silently discard later changes.
  revert(overrideId, { actor } = {}) {
    if (!actor) throw new ValidationError('actor is required');
    const rec = this.history.find((r) => r.id === overrideId);
    if (!rec) throw new NotFoundError(`Unknown override: ${overrideId}`);
    if (rec.revertedAt) throw new ValidationError('Override already reverted');
    const latest = [...this.history].reverse().find((r) => r.dataset === rec.dataset && !r.revertedAt);
    if (latest.id !== rec.id) {
      throw new ValidationError(`Revert newer override ${latest.id} first`);
    }
    this.data[rec.dataset] = clone(rec.before);
    rec.revertedAt = new Date().toISOString();
    rec.revertedBy = actor;
    return clone(rec);
  }
}

module.exports = { DatasetStore, DATASET_IDS, DEFAULTS, ValidationError, NotFoundError, validatePatch };
