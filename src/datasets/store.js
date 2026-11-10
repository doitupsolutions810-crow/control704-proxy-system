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
const FORBIDDEN_KEYS = new Set(['__proto__', 'constructor', 'prototype']);
// Bidi controls / invisible format chars / C0-C1 controls: rejected in free text that ends up
// in the audit trail, to prevent "Trojan Source"-style spoofing. (ZWJ U+200D is allowed so
// emoji sequences in reasons still work.)
const SPOOF_CHARS = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f\u061c\u200b\u200c\u200e\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f\ufeff\ufff9-\ufffb\ufffd]/u;
const LONE_SURROGATE = /[\ud800-\udbff](?![\udc00-\udfff])|(?<![\ud800-\udbff])[\udc00-\udfff]/;
const isCleanText = (s) => !SPOOF_CHARS.test(s) && !LONE_SURROGATE.test(s);
const DEFAULT_MAX_HISTORY = 1000;

const VALIDATORS = {
  endpoint: (v) => typeof v === 'string' && /^\/proxy\/[a-z0-9][a-z0-9/_-]{0,63}$/.test(v)
    && !v.includes('..') && !v.includes('//') && !v.endsWith('/'),
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
    && Object.entries(v).every(([k, val]) => /^[A-Za-z0-9_.-]{1,64}$/.test(k) && !FORBIDDEN_KEYS.has(k)
      && (typeof val === 'string' ? val.length <= 512 && isCleanText(val)
        : ((typeof val === 'number' && Number.isFinite(val)) || typeof val === 'boolean'))),
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
  constructor(initial = DEFAULTS, { maxHistory = DEFAULT_MAX_HISTORY } = {}) {
    if (!Number.isInteger(maxHistory) || maxHistory < 1) throw new Error('maxHistory must be a positive integer');
    this.data = clone(initial);
    this.history = []; // override records (bounded; see _compact)
    this.maxHistory = maxHistory;
    this.compacted = 0;
  }

  // Bounded history: once more than maxHistory records exist, the oldest are dropped.
  // Dropping an old record only means it can no longer be reverted (revert is LIFO, so
  // newer overrides remain fully revertible); current dataset state is unaffected.
  _compact() {
    const excess = this.history.length - this.maxHistory;
    if (excess > 0) {
      this.history.splice(0, excess);
      this.compacted += excess;
    }
  }

  get(id) { return clone(this.data[normalizeId(id)]); }

  all() { return clone(this.data); }

  override(id, patch, { actor, reason } = {}) {
    const ds = normalizeId(id);
    if (!actor) throw new ValidationError('actor is required');
    if (typeof reason !== 'string' || reason.trim().length < 3 || reason.trim().length > 500) {
      throw new ValidationError('reason is required (3-500 chars)');
    }
    if (!isCleanText(reason)) throw new ValidationError('reason contains control or bidi characters');
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
    this._compact();
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
    // The endpoint being restored may since have been claimed by another dataset.
    const clash = DATASET_IDS.find((o) => o !== rec.dataset && this.data[o].endpoint === rec.before.endpoint);
    if (clash) {
      throw new ValidationError(`Cannot revert: endpoint ${rec.before.endpoint} is now used by dataset ${clash}`);
    }
    this.data[rec.dataset] = clone(rec.before);
    rec.revertedAt = new Date().toISOString();
    rec.revertedBy = actor;
    return clone(rec);
  }
}

module.exports = { DatasetStore, DATASET_IDS, DEFAULTS, ValidationError, NotFoundError, validatePatch };
