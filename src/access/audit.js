'use strict';
// Structured (JSON lines) audit logger. Never logs tokens or Authorization headers: sensitive
// keys are dropped (top level) or redacted (nested), and JWT-shaped or Bearer/Basic credential
// strings are redacted anywhere in an entry.
//
// Integrity guarantees:
// - `seq` (strictly increasing) and `ts` are assigned by the logger and cannot be supplied
//   or overridden by callers.
// - Entries are deep-copied and deep-frozen on write: nothing (callers, readers, the HTTP
//   layer) can mutate an entry after it is recorded.
// - Each entry is a single JSON line (JSON.stringify escapes CR/LF), so log lines cannot be
//   forged by embedding newlines.
// - A failing sink never breaks the request path: errors are counted (and optionally
//   reported via onSinkError) while the in-memory ring buffer keeps the entry.
// - The in-memory buffer is a bounded ring (maxEntries); the sink receives every event.

function deepFreeze(o) {
  if (o && typeof o === 'object' && !Object.isFrozen(o)) {
    Object.freeze(o);
    for (const v of Object.values(o)) deepFreeze(v);
  }
  return o;
}

const REDACTED_KEYS = new Set(['token', 'authorization', 'Authorization', 'secret', 'password']);
// Nested keys are matched case-insensitively with '-'/'_' removed (exact names, not substrings,
// so e.g. "secretary" or "tokens_used" are kept).
const SENSITIVE_NESTED = new Set(['token', 'accesstoken', 'refreshtoken', 'idtoken', 'bearer', 'authorization', 'proxyauthorization',
  'secret', 'clientsecret', 'jwtsecret', 'password', 'passwd', 'apikey', 'xapikey', 'cookie', 'setcookie', 'privatekey', 'session', 'sessionid']);
const JWT_LIKE = /eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*/g;
const CREDENTIAL = /\b(Bearer|Basic)(\s+)[A-Za-z0-9._~+/=-]{4,}/gi;
const REDACTED = '[REDACTED]';

function scrubString(v) {
  return v.replace(JWT_LIKE, '[REDACTED_JWT]').replace(CREDENTIAL, (_, scheme, ws) => `${scheme}${ws}${REDACTED}`);
}
// Applied to the JSON-safe copy only: stored data and API responses are not changed.
function redactDeep(v, depth = 0) {
  if (typeof v === 'string') return scrubString(v);
  if (!v || typeof v !== 'object') return v;
  if (depth > 64) return REDACTED;
  if (Array.isArray(v)) return v.map((x) => redactDeep(x, depth + 1));
  const out = {};
  for (const [k, x] of Object.entries(v)) {
    out[k] = depth > 0 && SENSITIVE_NESTED.has(k.toLowerCase().replace(/[-_]/g, '')) ? REDACTED : redactDeep(x, depth + 1);
  }
  return out;
}

function createAuditLogger({ sink, maxEntries = 1000, onSinkError } = {}) {
  if (!Number.isInteger(maxEntries) || maxEntries < 1) throw new Error('maxEntries must be a positive integer');
  const entries = [];
  const write = sink || ((line) => process.stdout.write(line + '\n'));
  let seq = 0;
  let sinkErrors = 0;
  let evicted = 0;

  return {
    log(event) {
      const src = event && typeof event === 'object' && !Array.isArray(event) ? event : { type: 'invalid_event' };
      const rest = {};
      for (const [k, v] of Object.entries(src)) {
        if (k === 'ts' || k === 'seq' || REDACTED_KEYS.has(k)) continue;
        rest[k] = v;
      }
      let copy;
      try {
        copy = redactDeep(JSON.parse(JSON.stringify(rest)));
      } catch {
        copy = { type: 'audit.unserializable', originalType: typeof src.type === 'string' ? src.type : null };
      }
      seq += 1;
      const entry = deepFreeze({ ...copy, seq, ts: new Date().toISOString() });
      entries.push(entry);
      if (entries.length > maxEntries) { entries.shift(); evicted += 1; }
      try {
        write(JSON.stringify(entry));
      } catch (err) {
        sinkErrors += 1;
        if (typeof onSinkError === 'function') {
          try { onSinkError(err, entry); } catch { /* never propagate */ }
        }
      }
      return entry;
    },
    // Most recent `limit` entries, oldest first. Invalid/negative limits are clamped.
    recent(limit = 100) {
      const n = Number.isFinite(limit) ? Math.max(0, Math.min(Math.floor(limit), entries.length)) : entries.length;
      return n === 0 ? [] : entries.slice(entries.length - n);
    },
    stats() {
      return { seq, size: entries.length, maxEntries, evicted, sinkErrors };
    },
  };
}

module.exports = { createAuditLogger, deepFreeze, redactDeep };
