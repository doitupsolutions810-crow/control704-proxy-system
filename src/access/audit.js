'use strict';
// Structured (JSON lines) audit logger. Never logs tokens or Authorization headers.

function createAuditLogger({ sink, maxEntries = 1000 } = {}) {
  const entries = [];
  const write = sink || ((line) => process.stdout.write(line + '\n'));
  return {
    log(event) {
      const entry = { ts: new Date().toISOString(), ...event };
      delete entry.token;
      delete entry.authorization;
      entries.push(entry);
      if (entries.length > maxEntries) entries.shift();
      write(JSON.stringify(entry));
      return entry;
    },
    recent(limit = 100) {
      return entries.slice(-limit);
    },
  };
}

module.exports = { createAuditLogger };
