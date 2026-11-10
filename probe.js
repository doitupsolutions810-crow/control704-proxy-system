const { createAvroneProvider } = require('./src/auth/avroneProvider');
const { createApp } = require('./src/server');
const { createAuditLogger } = require('./src/access/audit');
const { sign, claims, config } = require('./test/helpers');
const http = require('http');
(async () => {
  process.on('unhandledRejection', (e) => console.log('UNHANDLED', e.message));
  const app = createApp({ provider: createAvroneProvider(config), audit: createAuditLogger({ sink: () => {} }) });
  const s = app.server(); await new Promise(r => s.listen(0, r)); const port = s.address().port;
  const base = `http://127.0.0.1:${port}`;
  const r1 = await fetch(`${base}/proxy/x`, { headers: { authorization: 'Bearer ' + sign(claims({ roles: ['__proto__'] })) } });
  console.log('proto role', r1.status);
  const admin = 'Bearer ' + sign(claims({ roles: ['admin'] }));
  const r2 = await fetch(`${base}/admin/datasets/X/overrides`, { method: 'POST', headers: { authorization: admin, 'content-type': 'application/json' }, body: 'null' });
  console.log('null body', r2.status);
  try { const r3 = await fetch(`${base}/admin/datasets/X/overrides`, { method: 'POST', headers: { authorization: admin, 'content-type': 'application/json' }, body: 'x'.repeat(100000) }); console.log('big', r3.status); } catch (e) { console.log('big ERR', e.cause && e.cause.code || e.message); }
  const p = createAvroneProvider({ ...config, clockSkewSec: NaN });
  try { await p.verify(sign(claims({ exp: 1 }))); console.log('NaN skew: expired token ACCEPTED'); } catch (e) { console.log('NaN skew', e.message); }
  const now = Math.floor(Date.now()/1000);
  try { await createAvroneProvider(config).verify(sign(claims({ iat: now + 99999 }))); console.log('future iat ACCEPTED'); } catch (e) { console.log(e.message); }
  try { await createAvroneProvider(config).verify(sign(claims({ nbf: 'later' }))); console.log('string nbf ACCEPTED'); } catch (e) { console.log(e.message); }
  // raw bad URL
  await new Promise((res) => { const req = http.request({ port, path: 'http://[', method: 'GET' }, (r) => { console.log('bad url', r.statusCode); res(); }); req.on('error', (e) => { console.log('bad url ERR', e.code); res(); }); req.end(); });
  await new Promise(r => setTimeout(r, 200));
  s.close();
})();
