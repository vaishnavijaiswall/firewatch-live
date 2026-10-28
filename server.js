// FireWatch Live backend: auth (scrypt + httpOnly sessions), server-side RBAC,
// persistent alerts/messages (SQLite), FIRMS proxy (key stays server-side).
const fs = require('fs'), path = require('path'), crypto = require('crypto');
const express = require('express');
const { DatabaseSync } = require('node:sqlite');
try { for (const l of fs.readFileSync(path.join(__dirname, '.env'), 'utf8').split('\n')) { const m = l.match(/^\s*([A-Z_]+)\s*=\s*(.*)\s*$/); if (m && !(m[1] in process.env)) process.env[m[1]] = m[2]; } } catch {}
const PROD = process.env.NODE_ENV === 'production';
const db = new DatabaseSync(process.env.DB_FILE || path.join(__dirname, 'firewatch.db'));
db.exec(`
PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS users(id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, name TEXT NOT NULL, salt TEXT NOT NULL, hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK(role IN('user','admin')), country TEXT, state TEXT, district TEXT, area TEXT, lat REAL, lon REAL, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE, expires_at INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY, title TEXT NOT NULL, body TEXT NOT NULL, actions TEXT, severity TEXT NOT NULL,
  scope TEXT NOT NULL, t_country TEXT, t_state TEXT, t_district TEXT, t_area TEXT, t_label TEXT, bbox TEXT,
  status TEXT NOT NULL DEFAULT 'active', created_by INTEGER NOT NULL REFERENCES users(id), created_at TEXT NOT NULL, resolved_at TEXT);
CREATE TABLE IF NOT EXISTS reads(user_id INTEGER NOT NULL, alert_id INTEGER NOT NULL, read_at TEXT NOT NULL, PRIMARY KEY(user_id,alert_id));
`);
// lightweight migration for databases created by v2.0: alerts gained an updated_at column
try { db.exec('ALTER TABLE alerts ADD COLUMN updated_at TEXT'); } catch { /* column already exists */ }
const now = () => new Date().toISOString();
const hashPw = (pw, salt) => crypto.scryptSync(pw, salt, 64, { N: 16384 }).toString('hex');
const newPw = pw => { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPw(pw, salt) }; };
const okPw = (pw, u) => crypto.timingSafeEqual(Buffer.from(hashPw(pw, u.salt), 'hex'), Buffer.from(u.hash, 'hex'));

// seed admin
{
  const email = (process.env.ADMIN_EMAIL || 'admin@example.com').toLowerCase();
  if (!db.prepare('SELECT 1 FROM users WHERE role=?').get('admin')) {
    const pw = process.env.ADMIN_PASSWORD || crypto.randomBytes(9).toString('base64url');
    const { salt, hash } = newPw(pw);
    db.prepare('INSERT INTO users(email,name,salt,hash,role,created_at) VALUES(?,?,?,?,?,?)').run(email, 'Administrator', salt, hash, 'admin', now());
    console.log(`[seed] admin created: ${email}` + (process.env.ADMIN_PASSWORD ? '' : `  password: ${pw}  (shown once)`));
  }
}

// helpers
const SEV = ['Information', 'Advisory', 'Warning', 'Emergency'], SCOPES = ['all', 'country', 'state', 'district', 'area'];
const str = (v, max, min = 0) => { if (typeof v !== 'string') return null; v = v.trim(); return v.length >= min && v.length <= max ? v : null; };
const bad = (res, m, c = 400) => res.status(c).json({ error: m });
const hits = new Map();
const limit = (key, max, winMs) => (req, res, next) => {
  const k = key + ':' + req.ip, t = Date.now(), a = (hits.get(k) || []).filter(x => t - x < winMs);
  if (a.length >= max) return bad(res, 'Too many requests, try again later', 429);
  a.push(t); hits.set(k, a); next();
};
setInterval(() => { const t = Date.now(); for (const [k, a] of hits) if (!a.some(x => t - x < 3600e3)) hits.delete(k); }, 600e3).unref();

const app = express();
app.set('trust proxy', 1);
app.use((req, res, next) => {
  res.set({ 'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'DENY', 'Referrer-Policy': 'strict-origin-when-cross-origin' });
  if (req.method !== 'GET' && req.method !== 'HEAD' && !(req.headers['content-type'] || '').startsWith('application/json') && req.path.startsWith('/api/'))
    return bad(res, 'JSON required', 415);
  next();
});
app.use(express.json({ limit: '20kb' }));

// tolerant cookie parser: a malformed cookie (bad %-escape) must never crash a request
const dec = s => { try { return decodeURIComponent(s); } catch { return s; } };
const cookie = req => Object.fromEntries((req.headers.cookie || '').split(';').map(c => { const i = c.indexOf('='); return i < 0 ? [] : [dec(c.slice(0, i).trim()), dec(c.slice(i + 1).trim())]; }).filter(a => a[0]));
function setSession(res, uid) {
  const token = crypto.randomBytes(32).toString('base64url'), exp = Date.now() + 7 * 864e5;
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(token, uid, exp);
  res.set('Set-Cookie', `fw_sid=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7 * 86400}${PROD ? '; Secure' : ''}`);
}
app.use((req, res, next) => {
  const t = cookie(req).fw_sid; req.user = null;
  if (t) {
    const s = db.prepare('SELECT user_id,expires_at FROM sessions WHERE token=?').get(t);
    if (s && s.expires_at > Date.now()) req.user = db.prepare('SELECT * FROM users WHERE id=?').get(s.user_id);
    else if (s) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
  }
  next();
});
const needUser = (req, res, next) => req.user ? next() : bad(res, 'Login required', 401);
const needAdmin = (req, res, next) => !req.user ? bad(res, 'Login required', 401) : req.user.role !== 'admin' ? bad(res, 'Administrator only', 403) : next();
const pub = u => u && ({ id: u.id, email: u.email, name: u.name, role: u.role, country: u.country, state: u.state, district: u.district, area: u.area, lat: u.lat, lon: u.lon });

function readLoc(b) {
  const o = {}; for (const k of ['country', 'state', 'district', 'area']) { const v = b[k] == null || b[k] === '' ? null : str(b[k], 120); if (b[k] && v === null) return null; o[k] = v; }
  for (const k of ['lat', 'lon']) { const v = b[k] == null ? null : Number(b[k]); if (v !== null && !Number.isFinite(v)) return null; o[k] = v; }
  if (o.lat !== null && Math.abs(o.lat) > 90 || o.lon !== null && Math.abs(o.lon) > 180) return null;
  return o;
}
app.post('/api/register', limit('reg', 10, 3600e3), (req, res) => {
  const email = str(req.body.email, 200, 5)?.toLowerCase(), name = str(req.body.name, 80, 1), pw = str(req.body.password, 200, 8), loc = readLoc(req.body);
  if (!email || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) return bad(res, 'Valid email required');
  if (!name) return bad(res, 'Name required'); if (!pw) return bad(res, 'Password must be at least 8 characters'); if (!loc) return bad(res, 'Invalid location');
  if (db.prepare('SELECT 1 FROM users WHERE email=?').get(email)) return bad(res, 'Email already registered', 409);
  const { salt, hash } = newPw(pw);
  const r = db.prepare('INSERT INTO users(email,name,salt,hash,role,country,state,district,area,lat,lon,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)') // role is ALWAYS 'user' here
    .run(email, name, salt, hash, 'user', loc.country, loc.state, loc.district, loc.area, loc.lat, loc.lon, now());
  setSession(res, Number(r.lastInsertRowid));
  res.json({ user: pub(db.prepare('SELECT * FROM users WHERE id=?').get(r.lastInsertRowid)) });
});
app.post('/api/login', limit('login', 10, 600e3), (req, res) => {
  const email = str(req.body.email, 200)?.toLowerCase(), pw = str(req.body.password, 200);
  const u = email && db.prepare('SELECT * FROM users WHERE email=?').get(email);
  if (!u || !pw || !okPw(pw, u)) return bad(res, 'Invalid email or password', 401);
  // Separate portals: the administrator login only admits administrators, and the local-user login only local users.
  // Checked after the password so the role of an account is never revealed to someone who cannot authenticate as it.
  const portal = req.body.portal;
  if (portal === 'admin' && u.role !== 'admin') return bad(res, 'This account is not an administrator. Use the Local user login.', 403);
  if (portal === 'user' && u.role === 'admin') return bad(res, 'This is an administrator account. Use the Administrator login.', 403);
  setSession(res, u.id); res.json({ user: pub(u) });
});
app.post('/api/logout', (req, res) => {
  const t = cookie(req).fw_sid; if (t) db.prepare('DELETE FROM sessions WHERE token=?').run(t);
  res.set('Set-Cookie', 'fw_sid=; HttpOnly; Path=/; Max-Age=0'); res.json({ ok: true });
});
app.get('/api/me', (req, res) => res.json({ user: pub(req.user) }));
app.put('/api/me/location', needUser, (req, res) => {
  const l = readLoc(req.body); if (!l) return bad(res, 'Invalid location');
  db.prepare('UPDATE users SET country=?,state=?,district=?,area=?,lat=?,lon=? WHERE id=?').run(l.country, l.state, l.district, l.area, l.lat, l.lon, req.user.id);
  res.json({ user: pub(db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id)) });
});

// ---- targeting: an alert reaches a user if the user's saved place falls inside the alert's target
const lc = s => (s || '').toLowerCase();
function matches(a, u) {
  if (a.scope === 'all') return true;
  if (lc(a.t_country) !== lc(u.country)) return false; if (a.scope === 'country') return true;
  if (lc(a.t_state) !== lc(u.state)) return false; if (a.scope === 'state') return true;
  if (lc(a.t_district) !== lc(u.district)) return false; if (a.scope === 'district') return true;
  return lc(a.t_area) === lc(u.area);
}
const alertOut = (a, read) => ({ id: a.id, title: a.title, body: a.body, actions: a.actions ? JSON.parse(a.actions) : [], severity: a.severity, scope: a.scope, region: a.t_label || 'All users', bbox: a.bbox ? JSON.parse(a.bbox) : null, status: a.status, created_at: a.created_at, updated_at: a.updated_at || null, resolved_at: a.resolved_at, ...(read === undefined ? {} : { read }) });
app.get('/api/messages', needUser, (req, res) => {
  const reads = new Set(db.prepare('SELECT alert_id FROM reads WHERE user_id=?').all(req.user.id).map(r => r.alert_id));
  const list = db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT 500').all().filter(a => matches(a, req.user)).map(a => alertOut(a, reads.has(a.id)));
  res.json({ messages: list, unread: list.filter(m => !m.read).length });
});
app.post('/api/messages/:id/read', needUser, (req, res) => {
  const id = Number(req.params.id), a = db.prepare('SELECT * FROM alerts WHERE id=?').get(id);
  if (!a || !matches(a, req.user)) return bad(res, 'Not found', 404);
  db.prepare('INSERT OR IGNORE INTO reads VALUES(?,?,?)').run(req.user.id, id, now()); res.json({ ok: true });
});
app.post('/api/messages/read-all', needUser, (req, res) => {
  for (const a of db.prepare('SELECT * FROM alerts').all()) if (matches(a, req.user)) db.prepare('INSERT OR IGNORE INTO reads VALUES(?,?,?)').run(req.user.id, a.id, now());
  res.json({ ok: true });
});

// ---- admin
app.post('/api/admin/alerts', needAdmin, limit('alert', 20, 3600e3), (req, res) => {
  const b = req.body, title = str(b.title, 120, 3), body = str(b.body, 2000, 5);
  if (!title || !body) return bad(res, 'Title (3+) and message (5+) required');
  if (!SEV.includes(b.severity)) return bad(res, 'Invalid severity'); if (!SCOPES.includes(b.scope)) return bad(res, 'Invalid audience');
  const loc = readLoc({ country: b.t_country, state: b.t_state, district: b.t_district, area: b.t_area }); if (!loc) return bad(res, 'Invalid target');
  const need = { country: ['country'], state: ['country', 'state'], district: ['country', 'state', 'district'], area: ['country', 'state', 'district', 'area'] }[b.scope] || [];
  if (need.some(k => !loc[k])) return bad(res, `Audience "${b.scope}" needs: ${need.join(', ')}`);
  const actions = Array.isArray(b.actions) ? b.actions.map(x => str(x, 200, 1)).filter(Boolean).slice(0, 8) : [];
  let bbox = null; if (Array.isArray(b.bbox) && b.bbox.length === 4 && b.bbox.every(Number.isFinite)) bbox = JSON.stringify(b.bbox);
  const label = b.scope === 'all' ? 'All users' : need.map(k => loc[k]).reverse().join(', ');
  const r = db.prepare('INSERT INTO alerts(title,body,actions,severity,scope,t_country,t_state,t_district,t_area,t_label,bbox,created_by,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)')
    .run(title, body, JSON.stringify(actions), b.severity, b.scope, loc.country, loc.state, loc.district, loc.area, label, bbox, req.user.id, now());
  res.json({ id: Number(r.lastInsertRowid) });
});
app.get('/api/admin/alerts', needAdmin, (req, res) => {
  const users = db.prepare("SELECT * FROM users WHERE role='user'").all();
  const rd = db.prepare('SELECT COUNT(*) c FROM reads WHERE alert_id=?');
  res.json({ alerts: db.prepare('SELECT * FROM alerts ORDER BY id DESC LIMIT 200').all().map(a => ({ ...alertOut(a), recipients: users.filter(u => matches(a, u)).length, read_count: rd.get(a.id).c, delivery: 'in-app inbox only (no external channel configured)' })) });
});
// Edit the wording / severity / safety instructions of an already-published alert (audience cannot change: publish a new alert instead).
app.put('/api/admin/alerts/:id', needAdmin, limit('alertedit', 60, 3600e3), (req, res) => {
  const id = Number(req.params.id), a = db.prepare('SELECT * FROM alerts WHERE id=?').get(id);
  if (!a) return bad(res, 'Not found', 404);
  const b = req.body, title = b.title === undefined ? a.title : str(b.title, 120, 3), body = b.body === undefined ? a.body : str(b.body, 2000, 5);
  if (!title || !body) return bad(res, 'Title (3+) and message (5+) required');
  const severity = b.severity === undefined ? a.severity : b.severity; if (!SEV.includes(severity)) return bad(res, 'Invalid severity');
  const actions = b.actions === undefined ? a.actions : JSON.stringify(Array.isArray(b.actions) ? b.actions.map(x => str(x, 200, 1)).filter(Boolean).slice(0, 8) : []);
  db.prepare('UPDATE alerts SET title=?,body=?,severity=?,actions=?,updated_at=? WHERE id=?').run(title, body, severity, actions, now(), id);
  res.json({ ok: true });
});
app.post('/api/admin/alerts/:id/resolve', needAdmin, (req, res) => {
  const r = db.prepare("UPDATE alerts SET status='resolved',resolved_at=? WHERE id=? AND status='active'").run(now(), Number(req.params.id));
  r.changes ? res.json({ ok: true }) : bad(res, 'Not found or already resolved', 404);
});
app.get('/api/admin/users', needAdmin, (req, res) => res.json({ users: db.prepare('SELECT * FROM users ORDER BY id').all().map(pub) }));
app.put('/api/admin/users/:id/role', needAdmin, (req, res) => {
  const id = Number(req.params.id), role = req.body.role;
  if (!['user', 'admin'].includes(role)) return bad(res, 'Invalid role'); if (id === req.user.id) return bad(res, 'You cannot change your own role');
  db.prepare('UPDATE users SET role=? WHERE id=?').run(role, id); res.json({ ok: true });
});
app.get('/api/admin/stats', needAdmin, (req, res) => res.json({
  users: db.prepare("SELECT COUNT(*) c FROM users WHERE role='user'").get().c, admins: db.prepare("SELECT COUNT(*) c FROM users WHERE role='admin'").get().c,
  activeAlerts: db.prepare("SELECT COUNT(*) c FROM alerts WHERE status='active'").get().c, totalAlerts: db.prepare('SELECT COUNT(*) c FROM alerts').get().c }));

// ---- NASA FIRMS proxy (real satellite detections; never fabricated)
const fcache = new Map();
app.get('/api/fires', needUser, async (req, res) => {
  const key = process.env.FIRMS_MAP_KEY;
  if (!key) return res.status(503).json({ error: 'not_configured', message: 'FIRMS_MAP_KEY is not set on the server; satellite fire detections are unavailable.' });
  const bb = String(req.query.bbox || '').split(',').map(Number), days = Math.min(5, Math.max(1, Number(req.query.days) || 1));
  if (bb.length !== 4 || bb.some(n => !Number.isFinite(n))) return bad(res, 'bbox=west,south,east,north required');
  const [w, s, e, n] = bb.map(v => Math.round(v * 10) / 10);
  if ((e - w) * (n - s) > 25 * 25) return res.json({ fires: [], note: 'Zoom in (area too large for FIRMS query)', tooLarge: true });
  const ck = [w, s, e, n, days].join(); const c = fcache.get(ck);
  if (c && Date.now() - c.t < 300e3) return res.json(c.v);
  try {
    const r = await fetch(`https://firms.modaps.eosdis.nasa.gov/api/area/csv/${key}/VIIRS_SNPP_NRT/${w},${s},${e},${n}/${days}`, { signal: AbortSignal.timeout(15000) });
    const txt = await r.text(); if (!r.ok || !txt.startsWith('latitude')) return res.status(502).json({ error: 'upstream', message: 'FIRMS returned an error or rate-limited the key.' });
    const [h, ...rows] = txt.trim().split('\n'), cols = h.split(',');
    const fires = rows.map(l => { const v = l.split(','), o = Object.fromEntries(cols.map((k, i) => [k, v[i]]));
      return { lat: +o.latitude, lon: +o.longitude, time: `${o.acq_date} ${String(o.acq_time).padStart(4, '0').replace(/(..)(..)/, '$1:$2')} UTC`, confidence: o.confidence, frp: +o.frp, satellite: o.satellite, source: 'NASA FIRMS VIIRS S-NPP NRT' }; });
    const out = { fires, fetched_at: now(), days }; fcache.set(ck, { t: Date.now(), v: out }); res.json(out);
  } catch { res.status(502).json({ error: 'upstream', message: 'Could not reach NASA FIRMS.' }); }
});

app.use('/api', (req, res) => bad(res, 'Not found', 404));
app.use(express.static(path.join(__dirname, 'public')));
// last-resort error handler: always JSON for the API, never a stack trace
app.use((err, req, res, next) => { // eslint-disable-line no-unused-vars
  const status = err.status === 413 || err.status === 400 ? err.status : 500;
  if (status === 500) console.error('[error]', err);
  res.status(status).json({ error: status === 400 ? 'Malformed JSON body' : status === 413 ? 'Request too large' : 'Server error' });
});
const port = Number(process.env.PORT) || 3000;
if (require.main === module) app.listen(port, () => console.log(`FireWatch Live on http://localhost:${port}`));
module.exports = app;
