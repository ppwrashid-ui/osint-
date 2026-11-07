const express = require('express'), helmet = require('helmet'), rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs'), crypto = require('crypto'), path = require('path'), db = require('./db');
const PROD = process.env.NODE_ENV === 'production', TYPES = ['user','email','domain','ip','phone','name','img'];
const app = express(); app.set('trust proxy', 1);
app.use(helmet({ contentSecurityPolicy: { directives: {
  defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'", "'unsafe-inline'"], imgSrc: ["'self'", 'data:'],
  connectSrc: ["'self'"], objectSrc: ["'none'"], frameAncestors: ["'none'"], upgradeInsecureRequests: PROD ? [] : null } } }));
app.use(express.json({ limit: '10kb' }));
// CSRF: cookies are SameSite=Strict + every non-GET request must carry this custom header
app.use((req, res, next) => (req.method !== 'GET' && req.get('X-Requested-With') !== 'fetch') ? res.status(403).json({ e: 'forbidden' }) : next());

const sha = s => crypto.createHash('sha256').update(s).digest('hex');
const log = (u, a) => db.prepare('INSERT INTO audit_log(username,action) VALUES(?,?)').run(u || '-', String(a).slice(0, 200));
const okPass = p => typeof p === 'string' && p.length >= 8 && p.length <= 72;
const USER = /^[\w.-]{3,24}$/, DUMMY = bcrypt.hashSync('x', 12), TTL = 12 * 3600e3;
const cookieOpts = { httpOnly: true, sameSite: 'strict', secure: PROD, path: '/' };
const getSid = req => { const m = (req.headers.cookie || '').split(';').map(s => s.trim()).find(s => s.startsWith('sid=')); return m ? decodeURIComponent(m.slice(4)) : null; };

function auth(req, res, next) {
  const t = getSid(req);
  if (t) {
    const u = db.prepare('SELECT u.id,u.username,u.role FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?').get(sha(t), Date.now());
    if (u) { req.user = u; return next(); }
  }
  res.status(401).json({ e: 'unauthorized' });
}
const admin = (req, res, next) => req.user.role === 'admin' ? next() : res.status(403).json({ e: 'forbidden' });

app.post('/api/login', rateLimit({ windowMs: 15 * 60e3, max: 10, standardHeaders: true, legacyHeaders: false, message: { e: 'too many attempts' } }), (req, res) => {
  const { n, p } = req.body || {};
  const u = typeof n === 'string' ? db.prepare('SELECT * FROM users WHERE username=?').get(n) : null;
  const ok = bcrypt.compareSync(typeof p === 'string' ? p : '', u ? u.pass_hash : DUMMY) && u;
  if (!ok) { log(null, 'failed login: ' + String(n).slice(0, 24)); return res.status(401).json({ e: 'invalid credentials' }); }
  db.prepare('DELETE FROM sessions WHERE expires_at<?').run(Date.now());
  const t = crypto.randomBytes(32).toString('hex');
  db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(sha(t), u.id, Date.now() + TTL);
  res.cookie('sid', t, { ...cookieOpts, maxAge: TTL }); log(u.username, 'login');
  res.json({ n: u.username, r: u.role });
});
app.post('/api/logout', auth, (req, res) => {
  db.prepare('DELETE FROM sessions WHERE token_hash=?').run(sha(getSid(req)));
  res.clearCookie('sid', cookieOpts); log(req.user.username, 'logout'); res.json({ ok: 1 });
});
app.get('/api/me', auth, (req, res) => res.json({ n: req.user.username, r: req.user.role }));
app.get('/api/tools', auth, (req, res) => res.json(db.prepare('SELECT id,type,name,url,descr FROM custom_tools ORDER BY id').all()));
app.post('/api/log', auth, (req, res) => { log(req.user.username, (req.body || {}).a || ''); res.json({ ok: 1 }); });
app.post('/api/me/password', auth, (req, res) => {
  const { o, p } = req.body || {}, u = db.prepare('SELECT * FROM users WHERE id=?').get(req.user.id);
  if (!bcrypt.compareSync(String(o || ''), u.pass_hash)) return res.status(400).json({ e: 'wrong current password' });
  if (!okPass(p)) return res.status(400).json({ e: 'password must be 8-72 chars' });
  db.prepare('UPDATE users SET pass_hash=? WHERE id=?').run(bcrypt.hashSync(p, 12), u.id);
  db.prepare('DELETE FROM sessions WHERE user_id=? AND token_hash<>?').run(u.id, sha(getSid(req)));
  log(u.username, 'password changed'); res.json({ ok: 1 });
});

// ---- admin ----
const A = express.Router(); A.use(auth, admin); app.use('/api/admin', A);
A.get('/users', (req, res) => res.json(db.prepare('SELECT id,username,role,created_at FROM users ORDER BY id').all()));
A.post('/users', (req, res) => {
  const { n, p, r } = req.body || {};
  if (typeof n !== 'string' || !USER.test(n)) return res.status(400).json({ e: 'invalid username' });
  if (!okPass(p)) return res.status(400).json({ e: 'password must be 8-72 chars' });
  if (!['admin', 'user'].includes(r)) return res.status(400).json({ e: 'invalid role' });
  try { db.prepare('INSERT INTO users(username,pass_hash,role) VALUES(?,?,?)').run(n, bcrypt.hashSync(p, 12), r); }
  catch (e) { return res.status(409).json({ e: 'username exists' }); }
  log(req.user.username, 'add user ' + n); res.json({ ok: 1 });
});
A.delete('/users/:id', (req, res) => {
  const id = +req.params.id, t = db.prepare('SELECT * FROM users WHERE id=?').get(id);
  if (!t) return res.status(404).json({ e: 'not found' });
  if (id === req.user.id) return res.status(400).json({ e: 'cannot delete yourself' });
  if (t.role === 'admin' && db.prepare("SELECT COUNT(*) c FROM users WHERE role='admin'").get().c < 2) return res.status(400).json({ e: 'last admin' });
  db.prepare('DELETE FROM users WHERE id=?').run(id); log(req.user.username, 'del user ' + t.username); res.json({ ok: 1 });
});
A.post('/tools', (req, res) => {
  const { type, name, url, descr } = req.body || {};
  if (!TYPES.includes(type) || typeof name !== 'string' || !name.trim() || name.length > 40) return res.status(400).json({ e: 'invalid type/name' });
  if (typeof url !== 'string' || url.length > 500 || !/^https?:\/\/[^\s]+\{q\}/.test(url)) return res.status(400).json({ e: 'url must be http(s) and contain {q}' });
  db.prepare('INSERT INTO custom_tools(type,name,url,descr) VALUES(?,?,?,?)').run(type, name.trim(), url, String(descr || '').slice(0, 120));
  log(req.user.username, 'add tool ' + name.slice(0, 40)); res.json({ ok: 1 });
});
A.delete('/tools/:id', (req, res) => { db.prepare('DELETE FROM custom_tools WHERE id=?').run(+req.params.id); log(req.user.username, 'del tool #' + +req.params.id); res.json({ ok: 1 }); });
A.get('/log', (req, res) => res.json(db.prepare('SELECT ts,username,action FROM audit_log ORDER BY id DESC LIMIT 200').all()));
A.delete('/log', (req, res) => { db.prepare('DELETE FROM audit_log').run(); log(req.user.username, 'log cleared'); res.json({ ok: 1 }); });
A.get('/export', (req, res) => {
  res.setHeader('Content-Disposition', 'attachment; filename="osint-backup.json"');
  res.json({ users: db.prepare('SELECT username,role,created_at FROM users').all(), tools: db.prepare('SELECT type,name,url,descr FROM custom_tools').all(), log: db.prepare('SELECT ts,username,action FROM audit_log').all() });
});

app.use(express.static(path.join(__dirname, 'public')));
app.use('/api', (req, res) => res.status(404).json({ e: 'not found' }));

// first admin: from env (ADMIN_USER / ADMIN_PASS) or `npm run create-admin -- user pass`
if (!db.prepare('SELECT 1 FROM users LIMIT 1').get()) {
  const { ADMIN_USER: n, ADMIN_PASS: p } = process.env;
  if (USER.test(n || '') && okPass(p)) { db.prepare("INSERT INTO users(username,pass_hash,role) VALUES(?,?, 'admin')").run(n, bcrypt.hashSync(p, 12)); console.log('Admin created: ' + n); }
  else console.log('No users yet. Run: npm run create-admin -- <username> <password>  (or set ADMIN_USER / ADMIN_PASS)');
}
app.listen(process.env.PORT || 3000, () => console.log('OSINT Hub on :' + (process.env.PORT || 3000)));
