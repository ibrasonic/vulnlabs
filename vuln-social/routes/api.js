// routes/api.js — JSON API with CORS reflection, BOLA, JWT alg=none acceptance.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { md5, signToken, requireJwt } = require('../lib/auth');

// VULN: CORS reflection with credentials.
router.use((req, res, next) => {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
    res.setHeader('Access-Control-Allow-Headers', 'Authorization,Content-Type,Origin,Accept');
  }
  if (req.method === 'OPTIONS') return res.sendStatus(204);
  next();
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ error: 'missing' });
  const u = db.prepare('SELECT * FROM users WHERE username = ? AND password_md5 = ?').get(username, md5(password));
  if (!u) return res.status(401).json({ error: 'bad creds' });
  res.json({ token: signToken(u), user: { id: u.id, username: u.username, role: u.role } });
});

// VULN: returns full row including password_md5
router.get('/me', requireJwt, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.jwt.sub);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

// VULN: BOLA -- no ownership check
router.get('/users/:id', requireJwt, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

// VULN: BOLA -- any DM by id, no membership check
router.get('/dms/:id', requireJwt, (req, res) => {
  const d = db.prepare('SELECT * FROM dms WHERE id = ?').get(req.params.id);
  if (!d) return res.status(404).json({ error: 'not found' });
  res.json(d);
});

// VULN: mass-assignment
router.put('/users/:id', requireJwt, (req, res) => {
  const allowed = ['email', 'display_name', 'bio', 'avatar', 'role', 'is_private'];
  const sets = []; const vals = [];
  for (const k of allowed) if (req.body[k] !== undefined) { sets.push(k + ' = ?'); vals.push(req.body[k]); }
  if (!sets.length) return res.status(400).json({ error: 'nothing to update' });
  vals.push(req.params.id);
  db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
  res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id));
});

// VULN: no-auth bulk dump
router.get('/v1/users', (req, res) => {
  res.json(db.prepare('SELECT id, username, email, password_md5, role FROM users').all());
});

// Tiny GraphQL-ish endpoint, no auth.
router.post('/graphql', (req, res) => {
  const q = (req.body && req.body.query) || '';
  if (/users\s*\{/.test(q)) return res.json({ data: { users: db.prepare('SELECT * FROM users').all() } });
  if (/posts\s*\{/.test(q)) return res.json({ data: { posts: db.prepare('SELECT * FROM posts').all() } });
  if (/dms\s*\{/.test(q))   return res.json({ data: { dms:   db.prepare('SELECT * FROM dms').all() } });
  res.status(400).json({ errors: [{ message: 'unsupported' }] });
});

module.exports = router;
