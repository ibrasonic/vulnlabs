// routes/api.js — REST + tiny graphql-ish endpoint with the usual API vulns.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { md5, signToken, requireJwt } = require('../lib/auth');

// VULN: CORS reflection w/ credentials.
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

// VULN: returns the entire row including password_md5
router.get('/me', requireJwt, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.jwt.sub);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

// VULN: BOLA — no ownership check
router.get('/users/:id', requireJwt, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

// VULN: mass assignment — accept any field
router.put('/users/:id', requireJwt, (req, res) => {
  const allowed = ['email', 'full_name', 'address', 'role', 'credits_cents'];
  const sets = []; const vals = [];
  for (const k of allowed) if (req.body[k] !== undefined) { sets.push(k + ' = ?'); vals.push(req.body[k]); }
  if (!sets.length) return res.status(400).json({ error: 'nothing to update' });
  vals.push(req.params.id);
  db.prepare(`UPDATE users SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
  res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id));
});

// VULN: BOLA — orders for any user
router.get('/orders/:id', requireJwt, (req, res) => {
  const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!o) return res.status(404).json({ error: 'not found' });
  const items = db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(o.id);
  res.json({ order: o, items });
});

// VULN: improper inventory — old API version with no auth
router.get('/v1/users', (req, res) => {
  res.json(db.prepare('SELECT id, username, email, password_md5, role FROM users').all());
});

// (real GraphQL endpoint lives in routes/graphql.js, mounted at /graphql)

// VULN: JSONP endpoint reflects the `callback` parameter verbatim into an
// executable application/javascript response with no validation. Under a
// script-src 'self' CSP this is a same-origin gadget that upgrades any
// HTML-injection into full script execution (CSP bypass):
//   <script src="/api/reviews.js?callback=confirm(document.domain)//"></script>
router.get('/reviews.js', (req, res) => {
  const cb = req.query.callback || 'onReviews';
  const summary = db.prepare('SELECT COUNT(*) AS count, ROUND(AVG(rating), 2) AS avg FROM reviews').get();
  res.type('application/javascript');
  res.send(`${cb}(${JSON.stringify(summary)});`);
});

module.exports = router;
