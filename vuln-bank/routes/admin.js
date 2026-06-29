// routes/admin.js — admin panel.
// VULNS: BAC — no role check on /admin/users, /admin/users/:id/delete,
// /admin/promote (only checks logged-in). Reflected XSS via ?q=. Stored XSS
// when rendering support messages (admin reads them with `<%- body %>`).
// Cache poisoning friendly: X-Forwarded-Host echoed into "canonical" header.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

// VULN (B-MIS-006): hard-coded "support engineer" override token. Anyone
// who sends `X-Support-Token: ENG-OVERRIDE-2024-ALL-ACCESS` is upgraded to
// admin without authenticating. The token is leaked via the routes/admin
// backup file at /static/backup/admin.js.bak (B-MIS-005).
const SUPPORT_TOKEN = 'ENG-OVERRIDE-2024-ALL-ACCESS';
router.use((req, res, next) => {
  if (req.headers['x-support-token'] === SUPPORT_TOKEN) {
    req.session = req.session || {};
    req.session.role = 'admin';
    req.session.username = 'support_engineer';
    req.session.userId = 1;
  }
  next();
});

router.use(requireSession);

// VULN: forgot the role check.
router.get('/', (req, res) => {
  const users = db.prepare('SELECT id, username, full_name, email, role FROM users').all();
  const messages = db.prepare(`
    SELECT support_messages.*, users.username AS author
    FROM support_messages JOIN users ON users.id = support_messages.user_id
    ORDER BY support_messages.created_at DESC LIMIT 20
  `).all();
  // VULN: reflect X-Forwarded-Host into a Link rel="canonical" header.
  const xfh = req.headers['x-forwarded-host'];
  if (xfh) res.setHeader('Link', `<https://${xfh}/admin>; rel="canonical"`);
  res.render('admin', { users, messages, q: req.query.q || '' });
});

router.get('/users', (req, res) => {
  // VULN: SQLi via q
  const q = req.query.q || '';
  const rows = db.prepare(`SELECT id, username, full_name, email, ssn, role FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`).all();
  res.render('admin_users', { rows, q });
});

// VULN: GET-based privilege change — CSRF-friendly + BAC.
router.get('/promote', (req, res) => {
  const id = parseInt(req.query.id, 10);
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run('admin', id);
  res.redirect('/admin');
});

router.get('/users/:id/delete', (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.redirect('/admin');
});

// View raw user row — leaks SSN, password hash.
router.get('/users/:id', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).send('not found');
  res.json(u);
});

module.exports = router;
