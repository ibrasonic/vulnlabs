// routes/admin.js - admin panel. Mounted at /admin. The gateway is supposed
// to block /admin/* on the public edge unless X-Internal-Auth is set; the
// back-end ALSO requires the internal header (defence in depth). Smuggled
// requests forge the header outright.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireInternal, FLAGS } = require('../lib/auth');

router.use(requireInternal);

router.get('/', (req, res) => {
  const stats = {
    users:    db.prepare('SELECT COUNT(*) AS c FROM users').get().c,
    articles: db.prepare('SELECT COUNT(*) AS c FROM articles').get().c,
    drafts:   db.prepare(`SELECT COUNT(*) AS c FROM articles WHERE status = 'draft'`).get().c,
    comments: db.prepare('SELECT COUNT(*) AS c FROM comments').get().c
  };
  const audit = db.prepare('SELECT * FROM audit_log ORDER BY at DESC LIMIT 25').all();
  res.render('admin', { stats, audit, FLAGS });
});

router.get('/users', (req, res) => {
  const users = db.prepare(`
    SELECT id, username, email, display_name, tier, created_at FROM users ORDER BY id
  `).all();
  res.render('admin_users', { users, FLAGS });
});

router.post('/users/:id/role', (req, res) => {
  const { tier } = req.body;
  const allowed = ['reader', 'subscriber', 'author', 'editor', 'admin'];
  if (!allowed.includes(tier)) return res.status(400).type('text').send('bad tier\n');
  db.prepare('UPDATE users SET tier = ? WHERE id = ?').run(tier, req.params.id);
  db.prepare('INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)')
    .run('admin-api', 'role_change', 'user_id=' + req.params.id + ' new=' + tier);
  res.redirect('/admin/users');
});

router.post('/users/:id/delete', (req, res) => {
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.redirect('/admin/users');
});

router.get('/audit.json', (req, res) => {
  res.json(db.prepare('SELECT * FROM audit_log ORDER BY at DESC LIMIT 200').all());
});

module.exports = router;
