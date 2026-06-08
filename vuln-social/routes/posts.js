// routes/posts.js — post create/detail/comment.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

// Detail
router.get('/:id', (req, res) => {
  const p = db.prepare(`
    SELECT p.*, u.username, u.display_name, u.avatar FROM posts p
    JOIN users u ON u.id = p.user_id WHERE p.id = ?
  `).get(req.params.id);
  if (!p) return res.status(404).send('not found');
  const comments = db.prepare(`
    SELECT c.*, u.username, u.display_name, u.avatar FROM comments c
    JOIN users u ON u.id = c.user_id WHERE c.post_id = ? ORDER BY c.id
  `).all(p.id);
  res.render('post_detail', { p, comments });
});

// VULN: no CSRF token on POST; body rendered with <%- %> later (stored XSS).
router.post('/', requireSession, (req, res) => {
  const body = req.body.body || '';
  const r = db.prepare('INSERT INTO posts (user_id, body) VALUES (?, ?)').run(req.session.userId, body);
  res.redirect('/p/' + r.lastInsertRowid);
});

router.post('/:id/comments', requireSession, (req, res) => {
  const body = req.body.body || '';
  db.prepare('INSERT INTO comments (post_id, user_id, body) VALUES (?, ?, ?)').run(req.params.id, req.session.userId, body);
  res.redirect('/p/' + req.params.id);
});

// VULN: report endpoint accepts GET so it is CSRF-able.
router.get('/:id/report', requireSession, (req, res) => {
  db.prepare('INSERT INTO reports (post_id, reporter_id, reason) VALUES (?, ?, ?)')
    .run(req.params.id, req.session.userId, req.query.reason || 'unspecified');
  db.prepare('UPDATE posts SET flagged = 1 WHERE id = ?').run(req.params.id);
  res.redirect('/p/' + req.params.id);
});

module.exports = router;
