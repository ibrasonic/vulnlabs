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
// ALSO: a naive blacklist tries to strip `<script>` tags AND event-handler
// attributes via the regex `/\son\w+\s*=/gi`. Both filters miss every payload
// that does not use a literal `<script>` tag AND does not put whitespace
// before the event handler. Bypasses include:
//   <svg/onload=alert(1)>            (slash separator, no space)
//   <svg\tonload=alert(1)>           (tab separator)
//   <img src=x ONERROR=alert(1)>     (uppercase survives the lookbehind)
//   <scr<script>ipt>alert(1)</script>  (nested-tag trick beats single-pass strip)
function naiveStrip(s) {
  return String(s || '')
    .replace(/<script[^>]*>.*?<\/script>/gi, '')
    .replace(/\son\w+\s*=/gi, ' ');
}
router.post('/', requireSession, (req, res) => {
  const body = naiveStrip(req.body.body || '');
  const r = db.prepare('INSERT INTO posts (user_id, body) VALUES (?, ?)').run(req.session.userId, body);
  res.redirect('/p/' + r.lastInsertRowid);
});

router.post('/:id/comments', requireSession, (req, res) => {
  const post = db.prepare('SELECT id FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).send('post not found');
  // Comments stay unfiltered for the easy-tier practice; only post bodies
  // run through the naive blacklist.
  const body = req.body.body || '';
  db.prepare('INSERT INTO comments (post_id, user_id, body) VALUES (?, ?, ?)').run(req.params.id, req.session.userId, body);
  res.redirect('/p/' + req.params.id);
});

// VULN: report endpoint accepts GET so it is CSRF-able.
router.get('/:id/report', requireSession, (req, res) => {
  const post = db.prepare('SELECT id FROM posts WHERE id = ?').get(req.params.id);
  if (!post) return res.status(404).send('post not found');
  db.prepare('INSERT INTO reports (post_id, reporter_id, reason) VALUES (?, ?, ?)')
    .run(req.params.id, req.session.userId, req.query.reason || 'unspecified');
  db.prepare('UPDATE posts SET flagged = 1 WHERE id = ?').run(req.params.id);
  res.redirect('/p/' + req.params.id);
});

module.exports = router;
