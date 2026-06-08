// routes/follow.js — follow/unfollow (CSRF: GET-based, no token).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

router.get('/:name', (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.name);
  if (!u) return res.status(404).send('no user');
  db.prepare('INSERT OR IGNORE INTO follows (follower_id, followee_id) VALUES (?, ?)')
    .run(req.session.userId, u.id);
  res.redirect('/u/' + req.params.name);
});

router.get('/:name/unfollow', (req, res) => {
  const u = db.prepare('SELECT id FROM users WHERE username = ?').get(req.params.name);
  if (!u) return res.status(404).send('no user');
  db.prepare('DELETE FROM follows WHERE follower_id = ? AND followee_id = ?')
    .run(req.session.userId, u.id);
  res.redirect('/u/' + req.params.name);
});

module.exports = router;
