// routes/dm.js — direct messages with IDOR + CSRF (GET send).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

router.get('/', (req, res) => {
  const peers = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.avatar,
           MAX(d.id) AS last_id, MAX(d.created_at) AS last_at
    FROM dms d JOIN users u ON u.id = CASE WHEN d.sender_id = ? THEN d.recipient_id ELSE d.sender_id END
    WHERE d.sender_id = ? OR d.recipient_id = ?
    GROUP BY u.id ORDER BY last_at DESC
  `).all(req.session.userId, req.session.userId, req.session.userId);
  res.render('dm_inbox', { peers });
});

// VULN: IDOR -- thread is looked up by ?with=id with no membership check.
router.get('/thread', (req, res) => {
  const otherId = parseInt(req.query.with || '0', 10);
  if (!otherId) return res.redirect('/dm');
  const messages = db.prepare(`
    SELECT d.*, u.username, u.display_name FROM dms d JOIN users u ON u.id = d.sender_id
    WHERE d.sender_id IN (?, ?) AND d.recipient_id IN (?, ?)
    ORDER BY d.id
  `).all(req.session.userId, otherId, req.session.userId, otherId);
  // BUT we also expose another vector: ?as=N -> view as another user.
  // VULN: classic horizontal-privilege bypass.
  const viewerId = parseInt(req.query.as || req.session.userId, 10);
  const messagesAny = db.prepare(`
    SELECT d.*, u.username AS sender_name FROM dms d JOIN users u ON u.id = d.sender_id
    WHERE (d.sender_id = ? AND d.recipient_id = ?) OR (d.sender_id = ? AND d.recipient_id = ?)
    ORDER BY d.id
  `).all(viewerId, otherId, otherId, viewerId);
  const other = db.prepare('SELECT * FROM users WHERE id = ?').get(otherId) || { username: 'unknown', display_name: 'unknown' };
  res.render('dm_thread', { other, messages: messagesAny });
});

// VULN: send via GET -> CSRF-able. No verification you ever followed this user.
router.get('/send', (req, res) => {
  const to = parseInt(req.query.to || '0', 10);
  const body = req.query.body || '';
  if (!to || !body) return res.status(400).send('missing to or body');
  db.prepare('INSERT INTO dms (sender_id, recipient_id, body) VALUES (?, ?, ?)')
    .run(req.session.userId, to, body);
  res.redirect('/dm/thread?with=' + to);
});

module.exports = router;
