// routes/support.js — submit support messages (stored XSS sink rendered in admin).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

router.get('/', (req, res) => {
  const mine = db.prepare('SELECT * FROM support_messages WHERE user_id = ? ORDER BY created_at DESC')
    .all(req.session.userId);
  res.render('support', { mine, ok: req.query.ok });
});

router.post('/submit', (req, res) => {
  const { subject, body } = req.body;
  db.prepare('INSERT INTO support_messages (user_id, subject, body) VALUES (?, ?, ?)')
    .run(req.session.userId, subject || '(no subject)', body || '');
  res.redirect('/support?ok=1');
});

module.exports = router;
