// routes/auth.js — login/register/logout.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { md5, signToken } = require('../lib/auth');

router.get('/login', (req, res) => res.render('login', { error: null, next: req.query.next || '/' }));

// VULN: SQL injection (string interpolation in WHERE).
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const next = req.body.next || '/';
  let user;
  try {
    user = db.prepare(`SELECT * FROM users WHERE username = '${username}' LIMIT 1`).get();
  } catch (e) {
    return res.status(500).render('login', { error: 'DB: ' + e.message, next });
  }
  if (!user) return res.status(401).render('login', { error: 'No such user.', next });
  let ok = false;
  try {
    const row = db.prepare(`SELECT 1 AS ok FROM users WHERE username = '${username}' AND (password_md5 = '${md5(password || '')}' OR password_md5 = '${password}')`).get();
    ok = !!(row && row.ok);
  } catch (e) {
    return res.status(500).render('login', { error: 'DB: ' + e.message, next });
  }
  if (!ok) return res.status(401).render('login', { error: 'Wrong password.', next });
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.role = user.role;
  // VULN: open redirect via `next`
  res.redirect(next);
});

router.get('/logout', (req, res) => req.session.destroy(() => res.redirect('/login')));

router.get('/register', (req, res) => res.render('register', { error: null }));

// VULN: mass-assignment — `role` and `is_private` come straight from body.
router.post('/register', (req, res) => {
  const { username, password, email, display_name, bio, role, is_private } = req.body;
  try {
    const r = db.prepare(`
      INSERT INTO users (username, password_md5, email, display_name, bio, role, is_private)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      username, md5(password || ''),
      email || (username + '@x.test'),
      display_name || username,
      bio || '',
      role || 'user',           // VULN
      parseInt(is_private || '0', 10)
    );
    req.session.userId = r.lastInsertRowid;
    req.session.username = username;
    req.session.role = role || 'user';
    res.redirect('/');
  } catch (e) {
    res.status(400).render('register', { error: e.message });
  }
});

module.exports = router;
