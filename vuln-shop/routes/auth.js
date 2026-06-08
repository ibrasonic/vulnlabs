// routes/auth.js — login/register/logout.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { md5, signToken } = require('../lib/auth');

router.get('/', (req, res) => res.redirect('/products'));

router.get('/login', (req, res) => {
  res.render('login', { error: null, next: req.query.next || '/products' });
});

// VULN: SQL injection in login.
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const next = req.body.next || '/products';
  let user;
  try {
    user = db.prepare(`SELECT * FROM users WHERE username = '${username}' LIMIT 1`).get();
  } catch (e) {
    return res.status(500).render('login', { error: 'DB error: ' + e.message, next });
  }
  if (!user) {
    // VULN: user enumeration
    return res.status(401).render('login', { error: 'No such user.', next });
  }
  let ok = false;
  try {
    const row = db.prepare(`SELECT 1 AS ok FROM users WHERE username = '${username}' AND (password_md5 = '${md5(password || '')}' OR password_md5 = '${password}')`).get();
    ok = !!(row && row.ok);
  } catch (e) {
    return res.status(500).render('login', { error: 'DB error: ' + e.message, next });
  }
  if (!ok) return res.status(401).render('login', { error: 'Password incorrect.', next });
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.role = user.role;
  // VULN: open redirect via next
  return res.redirect(next);
});

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

router.get('/register', (req, res) => res.render('register', { error: null }));

// VULN: mass-assignment register
router.post('/register', (req, res) => {
  const { username, password, email, full_name, address, role, credits_cents } = req.body;
  try {
    const r = db.prepare(`
      INSERT INTO users (username, password_md5, email, full_name, address, role, credits_cents)
      VALUES (?, ?, ?, ?, ?, ?, ?)
    `).run(
      username, md5(password || ''), email || (username + '@x.test'),
      full_name || username, address || '',
      role || 'customer',
      parseInt(credits_cents || '0', 10) || 0   // VULN: user can grant themselves store credit
    );
    req.session.userId = r.lastInsertRowid;
    req.session.username = username;
    req.session.role = role || 'customer';
    return res.redirect('/products');
  } catch (e) {
    return res.status(400).render('register', { error: e.message });
  }
});

// API login (JWT)
router.post('/api/login', (req, res, next) => res.redirect(307, '/api/_login'));

module.exports = router;
