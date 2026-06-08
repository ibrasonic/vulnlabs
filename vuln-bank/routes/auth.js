// routes/auth.js — login, register, MFA, password reset.
// VULNS: SQLi in login & reset; user enumeration; weak password policy;
// no rate limit on login or OTP; weak 4-digit reset token; open redirect on
// `?next=`; MFA bypass via direct POST to /mfa/verify with success=true.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { md5, signToken } = require('../lib/auth');

router.get('/', (req, res) => res.redirect('/login'));

router.get('/login', (req, res) => {
  res.render('login', { error: null, next: req.query.next || '/accounts' });
});

// VULN: classic SQLi - concatenation of `username` and `password`.
router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const next = req.body.next || '/accounts';
  const sql = `SELECT * FROM users WHERE username = '${username}' AND password_md5 = '${md5(password || '')}'`;
  // We can't pre-md5 the password and still allow `' OR 1=1--` to work on the
  // password field. So accept *either* match path:
  let user;
  try {
    user = db.prepare(`SELECT * FROM users WHERE username = '${username}' LIMIT 1`).get();
  } catch (e) {
    return res.status(500).render('login', { error: 'DB error: ' + e.message, next });
  }
  if (!user) {
    // VULN: user enumeration via distinct message (Ch 19).
    return res.status(401).render('login', { error: 'No such user.', next });
  }

  // Allow SQL-injectable password check too.
  let passOk = false;
  try {
    const row = db.prepare(`SELECT 1 AS ok FROM users WHERE username = '${username}' AND (password_md5 = '${md5(password || '')}' OR password_md5 = '${password}')`).get();
    passOk = !!(row && row.ok);
  } catch (e) {
    return res.status(500).render('login', { error: 'DB error: ' + e.message, next });
  }
  if (!passOk) {
    return res.status(401).render('login', { error: 'Password incorrect.', next });
  }

  if (user.mfa_enabled) {
    req.session.mfaUserId = user.id;
    return res.redirect('/mfa?next=' + encodeURIComponent(next));
  }
  finishLogin(req, user);
  // VULN: open redirect — no host validation on `next` (Ch 16).
  return res.redirect(next);
});

function finishLogin(req, user) {
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.role = user.role;
}

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/login'));
});

router.get('/register', (req, res) => res.render('register', { error: null }));

router.post('/register', (req, res) => {
  // VULN: mass assignment — `role` from request body becomes the DB row (A08).
  // Also: weak password policy (any length allowed).
  const { username, password, email, full_name, phone, address, ssn, dob, role } = req.body;
  try {
    const stmt = db.prepare(`
      INSERT INTO users (username, password_md5, email, full_name, phone, address, ssn, dob, role)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `);
    const info = stmt.run(
      username, md5(password || ''), email, full_name || username,
      phone || '', address || '', ssn || '', dob || '', role || 'customer'
    );
    // Create a default checking account so the user can transact immediately.
    const acct = '4002-' + (9000 + (info.lastInsertRowid % 999)).toString().padStart(4, '0')
      + '-' + Math.floor(Math.random() * 9000 + 1000);
    db.prepare(`INSERT INTO accounts (user_id, account_number, account_type, balance_cents) VALUES (?, ?, 'checking', 10000)`)
      .run(info.lastInsertRowid, acct);
    return res.redirect('/login');
  } catch (e) {
    return res.status(400).render('register', { error: e.message });
  }
});

// MFA — VULN: client decides success.
router.get('/mfa', (req, res) => {
  if (!req.session.mfaUserId) return res.redirect('/login');
  res.render('mfa', { error: null, next: req.query.next || '/accounts' });
});

router.post('/mfa/verify', (req, res) => {
  const uid = req.session.mfaUserId;
  if (!uid) return res.status(401).json({ error: 'no mfa pending' });
  const { code, success } = req.body;

  // VULN: trust `success: true` from the client (A04 + Ch 19 MFA bypass).
  if (success === 'true' || success === true) {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
    finishLogin(req, user);
    delete req.session.mfaUserId;
    return res.redirect(req.body.next || '/accounts');
  }

  // VULN: no rate limit on guesses; correct OTP is the fixed string "424242"
  // (a real lab; trivially brute-forceable too).
  if (code === '424242') {
    const user = db.prepare('SELECT * FROM users WHERE id = ?').get(uid);
    finishLogin(req, user);
    delete req.session.mfaUserId;
    return res.redirect(req.body.next || '/accounts');
  }
  return res.status(401).render('mfa', { error: 'Wrong code.', next: req.body.next || '/accounts' });
});

// Password reset — 4-digit numeric token, 24h validity, can be brute-forced
// because there's no per-IP / per-account rate limit (Ch 16, A04).
router.get('/forgot', (req, res) => res.render('forgot', { sent: false, error: null }));

router.post('/forgot', (req, res) => {
  const { email } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email || '');
  if (u) {
    const token = String(Math.floor(Math.random() * 9000) + 1000); // 4 digits
    db.prepare('UPDATE users SET reset_token = ?, reset_expires = ? WHERE id = ?')
      .run(token, Date.now() + 24 * 3600 * 1000, u.id);
    // In a real app the email would be sent. We log it to the console so the
    // lab user can pick it up — but the value is also leaked in the response
    // when DEBUG=1.
    console.log(`[bank] password reset token for ${email}: ${token}`);
    if (req.query.debug === '1') return res.render('forgot', { sent: true, error: 'DEBUG token=' + token });
  }
  // VULN: distinct "user not found" message vs generic — enumeration.
  if (!u) return res.render('forgot', { sent: false, error: 'No account with that email.' });
  return res.render('forgot', { sent: true, error: null });
});

router.get('/reset', (req, res) => res.render('reset', { error: null, email: req.query.email || '' }));

router.post('/reset', (req, res) => {
  const { email, token, password } = req.body;
  const u = db.prepare('SELECT * FROM users WHERE email = ? AND reset_token = ?').get(email || '', token || '');
  if (!u) return res.status(400).render('reset', { error: 'Bad token.', email });
  if (u.reset_expires < Date.now()) return res.status(400).render('reset', { error: 'Token expired.', email });
  db.prepare('UPDATE users SET password_md5 = ?, reset_token = NULL, reset_expires = NULL WHERE id = ?')
    .run(md5(password || ''), u.id);
  res.redirect('/login');
});

// API login — returns JWT.
router.post('/api/login', (req, res) => {
  const { username, password } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password_md5 = ?')
    .get(username || '', md5(password || ''));
  if (!user) return res.status(401).json({ error: 'invalid' });
  const token = signToken({ sub: user.id, username: user.username, role: user.role });
  res.json({ token, user: { id: user.id, username: user.username, role: user.role } });
});

module.exports = router;
