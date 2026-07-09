// routes/passwordless.js — "email me a login code" (passwordless sign-in).
//
// VULN (Ch 21, time-sensitive vulnerability): the login code is derived from
// the current second, so two requests made in the same second are handed the
// SAME code. An attacker requests a code for the victim's address AND for their
// own address at the same instant; both codes are identical, so the attacker
// reads the code delivered to their own inbox and uses it to sign in as the
// victim -- no interception of the victim's email required.
//
// The fix: generate the code from a CSPRNG (crypto.randomInt), bind it to the
// exact account, and never derive secrets from a clock.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');

// VULN: seeded only by the current second -> collisions within the same second.
function timeCode() {
  return String(Math.floor(Date.now() / 1000) % 1000000).padStart(6, '0');
}

router.get('/login/code', (req, res) => {
  res.render('login_code', {
    sent: req.query.sent || null,
    error: req.query.error || null,
    debugCode: null,
    email: req.query.email || '',
  });
});

router.post('/login/code/request', (req, res) => {
  const email = String(req.body.email || '').trim();
  const code = timeCode();
  // Issue a code even for unknown addresses would be safer (no enumeration),
  // but the vuln we care about is the predictable code, so mirror a real app:
  const u = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (u) {
    db.prepare('INSERT INTO login_codes (email, code) VALUES (?, ?)').run(email, code);
    console.log(`[bank] passwordless login code for ${email}: ${code}`);
  }
  const q = 'sent=' + encodeURIComponent('If that address exists, a code is on its way.') +
            '&email=' + encodeURIComponent(email) +
            (req.query.debug === '1' && u ? '&_dbg=' + code : '');
  if (req.query.debug === '1' && u) {
    return res.render('login_code', {
      sent: 'If that address exists, a code is on its way.', error: null,
      debugCode: code, email,
    });
  }
  return res.redirect('/login/code?' + q);
});

router.post('/login/code/verify', (req, res) => {
  const email = String(req.body.email || '').trim();
  const code = String(req.body.code || '').trim();
  const row = db.prepare(
    'SELECT * FROM login_codes WHERE email = ? AND code = ? AND used = 0 ORDER BY id DESC LIMIT 1'
  ).get(email, code);
  if (!row) return res.redirect('/login/code?error=' + encodeURIComponent('invalid or expired code') + '&email=' + encodeURIComponent(email));
  // 10-minute validity.
  const ageMs = Date.now() - Date.parse((row.created_at || '').replace(' ', 'T') + 'Z');
  if (isFinite(ageMs) && ageMs > 10 * 60 * 1000) {
    return res.redirect('/login/code?error=' + encodeURIComponent('code expired') + '&email=' + encodeURIComponent(email));
  }
  db.prepare('UPDATE login_codes SET used = 1 WHERE id = ?').run(row.id);
  const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email);
  if (!user) return res.redirect('/login/code?error=' + encodeURIComponent('no such account'));
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.role = user.role;
  return res.redirect('/accounts');
});

module.exports = router;
