// routes/security.js — step-up verification ("confirm it's you") before a
// sensitive action, using a one-time code the bank "texts" you.
//
// VULN (Ch 21, rate-limit bypass by race): a 6-digit code allows only 5 wrong
// attempts before it locks. But the verify handler reads the attempt count,
// checks it is under the limit, waits (the SMS/fraud round trip), and only
// THEN increments on a miss. The read-check-increment is non-atomic, so N
// concurrent guesses all pass the "attempts < 5" gate before any of them bumps
// the counter -- the lock never trips and the whole 6-digit space is guessable
// in bulk.
//
// The fix: increment atomically and act on the new value, e.g.
//   UPDATE otp_challenges SET attempts = attempts + 1
//     WHERE id = ? AND status = 'pending' AND attempts < 5
// and treat changes===0 as "locked / no attempt left".
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

const MAX_ATTEMPTS = 5;
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function currentChallenge(userId) {
  return db.prepare(
    "SELECT * FROM otp_challenges WHERE user_id = ? AND purpose = 'step_up' ORDER BY id DESC LIMIT 1"
  ).get(userId);
}

router.use(requireSession);

router.get('/verify', (req, res) => {
  let ch = currentChallenge(req.session.userId);
  if (!ch || ch.status !== 'pending') {
    const code = String(Math.floor(Math.random() * 900000) + 100000); // 6 digits
    const info = db.prepare(
      "INSERT INTO otp_challenges (user_id, purpose, code, status) VALUES (?, 'step_up', ?, 'pending')"
    ).run(req.session.userId, code);
    // In production this is texted to the customer; here it goes to the server
    // log so a learner can follow the honest path.
    console.log(`[bank] step-up code for user ${req.session.userId}: ${code}`);
    ch = db.prepare('SELECT * FROM otp_challenges WHERE id = ?').get(info.lastInsertRowid);
  }
  res.render('security_verify', {
    challenge: ch,
    error: req.query.error || null,
    ok: req.query.ok || null,
    debugCode: req.query.debug === '1' ? ch.code : null,
  });
});

router.post('/verify', async (req, res) => {
  const id = parseInt(req.body.challenge_id, 10);
  const code = String(req.body.code || '').trim();
  const ch = db.prepare('SELECT * FROM otp_challenges WHERE id = ? AND user_id = ?')
    .get(id, req.session.userId);
  if (!ch) return res.redirect('/security/verify?error=' + encodeURIComponent('no challenge'));

  // VULN (time-of-check): the gate that is supposed to stop brute force.
  if (ch.status !== 'pending') return res.redirect('/security/verify?error=' + encodeURIComponent('already ' + ch.status));
  if (ch.attempts >= MAX_ATTEMPTS) {
    db.prepare("UPDATE otp_challenges SET status = 'locked' WHERE id = ?").run(id);
    return res.redirect('/security/verify?error=' + encodeURIComponent('locked: too many attempts'));
  }

  // VULN (race window): the SMS/fraud round trip. The event loop runs the other
  // concurrent guesses here, all of which already passed the check above.
  await sleep(200);

  // time-of-use.
  if (code === ch.code) {
    db.prepare("UPDATE otp_challenges SET status = 'verified' WHERE id = ?").run(id);
    return res.redirect('/security/verify?ok=' + encodeURIComponent('verified'));
  }
  db.prepare('UPDATE otp_challenges SET attempts = attempts + 1 WHERE id = ?').run(id);
  return res.redirect('/security/verify?error=' + encodeURIComponent('wrong code'));
});

module.exports = router;
