// routes/rewards.js — redeem a promotional gift-card / reward code.
//
// VULN (Ch 21, race condition / limit overrun): redemption reads the card,
// checks it is not yet redeemed, waits, then credits the account AND marks the
// card redeemed. The read, the check and the two writes are separate,
// non-atomic statements. Two (or twenty) concurrent redemptions of the SAME
// code all pass the `redeemed = 0` check before any of them flips the flag, so
// each one credits the account: a single $50 card mints $50 x N.
//
// The fix (see the chapter) is one atomic statement that claims the card:
//   UPDATE gift_cards SET redeemed = 1, redeemed_by = ? WHERE code = ? AND redeemed = 0
// then credit only when `changes === 1`.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

function primaryAccount(userId) {
  return db.prepare(
    "SELECT * FROM accounts WHERE user_id = ? AND account_type = 'checking' ORDER BY id LIMIT 1"
  ).get(userId);
}

router.get('/', (req, res) => {
  const acct = primaryAccount(req.session.userId);
  res.render('rewards', {
    account: acct,
    error: req.query.error || null,
    ok: req.query.ok || null,
  });
});

router.post('/redeem', async (req, res) => {
  const code = String(req.body.code || '').trim().toUpperCase();
  const acct = primaryAccount(req.session.userId);
  if (!acct) return res.redirect('/rewards?error=' + encodeURIComponent('no checking account'));

  const card = db.prepare('SELECT * FROM gift_cards WHERE code = ?').get(code);
  if (!card) return res.redirect('/rewards?error=' + encodeURIComponent('unknown code'));
  // VULN (TOCTOU): time-of-check.
  if (card.redeemed) return res.redirect('/rewards?error=' + encodeURIComponent('already redeemed'));

  // VULN (race window): a real asynchronous gap between the check above and the
  // writes below. In production this is the call to the rewards/ledger service;
  // here it is an await, so the event loop interleaves other redemptions of the
  // same code between this one's check and its credit.
  await sleep(200);

  // time-of-use: credit the account and mark the card spent (non-atomic).
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?')
    .run(card.amount_cents, acct.id);
  db.prepare('UPDATE gift_cards SET redeemed = 1, redeemed_by = ?, redeemed_at = NOW() WHERE id = ?')
    .run(req.session.userId, card.id);

  const dollars = (card.amount_cents / 100).toFixed(2);
  return res.redirect('/rewards?ok=' + encodeURIComponent('Credited $' + dollars + ' from ' + card.code));
});

module.exports = router;
