// routes/transfers.js — initiate a transfer between accounts.
// VULNS: no CSRF protection (state-changing GET *and* POST without token);
// race condition (re-read balance, then write — no row-level lock);
// IDOR (source account not checked for ownership);
// negative-amount accepted (business logic).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

router.get('/', (req, res) => {
  const accts = db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.session.userId);
  res.render('transfer', { accounts: accts, error: null, ok: req.query.ok || null });
});

function doTransfer({ from, to, amount, memo }) {
  const src = db.prepare('SELECT * FROM accounts WHERE account_number = ?').get(from);
  const dst = db.prepare('SELECT * FROM accounts WHERE account_number = ?').get(to);
  if (!src || !dst) throw new Error('account not found');
  // VULN: deliberate non-atomic balance update. The developer "fixed" the
  // concurrency worry by re-reading the balance here — but the read, the check
  // and the write are three separate statements with no transaction, so two
  // requests that overlap both pass the check before either writes.
  const fresh = db.prepare('SELECT balance_cents FROM accounts WHERE id = ?').get(src.id);
  if (fresh.balance_cents < amount) throw new Error('insufficient funds');
  // VULN (race window): a REAL asynchronous gap between the check and the
  // write. In production this is the network call to a fraud/limits service or
  // an SMS gateway; here it is an await so Node's event loop interleaves a
  // second (and third...) request between this request's check and its debit.
  return sleep(200).then(() => {
    db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE id = ?').run(amount, src.id);
    db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE id = ?').run(amount, dst.id);
    db.prepare('INSERT INTO transfers (from_account, to_account, amount_cents, memo) VALUES (?, ?, ?, ?)')
      .run(from, to, amount, memo || '');
  });
}
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// VULN: GET form-handler so any <img src=...> CSRF works (Ch 23).
router.get('/send', async (req, res) => {
  const { from, to, amount, memo } = req.query;
  try {
    await doTransfer({ from, to, amount: parseInt(amount, 10), memo });
    return res.redirect('/transfer?ok=1');
  } catch (e) {
    return res.status(400).render('transfer', {
      accounts: db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.session.userId),
      error: e.message, ok: null
    });
  }
});

// POST handler — also no CSRF token check.
router.post('/send', async (req, res) => {
  const { from, to, amount, memo } = req.body;
  try {
    await doTransfer({ from, to, amount: parseInt(amount, 10), memo });
    return res.redirect('/transfer?ok=1');
  } catch (e) {
    return res.status(400).render('transfer', {
      accounts: db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.session.userId),
      error: e.message, ok: null
    });
  }
});

module.exports = router;
