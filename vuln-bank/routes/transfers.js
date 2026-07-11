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
  // VULN (A08 prototype-pollution GADGET): the per-transfer limits are read
  // from a fresh {} with no own-property check, so `overdraftLimit` is read
  // straight off Object.prototype. Un-polluted it is undefined -> 0, so the
  // check is exactly `balance < amount` (behaviour unchanged). If the prototype
  // was polluted via POST /profile ({"__proto__":{"overdraftLimit":<cents>}}),
  // the customer may now move that many cents MORE than they actually hold.
  const limits = {};
  const overdraft = limits.overdraftLimit || 0;
  if (fresh.balance_cents + overdraft < amount) throw new Error('insufficient funds');
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

// ---------------------------------------------------------------------------
// Two-step confirmation for large transfers. A customer initiates the transfer
// (which stages it as "pending"), then confirms it on a second page. VULN
// (Ch 21, multi-endpoint race): the CHECK ("is this still pending?") is on the
// confirm endpoint, the CHANGE (debit + mark executed) follows an async gap,
// and the two are not atomic -- so racing the confirm executes ONE authorised
// transfer many times.
//
// The fix: claim the row before moving money, e.g.
//   UPDATE pending_transfers SET status='executed' WHERE id=? AND status='pending'
// and only debit when changes===1.
router.post('/initiate', (req, res) => {
  const { from, to, amount, memo } = req.body;
  const cents = parseInt(amount, 10);
  const src = db.prepare('SELECT * FROM accounts WHERE account_number = ? AND user_id = ?')
    .get(from, req.session.userId);
  const dst = db.prepare('SELECT * FROM accounts WHERE account_number = ?').get(to);
  if (!src || !dst || !(cents > 0)) {
    return res.status(400).render('transfer', {
      accounts: db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.session.userId),
      error: 'check the source account (must be yours), destination and amount', ok: null
    });
  }
  const info = db.prepare(
    "INSERT INTO pending_transfers (user_id, from_account, to_account, amount_cents, memo, status) VALUES (?, ?, ?, ?, ?, 'pending')"
  ).run(req.session.userId, from, to, cents, memo || '');
  return res.redirect('/transfer/confirm/' + info.lastInsertRowid);
});

router.get('/confirm/:id', (req, res) => {
  const p = db.prepare('SELECT * FROM pending_transfers WHERE id = ? AND user_id = ?')
    .get(parseInt(req.params.id, 10), req.session.userId);
  if (!p) return res.redirect('/transfer');
  res.render('transfer_confirm', { p, error: null });
});

router.post('/confirm', async (req, res) => {
  const id = parseInt(req.body.id, 10);
  const p = db.prepare('SELECT * FROM pending_transfers WHERE id = ? AND user_id = ?')
    .get(id, req.session.userId);
  if (!p) return res.status(404).render('transfer', {
    accounts: db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.session.userId),
    error: 'no such pending transfer', ok: null
  });
  // VULN (time-of-check): is it still pending?
  if (p.status !== 'pending') {
    return res.redirect('/transfer?ok=1');
  }
  // VULN (race window): the confirmation/fraud round trip. Concurrent confirms
  // of the same pending row all passed the check above during this await.
  await sleep(200);
  // time-of-use: move the money and mark it done (non-atomic with the check).
  db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE account_number = ?')
    .run(p.amount_cents, p.from_account);
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE account_number = ?')
    .run(p.amount_cents, p.to_account);
  db.prepare('INSERT INTO transfers (from_account, to_account, amount_cents, memo) VALUES (?, ?, ?, ?)')
    .run(p.from_account, p.to_account, p.amount_cents, p.memo || 'confirmed');
  db.prepare("UPDATE pending_transfers SET status = 'executed' WHERE id = ?").run(id);
  return res.redirect('/transfer?ok=1');
});

module.exports = router;
