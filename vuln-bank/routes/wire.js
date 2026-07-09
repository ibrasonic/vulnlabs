// routes/wire.js — international wire wizard: draft -> compliance review ->
// execute. Each step is individually guarded, but the ORDER of the steps is
// not enforced.
//
// VULN (Ch 21, hidden multi-step race): a wire over the daily limit is supposed
// to be stopped at the review step (status -> 'blocked'), and execute refuses a
// blocked wire. But racing /wire/execute against /wire/review lets execute read
// the still-'draft' status during review's compliance round trip -- so the
// over-limit wire executes before the block is written, skipping the gate.
//
// The fix: make execute require the POSITIVE state it depends on
// (status === 'reviewed') and set it atomically, e.g.
//   UPDATE wires SET status='executing' WHERE id=? AND status='reviewed'
// and move money only when changes===1.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

const DAILY_LIMIT_CENTS = 1000000; // $10,000 compliance threshold
function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

router.use(requireSession);

router.get('/', (req, res) => {
  const accts = db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.session.userId);
  res.render('wire', { accounts: accts, error: null });
});

// Step 1 — stage a draft.
router.post('/draft', (req, res) => {
  const { from, to, amount } = req.body;
  const cents = parseInt(amount, 10);
  const src = db.prepare('SELECT * FROM accounts WHERE account_number = ? AND user_id = ?')
    .get(from, req.session.userId);
  if (!src || !to || !(cents > 0)) {
    return res.status(400).render('wire', {
      accounts: db.prepare('SELECT * FROM accounts WHERE user_id = ?').all(req.session.userId),
      error: 'check the source account (must be yours), destination and amount',
    });
  }
  const info = db.prepare(
    "INSERT INTO wires (user_id, from_account, to_account, amount_cents, status) VALUES (?, ?, ?, ?, 'draft')"
  ).run(req.session.userId, from, to, cents);
  return res.redirect('/wire/' + info.lastInsertRowid);
});

router.get('/:id', (req, res) => {
  const w = db.prepare('SELECT * FROM wires WHERE id = ? AND user_id = ?')
    .get(parseInt(req.params.id, 10), req.session.userId);
  if (!w) return res.redirect('/wire');
  res.render('wire_detail', { w, limit: DAILY_LIMIT_CENTS });
});

// Step 2 — compliance review. Blocks wires over the daily limit.
router.post('/review', async (req, res) => {
  const id = parseInt(req.body.id, 10);
  const w = db.prepare('SELECT * FROM wires WHERE id = ? AND user_id = ?').get(id, req.session.userId);
  if (!w) return res.status(404).redirect('/wire');
  // VULN (race window): the compliance-provider round trip. During this gap a
  // raced execute reads the still-'draft' status.
  await sleep(200);
  const verdict = w.amount_cents > DAILY_LIMIT_CENTS ? 'blocked' : 'reviewed';
  db.prepare('UPDATE wires SET status = ? WHERE id = ?').run(verdict, id);
  return res.redirect('/wire/' + id);
});

// Step 3 — execute. Refuses a blocked wire, but does NOT require that review
// has run at all -- so racing it past review skips the compliance block.
router.post('/execute', async (req, res) => {
  const id = parseInt(req.body.id, 10);
  const w = db.prepare('SELECT * FROM wires WHERE id = ? AND user_id = ?').get(id, req.session.userId);
  if (!w) return res.status(404).redirect('/wire');
  // VULN (time-of-check): only blocks an ALREADY-blocked wire; a 'draft' wire
  // (review not finished) sails through.
  if (w.status === 'blocked') return res.redirect('/wire/' + id);
  if (w.status === 'executed') return res.redirect('/wire/' + id);
  // VULN (race window): the settlement round trip.
  await sleep(200);
  db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE account_number = ?')
    .run(w.amount_cents, w.from_account);
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE account_number = ?')
    .run(w.amount_cents, w.to_account);
  db.prepare('INSERT INTO transfers (from_account, to_account, amount_cents, memo) VALUES (?, ?, ?, ?)')
    .run(w.from_account, w.to_account, w.amount_cents, 'wire ' + id);
  db.prepare("UPDATE wires SET status = 'executed' WHERE id = ?").run(id);
  return res.redirect('/wire/' + id);
});

module.exports = router;
