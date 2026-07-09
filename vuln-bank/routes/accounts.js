// routes/accounts.js — list and view accounts.
// VULNS: IDOR on /accounts/:id (no ownership check); reflected XSS via ?msg=.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

function sleep(ms) { return new Promise((r) => setTimeout(r, ms)); }

// VULN (Ch 21, partial-construction race): open a savings account with a one-
// time $100 welcome bonus. The handler CHECKS whether the customer has already
// claimed a bonus, waits (KYC/provisioning), and only THEN builds the account
// with the $100 inside and records the claim. The check and the claim straddle
// the gap, so concurrent opens all read "not yet claimed" and each builds a
// bonus-laden account -- the objects are constructed before the guard that was
// supposed to make the bonus one-per-customer is written.
//
// The fix: claim first, atomically -- INSERT welcome_bonus_claims (UNIQUE
// user_id) and credit the $100 only when that insert succeeds; otherwise open a
// $0 account.
router.post('/open', async (req, res) => {
  const uid = req.session.userId;
  const num = '4002-7' + String(Math.floor(Math.random() * 900) + 100) +
              '-' + String(Math.floor(Math.random() * 9000) + 1000);
  // time-of-check: has this customer already had a welcome bonus?
  const claimed = db.prepare('SELECT 1 AS ok FROM welcome_bonus_claims WHERE user_id = ?').get(uid);
  if (claimed) {
    db.prepare("INSERT INTO accounts (user_id, account_number, account_type, balance_cents) VALUES (?, ?, 'savings', 0)").run(uid, num);
    return res.redirect('/accounts?msg=' + encodeURIComponent('Opened ' + num + ' (no bonus \u2014 already claimed)'));
  }
  // VULN (race window): the KYC / provisioning round trip. Concurrent opens all
  // passed the "not claimed" check above during this await.
  await sleep(200);
  // time-of-use: build the account WITH the bonus and record the claim.
  db.prepare("INSERT INTO accounts (user_id, account_number, account_type, balance_cents) VALUES (?, ?, 'savings', 10000)").run(uid, num);
  try { db.prepare('INSERT INTO welcome_bonus_claims (user_id) VALUES (?)').run(uid); } catch (e) { /* unique race */ }
  return res.redirect('/accounts?msg=' + encodeURIComponent('Opened ' + num + ' with a $100 welcome bonus'));
});

router.get('/', (req, res) => {
  const accts = db.prepare('SELECT * FROM accounts WHERE user_id = ? ORDER BY id').all(req.session.userId);
  // VULN: reflected XSS in a URL (href) context. `?payto=` is dropped
  // straight into an <a href="…"> with no scheme validation, so a
  // `javascript:` URL executes when the “resume payment” link is followed.
  res.render('accounts', { accounts: accts, msg: req.query.msg || '', payto: req.query.payto || '' });
});

// Search — VULNs: SQLi via concatenated LIKE, reflected XSS in element body,
// reflected XSS in attribute context, plus an optional naive blacklist filter
// (?strict=1) that strips literal <script> tags but is bypassable by every
// non-<script> payload family.
// IMPORTANT: must be registered before `/:id` or Express matches
// `/search` against the param route.
router.get('/search', (req, res) => {
  const rawQ = req.query.q || '';
  // ?strict=1 toggles a naive single-pass <script> blacklist. The filter is
  // case-insensitive but only matches the literal <script>...</script>
  // shape; <svg onload>, <img onerror>, and nested tags survive trivially.
  const strictMode = req.query.strict === '1';
  const q = strictMode ? rawQ.replace(/<script[^>]*>.*?<\/script>/gi, '') : rawQ;
  try {
    const rows = db.prepare(`
      SELECT account_number, full_name, balance_cents
      FROM accounts JOIN users ON users.id = accounts.user_id
      WHERE full_name LIKE '%${q}%' OR account_number LIKE '%${q}%'
    `).all();
    res.render('account_search', { rows, q, strictMode, error: null });
  } catch (e) {
    res.status(500).render('account_search', { rows: [], q, strictMode, error: e.message });
  }
});

// VULN: IDOR — no `WHERE user_id = ?` filter (A01, Ch 11).
router.get('/:id', (req, res) => {
  const acct = db.prepare('SELECT * FROM accounts WHERE id = ?').get(req.params.id);
  if (!acct) return res.status(404).send('not found');
  // Fetch recent activity for *this* account (also unowned).
  const tx = db.prepare(`
    SELECT * FROM transfers
    WHERE from_account = ? OR to_account = ?
    ORDER BY created_at DESC LIMIT 25
  `).all(acct.account_number, acct.account_number);
  const owner = db.prepare('SELECT username, full_name FROM users WHERE id = ?').get(acct.user_id);
  res.render('account_detail', { acct, tx, owner });
});

module.exports = router;
