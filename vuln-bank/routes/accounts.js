// routes/accounts.js — list and view accounts.
// VULNS: IDOR on /accounts/:id (no ownership check); reflected XSS via ?msg=.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

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
