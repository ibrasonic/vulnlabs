// routes/api.js — JSON API with JWT auth.
// VULNS: JWT accepts alg=none (lib/auth.js); BOLA / IDOR (any token can read
// any user's accounts via /api/users/:id); CORS wide open; no rate limit;
// excessive data exposure (returns SSN, password_md5).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireJwt } = require('../lib/auth');

// VULN: CORS — Origin reflected, credentials allowed (Ch 17).
router.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

router.get('/me', requireJwt, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.jwt.sub);
  res.json(u);   // VULN: returns the whole row including SSN + password_md5
});

// VULN: BOLA — any authenticated user can read any other user (Ch 32 API1).
router.get('/users/:id', requireJwt, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

// Same BOLA on accounts and transfers.
router.get('/accounts/:id', requireJwt, (req, res) => {
  res.json(db.prepare('SELECT * FROM accounts WHERE id = ?').get(req.params.id) || null);
});

router.get('/accounts/:id/transfers', requireJwt, (req, res) => {
  const acct = db.prepare('SELECT account_number FROM accounts WHERE id = ?').get(req.params.id);
  if (!acct) return res.json([]);
  res.json(db.prepare(`
    SELECT * FROM transfers WHERE from_account = ? OR to_account = ?
    ORDER BY created_at DESC LIMIT 50
  `).all(acct.account_number, acct.account_number));
});

// VULN: mass assignment on profile update — every field accepted, role included.
router.put('/users/:id', requireJwt, express.json(), (req, res) => {
  const id = parseInt(req.params.id, 10);
  // Note: no `if (id === req.jwt.sub)` ownership check.
  const fields = ['email', 'full_name', 'phone', 'address', 'role', 'mfa_enabled'];
  const updates = [];
  const values = [];
  for (const f of fields) {
    if (f in req.body) { updates.push(`${f} = ?`); values.push(req.body[f]); }
  }
  if (!updates.length) return res.status(400).json({ error: 'no fields' });
  values.push(id);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(id));
});

// Versioned endpoint — VULN: /api/v1/users skips auth entirely (Ch 32 API9).
router.get('/v1/users', (req, res) => {
  res.json(db.prepare('SELECT id, username, email, role FROM users').all());
});

module.exports = router;
