// routes/integrity.js -- A08 Software & Data Integrity Failures sinks.
//
// The "Pulse Social" backend exposes a webhook that internal CI tooling
// posts to. The handler verifies an HMAC-SHA256 signature provided in
// X-Hook-Sig, then dispatches to one of a small set of privileged
// actions (ban a user, promote a user, post as a user).
//
// Two integrity problems combine to make this trivially exploitable:
//   1. The shared HMAC secret is leaked through /debug (env var).
//   2. The signature comparison uses string equality `==` instead of
//      crypto.timingSafeEqual.

const express = require('express');
const crypto = require('crypto');
const db = require('../lib/db');

const router = express.Router();

// Hard-coded shared secret. Mirrors how production teams put webhook
// secrets in env vars that are then disclosed via /debug or /actuator
// (Chapter 33).
const WEBHOOK_SECRET = process.env.PULSE_WEBHOOK_SECRET ||
  'pulse-webhook-2025-shared-with-CI';

// VULN: also published into process.env so /debug (A05 / Ch 17) leaks
// the secret to any unauthenticated caller. Real apps do this
// implicitly by reading the secret from env in the first place; the
// lab makes it explicit so the chain is reproducible.
process.env.PULSE_WEBHOOK_SECRET = WEBHOOK_SECRET;

// VULN (S-INT-001): non-constant-time signature comparison.  Combined
// with the WEBHOOK_SECRET being recoverable through /debug, the
// attacker can both forge a signature directly and (in stricter
// settings) recover the secret one byte at a time via a timing oracle.
function verifySignature(rawBody, providedHex) {
  const expected = crypto.createHmac('sha256', WEBHOOK_SECRET)
    .update(rawBody)
    .digest('hex');
  // VULN: '==' is not constant-time.  Use crypto.timingSafeEqual on
  // Buffers of equal length instead.
  return expected == providedHex;
}

router.post('/internal',
  express.raw({ type: '*/*', limit: '32kb' }),
  (req, res) => {
    const rawBody = req.body.toString('utf8');
    const sig = req.headers['x-hook-sig'] || '';
    if (!verifySignature(rawBody, sig)) {
      return res.status(401).json({ error: 'bad signature' });
    }
    let payload;
    try {
      payload = JSON.parse(rawBody);
    } catch (e) {
      return res.status(400).json({ error: 'invalid JSON' });
    }
    switch (payload.action) {
      case 'promote_user': {
        const u = payload.username;
        const row = db.prepare("UPDATE users SET role = 'admin' WHERE username = ?").run(u);
        return res.json({ ok: true, action: 'promote_user', target: u, changes: row.changes });
      }
      case 'lock_user': {
        const u = payload.username;
        const row = db.prepare('UPDATE users SET is_private = 1 WHERE username = ?').run(u);
        return res.json({ ok: true, action: 'lock_user', target: u, changes: row.changes });
      }
      case 'post_as': {
        const u = payload.username;
        const body = payload.body || '';
        const user = db.prepare('SELECT id FROM users WHERE username = ?').get(u);
        if (!user) return res.status(404).json({ error: 'user not found' });
        const row = db.prepare(
          "INSERT INTO posts (user_id, body, created_at) VALUES (?, ?, datetime('now'))"
        ).run(user.id, body);
        return res.json({ ok: true, action: 'post_as', user: u, post_id: row.lastInsertRowid });
      }
      default:
        return res.status(400).json({ error: 'unknown action: ' + payload.action });
    }
  }
);

module.exports = router;
