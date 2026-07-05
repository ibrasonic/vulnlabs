// routes/apiv2.js — "NovaTrust Partner API v2" (RS256 + JWKS).
// The verification logic lives in lib/jwt-lab.js and is deliberately
// vulnerable to jwk / jku / kid header injection and RS256<->HS256 algorithm
// confusion. These endpoints exist so those flaws can be reached and proven.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { md5 } = require('../lib/auth');
const { publicJwk, signV2, requireJwtV2 } = require('../lib/jwt-lab');

// Published key set — the PUBLIC half of the RS256 signing key. Handing this
// out is normal for RS256; it is only a problem because the verifier also
// accepts HS256 with this same key (algorithm confusion).
router.get('/.well-known/jwks.json', (req, res) => {
  res.json({ keys: [publicJwk()] });
});

// Partner API login — issues an RS256 access token.
router.post('/login', (req, res) => {
  const { username, password } = req.body || {};
  const user = db.prepare('SELECT * FROM users WHERE username = ? AND password_md5 = ?')
    .get(username || '', md5(password || ''));
  if (!user) return res.status(401).json({ error: 'invalid credentials' });
  const token = signV2({ sub: user.id, username: user.username, role: user.role });
  res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
});

// Whoami — protected by the (vulnerable) v2 verifier.
router.get('/me', requireJwtV2, (req, res) => {
  const u = db.prepare('SELECT id, username, email, role FROM users WHERE id = ?').get(req.jwt.sub);
  res.json({ token_claims: req.jwt, user: u });
});

// Admin-only partner report — authorises purely on the token's `role` claim,
// so forging role=admin in any of the four ways grants it.
router.get('/admin/report', requireJwtV2, (req, res) => {
  if (req.jwt.role !== 'admin') return res.status(403).json({ error: 'admin only' });
  res.json({
    ok: true,
    report: 'NovaTrust partner revenue 2026',
    users: db.prepare('SELECT id, username, email, role FROM users').all(),
  });
});

module.exports = router;
