// routes/connected.js — "Connected apps & API access" (Open Banking style).
//
// The bank's own web front-end is API-backed: it obtains a short-lived RS256
// access token for the logged-in session (GET /connected/token) and calls the
// NovaTrust API (routes/apiv2.js, verified by lib/jwt-lab.js) to render. The
// account dashboard uses this on load, so a normal sign-in already sends
// `Authorization: Bearer <RS256 JWT>` to /api/v2/me. Under Settings, customers
// can also review the third-party apps connected to their account and copy
// their personal API token.
//
// Why it matters for the lab (Chapter 18): the RS256 JWT attack surface is
// discoverable by simply using the app — the Bearer and the JWKS lookup land
// in Reqlore's History with no prior knowledge of the endpoints. The
// admin/partner endpoint (/api/v2/admin/report) is NOT advertised here; it is
// found by enumerating /api/v2/* (improper inventory, [30]).
const express = require('express');
const router = express.Router();
const { requireSession } = require('../lib/auth');
const { signV2 } = require('../lib/jwt-lab');

// Session -> RS256 API token bridge. The web front-end exchanges the logged-in
// session for a NovaTrust API access token. No password is needed because the
// browser session already proves who you are. Used by the account dashboard
// and by the Connected-apps page below.
router.get('/token', requireSession, (req, res) => {
  const token = signV2({
    sub: req.session.userId,
    username: req.session.username,
    role: req.session.role,
  });
  res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
});

// Settings -> "Connected apps & API access".
router.get('/', requireSession, (req, res) => {
  res.render('connected', { title: 'Connected apps & API access' });
});

module.exports = router;
