// routes/mobile.js — "NovaTrust Mobile & Partner API" surface.
//
// This is the UI entry point for the RS256 Partner API v2 (lib/jwt-lab.js +
// routes/apiv2.js). Business story: NovaTrust customers use a mobile app, and
// fintech partners integrate through the Partner API. The mobile *web*
// dashboard is a small SPA that bootstraps an RS256 access token from the
// browser session and then calls /api/v2/* to render — exactly how a real
// bank's SPA / mobile front-end talks to its own API.
//
// Why it matters for the lab (Chapter 18): opening /mobile after login makes
// the browser send  Authorization: Bearer <RS256 JWT>  to /api/v2/me, so the
// token and the JWKS lookup appear in Reqlore's History with NO prior
// knowledge — the JWT attack surface is now discoverable by browsing, not by
// being told the endpoints exist.
const express = require('express');
const router = express.Router();
const { requireSession } = require('../lib/auth');
const { signV2 } = require('../lib/jwt-lab');

// The Mobile & Developer dashboard page.
router.get('/', requireSession, (req, res) => {
  res.render('mobile', { title: 'Mobile & Partner API' });
});

// Session -> RS256 API token bridge. A logged-in web session exchanges itself
// for a Partner API v2 access token — the way a bank's SPA / mobile web
// front-end bootstraps a Bearer for its API calls. No password is needed
// because the browser session already proves who you are.
router.get('/token', requireSession, (req, res) => {
  const token = signV2({
    sub: req.session.userId,
    username: req.session.username,
    role: req.session.role,
  });
  res.json({ access_token: token, token_type: 'Bearer', expires_in: 3600 });
});

module.exports = router;
