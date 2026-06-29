// routes/api.js - small JSON surface used by the SPA fragments and by the
// "preview / share" feature that reflects request headers back to the
// caller. The header echo is the disclosure sink for smuggling reveal.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');

router.get('/articles', (req, res) => {
  const rows = db.prepare(`
    SELECT id, slug, title, deck, category, status, paywall, published_at
    FROM articles WHERE status = 'published' ORDER BY published_at DESC LIMIT 30
  `).all();
  res.json(rows);
});

router.get('/me', (req, res) => {
  if (!req.session || !req.session.userId) return res.json({ user: null });
  res.json({
    user: {
      id: req.session.userId, username: req.session.username,
      display: req.session.display, tier: req.session.tier
    }
  });
});

// /api/echo reflects ALL inbound headers and body. It exists so authors can
// preview how their request looks in shares. When a smuggled request lands
// here it discloses what the gateway is silently adding to upstream traffic
// (X-Forwarded-For, X-Internal-Auth, X-User-Tier, X-Request-ID, etc.).
router.all('/echo', (req, res) => {
  let body = '';
  req.on('data', (c) => { body += c.toString('utf8'); });
  req.on('end', () => {
    res.json({
      method: req.method, path: req.originalUrl,
      headers: req.headers,
      body: body.slice(0, 4000)
    });
  });
});

router.get('/health', (req, res) => res.type('text').send('ok\n'));

module.exports = router;
