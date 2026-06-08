// routes/proxy.js — image proxy (SSRF sink).
const express = require('express');
const router = express.Router();
const fetch = require('node-fetch');

// VULN: classic SSRF proxy — no allowlist, no IP filtering.
// /proxy/image?u=http://internal:port/path
router.get('/image', async (req, res) => {
  const u = req.query.u;
  if (!u) return res.status(400).send('missing u');
  try {
    const r = await fetch(u, { timeout: 5000 });
    const buf = await r.buffer();
    res.set('Content-Type', r.headers.get('content-type') || 'application/octet-stream');
    res.send(buf);
  } catch (e) {
    res.status(502).send('proxy failed: ' + e.message);
  }
});

module.exports = router;
