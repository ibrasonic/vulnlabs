// routes/profile.js — view/edit profile + webhook.
// VULNS: lodash.merge prototype pollution on PUT /profile (A08);
// stored XSS via display_name (rendered with <%- %>);
// open redirect on /go?u=...; SSRF on POST /webhooks.
const express = require('express');
const router = express.Router();
const _ = require('lodash');
const fetch = require('node-fetch');
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

// VULN: hand-rolled deep merge that walks `__proto__` (lodash 4.17.20+
// patched `_.merge` to skip it, so we use this to keep the lab reproducible).
function unsafeDeepMerge(target, source) {
  for (const key in source) {
    const sv = source[key];
    if (sv && typeof sv === 'object' && !Array.isArray(sv)) {
      if (target[key] === undefined || target[key] === null) target[key] = {};
      unsafeDeepMerge(target[key], sv);
    } else {
      target[key] = sv;
    }
  }
  return target;
}

router.get('/profile', requireSession, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  res.render('profile', { u, msg: req.query.msg || '', error: null });
});

// VULN: lodash.merge deep-merge with user-controlled keys -> prototype
// pollution. Setting `__proto__.isAdmin = true` flips a check elsewhere.
router.post('/profile', requireSession, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  let profile = {};
  try { profile = JSON.parse(u.profile_json || '{}'); } catch (e) {}
  // Body is form-urlencoded; "settings" is a JSON string.
  let incoming = {};
  try { incoming = JSON.parse(req.body.settings || '{}'); } catch (e) {
    return res.status(400).render('profile', { u, msg: '', error: 'invalid JSON' });
  }
  unsafeDeepMerge(profile, incoming);     // <-- the sink
  db.prepare('UPDATE users SET profile_json = ?, full_name = ?, phone = ?, address = ? WHERE id = ?')
    .run(JSON.stringify(profile),
         req.body.full_name || u.full_name,
         req.body.phone || u.phone,
         req.body.address || u.address,
         u.id);
  res.redirect('/profile?msg=' + encodeURIComponent('saved'));
});

// Used by the dashboard to demonstrate the pollution effect.
router.get('/profile/admin-check', requireSession, (req, res) => {
  const flag = {};                        // empty object — picks up polluted props
  res.json({
    isAdmin: flag.isAdmin === true,
    isPaidUser: flag.isPaidUser === true,
    overdraftLimit: flag.overdraftLimit || 0
  });
});

// VULN: open redirect — no validation of host (Ch 16, used in phishing chain).
router.get('/go', (req, res) => {
  const u = req.query.u || '/';
  return res.redirect(u);
});

// "Return to your bank" after visiting a partner site. VULN (Ch 22, open
// redirect via a naive allow-list): the developer tried to keep the target on
// the bank's own host by checking the URL merely CONTAINS the host string
// `localhost` (in production this would be the real domain, e.g. `novatrust.com`
// -- the bug is identical). A substring check is not host validation, so every
// classic bypass sails through:
//   http://localhost.evil.example/...     (attacker subdomain contains it)
//   http://evil.example/?ref=localhost    (it is in the path/query)
//   http://localhost@evil.example/        (userinfo, real host is evil.example)
//   http://localhost:3001@evil.example/   (same, with the port)
// The fix is to parse the URL and match the HOST against an exact allow-list,
// and to only ever redirect to a relative path that begins with a single '/'.
router.get('/return', (req, res) => {
  const to = String(req.query.to || '/');
  if (!/localhost/i.test(to)) {
    return res.status(400).type('text/plain').send('Only NovaTrust (localhost) destinations are allowed.');
  }
  return res.redirect(to);
});

// VULN: SSRF via webhook registration — server fetches the URL immediately
// to "validate" it. Includes the user's session cookie? No — but it does
// fetch internal addresses freely.
router.post('/webhooks', requireSession, async (req, res) => {
  const { url, event } = req.body;
  try {
    const r = await fetch(url, { method: 'GET', timeout: 5000 });
    const body = await r.text();
    db.prepare('INSERT INTO webhooks (user_id, url, event) VALUES (?, ?, ?)')
      .run(req.session.userId, url, event || 'transfer.completed');
    res.type('text/plain').send('registered. probe response:\n' + body.slice(0, 5000));
  } catch (e) {
    res.status(500).type('text/plain').send('probe failed: ' + e.message);
  }
});

module.exports = router;
