// routes/profile.js — profile view/edit with deep-merge sink.
const express = require('express');
const router = express.Router();
const fetch = require('node-fetch');
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

// VULN: hand-rolled deep merge walks __proto__ — prototype pollution sink.
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

router.post('/profile', requireSession, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  let profile = {};
  try { profile = JSON.parse(u.profile_json || '{}'); } catch (e) {}
  let incoming = {};
  try { incoming = JSON.parse(req.body.settings || '{}'); } catch (e) {
    return res.status(400).render('profile', { u, msg: '', error: 'invalid JSON' });
  }
  unsafeDeepMerge(profile, incoming);
  db.prepare('UPDATE users SET profile_json = ?, full_name = ?, address = ? WHERE id = ?')
    .run(JSON.stringify(profile), req.body.full_name || u.full_name, req.body.address || u.address, u.id);
  res.redirect('/profile?msg=saved');
});

router.get('/profile/perks-check', requireSession, (req, res) => {
  const flag = {};
  res.json({
    isAdmin: flag.isAdmin === true,
    isVip:   flag.isVip === true,
    freeShipping: flag.freeShipping === true,
    creditMultiplier: flag.creditMultiplier || 1
  });
});

// VULN: open redirect /go?u=
router.get('/go', (req, res) => res.redirect(req.query.u || '/'));

module.exports = router;
