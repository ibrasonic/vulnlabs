// routes/profile.js — profile view + edit (prototype-pollution sink).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

function unsafeDeepMerge(target, source) {  // VULN: walks __proto__
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

// Public profile by username.  bio rendered with <%- %> -> stored XSS.
router.get('/u/:name', (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE username = ?').get(req.params.name);
  if (!u) return res.status(404).send('no such user');
  const posts = db.prepare(`
    SELECT p.*, u.username, u.display_name, u.avatar FROM posts p
    JOIN users u ON u.id = p.user_id WHERE p.user_id = ? ORDER BY p.id DESC LIMIT 50
  `).all(u.id);
  const followers = db.prepare(`SELECT COUNT(*) AS c FROM follows WHERE followee_id = ?`).get(u.id).c;
  const following = db.prepare(`SELECT COUNT(*) AS c FROM follows WHERE follower_id = ?`).get(u.id).c;
  res.render('user_profile', { u, posts, followers, following });
});

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
  db.prepare(`UPDATE users SET profile_json = ?, display_name = ?, bio = ?, avatar = ? WHERE id = ?`)
    .run(JSON.stringify(profile),
         req.body.display_name || u.display_name,
         req.body.bio !== undefined ? req.body.bio : u.bio,
         req.body.avatar || u.avatar,
         u.id);
  res.redirect('/profile?msg=saved');
});

router.get('/profile/perks-check', requireSession, (req, res) => {
  const f = {};
  res.json({
    isAdmin: f.isAdmin === true,
    isPremium: f.isPremium === true,
    canBroadcast: f.canBroadcast === true,
    creditMultiplier: f.creditMultiplier || 1
  });
});

// VULN: avatar fetch path-joins `name` without sanitisation -> LFI.
const fs = require('fs');
const path = require('path');
router.get('/avatars/:name', (req, res) => {
  const root = path.join(__dirname, '..', 'public', 'img', 'avatars');
  const fp = path.join(root, req.params.name);
  try {
    const buf = fs.readFileSync(fp);
    if (fp.endsWith('.svg')) res.set('Content-Type', 'image/svg+xml');
    res.send(buf);
  } catch (e) {
    res.status(404).type('text/plain').send('avatar not found: ' + e.message);
  }
});

// VULN: open redirect /go?u=
router.get('/go', (req, res) => res.redirect(req.query.u || '/'));

module.exports = router;
