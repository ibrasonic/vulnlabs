// routes/broadcast.js — platform broadcast / post boost (Ch23 prototype-pollution gadget).
//
// VULN (A08 prototype-pollution GADGET with REAL impact): whether a user may
// broadcast to the whole platform, and how far the post reaches, are read off a
// FRESH {} with no own-property check, so they resolve through Object.prototype.
// Un-polluted, `canBroadcast` is undefined -> false (regular users are blocked,
// 403) and `creditMultiplier` is undefined -> 1 (base reach). Once a user pollutes
// the prototype via POST /profile:
//     settings = {"__proto__":{"canBroadcast":true,"creditMultiplier":50}}
// a plain account can post a platform-wide broadcast (a Premium-only action) with
// an amplified reach. Broadcasts live in their own table, so nothing here can
// affect another chapter's data.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

const BASE_REACH = 1000;   // followers reached by a base broadcast

router.get('/', requireSession, (req, res) => {
  const perks = {};                             // <-- fresh object; reads Object.prototype
  const canBroadcast = perks.canBroadcast === true;
  const rows = db.prepare(`
    SELECT b.body, b.reach, b.created_at, u.username
    FROM broadcasts b JOIN users u ON u.id = b.user_id
    ORDER BY b.id DESC LIMIT 20
  `).all();
  res.render('broadcast', { canBroadcast, rows, error: req.query.error || '', msg: req.query.msg || '' });
});

router.post('/', requireSession, (req, res) => {
  const perks = {};                             // <-- fresh object; reads Object.prototype
  if (perks.canBroadcast !== true) {
    return res.status(403).render('broadcast', {
      canBroadcast: false,
      rows: db.prepare(`SELECT b.body, b.reach, b.created_at, u.username
                        FROM broadcasts b JOIN users u ON u.id = b.user_id
                        ORDER BY b.id DESC LIMIT 20`).all(),
      error: 'Broadcasting to the whole platform is a Premium (verified) feature.',
      msg: ''
    });
  }
  const multiplier = perks.creditMultiplier || 1;   // reach amplifier; normally 1
  const reach = BASE_REACH * multiplier;
  const body = String(req.body.body || '').slice(0, 280);
  db.prepare('INSERT INTO broadcasts (user_id, body, reach) VALUES (?, ?, ?)')
    .run(req.session.userId, body, reach);
  res.redirect('/broadcast?msg=' + encodeURIComponent('Broadcast sent to ' + reach.toLocaleString() + ' accounts.'));
});

module.exports = router;
