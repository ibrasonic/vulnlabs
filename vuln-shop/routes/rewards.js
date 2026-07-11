// routes/rewards.js — store-credit rewards wallet (Ch23 prototype-pollution gadget).
//
// VULN (A08 prototype-pollution GADGET with REAL impact): the reward multiplier
// and the free-shipping perk are read off a FRESH {} with no own-property check,
// so they resolve through Object.prototype. Un-polluted, `creditMultiplier` is
// undefined -> 1 and `freeShipping` is undefined -> false, so the feature behaves
// normally (a $5 welcome reward, shipping charged). Once a customer pollutes the
// prototype via POST /profile:
//     settings = {"__proto__":{"creditMultiplier":100,"freeShipping":true}}
// every claim mints 100x store credit and shipping shows FREE for everyone in the
// process. The wallet lives in its own table (reward_wallet), so nothing here can
// affect another chapter's data.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

const WELCOME_CENTS = 500;   // $5.00 base welcome reward
const SHIP_CENTS = 599;      // $5.99 standard shipping

function walletOf(userId) {
  const row = db.prepare('SELECT credit_cents FROM reward_wallet WHERE user_id = ?').get(userId);
  return row ? row.credit_cents : 0;
}

router.get('/', requireSession, (req, res) => {
  const perks = {};                              // <-- fresh object; reads Object.prototype
  const freeShipping = perks.freeShipping === true;
  res.render('rewards', {
    balance: walletOf(req.session.userId),
    shipping: freeShipping ? 0 : SHIP_CENTS,
    freeShipping,
    msg: req.query.msg || ''
  });
});

router.post('/claim', requireSession, (req, res) => {
  const perks = {};                              // <-- fresh object; reads Object.prototype
  const multiplier = perks.creditMultiplier || 1;   // normally 1; polluted -> big
  const add = WELCOME_CENTS * multiplier;
  db.prepare(`INSERT INTO reward_wallet (user_id, credit_cents) VALUES (?, ?)
              ON CONFLICT(user_id) DO UPDATE SET credit_cents = credit_cents + ?`)
    .run(req.session.userId, add, add);
  const msg = 'Added $' + (add / 100).toFixed(2) + ' store credit (x' + multiplier + ' multiplier).';
  res.redirect('/rewards?msg=' + encodeURIComponent(msg));
});

module.exports = router;
