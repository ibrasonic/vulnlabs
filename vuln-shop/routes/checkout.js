// routes/checkout.js — coupon application + place order.
// VULNS: coupon-code enumeration (no rate limit + low-entropy codes);
// IDOR via shipping override; race condition on stock decrement;
// allows negative-quantity items (refund-style abuse).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

router.get('/', (req, res) => {
  const cart = db.prepare('SELECT * FROM carts WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(req.session.userId);
  if (!cart) return res.redirect('/cart');
  const items = db.prepare(`
    SELECT cart_items.*, products.name FROM cart_items
    JOIN products ON products.id = cart_items.product_id WHERE cart_id = ?
  `).all(cart.id);
  const subtotal = items.reduce((s, i) => s + i.qty * i.price_cents, 0);
  res.render('checkout', { cart, items, subtotal, msg: req.query.msg || '', error: null });
});

// VULN: coupon code lookup is direct equality; no rate limit on attempts.
// Combined with low-entropy codes (STAFF50, SUMMER25) makes brute force cheap.
// VULN (Ch 21, single-endpoint race): only ONE coupon is allowed per order,
// but the "already has a coupon?" check and the insert are non-atomic with an
// async gap between them, so racing two DIFFERENT codes lets both attach and
// their discounts stack (e.g. SUMMER25 + STAFF50 = 75% off).
router.post('/apply-coupon', async (req, res) => {
  const code = (req.body.code || '').trim().toUpperCase();
  const c = db.prepare('SELECT * FROM coupons WHERE code = ?').get(code);
  if (!c) {
    // VULN: distinguishable response — coupon enumeration
    return res.status(404).json({ ok: false, error: 'unknown coupon' });
  }
  const cart = db.prepare('SELECT * FROM carts WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(req.session.userId);
  if (!cart) return res.status(400).json({ ok: false, error: 'no cart' });

  // VULN (time-of-check): one coupon per order.
  const already = db.prepare('SELECT COUNT(*) AS n FROM cart_coupons WHERE cart_id = ?').get(cart.id).n;
  if (already >= 1) return res.status(409).json({ ok: false, error: 'one coupon per order' });

  // VULN (race window): the loyalty/pricing-service round trip. Concurrent
  // applies of different codes all passed the check above during this await.
  await new Promise(r => setTimeout(r, 150));

  // time-of-use: attach the coupon (no re-check).
  db.prepare('INSERT INTO cart_coupons (cart_id, code, percent_off) VALUES (?, ?, ?)').run(cart.id, c.code, c.percent_off);
  const stacked = db.prepare('SELECT COALESCE(SUM(percent_off),0) AS s FROM cart_coupons WHERE cart_id = ?').get(cart.id).s;
  return res.json({ ok: true, code: c.code, percent_off: c.percent_off, stacked_total: Math.min(stacked, 90) });
});

// Place order — pays from credits (no real payment).
router.post('/place', async (req, res) => {
  const cart = db.prepare('SELECT * FROM carts WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(req.session.userId);
  if (!cart) return res.status(400).send('no cart');
  const items = db.prepare(`
    SELECT cart_items.*, products.name, products.stock FROM cart_items
    JOIN products ON products.id = cart_items.product_id WHERE cart_id = ?
  `).all(cart.id);
  if (!items.length) return res.status(400).send('empty cart');

  // VULN: artificial delay between stock check and decrement -> race condition
  let total = 0;
  for (const it of items) {
    // VULN: doesn't reject negative qty
    total += it.qty * it.price_cents;
  }
  // Stacked coupons attached to this cart (see the /apply-coupon race): sum
  // their percent_off, capped at 90%.
  const applied = db.prepare('SELECT code, percent_off FROM cart_coupons WHERE cart_id = ?').all(cart.id);
  const pct = Math.min(90, applied.reduce((s, c) => s + c.percent_off, 0));
  total = Math.max(0, Math.floor(total * (100 - pct) / 100));
  const couponLabel = applied.map(c => c.code).join('+') || null;

  // Race window
  await new Promise(r => setTimeout(r, 40));

  // VULN: doesn't atomically check + decrement stock
  for (const it of items) {
    db.prepare('UPDATE products SET stock = stock - ? WHERE id = ?').run(it.qty, it.product_id);
  }

  // VULN: shipping_address from body, no validation; rendered raw in admin
  const shipping = req.body.shipping_address || 'unspecified';
  const r = db.prepare(`
    INSERT INTO orders (user_id, total_cents, coupon, status, shipping_address)
    VALUES (?, ?, ?, 'placed', ?)
  `).run(req.session.userId, total, couponLabel, shipping);
  const orderId = r.lastInsertRowid;
  for (const it of items) {
    db.prepare('INSERT INTO order_items (order_id, product_id, qty, price_cents) VALUES (?, ?, ?, ?)')
      .run(orderId, it.product_id, it.qty, it.price_cents);
  }
  // Clear cart
  db.prepare('DELETE FROM cart_items WHERE cart_id = ?').run(cart.id);
  db.prepare('DELETE FROM cart_coupons WHERE cart_id = ?').run(cart.id);
  req.session.coupon = null;
  req.session.couponPct = 0;

  res.redirect('/orders/' + orderId);
});

module.exports = router;
