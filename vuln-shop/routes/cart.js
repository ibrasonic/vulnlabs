// routes/cart.js — shopping cart with deliberate price tampering and IDOR.
const express = require('express');
const router = express.Router();
const serialize = require('node-serialize');
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

function getOrCreateCart(userId) {
  let cart = db.prepare('SELECT * FROM carts WHERE user_id = ? ORDER BY id DESC LIMIT 1').get(userId);
  if (!cart) {
    const r = db.prepare('INSERT INTO carts (user_id) VALUES (?)').run(userId);
    cart = { id: r.lastInsertRowid, user_id: userId };
  }
  return cart;
}

router.use(requireSession);

router.get('/', (req, res) => {
  const cart = getOrCreateCart(req.session.userId);
  const items = db.prepare(`
    SELECT cart_items.*, products.name, products.sku, products.image_url
    FROM cart_items JOIN products ON products.id = cart_items.product_id
    WHERE cart_id = ?
  `).all(cart.id);
  const total = items.reduce((s, i) => s + i.qty * i.price_cents, 0);
  res.render('cart', { cart, items, total, msg: req.query.msg || '' });
});

// VULN: client-supplied price! Adds with whatever price_cents the form posts.
router.post('/add', (req, res) => {
  const cart = getOrCreateCart(req.session.userId);
  const productId = parseInt(req.body.product_id, 10);
  const qty = Math.max(1, parseInt(req.body.qty || '1', 10));
  const product = db.prepare('SELECT * FROM products WHERE id = ?').get(productId);
  if (!product) return res.status(404).send('no product');
  // VULN: price_cents from request body — should come from product.
  const price = req.body.price_cents !== undefined ? parseInt(req.body.price_cents, 10) : product.price_cents;
  db.prepare('INSERT INTO cart_items (cart_id, product_id, qty, price_cents) VALUES (?, ?, ?, ?)')
    .run(cart.id, productId, qty, price);
  res.redirect('/cart?msg=added');
});

// "Shareable cart" feature (registered BEFORE /:id so /export and /import work).
// VULN: cart token is node-serialize.serialize(...) base64; import deserialises
// untrusted bytes via node-serialize.unserialize() -> CVE-2017-5941 RCE.
// Trigger payload value:   _$$ND_FUNC$$_function(){...}()
// The IIFE suffix `()` causes eval at deserialise time.
router.get('/export', (req, res) => {
  const cart = getOrCreateCart(req.session.userId);
  const items = db.prepare(`
    SELECT cart_items.product_id, cart_items.qty, cart_items.price_cents,
           products.name, products.sku
    FROM cart_items JOIN products ON products.id = cart_items.product_id
    WHERE cart_id = ?
  `).all(cart.id);
  const payload = {
    v: 1,
    owner_id: req.session.userId,
    owner_username: req.session.username,
    exported_at: Date.now(),
    note: 'Northwind Outfitters portable cart - paste at /cart/import to restore.',
    items
  };
  const token = Buffer.from(serialize.serialize(payload), 'utf8').toString('base64');
  res.render('cart_export', { token, count: items.length });
});

router.get('/import', (req, res) => {
  res.render('cart_import', { error: req.query.err || '', preview: null });
});

router.post('/import', (req, res) => {
  const tok = (req.body.token || '').trim();
  if (!tok) return res.render('cart_import', { error: 'paste a token first', preview: null });
  let raw, payload;
  try {
    raw = Buffer.from(tok, 'base64').toString('utf8');
  } catch (e) {
    return res.render('cart_import', { error: 'base64 decode failed: ' + e.message, preview: null });
  }
  try {
    // VULN: untrusted bytes -> node-serialize.unserialize -> eval of any
    // value of the form "_$$ND_FUNC$$_<fn>()". CVE-2017-5941.
    payload = serialize.unserialize(raw);
  } catch (e) {
    return res.render('cart_import', { error: 'token parse error: ' + e.message, preview: null });
  }
  if (!payload || typeof payload !== 'object' || !Array.isArray(payload.items)) {
    return res.render('cart_import', { error: 'token has no items', preview: payload });
  }
  // VULN: owner_id is trusted from the token itself, not the session, so an
  // attacker can append items to another user's cart by forging the field.
  const targetUser = parseInt(payload.owner_id, 10) || req.session.userId;
  const cart = getOrCreateCart(targetUser);
  for (const it of payload.items) {
    const pid = parseInt(it.product_id, 10);
    if (!pid) continue;
    const qty = Math.max(1, parseInt(it.qty, 10) || 1);
    // VULN: price_cents from the token is honoured (chains with V-SHOP-050).
    const price = parseInt(it.price_cents, 10) || 0;
    db.prepare('INSERT INTO cart_items (cart_id, product_id, qty, price_cents) VALUES (?, ?, ?, ?)')
      .run(cart.id, pid, qty, price);
  }
  res.redirect('/cart?msg=imported');
});

// VULN: IDOR — cart_id taken from path, no ownership check.
router.get('/:id', (req, res) => {
  const cart = db.prepare('SELECT * FROM carts WHERE id = ?').get(req.params.id);
  if (!cart) return res.status(404).send('not found');
  const items = db.prepare(`
    SELECT cart_items.*, products.name, products.sku
    FROM cart_items JOIN products ON products.id = cart_items.product_id
    WHERE cart_id = ?
  `).all(cart.id);
  res.json({ cart, items });
});

// VULN: also allow updating qty via GET (CSRF + no auth check on item ownership)
router.get('/:id/remove/:itemId', (req, res) => {
  db.prepare('DELETE FROM cart_items WHERE id = ? AND cart_id = ?').run(req.params.itemId, req.params.id);
  res.redirect('/cart?msg=removed');
});

module.exports = router;

