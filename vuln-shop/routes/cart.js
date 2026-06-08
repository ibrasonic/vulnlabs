// routes/cart.js — shopping cart with deliberate price tampering and IDOR.
const express = require('express');
const router = express.Router();
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
