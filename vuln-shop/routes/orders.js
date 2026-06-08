// routes/orders.js — order list and detail (IDOR sink).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

router.get('/', (req, res) => {
  const list = db.prepare('SELECT * FROM orders WHERE user_id = ? ORDER BY id DESC').all(req.session.userId);
  res.render('orders', { list });
});

// VULN: IDOR — no `AND user_id = ?` filter on order_id.
router.get('/:id', (req, res) => {
  const o = db.prepare('SELECT * FROM orders WHERE id = ?').get(req.params.id);
  if (!o) return res.status(404).send('not found');
  const items = db.prepare(`
    SELECT order_items.*, products.name, products.sku, products.image_url
    FROM order_items JOIN products ON products.id = order_items.product_id
    WHERE order_id = ?
  `).all(o.id);
  res.render('order_detail', { o, items });
});

module.exports = router;
