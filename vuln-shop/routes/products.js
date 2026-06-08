// routes/products.js — catalog, search, detail, reviews.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');

// Catalog
router.get('/', (req, res) => {
  const cat = req.query.category;
  let prods;
  if (cat) {
    prods = db.prepare('SELECT * FROM products WHERE category = ? ORDER BY id').all(cat);
  } else {
    prods = db.prepare('SELECT * FROM products ORDER BY id').all();
  }
  res.render('products', { prods, q: req.query.q || '', cat: cat || '' });
});

// VULN: SQL injection on search query.
// IMPORTANT: register before `/:id`.
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  try {
    const rows = db.prepare(`
      SELECT * FROM products
      WHERE name LIKE '%${q}%' OR description LIKE '%${q}%' OR sku LIKE '%${q}%'
    `).all();
    res.render('product_search', { rows, q, error: null });
  } catch (e) {
    res.status(500).render('product_search', { rows: [], q, error: e.message });
  }
});

// Product detail with reviews — reviews rendered with <%- %> (stored XSS).
router.get('/:id', (req, res) => {
  const p = db.prepare('SELECT * FROM products WHERE id = ?').get(req.params.id);
  if (!p) return res.status(404).send('not found');
  const reviews = db.prepare(`
    SELECT reviews.*, users.username
    FROM reviews LEFT JOIN users ON users.id = reviews.user_id
    WHERE product_id = ? ORDER BY reviews.id DESC
  `).all(req.params.id);
  res.render('product_detail', { p, reviews, msg: req.query.msg || '' });
});

// VULN: stored XSS in review body (no escaping in template).
router.post('/:id/reviews', (req, res) => {
  if (!req.session || !req.session.userId) return res.redirect('/login?next=/products/' + req.params.id);
  const r = parseInt(req.body.rating || '5', 10);
  const body = req.body.body || '';
  db.prepare('INSERT INTO reviews (product_id, user_id, rating, body) VALUES (?, ?, ?, ?)')
    .run(req.params.id, req.session.userId, r, body);
  res.redirect('/products/' + req.params.id + '?msg=review_added');
});

module.exports = router;
