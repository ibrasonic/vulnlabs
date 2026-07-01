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
  // VULN: cache poisoning (V-SHOP-110).
  // X-Forwarded-Host is unkeyed by the edge cache but reaches the rendered
  // page body via res.locals.canonicalHost, which the layout uses to build
  // the analytics script-src. An attacker who sends the request first wins
  // the cache slot for every subsequent visitor for the TTL.
  const host = req.headers['x-forwarded-host'] || req.headers['host'];
  res.locals.canonicalHost = host;
  res.setHeader('Cache-Control', 'public, max-age=30');
  res.setHeader('X-Canonical-Host', host);
  res.render('products', { prods, q: req.query.q || '', cat: cat || '' });
});

// VULN: SQL injection on search query.
// Also: reflected XSS variants. The query parameter `q` is reflected into
// the page in TWO contexts:
//   * element body (always unescaped) -> classic reflected XSS
//   * <input value="..."> attribute (only `<` and `>` are escaped) ->
//     attribute breakout via `"`, e.g. q=" autofocus onfocus=alert(1) x="
// The ?safe=1 mode forces the `<>`-only encoder on the element body too,
// so the only remaining path is the attribute breakout. Real-world
// half-fix.
// IMPORTANT: register before `/:id`.
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  const safe = req.query.safe === '1';
  // Naive sanitiser: encodes `<` and `>` ONLY. Quotes pass through.
  const lt = (s) => String(s).replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const qBody = safe ? lt(q) : q;
  const qAttr = lt(q);
  try {
    const rows = db.prepare(`
      SELECT * FROM products
      WHERE name LIKE '%${q}%' OR description LIKE '%${q}%' OR sku LIKE '%${q}%'
    `).all();
    res.render('product_search', { rows, q: qBody, qAttr, safe, error: null });
  } catch (e) {
    res.status(500).render('product_search', { rows: [], q: qBody, qAttr, safe, error: e.message });
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
  // VULN (CSP present-but-bypassable): ?csp=1 turns on a Content-Security-
  // Policy that blocks inline event handlers, so a stored <img onerror>
  // review stops firing and the page *looks* fixed. But script-src 'self'
  // still trusts same-origin scripts, and /api/reviews.js is a JSONP gadget
  // that reflects its callback verbatim. A stored review of
  //   <script src="/api/reviews.js?callback=confirm(document.domain)//"></script>
  // is same-origin, so the CSP allows it and the payload runs anyway.
  if (req.query.csp === '1') {
    res.setHeader('Content-Security-Policy',
      "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'");
  }
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
