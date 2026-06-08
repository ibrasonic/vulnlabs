// routes/admin.js — admin product management.
// VULNS: NO role check (BAC); arbitrary file upload (RCE-via-HTML/JS via
// uploads/ being served statically); cache-poisoning via X-Forwarded-Host;
// stored XSS on /admin via support_messages body unescaped.
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

const UPLOAD_DIR = path.join(__dirname, '..', 'data', 'uploads');
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, file.originalname)  // VULN
});
const upload = multer({ storage });

router.use(requireSession);
// VULN: NO requireRole('admin') middleware.

router.get('/', (req, res) => {
  const support = db.prepare('SELECT s.*, u.username FROM support_messages s LEFT JOIN users u ON u.id = s.user_id ORDER BY s.id DESC').all();
  const orders = db.prepare('SELECT o.*, u.username FROM orders o JOIN users u ON u.id = o.user_id ORDER BY o.id DESC LIMIT 20').all();
  // VULN: cache poisoning — Link rel=canonical built from X-Forwarded-Host.
  const host = req.headers['x-forwarded-host'] || req.headers['host'];
  res.setHeader('Link', `<https://${host}/admin>; rel="canonical"`);
  res.render('admin', { support, orders });
});

router.get('/products', (req, res) => {
  const list = db.prepare('SELECT * FROM products ORDER BY id').all();
  res.render('admin_products', { list, msg: req.query.msg || '' });
});

router.post('/products', (req, res) => {
  const { sku, name, description, price_cents, stock, image_url, category } = req.body;
  db.prepare('INSERT INTO products (sku, name, description, price_cents, stock, image_url, category) VALUES (?, ?, ?, ?, ?, ?, ?)')
    .run(sku, name, description, parseInt(price_cents || '0', 10), parseInt(stock || '0', 10), image_url || '', category || '');
  res.redirect('/admin/products?msg=added');
});

router.post('/products/:id/delete', (req, res) => {
  db.prepare('DELETE FROM products WHERE id = ?').run(req.params.id);
  res.redirect('/admin/products?msg=deleted');
});

router.get('/users', (req, res) => {
  const q = req.query.q || '';
  let list;
  try {
    // VULN: SQLi
    list = db.prepare(`SELECT * FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%' ORDER BY id`).all();
  } catch (e) {
    return res.status(500).send('DB: ' + e.message);
  }
  res.render('admin_users', { list, q });
});

router.get('/users/:id', (req, res) => {
  // VULN: returns full row including password_md5
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).send('not found');
  res.json(u);
});

// VULN: GET-based privilege change (CSRF + BAC).
router.get('/users/:id/promote', (req, res) => {
  db.prepare(`UPDATE users SET role = 'admin' WHERE id = ?`).run(req.params.id);
  res.redirect('/admin/users');
});

// VULN: upload any extension into /uploads which is served statically.
router.post('/upload', upload.single('file'), (req, res) => {
  db.prepare('INSERT INTO uploads (user_id, filename, purpose) VALUES (?, ?, ?)')
    .run(req.session.userId, req.file.filename, req.body.purpose || 'misc');
  res.json({ ok: true, url: '/uploads/' + req.file.filename });
});

module.exports = router;
