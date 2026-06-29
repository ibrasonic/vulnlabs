// routes/articles.js - public newsroom: home, category, article detail, search, comments.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireTier, FLAGS } = require('../lib/auth');

function previewBody(html, n) {
  const text = String(html || '').replace(/<[^>]+>/g, '').replace(/\s+/g, ' ').trim();
  return text.length > n ? text.slice(0, n) + '...' : text;
}

router.get('/', (req, res) => {
  const articles = db.prepare(`
    SELECT a.*, u.display_name AS author_name
    FROM articles a JOIN users u ON u.id = a.author_id
    WHERE a.status = 'published'
    ORDER BY a.published_at DESC
    LIMIT 12
  `).all().map(a => ({ ...a, preview: previewBody(a.body, 200) }));
  res.set('Cache-Control', 'public, max-age=30');
  res.render('home', { articles });
});

router.get('/category/:name', (req, res) => {
  const name = req.params.name;
  const articles = db.prepare(`
    SELECT a.*, u.display_name AS author_name
    FROM articles a JOIN users u ON u.id = a.author_id
    WHERE a.status = 'published' AND a.category = ?
    ORDER BY a.published_at DESC
  `).all(name).map(a => ({ ...a, preview: previewBody(a.body, 160) }));
  res.set('Cache-Control', 'public, max-age=30');
  res.render('category', { name, articles });
});

router.get('/search', (req, res) => {
  const q = (req.query.q || '').toString();
  let hits = [];
  if (q) {
    const like = '%' + q + '%';
    hits = db.prepare(`
      SELECT a.*, u.display_name AS author_name
      FROM articles a JOIN users u ON u.id = a.author_id
      WHERE a.status = 'published'
        AND (a.title LIKE ? OR a.deck LIKE ? OR a.body LIKE ?)
      ORDER BY a.published_at DESC
      LIMIT 30
    `).all(like, like, like);
  }
  res.render('search', { q, hits });
});

router.get('/article/:slug', (req, res) => {
  const a = db.prepare(`
    SELECT a.*, u.display_name AS author_name, u.username AS author_handle
    FROM articles a JOIN users u ON u.id = a.author_id
    WHERE a.slug = ?
  `).get(req.params.slug);
  if (!a) return res.status(404).render('error', { code: 404, message: 'No such article.' });
  // Drafts and scheduled posts must NEVER appear here. The /cms route is the
  // only legitimate place to read them - and that route is gateway-blocked.
  if (a.status !== 'published') {
    return res.status(404).render('error', { code: 404, message: 'No such article.' });
  }
  // Paywall.
  if (a.paywall) {
    const order = { reader: 0, subscriber: 1, author: 2, editor: 3, admin: 4 };
    const sessionTier = (req.session && req.session.tier) || 'reader';
    // Same trust-X-User-Tier vulnerability as in requireTier - smuggling
    // can forge tier=subscriber to bypass the paywall.
    const hdrTier = req.headers['x-user-tier'];
    const tier = (hdrTier && order[hdrTier] !== undefined) ? hdrTier : sessionTier;
    if (order[tier] < order.subscriber) {
      return res.status(402).render('paywall', { a });
    }
  }
  const comments = db.prepare(`
    SELECT * FROM comments WHERE article_id = ? ORDER BY created_at ASC
  `).all(a.id);
  res.set('Cache-Control', 'public, max-age=30');
  res.render('article', { a, comments, leak: null });
});

// Anyone with a session can comment. Anonymous comments are accepted too.
router.post('/article/:slug/comment', (req, res) => {
  const a = db.prepare('SELECT id FROM articles WHERE slug = ?').get(req.params.slug);
  if (!a) return res.status(404).type('text').send('no such article\n');
  const sess = req.session || {};
  const author_label = (sess.display || req.body.author_label || 'Guest').toString().slice(0, 80);
  const body = (req.body.body || '').toString().slice(0, 8000);
  if (!body.trim()) return res.status(400).type('text').send('empty\n');
  db.prepare(`
    INSERT INTO comments (article_id, user_id, author_label, body)
    VALUES (?, ?, ?, ?)
  `).run(a.id, sess.userId || null, author_label, body);
  if (req.headers.accept && req.headers.accept.includes('text/html')) {
    return res.redirect('/article/' + req.params.slug + '#comments');
  }
  res.status(201).type('text').send('ok\n');
});

module.exports = router;
