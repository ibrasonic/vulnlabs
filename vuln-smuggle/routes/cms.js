// routes/cms.js - staff-only newsroom CMS. Mounted at /cms. The gateway is
// supposed to block /cms/* on the public edge unless X-Internal-Auth is set.
// Smuggled requests can bypass that path block entirely.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireTier, FLAGS } = require('../lib/auth');

router.use(requireTier('author'));

router.get('/', (req, res) => {
  const my = db.prepare(`
    SELECT a.*, u.display_name AS author_name FROM articles a JOIN users u ON u.id = a.author_id
    ORDER BY (status = 'draft') DESC, COALESCE(published_at, created_at) DESC
    LIMIT 50
  `).all();
  res.render('cms_dashboard', { articles: my, tier: req.effectiveTier, FLAGS });
});

router.get('/new', (req, res) => res.render('cms_new'));

router.get('/article/:id', (req, res) => {
  const a = db.prepare('SELECT * FROM articles WHERE id = ?').get(req.params.id);
  if (!a) return res.status(404).type('text').send('no such article\n');
  res.render('cms_article', { a, FLAGS });
});

router.post('/article/new', (req, res) => {
  const { slug, title, deck, body, category, paywall } = req.body;
  if (!slug || !title) return res.status(400).type('text').send('slug+title required\n');
  try {
    db.prepare(`
      INSERT INTO articles (slug, title, deck, body, category, author_id, status, paywall)
      VALUES (?, ?, ?, ?, ?, ?, 'draft', ?)
    `).run(slug, title, deck || '', body || '', category || 'opinion',
           req.session.userId, parseInt(paywall || '0', 10));
  } catch (e) { return res.status(400).type('text').send(e.message + '\n'); }
  res.redirect('/cms');
});

router.post('/article/:id/publish', (req, res) => {
  if (req.effectiveTier !== 'editor' && req.effectiveTier !== 'admin') {
    return res.status(403).type('text').send('only editors publish\n');
  }
  db.prepare(`
    UPDATE articles SET status = 'published', published_at = datetime('now') WHERE id = ?
  `).run(req.params.id);
  res.redirect('/cms');
});

router.post('/article/:id/retract', (req, res) => {
  if (req.effectiveTier !== 'editor' && req.effectiveTier !== 'admin') {
    return res.status(403).type('text').send('only editors retract\n');
  }
  db.prepare('UPDATE articles SET status = ? WHERE id = ?').run('retracted', req.params.id);
  res.redirect('/cms');
});

module.exports = router;
