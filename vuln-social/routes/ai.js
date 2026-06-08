// routes/ai.js — AI-summary endpoint (Google Gemini + prompt-injection sink).
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');
const llm = require('../lib/llm');

router.use(requireSession);

router.get('/', (req, res) => {
  const recent = db.prepare(`
    SELECT a.*, u.username FROM ai_logs a LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.id DESC LIMIT 10
  `).all();
  res.render('ai', { recent, msg: req.query.msg || '', summary: null, postId: req.query.post_id || '' });
});

// VULN: prompt injection sink. The post body is concatenated into the prompt.
// VULN: any logged-in user can summarise any post (no admin check) so an
// attacker can plant payload in their own post and then call summarize on it.
router.post('/summarize', async (req, res) => {
  const postId = parseInt(req.body.post_id || '0', 10);
  if (!postId) return res.status(400).send('missing post_id');
  const p = db.prepare('SELECT * FROM posts WHERE id = ?').get(postId);
  if (!p) return res.status(404).send('no such post');
  const ctx = req.body.extra_context || '';
  let summary = '';
  let provider = 'unknown';
  try {
    const out = await llm.summarizePost(p.body, ctx);
    summary = out.text; provider = out.provider;
  } catch (e) {
    summary = '[error] ' + e.message;
  }
  db.prepare('INSERT INTO ai_logs (user_id, prompt, response) VALUES (?, ?, ?)')
    .run(req.session.userId, p.body, summary);
  const recent = db.prepare(`
    SELECT a.*, u.username FROM ai_logs a LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.id DESC LIMIT 10
  `).all();
  res.render('ai', { recent, msg: 'provider: ' + provider, summary, postId });
});

module.exports = router;
