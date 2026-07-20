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
  res.render('ai', {
    recent, msg: req.query.msg || '', summary: null, postId: req.query.post_id || '',
    searchQuery: '', searchHits: null, agentTrace: null
  });
});

// VULN: prompt injection sink. The post body is concatenated into the prompt.
// VULN: any logged-in user can summarise any post (no admin check) so an
// attacker can plant payload in their own post and then call summarize on it.
// VULN (V-SOC-083): when mode=agent, the model is given a web_fetch tool with
// no host allow-list. Prompt injection then chains into SSRF.
// VULN (V-SOC-087): the summary this stores in ai_logs is later rendered as
// raw HTML by views/ai.ejs (improper output handling, LLM05), so a payload
// that makes the model emit an <img onerror=...> tag becomes stored XSS in
// the moderator dashboard.
router.post('/summarize', async (req, res) => {
  const postId = parseInt(req.body.post_id || '0', 10);
  if (!postId) return res.status(400).send('missing post_id');
  const p = db.prepare('SELECT * FROM posts WHERE id = ?').get(postId);
  if (!p) return res.status(404).send('no such post');
  const ctx = req.body.extra_context || '';
  const mode = (req.body.mode || req.query.mode || 'summary').toLowerCase();
  let summary = '';
  let provider = 'unknown';
  let trace = null;
  try {
    if (mode === 'agent') {
      const out = await llm.summarizePostWithTools(p.body, ctx, 3);
      summary = out.text; provider = out.provider; trace = out.trace || null;
    } else {
      const out = await llm.summarizePost(p.body, ctx);
      summary = out.text; provider = out.provider;
    }
  } catch (e) {
    summary = '[error] ' + e.message;
  }
  db.prepare('INSERT INTO ai_logs (user_id, prompt, response) VALUES (?, ?, ?)')
    .run(req.session.userId, p.body, summary);
  const recent = db.prepare(`
    SELECT a.*, u.username FROM ai_logs a LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.id DESC LIMIT 10
  `).all();
  res.render('ai', {
    recent, msg: 'provider: ' + provider + ' mode: ' + mode, summary, postId,
    searchQuery: '', searchHits: null, agentTrace: trace
  });
});

// VULN (V-SOC-084 + V-SOC-085): retrieval-augmented search. Mixes kb_docs
// (including visibility='internal' rows that carry hotline overrides and
// pager rotations) with recent posts (so any user-planted post becomes
// indirect-injection content for any searcher). No auth scoping, no
// visibility enforcement, no provenance tagging of retrieved snippets.
router.all('/search', async (req, res) => {
  const q = (req.method === 'POST' ? req.body.q : req.query.q) || '';
  let result = null;
  let hits = null;
  let provider = 'unknown';
  if (q) {
    try {
      const out = await llm.searchAndSummarize(db, q);
      result = out.text; provider = out.provider; hits = out.hits;
    } catch (e) {
      result = '[error] ' + e.message;
    }
    db.prepare('INSERT INTO ai_logs (user_id, prompt, response) VALUES (?, ?, ?)')
      .run(req.session.userId, 'SEARCH: ' + q, result);
  }
  const recent = db.prepare(`
    SELECT a.*, u.username FROM ai_logs a LEFT JOIN users u ON u.id = a.user_id
    ORDER BY a.id DESC LIMIT 10
  `).all();
  res.render('ai', {
    recent, msg: q ? 'provider: ' + provider : '', summary: result, postId: '',
    searchQuery: q, searchHits: hits, agentTrace: null
  });
});

module.exports = router;
