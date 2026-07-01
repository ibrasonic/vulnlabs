// routes/feed.js — home timeline + user search.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');

router.get('/', (req, res) => {
  const posts = db.prepare(`
    SELECT p.*, u.username, u.display_name, u.avatar
    FROM posts p JOIN users u ON u.id = p.user_id
    ORDER BY p.id DESC LIMIT 60
  `).all();
  const counts = {};
  for (const p of posts) {
    counts[p.id] = db.prepare('SELECT COUNT(*) AS c FROM comments WHERE post_id = ?').get(p.id).c;
  }
  res.render('feed', { posts, counts, q: '' });
});

// VULN: SQL injection on user search.
// VULN: reflected XSS on the “Showing results for…” banner (q is echoed
// unescaped by search.ejs). ?safe=1 turns on a naive <script>-only blacklist
// that any non-<script> tag (<img>, <svg>, <details>…) trivially bypasses.
// ?enc=1 demonstrates the DOUBLE-URL-ENCODING bypass: the <script> blacklist
// runs on the value Express already decoded once, but the code then decodes
// it a SECOND time before echoing. A doubly-encoded payload (for example
// %253Csvg%2520onload%253Dalert(1)%253E) reaches the filter as
// %3Csvg... (no literal <script>, so it passes) and is decoded back to
// <svg onload=alert(1)> for display.
router.get('/search', (req, res) => {
  const q = req.query.q || '';
  const safe = req.query.safe === '1';
  const enc = req.query.enc === '1';
  let qEcho;
  if (enc) {
    const filtered = q.replace(/<script[^>]*>.*?<\/script>/gi, '');
    try { qEcho = decodeURIComponent(filtered); } catch (e) { qEcho = filtered; }
  } else if (safe) {
    qEcho = q.replace(/<script[^>]*>.*?<\/script>/gi, '');
  } else {
    qEcho = q;
  }
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(`SELECT id, username, display_name, avatar, bio FROM users WHERE username LIKE '%${q}%' OR display_name LIKE '%${q}%'`).all();
  } catch (e) { error = e.message; }
  res.render('search', { q, qEcho, safe, enc, rows, error });
});

module.exports = router;
