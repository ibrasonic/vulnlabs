// routes/admin.js — admin dashboard + reports + user mgmt (no role check).
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');
const { modLog, LOG_FILE: MOD_LOG_FILE } = require('../lib/mod-log');

const UPLOAD_DIR = path.join(__dirname, '..', 'data', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
// VULN: keeps originalname so user can pick the extension (and path).
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

router.use(requireSession);
// VULN: NO requireAdmin middleware.

router.get('/', (req, res) => {
  const reports = db.prepare(`
    SELECT r.*, p.body AS post_body, u.username AS reporter FROM reports r
    JOIN posts p ON p.id = r.post_id LEFT JOIN users u ON u.id = r.reporter_id
    ORDER BY r.id DESC
  `).all();
  const users = db.prepare('SELECT id, username, display_name, role, created_at FROM users ORDER BY id').all();
  res.render('admin', { reports, users });
});

router.get('/users', (req, res) => {
  const q = req.query.q || '';
  // VULN: SQLi
  let rows = [];
  let error = null;
  try {
    rows = db.prepare(`SELECT * FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%' ORDER BY id`).all();
  } catch (e) { error = e.message; }
  res.render('admin_users', { rows, q, error });
});

// VULN: GET-based role change (CSRF + BAC).
router.get('/users/:id/promote', (req, res) => {
  const target = db.prepare('SELECT username FROM users WHERE id = ?').get(req.params.id);
  db.prepare(`UPDATE users SET role = 'admin' WHERE id = ?`).run(req.params.id);
  // VULN (S-MOD-LOG-001): `note` is the raw target username, which is
  // an attacker-controlled field at registration time -- CRLF in the
  // username forges additional moderation entries.
  modLog(req.session.username, 'promote_user', req.params.id, target && target.username);
  res.redirect('/admin/users');
});

router.get('/users/:id/delete', (req, res) => {
  const uid = req.params.id;
  const postIds = db.prepare('SELECT id FROM posts WHERE user_id = ?').all(uid).map(r => r.id);
  for (const pid of postIds) {
    db.prepare('DELETE FROM comments WHERE post_id = ?').run(pid);
    db.prepare('DELETE FROM reports  WHERE post_id = ?').run(pid);
  }
  db.prepare('DELETE FROM comments WHERE user_id = ?').run(uid);
  db.prepare('DELETE FROM reports  WHERE reporter_id = ?').run(uid);
  db.prepare('DELETE FROM posts    WHERE user_id = ?').run(uid);
  db.prepare('DELETE FROM follows  WHERE follower_id = ? OR followee_id = ?').run(uid, uid);
  db.prepare('DELETE FROM dms      WHERE sender_id = ? OR recipient_id = ?').run(uid, uid);
  db.prepare('DELETE FROM ai_logs  WHERE user_id = ?').run(uid);
  db.prepare('DELETE FROM uploads  WHERE user_id = ?').run(uid);
  db.prepare('DELETE FROM users    WHERE id = ?').run(uid);
  res.redirect('/admin/users');
});

// VULN: arbitrary upload extension into a static-served directory.
router.post('/upload', upload.single('file'), (req, res) => {
  db.prepare('INSERT INTO uploads (user_id, filename, purpose) VALUES (?, ?, ?)')
    .run(req.session.userId, req.file.filename, req.body.purpose || 'misc');
  res.json({ ok: true, url: '/uploads/' + req.file.filename });
});

// VULN (S-MOD-LOG-003): no role check, any logged-in user can read
// the moderation log -- including the lines they themselves forged
// via CRLF in their username.
router.get('/moderation', (req, res) => {
  const tail = parseInt(req.query.tail || '200', 10);
  let text = '';
  try { text = fs.readFileSync(MOD_LOG_FILE, 'utf8'); } catch (_) {}
  const lines = text.split('\n').filter(Boolean);
  res.type('text/plain').send(lines.slice(-tail).join('\n'));
});

module.exports = router;
