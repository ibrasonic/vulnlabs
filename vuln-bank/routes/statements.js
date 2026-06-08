// routes/statements.js — upload + download PDF statements.
// VULNS: arbitrary file upload (no MIME/ext check, no auth on view), path
// traversal on /statements/file?name=, SSRF via /statements/import?url=,
// XXE via /statements/import-xml (text/xml body, external entities resolved).
const express = require('express');
const router = express.Router();
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const fetch = require('node-fetch');
const xml2js = require('xml2js');
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

const UPLOAD_DIR = path.join(__dirname, '..', 'data', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

// VULN: filename trusted from the client — leads to overwriting and traversal.
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOAD_DIR),
  filename: (req, file, cb) => cb(null, file.originalname)
});
const upload = multer({ storage });

router.get('/', requireSession, (req, res) => {
  const stmts = db.prepare(`
    SELECT statements.*, accounts.account_number
    FROM statements JOIN accounts ON accounts.id = statements.account_id
    WHERE accounts.user_id = ?
    ORDER BY statements.created_at DESC
  `).all(req.session.userId);
  res.render('statements', { stmts, error: null, ok: req.query.ok });
});

router.post('/upload', requireSession, upload.single('file'), (req, res) => {
  // VULN: account_id from form — no ownership check, so a customer can attach
  // a statement to ANOTHER customer's account.
  const accountId = parseInt(req.body.account_id, 10);
  db.prepare('INSERT INTO statements (account_id, filename, uploaded_by) VALUES (?, ?, ?)')
    .run(accountId, req.file.filename, req.session.userId);
  res.redirect('/statements?ok=uploaded');
});

// VULN: path traversal — name comes from query, joined raw.
router.get('/file', requireSession, (req, res) => {
  const name = req.query.name || '';
  const fp = path.join(UPLOAD_DIR, name);  // no normalisation
  if (!fs.existsSync(fp)) return res.status(404).send('not found');
  res.sendFile(fp);
});

// VULN: SSRF — fetches an arbitrary URL server-side. Used to "import" a
// statement from a cloud-storage URL.
router.post('/import', requireSession, async (req, res) => {
  const url = req.body.url;
  try {
    const r = await fetch(url, { timeout: 5000 });
    const text = await r.text();
    return res.type('text/plain').send(text.slice(0, 50000));
  } catch (e) {
    return res.status(500).send('fetch failed: ' + e.message);
  }
});

// VULN: XXE — Node has no libxml2 by default, so to keep the lab reproducible
// we implement a small DTD entity resolver that mimics what a vulnerable Java
// or PHP parser does: it reads `<!ENTITY name SYSTEM "file://...">` and
// `<!ENTITY name SYSTEM "http://...">` declarations and expands `&name;` in
// the document body. This is functionally identical to a real XXE sink.
router.post('/import-xml', requireSession, async (req, res) => {
  const xml = req.body && typeof req.body === 'string' ? req.body : '';
  let expanded = xml;
  const entityRe = /<!ENTITY\s+(\w+)\s+SYSTEM\s+["']([^"']+)["']\s*>/g;
  const entities = {};
  let m;
  while ((m = entityRe.exec(xml))) entities[m[1]] = m[2];
  for (const [name, uri] of Object.entries(entities)) {
    let value = '';
    try {
      if (uri.startsWith('file://')) {
        // Strip the file:// scheme. Handle Windows triple-slash `file:///C:/...`
        // by also dropping the leading slash so `C:/Windows/...` becomes a
        // valid path on win32. POSIX paths like `file:///etc/passwd` remain
        // absolute (`/etc/passwd`).
        let fp = uri.replace(/^file:\/\//, '');
        if (process.platform === 'win32' && /^\/[A-Za-z]:\//.test(fp)) fp = fp.slice(1);
        value = fs.readFileSync(fp, 'utf8');
      } else if (uri.startsWith('http://') || uri.startsWith('https://')) {
        const r = await fetch(uri, { timeout: 5000 });
        value = await r.text();
      }
    } catch (e) { value = '[xxe-error: ' + e.message + ']'; }
    expanded = expanded.split('&' + name + ';').join(value);
  }
  const parser = new xml2js.Parser({ explicitArray: false });
  parser.parseString(expanded, (err, result) => {
    if (err) return res.status(400).type('text/plain').send('parse error: ' + err.message + '\n---\nexpanded body:\n' + expanded);
    res.json(result);
  });
});

module.exports = router;
