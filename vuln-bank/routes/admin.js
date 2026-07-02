// routes/admin.js — admin panel.
// VULNS: BAC — no role check on /admin/users, /admin/users/:id/delete,
// /admin/promote (only checks logged-in). Reflected XSS via ?q=. Stored XSS
// when rendering support messages (admin reads them with `<%- body %>`).
// Cache poisoning friendly: X-Forwarded-Host echoed into "canonical" header.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');
const { audit } = require('../lib/audit');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const xpath = require('xpath');
const { DOMParser } = require('@xmldom/xmldom');

// Legacy staff directory, parsed once at boot from a pre-acquisition XML
// export (see data/staff-directory.xml). Queried by /admin/directory.
const STAFF_XML_PATH = path.join(__dirname, '..', 'data', 'staff-directory.xml');
let staffDoc = null;
function loadStaffDoc() {
  try {
    const xml = fs.readFileSync(STAFF_XML_PATH, 'utf8');
    staffDoc = new DOMParser({ errorHandler: () => {} }).parseFromString(xml, 'text/xml');
  } catch (e) {
    console.error('[admin] staff directory XML failed to load:', e.message);
    staffDoc = null;
  }
}
loadStaffDoc();

// VULN (B-MIS-006): hard-coded "support engineer" override token. Anyone
// who sends `X-Support-Token: ENG-OVERRIDE-2024-ALL-ACCESS` is upgraded to
// admin without authenticating. The token is leaked via the routes/admin
// backup file at /static/backup/admin.js.bak (B-MIS-005).
const SUPPORT_TOKEN = 'ENG-OVERRIDE-2024-ALL-ACCESS';
router.use((req, res, next) => {
  if (req.headers['x-support-token'] === SUPPORT_TOKEN) {
    req.session = req.session || {};
    req.session.role = 'admin';
    req.session.username = 'support_engineer';
    req.session.userId = 1;
  }
  next();
});

router.use(requireSession);

// VULN: forgot the role check.
router.get('/', (req, res) => {
  const users = db.prepare('SELECT id, username, full_name, email, role FROM users').all();
  const messages = db.prepare(`
    SELECT support_messages.*, users.username AS author
    FROM support_messages JOIN users ON users.id = support_messages.user_id
    ORDER BY support_messages.created_at DESC LIMIT 20
  `).all();
  // VULN: reflect X-Forwarded-Host into a Link rel="canonical" header.
  const xfh = req.headers['x-forwarded-host'];
  if (xfh) res.setHeader('Link', `<https://${xfh}/admin>; rel="canonical"`);
  res.render('admin', { users, messages, q: req.query.q || '' });
});

router.get('/users', (req, res) => {
  // VULN: SQLi via q
  const q = req.query.q || '';
  const rows = db.prepare(`SELECT id, username, full_name, email, ssn, role FROM users WHERE username LIKE '%${q}%' OR email LIKE '%${q}%'`).all();
  res.render('admin_users', { rows, q });
});

// VULN: GET-based privilege change — CSRF-friendly + BAC.
router.get('/promote', (req, res) => {
  const id = parseInt(req.query.id, 10);
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run('admin', id);
  // Promotion IS audited -- gives the defender a sense of coverage.
  audit(req.session.userId, 'promote_user', 'target_id=' + id);
  res.redirect('/admin');
});

router.get('/users/:id/delete', (req, res) => {
  // VULN (B-LOG-002): account deletion is NOT audited.
  db.prepare('DELETE FROM users WHERE id = ?').run(req.params.id);
  res.redirect('/admin');
});

// View raw user row — leaks SSN, password hash.
router.get('/users/:id', (req, res) => {
  // VULN (B-LOG-002): viewing a user row leaks SSN + password hash
  // and is NOT audited. Mass SSN enumeration is invisible.
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).send('not found');
  res.json(u);
});

// VULN (B-LOG-004): /admin/audit is reachable by ANY logged-in user
// (the router-level role check is missing). The defender's own audit
// trail leaks back to whoever wants to read it.
router.get('/audit', (req, res) => {
  const rows = db.prepare(
    'SELECT id, user_id, action, details, created_at FROM audit_log ORDER BY id DESC LIMIT 100'
  ).all();
  res.json({ count: rows.length, rows });
});

// ---------------------------------------------------------------------------
// VULN (B-INJ-001): OS command injection.
//
// "Network diagnostics" lets an operator ping a payment-gateway host to debug
// connectivity. The host value is concatenated straight into a shell command
// and run through /bin/sh, so shell metacharacters in ?host= execute on the
// server: 127.0.0.1; id   |   127.0.0.1 | cat /etc/passwd   |   $(whoami)  ...
// The fix is execFile('ping', ['-c','1', host]) — arguments as a vector, no
// shell. See Chapter 12.
// ---------------------------------------------------------------------------
router.get('/diagnostics', (req, res) => {
  const host = (req.query.host !== undefined) ? String(req.query.host) : '';
  let cmd = null;
  let output = null;
  if (host) {
    // VULN: the whole string is handed to the shell.
    cmd = `ping -c 1 -W 2 ${host}`;
    try {
      output = execSync(cmd, { timeout: 6000, encoding: 'utf8', shell: '/bin/sh' });
    } catch (e) {
      output =
        String(e.stdout || '') +
        String(e.stderr || '') +
        `\n[command exited with code ${e.status === undefined ? '?' : e.status}]`;
    }
  }
  res.render('diagnostics', { host, cmd, output });
});

// ---------------------------------------------------------------------------
// VULN (B-INJ-002): XPath injection.
//
// The legacy staff directory is an XML file (data/staff-directory.xml). The
// ?name= value is concatenated into the XPath expression that selects matching
// <employee> nodes, so a closed-quote predicate changes which nodes match:
//   ' or '1'='1                        -> every employee, incl. hidden tokens
//   nobody' or count(//employee)>3 or 'a'='b   -> boolean oracle
//   '] | //employee/api_token | a['    -> node-set union to surface tokens
// The template only prints name/title/email, but the api_token and clearance
// fields are in the same XML and are reachable with a blind substring() oracle.
// The fix is a parameterised XPath API that binds $name out of band. Ch 12.
// ---------------------------------------------------------------------------
router.get('/directory', (req, res) => {
  const name = (req.query.name !== undefined) ? String(req.query.name) : '';
  let expr = null;
  let error = null;
  let results = [];
  if (req.query.name !== undefined) {
    if (!staffDoc) loadStaffDoc();
    // VULN: user input spliced into the XPath expression.
    expr = `//employee[username/text()='${name}']`;
    try {
      const nodes = staffDoc ? xpath.select(expr, staffDoc) : [];
      results = nodes
        .filter((n) => n && n.nodeType === 1)
        .map((n) => ({
          username: xpath.select1('string(username)', n),
          full_name: xpath.select1('string(full_name)', n),
          title: xpath.select1('string(title)', n),
          email: xpath.select1('string(email)', n),
        }));
    } catch (e) {
      error = e.message;
    }
  }
  res.render('directory', { name, expr, error, results });
});

module.exports = router;
