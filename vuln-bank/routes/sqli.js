// routes/sqli.js — dedicated SQLi sinks for Chapter 11.
//
// All of these are reachable by ANY authenticated session (Alice's account is
// enough) and each one demonstrates one class of injection that the existing
// /accounts/search sink already supports, plus two extras that don't fit
// neatly into the search box:
//
//   GET /sqli/lookup           — header-based SQLi (X-Customer-ID).
//   GET /sqli/safe-lookup      — same sink with a naive `UNION SELECT`
//                                blacklist; trivially bypassed with
//                                `UNION/**/SELECT` or `UnIoN SeLeCt`.
//   GET /sqli/oob/leak         — convenience wrapper around the INTO OUTFILE
//                                payload (writes /tmp/leak-<id>.txt inside
//                                the container).
//
// The route is intentionally tiny so the chapter can quote every line.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);

// VULN (B-SQLI-001): header-based SQL injection.
// The `X-Customer-ID` header is glued straight into the WHERE clause.
// Attackers love header sinks because most WAFs only inspect the URL and
// body by default.
router.get('/lookup', (req, res) => {
  const cid = req.get('x-customer-id') || '0';
  const sql = `SELECT id, username, full_name, email FROM users WHERE id = ${cid}`;
  try {
    const rows = db.prepare(sql).all();
    res.json({ sql, rows });
  } catch (e) {
    // VULN: full SQL + error text returned to the client — error-based oracle.
    res.status(500).json({ sql, error: e.message });
  }
});

// VULN (B-SQLI-002): naive blacklist WAF.
// The "safe" version filters case-insensitive `UNION SELECT`, the literal
// two-dash comment marker, and the `;` separator.  Every one of those is
// trivially bypassed:
//   - `UNION/**/SELECT` survives the substring check.
//   - `UnIoN SeLeCt` is rejected here only because we lower-cased it; if the
//     filter forgot toLowerCase the case-shift alone would win.
//   - `#` is the MySQL line-comment alternative to `--` and is not filtered.
const BAD = [/union\s+select/i, /--/, /;/];
router.get('/safe-lookup', (req, res) => {
  const cid = req.get('x-customer-id') || '0';
  for (const re of BAD) {
    if (re.test(cid)) return res.status(400).json({ error: 'WAF blocked: ' + re });
  }
  const sql = `SELECT id, username, full_name, email FROM users WHERE id = ${cid}`;
  try {
    const rows = db.prepare(sql).all();
    res.json({ sql, rows });
  } catch (e) {
    res.status(500).json({ sql, error: e.message });
  }
});

// VULN (B-SQLI-003): convenience wrapper that demonstrates SELECT … INTO
// OUTFILE.  Takes ?path=/tmp/leak.txt and dumps every user row.  Real apps
// don't expose anything this blunt — but every classical SQLi against MySQL
// with FILE privilege boils down to this primitive.
router.get('/oob/leak', (req, res) => {
  const path = req.query.path || '/tmp/leak.txt';
  const sql = `SELECT username, password_md5, ssn FROM users INTO OUTFILE '${path}'`;
  try {
    db.prepare(sql).run();
    res.json({ ok: true, sql, path });
  } catch (e) {
    res.status(500).json({ sql, error: e.message });
  }
});

module.exports = router;
