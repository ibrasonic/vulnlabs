// lib/audit.js -- A09 demo helper.
//
// The bank ships an audit_log table that has been in the schema since
// day one but is only written to from a small, hand-picked set of
// routes. Every gap below is intentional and forms the Chapter 36
// (Security Logging and Monitoring Failures) lab surface:
//
//   B-LOG-001  Failed logins are NOT recorded.  An attacker can
//              brute-force credentials with zero footprint.
//   B-LOG-002  Reading a user row at /admin/users/:id (which leaks the
//              SSN and password hash) is NOT recorded.  Mass SSN
//              enumeration is invisible.
//   B-LOG-003  The `details` field is built from raw request bytes,
//              so an attacker who controls the username can inject
//              additional log lines (CRLF log forgery).
//   B-LOG-004  /admin/audit is mounted before the requireRole check
//              in routes/admin.js -- ANY logged-in user can read the
//              defender's audit trail.

const db = require('./db');

function audit(userId, action, details) {
  try {
    db.prepare('INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)')
      .run(userId == null ? null : Number(userId), String(action), String(details == null ? '' : details));
  } catch (e) {
    // VULN: failure to write the audit log is silently swallowed.
    // A real defender would alert on this.
    console.error('[audit] insert failed', e.message);
  }
}

module.exports = { audit };
