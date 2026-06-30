// lib/mod-log.js -- A09 Chapter 36 moderation log writer.
//
// VULN (S-MOD-LOG-001):  log lines are formatted with raw string
//   interpolation.  Any field that survives untouched from a request
//   body (display_name, post body, username on register) can carry
//   "\n" or "\r\n" and forge additional log entries the SOC will
//   index as their own (CRLF log injection / log forgery).
// VULN (S-MOD-LOG-002):  no integrity check (HMAC) over the line, so
//   a forged line is indistinguishable from a real one.
// VULN (S-MOD-LOG-003):  GET /admin/moderation streams the file with
//   only the existing session check (no requireAdmin), letting any
//   logged-in user read every moderator action.

const fs = require('fs');
const path = require('path');

const LOG_DIR  = path.join(__dirname, '..', 'data');
const LOG_FILE = path.join(LOG_DIR, 'moderation.log');

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

function modLog(actor, action, target, note) {
  const line = `${new Date().toISOString()} actor=${actor || '-'} action=${action} target=${target || '-'} note=${note || ''}\n`;
  fs.appendFile(LOG_FILE, line, () => {});
}

module.exports = { modLog, LOG_FILE };
