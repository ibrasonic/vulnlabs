// lib/access-log.js -- A09 Chapter 36 demo.
//
// This middleware writes one JSON line per HTTP request to
// data/access.log.  The file captures the full parsed request body
// because the team "wanted complete forensics" without thinking about
// what `body` contains on the login, register and checkout routes.
//
// VULN (S-LOG-001):  passwords, credit-card numbers and CVV codes are
//   written to the log file in clear text.
// VULN (S-LOG-002):  log file is created mode 0o644 and lives inside
//   data/ which is bind-mounted into the container; any tenant that
//   reads the host volume sees every customer's card.
// VULN (S-LOG-003):  no log rotation.  The file grows without bound.

const fs = require('fs');
const path = require('path');

const LOG_DIR  = path.join(__dirname, '..', 'data');
const LOG_FILE = path.join(LOG_DIR, 'access.log');

if (!fs.existsSync(LOG_DIR)) fs.mkdirSync(LOG_DIR, { recursive: true });

function safeStringify(obj) {
  try { return JSON.stringify(obj); } catch (_) { return '"[unserialisable]"'; }
}

function middleware(req, res, next) {
  const line = {
    t:      new Date().toISOString(),
    ip:     req.ip || req.socket.remoteAddress,
    method: req.method,
    url:    req.originalUrl,
    ua:     req.headers['user-agent'] || '',
    body:   req.body,    // VULN: includes password/credit_card/cvv on auth + checkout routes.
    cookie: req.headers['cookie'] || ''  // VULN: includes session id.
  };
  // Fire-and-forget; never block the response on disk I/O.
  fs.appendFile(LOG_FILE, safeStringify(line) + '\n', () => {});
  next();
}

module.exports = { middleware, LOG_FILE };
