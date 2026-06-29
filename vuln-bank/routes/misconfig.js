// routes/misconfig.js -- A05 Security Misconfiguration sinks.
//
// Mounted at the application root. Every endpoint here is a deliberate
// misconfiguration that a careful sysadmin would never ship.

const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();

const EXPOSED = path.join(__dirname, '..', 'data', 'exposed');

// ---------------------------------------------------------------------------
// B-MIS-001 -- exposed .env at web root.
//   curl http://127.0.0.1:3001/.env
// ---------------------------------------------------------------------------
router.get('/.env', (req, res) => {
  res.type('text/plain').sendFile(path.join(EXPOSED, '.env'), { dotfiles: 'allow' });
});

// ---------------------------------------------------------------------------
// B-MIS-002 -- exposed .git/ metadata at web root. Real attackers chain
// this with `git-dumper` to reconstruct the entire repository, then grep
// the history for past secrets that have since been "rotated".
// ---------------------------------------------------------------------------
router.use('/.git', express.static(path.join(EXPOSED, '_git'), {
  dotfiles: 'allow',
  index: false,
}));

// ---------------------------------------------------------------------------
// B-MIS-005 -- a "backup" of routes/admin.js left in /static/backup. The
// file is real and reveals the support-token primitive that the live
// admin.js (B-MIS-006) honours.
// ---------------------------------------------------------------------------
router.get('/static/backup/admin.js.bak', (req, res) => {
  res.type('text/plain').sendFile(path.join(EXPOSED, 'admin.js.bak'), { dotfiles: 'allow' });
});

// ---------------------------------------------------------------------------
// B-MIS-003 -- /internal/dashboard. HTTP Basic Auth, default creds admin:admin.
// ---------------------------------------------------------------------------
router.get('/internal/dashboard', (req, res) => {
  const auth = req.headers.authorization || '';
  if (!auth.startsWith('Basic ')) {
    res.setHeader('WWW-Authenticate', 'Basic realm="Internal Ops"');
    return res.status(401).type('text/plain').send('Authentication required\n');
  }
  const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
  const [user, pass] = decoded.split(':');
  if (user === 'admin' && pass === 'admin') {
    return res.type('text/html').send(`<!doctype html>
<title>Internal ops dashboard</title>
<h1>Internal ops dashboard</h1>
<p>Logged in as <b>${user}</b>.</p>
<ul>
  <li><a href="/internal/dashboard?action=restart-db">Restart database</a></li>
  <li><a href="/internal/dashboard?action=flush-cache">Flush cache</a></li>
  <li><a href="/debug">Debug bundle</a> (env + headers + session)</li>
  <li>Last deploy: 2026-06-12 by ci@vuln-bank.example</li>
</ul>
<h2>Recent admin actions</h2>
<pre>2026-06-29 14:11 julie.morgan rotated SESSION_SECRET (no-op, hard-coded)
2026-06-28 22:03 ci@vuln-bank.example deployed commit 9b1a3c5 to prod
2026-06-28 09:44 julie.morgan reset password for olivia.park</pre>`);
  }
  res.setHeader('WWW-Authenticate', 'Basic realm="Internal Ops"');
  return res.status(401).type('text/plain').send('Bad credentials\n');
});

// ---------------------------------------------------------------------------
// B-MIS-007 -- CORS reflected-origin with credentials. Any origin that
// asks for /api/* gets `Access-Control-Allow-Origin: <its-own-origin>` plus
// `Access-Control-Allow-Credentials: true`. An attacker page on
// attacker.example can make credentialed requests against the bank API
// and read every response.
// ---------------------------------------------------------------------------
function corsReflect(req, res, next) {
  const origin = req.headers.origin;
  if (origin) {
    res.setHeader('Access-Control-Allow-Origin', origin);
    res.setHeader('Access-Control-Allow-Credentials', 'true');
    res.setHeader('Access-Control-Allow-Headers', req.headers['access-control-request-headers'] || 'content-type,authorization,x-support-token');
    res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,PATCH,OPTIONS');
  }
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
}

// ---------------------------------------------------------------------------
// B-MIS-008 -- /uploads directory listing. If the user happens to know
// the parent path they can enumerate every other tenant's uploaded file.
// ---------------------------------------------------------------------------
function listingMiddleware(rootDir, publicPath) {
  return function (req, res, next) {
    // Only listen for requests whose effective path is a directory.
    const safeSubpath = path.posix.normalize(decodeURIComponent(req.path));
    if (safeSubpath.includes('..')) return next();
    const target = path.join(rootDir, safeSubpath);
    let stat;
    try { stat = fs.statSync(target); } catch (e) { return next(); }
    if (!stat.isDirectory()) return next();
    let entries;
    try { entries = fs.readdirSync(target); } catch (e) { return next(); }
    const trailingSlash = req.path.endsWith('/') ? '' : '/';
    const rows = entries.map(name => {
      let kind = '?', size = '-';
      try {
        const s = fs.statSync(path.join(target, name));
        kind = s.isDirectory() ? 'dir' : 'file';
        size = s.isFile() ? String(s.size) : '-';
      } catch {}
      return `<li><a href="${name}${kind === 'dir' ? '/' : ''}">${name}</a> -- ${kind} (${size} bytes)</li>`;
    }).join('\n');
    res.type('text/html').send(`<!doctype html>
<title>Index of ${publicPath}${safeSubpath}${trailingSlash}</title>
<h1>Index of ${publicPath}${safeSubpath}${trailingSlash}</h1>
<ul>${rows}</ul>`);
  };
}

module.exports = {
  router,
  corsReflect,
  listingMiddleware,
};
