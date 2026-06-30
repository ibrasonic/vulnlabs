// server.js — Vuln-Bank entry point.
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = parseInt(process.env.PORT || '3001', 10);
const HOST = process.env.HOST || '0.0.0.0';

// VULN: trust proxy headers blindly — X-Forwarded-Host reaches the response,
// X-Forwarded-For is logged & rate-limit-keyed. Enables host header injection
// and cache poisoning. (A05 / cache poisoning / Ch 31.)
app.set('trust proxy', true);

// VULN: EJS templates intentionally pipe untrusted data with `<%- %>` in
// several places (stored/reflected XSS, Ch 14).
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('dev'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: '5mb' }));
app.use(bodyParser.json({ limit: '5mb' }));
// VULN: parses XML bodies WITH external entities resolved (Ch 25 XXE).
app.use(bodyParser.text({ type: ['application/xml', 'text/xml'], limit: '5mb' }));

// VULN: session cookie is not HttpOnly, not Secure, no SameSite (Ch 19, A02).
app.use(session({
  name: 'sid',
  secret: 'change-me-please',           // VULN: hard-coded secret
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false, secure: false, sameSite: false, maxAge: 8 * 3600 * 1000 }
}));

// Expose serialized session into templates so vuln demos can render it.
app.use((req, res, next) => {
  res.locals.user = req.session && req.session.userId ? {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role
  } : null;
  res.locals.req = req;
  next();
});

// Static assets — including a `.js.map` source map intentionally exposed.
app.use('/static', express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, p) => {
    if (p.endsWith('.map')) res.setHeader('Content-Type', 'application/json');
  }
}));

// VULN (B-MIS-004): verbose Server banner advertising the exact stack.
// Combined with X-Powered-By (Express default), an attacker can pick the
// CVE list for the version disclosed.
app.use((req, res, next) => {
  res.setHeader('Server', 'nginx/1.18.0 (Ubuntu) + Express/4.19.2');
  next();
});

// VULN (B-MIS-001/002/003/005/006/007): A05 misconfiguration sinks.
const misconfig = require('./routes/misconfig');
app.use('/api', misconfig.corsReflect);  // B-MIS-007
app.use('/', misconfig.router);          // mounts /.env, /.git/*, /static/backup/*, /internal/dashboard

// Uploads directory — served with `express.static` for path-traversal demo
// because some routes do `path.join` without normalising. VULN (B-MIS-008):
// directory listing is enabled, so /uploads/ alone enumerates every file.
const UPLOAD_DIR = path.join(__dirname, 'data', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
app.use('/uploads', misconfig.listingMiddleware(UPLOAD_DIR, '/uploads'));
app.use('/uploads', express.static(UPLOAD_DIR));

// Mount routes.
app.use('/',         require('./routes/auth'));
app.use('/',         require('./routes/profile'));
app.use('/accounts', require('./routes/accounts'));
app.use('/transfer', require('./routes/transfers'));
app.use('/statements', require('./routes/statements'));
app.use('/admin/integrity', require('./routes/integrity'));
app.use('/admin',    require('./routes/admin'));
app.use('/support',  require('./routes/support'));
app.use('/api',      require('./routes/api'));
app.use('/',         require('./routes/oauth'));

// VULN: a "debug" endpoint left enabled in production (A05 / Ch 17).
app.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    headers: req.headers,
    session: req.session,
    cwd: process.cwd(),
    versions: process.versions
  });
});

// VULN: error handler leaks stack trace (A05).
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).type('text/html').send(
    `<h1>500 Internal Server Error</h1><pre>${err.stack || err}</pre>`
  );
});

// Run seed automatically if DB looks empty.
const db = require('./lib/db');
const haveUsers = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (!haveUsers) {
  console.log('[bank] empty DB detected, running seed...');
  require('./seed');
}

app.listen(PORT, HOST, () => {
  console.log(`\n=================================================================`);
  console.log(` vuln-bank listening on http://${HOST}:${PORT}`);
  console.log(`=================================================================`);
  console.log(` Login:       http://localhost:${PORT}/login`);
  console.log(` Register:    http://localhost:${PORT}/register`);
  console.log(` Dashboard:   http://localhost:${PORT}/accounts (after login)`);
  console.log(` Admin panel: http://localhost:${PORT}/admin (login as julie.morgan)`);
  console.log(` Debug:       http://localhost:${PORT}/debug`);
  console.log(` API base:    http://localhost:${PORT}/api`);
  console.log(` OAuth IdP:   http://localhost:${PORT}/.well-known/openid-configuration`);
  console.log(` OAuth RP:    http://localhost:${PORT}/partners/demo-app`);
  console.log(``);
  console.log(` Test creds:  alice.chen / Password123!  (customer)`);
  console.log(`              julie.morgan / Admin2024!   (admin)`);
  console.log(``);
  console.log(` See VULNERABILITIES.txt for exploit recipes.`);
  console.log(`=================================================================\n`);
});
