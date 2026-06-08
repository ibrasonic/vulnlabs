// server.js — Pulse Social Network entry point.
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');
const http = require('http');

const app = express();
const PORT = parseInt(process.env.PORT || '3003', 10);
const HOST = process.env.HOST || '0.0.0.0';

app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('dev'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));

// VULN: cookie missing security flags, no SameSite -> CSRF-friendly.
app.use(session({
  name: 'sid',
  secret: 'pulse-change-me',
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false, secure: false, sameSite: false, maxAge: 8 * 3600 * 1000 }
}));

app.use((req, res, next) => {
  res.locals.user = req.session && req.session.userId ? {
    id: req.session.userId, username: req.session.username, role: req.session.role
  } : null;
  res.locals.req = req;
  // VULN: NO X-Frame-Options or CSP -> clickjacking + DOM XSS amplification.
  next();
});

app.use('/static', express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, p) => {
    if (p.endsWith('.map')) res.setHeader('Content-Type', 'application/json');
  }
}));
const UPLOAD_DIR = path.join(__dirname, 'data', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
// VULN: uploads served statically, no Content-Disposition.
app.use('/uploads', express.static(UPLOAD_DIR));

app.use('/', require('./routes/feed'));
app.use('/', require('./routes/auth'));
app.use('/', require('./routes/profile'));
app.use('/p', require('./routes/posts'));
app.use('/follow', require('./routes/follow'));
app.use('/dm', require('./routes/dm'));
app.use('/admin', require('./routes/admin'));
app.use('/api', require('./routes/api'));
app.use('/ai-summary', require('./routes/ai'));

// VULN: debug endpoint
app.get('/debug', (req, res) => {
  res.json({
    env: process.env, headers: req.headers, session: req.session,
    cwd: process.cwd(), versions: process.versions
  });
});

// VULN: stack trace leak
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).type('text/html').send(`<h1>500</h1><pre>${err.stack || err}</pre>`);
});

const db = require('./lib/db');
if (!db.prepare('SELECT COUNT(*) AS c FROM users').get().c) {
  console.log('[pulse] empty DB, seeding...');
  require('./seed');
}

const server = http.createServer(app);
const { attach } = require('./sockets');
attach(server);

server.listen(PORT, HOST, () => {
  const llmKey = process.env.GEMINI_API_KEY ? 'gemini (' + (process.env.GEMINI_MODEL || 'gemini-2.0-flash') + ')' : 'stub (no GEMINI_API_KEY)';
  console.log('=================================================================');
  console.log(` vuln-social listening on http://${HOST}:${PORT}`);
  console.log('=================================================================');
  console.log(' Feed:        http://localhost:' + PORT + '/');
  console.log(' Login:       http://localhost:' + PORT + '/login');
  console.log(' Admin:       http://localhost:' + PORT + '/admin   (admin_eli / AdminEli!1)');
  console.log(' AI summary:  http://localhost:' + PORT + '/ai-summary');
  console.log(' Debug:       http://localhost:' + PORT + '/debug');
  console.log(' API:         http://localhost:' + PORT + '/api');
  console.log(' WS:          ws://localhost:' + PORT + '/socket.io/');
  console.log(' LLM:         ' + llmKey);
  console.log('');
  console.log(' Test creds:  aria / Aria2026!     (user)');
  console.log('              admin_eli / AdminEli!1  (admin)');
  console.log('');
  console.log(' Set GEMINI_API_KEY env var to use real Gemini for /ai-summary.');
  console.log(' See VULNERABILITIES.txt for exploit recipes.');
  console.log('=================================================================');
});
