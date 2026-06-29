// backend.js - NovaPress back-end (loopback 127.0.0.1:3094).
//
// The back-end is wired with `insecureHTTPParser: true`, which restores
// Node's pre-strict (llhttp lenient) parsing. With that flag, Node
// accepts requests that carry BOTH Content-Length and Transfer-Encoding:
// chunked, and per RFC 7230 treats them as chunked (TE wins). The
// front-end gateway in this lab is CL-only and does not honour TE -
// that disagreement is the request-smuggling bug.
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const path = require('path');
const http = require('http');

const PORT = parseInt(process.env.BE_PORT || '3094', 10);
const HOST = process.env.BE_HOST || '127.0.0.1';

const app = express();
app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan(':method :url :status -> :res[content-length]b'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: '4mb' }));
app.use(bodyParser.json({ limit: '4mb' }));
app.use(session({
  name: 'np_sid',
  secret: 'novapress-session-secret-2026',
  resave: false,
  saveUninitialized: false,
  cookie: { httpOnly: true, sameSite: 'lax', maxAge: 24 * 3600 * 1000 }
}));

app.use((req, res, next) => {
  res.locals.user = req.session && req.session.userId ? {
    id: req.session.userId,
    username: req.session.username,
    display: req.session.display,
    tier: req.session.tier
  } : null;
  res.locals.q = '';
  next();
});

app.use('/static', express.static(path.join(__dirname, 'public')));

// Routes.
app.use('/', require('./routes/auth'));
app.use('/', require('./routes/articles'));
app.use('/cms', require('./routes/cms'));
app.use('/admin', require('./routes/admin'));
app.use('/api', require('./routes/api'));
app.get('/about', (req, res) => res.render('about'));
app.get('/health', (req, res) => res.type('text').send('ok\n'));

app.use((err, req, res, next) => {
  console.error('[backend]', err);
  res.status(500).type('text').send('500: ' + (err.message || 'error') + '\n');
});

app.use((req, res) => {
  res.status(404).render('error', { code: 404, message: 'No such page.' });
});

// Seed if empty.
const db = require('./lib/db');
if (!db.prepare('SELECT COUNT(*) AS c FROM users').get().c) {
  console.log('[backend] empty DB, seeding...');
  require('./seed');
}

// HTTP server with the LEGACY parser explicitly enabled. This is the
// "real bug" of this back-end: it accepts ambiguous CL+TE requests and
// processes them as chunked, while the front-end thinks they were CL.
const server = http.createServer({ insecureHTTPParser: true }, app);
server.keepAliveTimeout = 60_000;
server.headersTimeout   = 65_000;
server.maxRequestsPerSocket = 0;
server.listen(PORT, HOST, () => {
  console.log('[backend] NovaPress (insecureHTTPParser=true) listening on ' + HOST + ':' + PORT);
});
