// server.js — Northwind Outfitters (vuln-shop) entry point.
const express = require('express');
const session = require('express-session');
const cookieParser = require('cookie-parser');
const bodyParser = require('body-parser');
const morgan = require('morgan');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = parseInt(process.env.PORT || '3002', 10);
const HOST = process.env.HOST || '0.0.0.0';
const EMAIL_SERVICE = process.env.EMAIL_SERVICE_URL || 'http://127.0.0.1:5002';

// VULN: trust proxy headers blindly.
app.set('trust proxy', true);
app.set('view engine', 'ejs');
app.set('views', path.join(__dirname, 'views'));

app.use(morgan('dev'));
app.use(cookieParser());
app.use(bodyParser.urlencoded({ extended: true, limit: '10mb' }));
app.use(bodyParser.json({ limit: '10mb' }));
app.use(bodyParser.text({ type: ['application/xml', 'text/xml'], limit: '10mb' }));

// VULN (S-LOG-001..003): write every request body to data/access.log.
app.use(require('./lib/access-log').middleware);

// VULN: session cookie missing flags (HttpOnly off, no SameSite).
app.use(session({
  name: 'sid',
  secret: 'shop-change-me',
  resave: false,
  saveUninitialized: true,
  cookie: { httpOnly: false, secure: false, sameSite: false, maxAge: 8 * 3600 * 1000 }
}));

app.use((req, res, next) => {
  res.locals.user = req.session && req.session.userId ? {
    id: req.session.userId,
    username: req.session.username,
    role: req.session.role
  } : null;
  res.locals.req = req;
  next();
});

// Static
app.use('/static', express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, p) => {
    if (p.endsWith('.map')) res.setHeader('Content-Type', 'application/json');
  }
}));
const UPLOAD_DIR = path.join(__dirname, 'data', 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });
// VULN: uploads served directly with original extension (RCE-via-HTML/JS).
app.use('/uploads', express.static(UPLOAD_DIR));

// Make EMAIL_SERVICE_URL reachable from contact route.
app.locals.EMAIL_SERVICE = EMAIL_SERVICE;

// VULN: naive in-process edge cache. Key is METHOD + URL only — no Vary,
// no Cookie, no host. Force-caches *.css/*.js/*.png/*.svg/*.ico for 60 s
// regardless of the underlying route's auth posture (cache deception sink).
// See lib/cache.js and Ch 28 (V-SHOP-110, V-SHOP-111).
app.use(require('./lib/cache'));

app.use('/', require('./routes/auth'));
app.use('/', require('./routes/profile'));
app.use('/products', require('./routes/products'));
app.use('/cart', require('./routes/cart'));
app.use('/checkout', require('./routes/checkout'));
app.use('/orders', require('./routes/orders'));
app.use('/admin', require('./routes/admin'));
app.use('/contact', require('./routes/contact'));
app.use('/import', require('./routes/import'));
app.use('/proxy', require('./routes/proxy'));
app.use('/api', require('./routes/api'));
app.use('/graphql', require('./routes/graphql'));
app.use('/components', require('./routes/components'));

// VULN: debug endpoint in production
app.get('/debug', (req, res) => {
  res.json({
    env: process.env,
    headers: req.headers,
    session: req.session,
    cwd: process.cwd(),
    versions: process.versions
  });
});

// VULN: stack trace in error response
app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).type('text/html').send(`<h1>500</h1><pre>${err.stack || err}</pre>`);
});

const db = require('./lib/db');
const haveUsers = db.prepare('SELECT COUNT(*) AS c FROM users').get().c;
if (!haveUsers) {
  console.log('[shop] empty DB, seeding...');
  require('./seed');
}

app.listen(PORT, HOST, () => {
  console.log('=================================================================');
  console.log(` vuln-shop listening on http://${HOST}:${PORT}`);
  console.log('=================================================================');
  console.log(' Storefront:   http://localhost:' + PORT + '/products');
  console.log(' Login:        http://localhost:' + PORT + '/login');
  console.log(' Admin:        http://localhost:' + PORT + '/admin (admin_kate / AdminKate!1)');
  console.log(' Debug:        http://localhost:' + PORT + '/debug');
  console.log(' API base:     http://localhost:' + PORT + '/api');
  console.log(' Email render: ' + EMAIL_SERVICE + '/render (SSTI sink)');
  console.log('');
  console.log(' Test creds:   olivia.park / OliviaP!23   (customer, 500 credits)');
  console.log('               admin_kate  / AdminKate!1  (admin)');
  console.log('');
  console.log(' See VULNERABILITIES.txt for exploit recipes.');
  console.log('=================================================================');
});
