// routes/api.js — JSON API with JWT auth.
// VULNS: JWT accepts alg=none (lib/auth.js); BOLA / IDOR (any token can read
// any user's accounts via /api/users/:id); CORS wide open; no rate limit;
// excessive data exposure (returns SSN, password_md5). Plus the API4 / API5 /
// API6 / API10 sinks and a public OpenAPI spec (API9) added at the foot.
const express = require('express');
const router = express.Router();
const fetch = require('node-fetch');
const db = require('../lib/db');
const { requireJwt, requireSession, signToken } = require('../lib/auth');

// VULN: CORS — Origin reflected, credentials allowed (Ch 17).
router.use((req, res, next) => {
  const origin = req.headers.origin || '*';
  res.setHeader('Access-Control-Allow-Origin', origin);
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,DELETE,OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Authorization, Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  next();
});

// Session -> v1 API token bridge. The bank's own web pages are API-backed:
// once you are signed in, the browser exchanges the session for a short-lived
// mobile-API token (HS256) and calls /api/* on your behalf. This is why simply
// USING the app (Profile, Transfer) makes real GET /api/me, PUT /api/users/:id
// and POST /api/transfers requests land in Reqlore's History — no prior
// knowledge of the API needed.
router.get('/token', requireSession, (req, res) => {
  const token = signToken({ sub: req.session.userId, username: req.session.username, role: req.session.role });
  res.json({ token, token_type: 'Bearer', expires_in: 3600 });
});

router.get('/me', requireJwt, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.jwt.sub);
  res.json(u);   // VULN: returns the whole row including SSN + password_md5
});

// VULN: BOLA — any authenticated user can read any other user (Ch 32 API1).
router.get('/users/:id', requireJwt, (req, res) => {
  const u = db.prepare('SELECT * FROM users WHERE id = ?').get(req.params.id);
  if (!u) return res.status(404).json({ error: 'not found' });
  res.json(u);
});

// Same BOLA on accounts and transfers.
router.get('/accounts/:id', requireJwt, (req, res) => {
  res.json(db.prepare('SELECT * FROM accounts WHERE id = ?').get(req.params.id) || null);
});

router.get('/accounts/:id/transfers', requireJwt, (req, res) => {
  const acct = db.prepare('SELECT account_number FROM accounts WHERE id = ?').get(req.params.id);
  if (!acct) return res.json([]);
  res.json(db.prepare(`
    SELECT * FROM transfers WHERE from_account = ? OR to_account = ?
    ORDER BY created_at DESC LIMIT 50
  `).all(acct.account_number, acct.account_number));
});

// VULN: mass assignment on profile update — every field accepted, role included.
router.put('/users/:id', requireJwt, express.json(), (req, res) => {
  const id = parseInt(req.params.id, 10);
  // Note: no `if (id === req.jwt.sub)` ownership check.
  const fields = ['email', 'full_name', 'phone', 'address', 'role', 'mfa_enabled'];
  const updates = [];
  const values = [];
  for (const f of fields) {
    if (f in req.body) { updates.push(`${f} = ?`); values.push(req.body[f]); }
  }
  if (!updates.length) return res.status(400).json({ error: 'no fields' });
  values.push(id);
  db.prepare(`UPDATE users SET ${updates.join(', ')} WHERE id = ?`).run(...values);
  res.json(db.prepare('SELECT * FROM users WHERE id = ?').get(id));
});

// Versioned endpoint — VULN: /api/v1/users skips auth entirely (Ch 32 API9).
router.get('/v1/users', (req, res) => {
  res.json(db.prepare('SELECT id, username, email, role FROM users').all());
});

// ---------------------------------------------------------------------------
// API4 — Unrestricted Resource Consumption. A batch lookup with NO cap on the
// array size: one request fans out to as many DB reads as the caller asks for
// (amplification / DoS), and it is BOLA at scale (no per-id ownership check).
router.post('/batch', requireJwt, (req, res) => {
  const ids = Array.isArray(req.body && req.body.ids) ? req.body.ids : [];
  const results = ids.map((id) =>
    db.prepare('SELECT id, username, email, role, ssn FROM users WHERE id = ?').get(id) || null);
  res.json({ count: results.length, results });
});

// API5 — Broken Function Level Authorisation. These "admin" API actions check
// AUTHENTICATION (any valid token) but never AUTHORISATION (the caller's role),
// so an ordinary customer's token can list every user and reassign roles.
router.get('/admin/users', requireJwt, (req, res) => {
  // VULN: missing  if (req.jwt.role !== 'admin') return res.status(403)...
  res.json(db.prepare('SELECT id, username, email, role, ssn FROM users').all());
});
router.post('/admin/users/:id/role', requireJwt, (req, res) => {
  // VULN: no role check — any token promotes/demotes any user.
  const id = parseInt(req.params.id, 10);
  const role = String((req.body && req.body.role) || 'customer');
  db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, id);
  res.json({ ok: true, id, role });
});

// API6 — Unrestricted access to a sensitive business flow. Money movement over
// the API with NO per-day limit, NO idempotency key, and NO check that the
// source account belongs to the caller: a stolen token drains any account, and
// the request replays to multiply the effect.
router.post('/transfers', requireJwt, (req, res) => {
  const from = String((req.body && req.body.from_account) || '');
  const to = String((req.body && req.body.to_account) || '');
  const cents = parseInt((req.body && req.body.amount_cents), 10) || 0;
  if (!from || !to || cents <= 0) {
    return res.status(400).json({ error: 'from_account, to_account, amount_cents required' });
  }
  db.prepare('UPDATE accounts SET balance_cents = balance_cents - ? WHERE account_number = ?').run(cents, from);
  db.prepare('UPDATE accounts SET balance_cents = balance_cents + ? WHERE account_number = ?').run(cents, to);
  db.prepare('INSERT INTO transfers (from_account, to_account, amount_cents, memo) VALUES (?,?,?,?)')
    .run(from, to, cents, 'mobile-api');
  res.json({ ok: true, from_account: from, to_account: to, amount_cents: cents });
});

// API10 — Unsafe Consumption of APIs. The FX endpoint consumes an external
// rates provider and TRUSTS the response verbatim to compute a money amount:
// no schema check, no bounds check. The provider URL is caller-selectable, so
// an attacker points it at their own server (also SSRF, Ch 15) and returns any
// rate they like.
router.get('/fx/rates', (req, res) => {                 // the "legit" upstream mock
  res.json({ base: 'USD', rates: { EUR: 0.92, GBP: 0.79, JPY: 157.0 } });
});
router.get('/fx', requireJwt, async (req, res) => {
  const to = String(req.query.to || 'EUR');
  const amount = parseFloat(req.query.amount || '0') || 0;
  const provider = String(req.query.provider || 'http://127.0.0.1:3001/api/fx/rates');
  try {
    const feed = await (await fetch(provider)).json();  // VULN: trusts whatever comes back
    const rate = feed.rates[to];                        // no validation of shape or bounds
    res.json({ from: 'USD', to, amount, rate, converted: amount * rate, provider });
  } catch (e) {
    res.status(502).json({ error: 'provider error', detail: e.message });
  }
});

// API9 (schema half) — Improper Inventory Management. The OpenAPI/Swagger spec
// is public and enumerates every endpoint, including the admin and legacy ones.
router.get(['/openapi.json', '/swagger.json'], (req, res) => {
  res.json({
    openapi: '3.0.0',
    info: { title: 'NovaTrust Mobile API', version: '3.1.0' },
    servers: [{ url: 'http://localhost:3001/api' }],
    components: {
      securitySchemes: { bearer: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' } },
      schemas: {
        Transfer: {
          type: 'object',
          required: ['from_account', 'to_account', 'amount_cents'],
          properties: {
            from_account: { type: 'string', example: '4002-1188-0001' },
            to_account: { type: 'string', example: '4002-1188-0002' },
            amount_cents: { type: 'integer', example: 2500 },
          },
        },
        UserPatch: {
          type: 'object',
          properties: {
            email: { type: 'string' }, full_name: { type: 'string' },
            phone: { type: 'string' }, address: { type: 'string' },
            role: { type: 'string', enum: ['customer', 'admin'], 'x-note': 'internal — set by staff only' },
            mfa_enabled: { type: 'boolean' },
          },
        },
        Batch: {
          type: 'object',
          properties: { ids: { type: 'array', items: { type: 'integer' }, example: [1, 2, 3] } },
        },
        RoleChange: {
          type: 'object',
          properties: { role: { type: 'string', enum: ['customer', 'admin'] } },
        },
      },
    },
    security: [{ bearer: [] }],
    paths: {
      '/login': { post: { summary: 'Exchange username/password for a bearer token', security: [] } },
      '/me': { get: { summary: 'The signed-in user (returns the full row)' } },
      '/users/{id}': {
        get: { summary: 'Read a user by id', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }] },
        put: {
          summary: 'Update a user',
          parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }],
          requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/UserPatch' } } } },
        },
      },
      '/accounts/{id}': { get: { summary: 'Read an account by id', parameters: [{ name: 'id', in: 'path', required: true, schema: { type: 'integer' } }] } },
      '/accounts/{id}/transfers': { get: { summary: 'Transactions for an account' } },
      '/batch': { post: { summary: 'Look up many users at once', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Batch' } } } } } },
      '/transfers': { post: { summary: 'Move money between accounts', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/Transfer' } } } } } },
      '/fx': { get: { summary: 'Convert an amount', parameters: [
        { name: 'to', in: 'query', schema: { type: 'string' } },
        { name: 'amount', in: 'query', schema: { type: 'number' } },
        { name: 'provider', in: 'query', schema: { type: 'string' }, description: 'rates feed URL' },
      ] } },
      '/admin/users': { get: { summary: 'List all users (staff)' } },
      '/admin/users/{id}/role': { post: { summary: 'Reassign a user role (staff)', requestBody: { content: { 'application/json': { schema: { $ref: '#/components/schemas/RoleChange' } } } } } },
      '/v1/users': { get: { summary: 'Legacy directory', security: [], 'x-note': 'legacy v1, unauthenticated \u2014 do not expose' } },
    },
  });
});

module.exports = router;
