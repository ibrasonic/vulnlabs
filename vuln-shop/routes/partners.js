// routes/partners.js — B2B partner portal API (Northwind Outfitters).
//
// VULN (S-INJ-001): NoSQL (MongoDB-shape) injection.
//
// The partner records live in an in-memory document collection queried with a
// MongoDB-style operator language. The JSON login endpoint passes the request
// body straight into the query as the match conditions, so a client can send
// query *operators* instead of plain strings:
//
//   { "username": { "$ne": null }, "password": { "$ne": null } }
//   { "username": "northwind_ops", "password": { "$gt": "" } }
//   { "username": { "$regex": "^a" }, "password": { "$ne": null } }
//   { "username": { "$gt": "" }, "password": { "$where": "1==1" } }
//
// Each operator is evaluated by the document store exactly as a real Mongo
// driver would, so an unauthenticated caller logs in as the first matching
// partner (the internal admin account) and the $where operator runs arbitrary
// JavaScript on the server.
//
// The fix is to coerce types at the boundary — String(req.body.username) — so
// the driver only ever sees a string, never an operator object. See Ch 12.
const express = require('express');
const router = express.Router();

// In-memory partner collection (the "documents").
const PARTNERS = [
  { _id: 1, username: 'acme_supply',   password: 'Acme!Wholesale7', company: 'Acme Supply Co.',        role: 'partner', api_key: 'pk_live_acme_4f1c8e02',   payout_iban: 'DE89370400440532013000' },
  { _id: 2, username: 'northwind_ops', password: 'OpsRootKey!2024', company: 'Northwind Internal Ops', role: 'admin',   api_key: 'pk_live_root_9a2b71f5',   payout_iban: 'US64SVBKUS6S3300958879' },
  { _id: 3, username: 'cascade_textiles', password: 'Casc@de2025',  company: 'Cascade Textiles Ltd',   role: 'partner', api_key: 'pk_live_casc_2d6004ab',   payout_iban: 'GB29NWBK60161331926819' },
  { _id: 4, username: 'summit_logistics', password: 'Summ1t!Ship',  company: 'Summit Logistics',       role: 'partner', api_key: 'pk_live_summ_77e1c930',   payout_iban: 'FR7630006000011234567890189' },
];

// --- Minimal MongoDB-style query evaluator -------------------------------
// Supports exactly the operators a JSON body can reach in a real driver.
function matchCondition(actual, cond) {
  if (cond !== null && typeof cond === 'object' && !Array.isArray(cond)) {
    return Object.keys(cond).every((op) => {
      const val = cond[op];
      switch (op) {
        case '$eq':  return actual === val;
        case '$ne':  return actual !== val;
        case '$gt':  return actual > val;
        case '$gte': return actual >= val;
        case '$lt':  return actual < val;
        case '$lte': return actual <= val;
        case '$in':  return Array.isArray(val) && val.indexOf(actual) !== -1;
        case '$nin': return Array.isArray(val) && val.indexOf(actual) === -1;
        case '$regex': return new RegExp(val, cond.$options || '').test(String(actual));
        case '$options': return true; // consumed by $regex
        default: return false;        // unknown operator never matches
      }
    });
  }
  // Plain value -> equality.
  return actual === cond;
}

function matchDocument(doc, query) {
  return Object.keys(query).every((field) => {
    if (field === '$where') {
      // VULN: server-side JavaScript evaluation, just like Mongo's $where.
      // `this` and bare field names both refer to the document.
      try {
        return Function('doc', `with (doc) { return (${query.$where}); }`).call(doc, doc);
      } catch (_) { return false; }
    }
    return matchCondition(doc[field], query[field]);
  });
}

function find(query) {
  return PARTNERS.filter((doc) => matchDocument(doc, query));
}

function publicView(p) {
  return { username: p.username, company: p.company, role: p.role, api_key: p.api_key };
}

// Landing page with a JSON-posting login form.
router.get('/', (req, res) => {
  res.render('partner', { result: null });
});

// VULN: JSON body fields used directly as query conditions.
router.post('/login', (req, res) => {
  const query = {
    username: req.body.username,
    password: req.body.password,
  };
  let matches = [];
  try {
    matches = find(query);
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }
  if (!matches.length) {
    return res.status(401).json({ ok: false, error: 'invalid partner credentials' });
  }
  const p = matches[0];
  req.session.partnerId = p._id;
  req.session.partnerRole = p.role;
  return res.json({
    ok: true,
    matched: matches.length,
    partner: publicView(p),
  });
});

// VULN: arbitrary JSON filter used to query the collection — data extraction
// and enumeration with $regex / $gt / $where.
router.post('/find', (req, res) => {
  const filter = (req.body && typeof req.body.filter === 'object') ? req.body.filter : (req.body || {});
  let matches = [];
  try {
    matches = find(filter);
  } catch (e) {
    return res.status(400).json({ ok: false, error: e.message });
  }
  return res.json({
    ok: true,
    count: matches.length,
    partners: matches.map(publicView),
  });
});

module.exports = router;
