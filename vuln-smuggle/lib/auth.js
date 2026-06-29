// lib/auth.js - session helpers + role guard for NovaPress.
const crypto = require('crypto');

const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || 'NP-INTERNAL-2026';
const ADMIN_FLAG    = 'AccessibleBBB{smuggle-bypass-frontend-acl}';
const DRAFT_FLAG    = 'AccessibleBBB{smuggle-leak-unpublished-draft}';
const CAPTURE_FLAG  = 'AccessibleBBB{smuggle-capture-subscriber-cookie}';
const CACHE_FLAG    = 'AccessibleBBB{smuggle-cache-poison-homepage}';
const QUEUE_FLAG    = 'AccessibleBBB{smuggle-response-queue-poison}';

function md5(s) { return crypto.createHash('md5').update(String(s)).digest('hex'); }

function genToken() {
  return 'np_' + crypto.randomBytes(16).toString('hex');
}

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

function requireTier(min) {
  // Tier order: reader < subscriber < author < editor < admin.
  // Anyone at or above `min` passes. Note: trusts req.session.tier OR the
  // back-end-trusted internal header X-User-Tier (see backend.js for why
  // that header is dangerous when smuggling is possible).
  const order = { reader: 0, subscriber: 1, author: 2, editor: 3, admin: 4 };
  return function (req, res, next) {
    let tier = (req.session && req.session.tier) || 'reader';
    // VULN: the back-end honors X-User-Tier from "trusted" upstream. Real
    // CDNs are supposed to strip this on inbound. The gateway in this lab
    // DOES strip it on the parsed front-end channel, but smuggled requests
    // arrive untouched, so an attacker can forge tier escalation.
    const injected = req.headers['x-user-tier'];
    if (injected && order[injected] !== undefined) tier = injected;
    if ((order[tier] ?? -1) >= order[min]) {
      req.effectiveTier = tier;
      return next();
    }
    if (req.path.startsWith('/api/')) {
      return res.status(403).json({ error: 'forbidden', need: min, have: tier });
    }
    return res.status(403).render('error', {
      code: 403, message: 'You need a "' + min + '" account to view this.'
    });
  };
}

function requireInternal(req, res, next) {
  // The gateway is meant to be the ONLY caller able to set this header.
  // Real CDNs strip on ingress. Smuggled requests bypass that.
  if (req.headers['x-internal-auth'] === INTERNAL_TOKEN) return next();
  return res.status(403).type('text').send('forbidden (internal)\n');
}

module.exports = {
  md5, genToken,
  requireSession, requireTier, requireInternal,
  INTERNAL_TOKEN,
  FLAGS: { ADMIN: ADMIN_FLAG, DRAFT: DRAFT_FLAG, CAPTURE: CAPTURE_FLAG, CACHE: CACHE_FLAG, QUEUE: QUEUE_FLAG }
};
