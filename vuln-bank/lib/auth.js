// lib/auth.js — Auth helpers.
// VULN: MD5 unsalted password hashing.
// VULN: JWT signed with HS256 using a weak secret; alg=none is also accepted.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

// Hard-coded weak secret. Real apps would load from env/secrets manager.
const JWT_SECRET = 'bank-dev-secret-2024';

function md5(s) {
  return crypto.createHash('md5').update(s).digest('hex');
}

function signToken(payload) {
  return jwt.sign(payload, JWT_SECRET, { algorithm: 'HS256', expiresIn: '7d' });
}

// VULN: explicitly accepts `alg: none` if the token is unsigned. We mimic
// the classic jsonwebtoken < 4.2.2 misuse by calling jwt.decode (which doesn't
// verify) when the token's alg header is "none". Real misconfigured services
// do the same when they pass `algorithms` containing "none".
function verifyToken(token) {
  if (!token) return null;
  try {
    const parts = token.split('.');
    if (parts.length !== 3) return null;
    const headerJson = Buffer.from(parts[0], 'base64').toString('utf8');
    const header = JSON.parse(headerJson);

    if (header.alg === 'none') {
      // VULN: trust the unsigned payload
      return jwt.decode(token);
    }
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
  } catch (e) {
    return null;
  }
}

// Session-based middleware (most pages). Sets req.user from session.
function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

// JWT-based middleware (API routes under /api).
function requireJwt(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const decoded = verifyToken(token);
  if (!decoded) return res.status(401).json({ error: 'invalid token' });
  req.jwt = decoded;
  next();
}

module.exports = { md5, signToken, verifyToken, requireSession, requireJwt, JWT_SECRET };
