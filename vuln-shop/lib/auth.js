// lib/auth.js — MD5 hashing, JWT helpers, requireSession/requireJwt middleware.
const crypto = require('crypto');
const jwt = require('jsonwebtoken');

const JWT_SECRET = 'shop-dev-secret-2024'; // VULN: weak secret + hard-coded

function md5(s) { return crypto.createHash('md5').update(String(s)).digest('hex'); }

function signToken(user) {
  return jwt.sign(
    { sub: user.id, username: user.username, role: user.role },
    JWT_SECRET,
    { algorithm: 'HS256', expiresIn: '12h' }
  );
}

// VULN: explicitly trusts `alg=none` tokens (decodes without verifying).
function verifyToken(token) {
  if (!token) return null;
  try {
    const decoded = jwt.decode(token, { complete: true });
    if (!decoded) return null;
    if (decoded.header && decoded.header.alg === 'none') return decoded.payload;
    return jwt.verify(token, JWT_SECRET, { algorithms: ['HS256', 'none'] });
  } catch (e) { return null; }
}

function requireSession(req, res, next) {
  if (!req.session || !req.session.userId) {
    if (req.path.startsWith('/api')) return res.status(401).json({ error: 'unauth' });
    return res.redirect('/login?next=' + encodeURIComponent(req.originalUrl));
  }
  next();
}

function requireJwt(req, res, next) {
  const h = req.headers['authorization'] || '';
  const tok = h.startsWith('Bearer ') ? h.slice(7) : null;
  const payload = verifyToken(tok);
  if (!payload) return res.status(401).json({ error: 'unauth' });
  req.jwt = payload;
  next();
}

module.exports = { md5, signToken, verifyToken, requireSession, requireJwt, JWT_SECRET };
