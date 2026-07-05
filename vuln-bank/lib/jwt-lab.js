// lib/jwt-lab.js — "NovaTrust Partner API v2" token verification.
//
// This models a partner/mobile service that migrated from the HS256 tokens in
// lib/auth.js to RS256 with a published JWKS. The verifier is DELIBERATELY
// vulnerable in the four classic ways a real RS256/JWKS verifier goes wrong:
//   A. It trusts an embedded `jwk` public key carried IN the token header.
//   B. It fetches the JWK Set from the token's `jku` URL (SSRF, no allow-list).
//   C. It reads an HMAC key FILE named by the token's `kid` (path traversal;
//      kid=../../../../dev/null yields an EMPTY key, so HMAC("") forges it).
//   D. It accepts BOTH RS256 and HS256 and verifies with the server's PUBLIC
//      key -> HS256-of-public-key algorithm confusion.
// Verification is implemented with `crypto` directly so each flaw is exact and
// does not depend on the installed jsonwebtoken version.
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

// Server RSA keypair, generated once at boot. The PUBLIC half is published at
// /api/v2/.well-known/jwks.json — which is exactly what enables attack D.
const { publicKey, privateKey } = crypto.generateKeyPairSync('rsa', {
  modulusLength: 2048,
  publicKeyEncoding:  { type: 'spki',  format: 'pem' },
  privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
});
const KID = 'novatrust-partner-2026';

// A directory of named HMAC signing keys, looked up by the token's `kid`.
const KEYS_DIR = path.join(__dirname, '..', 'data', 'jwt-keys');
try {
  fs.mkdirSync(KEYS_DIR, { recursive: true });
  const f = path.join(KEYS_DIR, 'partner-hmac');
  if (!fs.existsSync(f)) fs.writeFileSync(f, crypto.randomBytes(32).toString('hex'));
} catch (_) { /* best effort */ }

const b64url = (buf) => Buffer.from(buf).toString('base64url');
const decodeSeg = (s) => JSON.parse(Buffer.from(s, 'base64url').toString('utf8'));

// The JWK form of the server's public key, for the JWKS endpoint.
function publicJwk() {
  const jwk = crypto.createPublicKey(publicKey).export({ format: 'jwk' });
  return { ...jwk, use: 'sig', alg: 'RS256', kid: KID };
}

// Issue a normal RS256 token (the legitimate path).
function signV2(claims) {
  const header = { alg: 'RS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const payload = { ...claims, iss: 'novatrust-partner', iat: now, exp: now + 3600 };
  const input = b64url(JSON.stringify(header)) + '.' + b64url(JSON.stringify(payload));
  const sig = crypto.createSign('RSA-SHA256').update(input).sign(privateKey);
  return input + '.' + sig.toString('base64url');
}

function verifyRS256(input, sigB64, pubPem) {
  try {
    return crypto.createVerify('RSA-SHA256').update(input)
      .verify(pubPem, Buffer.from(sigB64, 'base64url'));
  } catch (_) { return false; }
}
function verifyHS256(input, sigB64, secret) {
  const expected = crypto.createHmac('sha256', secret).update(input).digest();
  const got = Buffer.from(sigB64, 'base64url');
  return expected.length === got.length && crypto.timingSafeEqual(expected, got);
}

// The vulnerable verifier. Precedence follows a real "honour whatever the
// header asks for" middleware: jwk -> jku -> kid -> alg.
async function verifyV2(token) {
  const parts = String(token || '').split('.');
  if (parts.length !== 3) return null;
  let header, payload;
  try { header = decodeSeg(parts[0]); payload = decodeSeg(parts[1]); }
  catch (_) { return null; }
  const input = parts[0] + '.' + parts[1];

  // A. Embedded JWK — trust a public key the TOKEN itself carries.
  if (header.jwk) {
    try {
      const pem = crypto.createPublicKey({ key: header.jwk, format: 'jwk' })
        .export({ type: 'spki', format: 'pem' });
      return verifyRS256(input, parts[2], pem) ? payload : null;
    } catch (_) { return null; }
  }
  // B. jku — fetch the JWK Set from the URL named IN THE TOKEN (SSRF, no allow-list).
  if (header.jku) {
    try {
      const set = await (await fetch(header.jku)).json();
      const jwkKey = (set.keys || [])[0];
      const pem = crypto.createPublicKey({ key: jwkKey, format: 'jwk' })
        .export({ type: 'spki', format: 'pem' });
      return verifyRS256(input, parts[2], pem) ? payload : null;
    } catch (_) { return null; }
  }
  // C. kid — read the HMAC key FILE named by kid, with no sanitisation.
  if (header.kid) {
    let secret;
    try { secret = fs.readFileSync(path.join(KEYS_DIR, header.kid)); }
    catch (_) { return null; }
    return verifyHS256(input, parts[2], secret) ? payload : null;
  }
  // D. Algorithm confusion — accept RS256 AND HS256, verifying with the PUBLIC key.
  if (header.alg === 'RS256') return verifyRS256(input, parts[2], publicKey) ? payload : null;
  if (header.alg === 'HS256') return verifyHS256(input, parts[2], publicKey) ? payload : null;
  return null;
}

async function requireJwtV2(req, res, next) {
  const auth = req.headers.authorization || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const claims = await verifyV2(token);
  if (!claims) return res.status(401).json({ error: 'invalid token' });
  req.jwt = claims;
  next();
}

module.exports = {
  publicKey, privateKey, KID, KEYS_DIR,
  publicJwk, signV2, verifyV2, requireJwtV2,
};
