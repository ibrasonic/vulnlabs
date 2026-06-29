// lib/cache.js — naive edge-style in-process cache (Ch 28 sink).
//
// VULN: cache key is METHOD + URL only.
//   - Vary header is IGNORED.
//   - Cookies and Authorization are IGNORED.
//   - Any header reflected into the response body becomes a public payload.
//
// VULN: any URL whose path ends in .css / .js / .png / .svg / .ico is
// treated as "static" and force-cached for 60 s, EVEN IF the route
// behind it returned auth-protected HTML (web cache deception sink).
//
// TTL 30 s for normal GETs, 60 s for force-cached extensions.
// `?_cb=<anything>` bypasses both read and write (cache-buster).

const store = new Map(); // key -> { status, headers, body, expires }
const NORMAL_TTL_MS = 30 * 1000;
const STATIC_TTL_MS = 60 * 1000;
const FORCE_CACHE_RE = /\.(css|js|png|svg|ico)(?:\?|$)/i;
const MAX_BODY = 1 * 1024 * 1024; // 1 MB

function keyFor(req) {
  // VULN: key does NOT include host, cookies, or any Vary headers.
  return req.method + ' ' + req.originalUrl.split('?')[0] +
         (req.originalUrl.includes('?_cb=') ? '' :
          (req.originalUrl.includes('?') ? req.originalUrl.slice(req.originalUrl.indexOf('?')) : ''));
}

function isBypass(req) {
  return /\?(?:.*&)?_cb=/.test(req.originalUrl);
}

function isForceCache(req) {
  return FORCE_CACHE_RE.test(req.originalUrl);
}

module.exports = function cacheMiddleware(req, res, next) {
  if (req.method !== 'GET') {
    res.setHeader('X-Cache', 'BYPASS');
    return next();
  }
  if (isBypass(req)) {
    res.setHeader('X-Cache', 'BYPASS');
    return next();
  }

  const key = keyFor(req);
  const hit = store.get(key);
  if (hit && hit.expires > Date.now()) {
    res.setHeader('X-Cache', 'HIT');
    res.setHeader('Age', String(Math.round((Date.now() - hit.stored) / 1000)));
    for (const [h, v] of Object.entries(hit.headers)) res.setHeader(h, v);
    res.status(hit.status).send(hit.body);
    return;
  }

  res.setHeader('X-Cache', 'MISS');

  const chunks = [];
  const origWrite = res.write.bind(res);
  const origEnd = res.end.bind(res);
  res.write = function (chunk, ...rest) {
    if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    return origWrite(chunk, ...rest);
  };
  res.end = function (chunk, ...rest) {
    if (chunk) chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
    const body = Buffer.concat(chunks);
    try {
      const cc = String(res.getHeader('Cache-Control') || '');
      const forceCache = isForceCache(req);
      const cacheable = (
        res.statusCode === 200 &&
        body.length <= MAX_BODY &&
        (forceCache || /max-age=\d+|public/i.test(cc))
      );
      if (cacheable) {
        const ttl = forceCache ? STATIC_TTL_MS : NORMAL_TTL_MS;
        const headers = {};
        for (const h of ['content-type', 'content-language', 'link', 'x-canonical-host']) {
          const v = res.getHeader(h);
          if (v !== undefined) headers[h] = v;
        }
        store.set(key, {
          status: res.statusCode,
          headers, body,
          stored: Date.now(),
          expires: Date.now() + ttl
        });
      }
    } catch (_) {}
    return origEnd(chunk, ...rest);
  };
  next();
};

module.exports.clear = () => store.clear();
module.exports.size = () => store.size;
