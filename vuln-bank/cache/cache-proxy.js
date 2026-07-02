// cache-proxy.js — a deliberately MISCONFIGURED caching reverse proxy.
//
// It fronts the bank (TARGET) and caches GET responses keyed ONLY on the
// request path (req.url). Host, X-Forwarded-Host and Cookie are NOT part of
// the cache key. That is the classic web-cache-poisoning setup: an "unkeyed"
// request header that still changes the response.
//
// The bank's GET /admin builds a `Link: <https://${X-Forwarded-Host}/admin>;
// rel="canonical"` response header from the attacker-controlled
// X-Forwarded-Host (routes/admin.js). Because this cache does not vary on that
// header, an attacker can prime the entry for `/admin` with a poisoned Link
// (or a rel="preload"; as="script" break-out) and every later visitor to the
// same path is served the stored, poisoned response. See Chapter 12.
//
// Dependency-free (Node built-in http only) so it builds and boots instantly.
const http = require('http');

const TARGET = process.env.TARGET || 'http://localhost:3001';
const PORT = parseInt(process.env.PORT || '8001', 10);
const TTL_MS = parseInt(process.env.CACHE_TTL_MS || '30000', 10);
const target = new URL(TARGET);

// key: req.url  ->  { status, headers, body, expires }
const cache = new Map();

const server = http.createServer((req, res) => {
  const key = req.url; // VULN: path only — Host / X-Forwarded-Host / Cookie are NOT in the key.
  const cacheable = req.method === 'GET';

  if (cacheable) {
    const hit = cache.get(key);
    if (hit && hit.expires > Date.now()) {
      res.writeHead(hit.status, Object.assign({}, hit.headers, { 'x-cache': 'HIT' }));
      res.end(hit.body);
      return;
    }
  }

  // Forward to the origin, preserving the client's headers (incl. X-Forwarded-Host).
  const opts = {
    protocol: target.protocol,
    hostname: target.hostname,
    port: target.port || 80,
    method: req.method,
    path: req.url,
    headers: Object.assign({}, req.headers, { host: target.host }),
  };

  const up = http.request(opts, (ur) => {
    const chunks = [];
    ur.on('data', (c) => chunks.push(c));
    ur.on('end', () => {
      const body = Buffer.concat(chunks);
      const headers = Object.assign({}, ur.headers);
      // A shared cache must not replay one user's Set-Cookie to the next.
      delete headers['set-cookie'];
      // We buffer the whole body, so normalise framing headers.
      delete headers['transfer-encoding'];
      headers['content-length'] = String(body.length);

      if (cacheable && ur.statusCode === 200) {
        cache.set(key, {
          status: 200,
          headers: Object.assign({}, headers),
          body,
          expires: Date.now() + TTL_MS,
        });
      }
      res.writeHead(ur.statusCode, Object.assign({}, headers, { 'x-cache': 'MISS' }));
      res.end(body);
    });
  });

  up.on('error', (e) => {
    res.writeHead(502, { 'content-type': 'text/plain' });
    res.end('cache upstream error: ' + e.message);
  });

  if (req.method === 'POST' || req.method === 'PUT' || req.method === 'PATCH' || req.method === 'DELETE') {
    req.pipe(up);
  } else {
    up.end();
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[cache] misconfigured cache proxy on :${PORT} -> ${TARGET}  (key = path only, TTL ${TTL_MS}ms)`);
});
