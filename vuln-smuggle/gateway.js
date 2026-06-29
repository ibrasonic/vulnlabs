// gateway.js - "Argus Edge", the legacy reverse-proxy in front of NovaPress.
//
// This is the real, intentionally-buggy front-end of the lab. It is written
// from raw TCP and does its own HTTP/1.1 parsing. The bug:
//
//   - Argus Edge frames request bodies using Content-Length ONLY.
//     Transfer-Encoding: chunked is not implemented; the header is left
//     in the headers list and forwarded verbatim (as proxies routinely
//     do for headers they do not recognise).
//
// The back-end on 127.0.0.1:3094 is a real Node HTTP server running with
// `insecureHTTPParser: true`, which accepts requests carrying BOTH
// Content-Length and Transfer-Encoding: chunked and, per RFC 7230,
// processes them as chunked. The two parsers therefore disagree about
// where the body ends - the classical CL.TE desync. See VULNERABILITIES.txt.
//
// The edge ALSO does:
//   - path-based ACL: /cms and /admin are 403'd on public ingress;
//   - inbound header strip: X-Internal-Auth, X-User-Tier, X-User-Id,
//     X-Request-ID are removed from anything an external client supplies;
//   - upstream header inject: the gateway adds X-Forwarded-For, X-Request-ID,
//     X-Internal-Auth on upstream traffic so the back-end can trust the
//     edge has authenticated the path;
//   - a tiny in-memory response cache for GET /, /article/*, /category/*
//     with a 30 s TTL (the cache-poisoning sink);
//   - upstream connection pooling. POOL_SIZE defaults to 1 to make the
//     response-queue desync directly observable. Production proxies use
//     larger pools, and the same desync still poisons any client
//     multiplexed onto the affected upstream socket.
const net = require('net');
const crypto = require('crypto');

const HOST       = process.env.GW_HOST || '0.0.0.0';
const PORT       = parseInt(process.env.GW_PORT || '3004', 10);
const UP_HOST    = process.env.UP_HOST || '127.0.0.1';
const UP_PORT    = parseInt(process.env.UP_PORT || '3094', 10);
const INTERNAL_TOKEN = process.env.INTERNAL_TOKEN || 'NP-INTERNAL-2026';
const POOL_SIZE  = parseInt(process.env.GW_POOL || '1', 10);
const CACHE_TTL_MS = parseInt(process.env.GW_CACHE_TTL || '30000', 10);

const STRIP_INBOUND = new Set([
  'x-internal-auth', 'x-user-tier', 'x-user-id', 'x-request-id'
]);
const BLOCKED_PREFIXES = ['/cms', '/admin'];

const cache = new Map();                  // key -> { expires, bytes }
const pool = new Array(POOL_SIZE).fill(null);
let   poolRR = 0;

function pickSlotIdx() { const i = poolRR; poolRR = (poolRR + 1) % POOL_SIZE; return i; }

// ---------------------------------------------------------------------------
// Upstream connection pool.

function getOrConnectSlot(idx) {
  let slot = pool[idx];
  if (slot && slot.sock && !slot.sock.destroyed) return slot;
  slot = {
    sock: null, buf: Buffer.alloc(0),
    waiting: [],         // FIFO of { client, cacheKey }
    orphanQueue: [],     // responses for which no waiter existed
    pendingForwards: [], // bytes queued before connect resolves
    connected: false
  };
  pool[idx] = slot;
  slot.sock = net.connect(UP_PORT, UP_HOST, () => {
    slot.connected = true;
    for (const f of slot.pendingForwards) slot.sock.write(f);
    slot.pendingForwards = [];
  });
  slot.sock.setKeepAlive(true);
  slot.sock.on('data', (chunk) => onUpstreamData(slot, chunk));
  slot.sock.on('close', () => {
    for (const w of slot.waiting) {
      if (w.client && !w.client.destroyed) writeError(w.client, 502, 'upstream closed\n');
    }
    pool[idx] = null;
  });
  slot.sock.on('error', (e) => console.error('[gw] upstream: ' + e.message));
  return slot;
}

function onUpstreamData(slot, chunk) {
  slot.buf = Buffer.concat([slot.buf, chunk]);
  while (true) {
    const r = parseResponse(slot.buf);
    if (!r) return;
    if (r.bad) {
      console.warn('[gw] upstream protocol error, dropping connection');
      slot.sock.destroy();
      return;
    }
    slot.buf = slot.buf.slice(r.total);
    const w = slot.waiting.shift();
    if (w && !w.client.destroyed) {
      w.client.write(r.raw);
      if (w.cacheKey) {
        cache.set(w.cacheKey, { expires: Date.now() + CACHE_TTL_MS, bytes: r.raw });
      }
    } else {
      // Orphan: the back-end emitted more responses than the gateway sent
      // requests on this socket. Classic response-queue desync.
      slot.orphanQueue.push(r.raw);
    }
  }
}

// ---------------------------------------------------------------------------
// HTTP/1.1 parsing - CL-only on request side; CL-only on response side.

function parseRequest(buf) {
  const headerEnd = buf.indexOf('\r\n\r\n');
  if (headerEnd < 0) return null;
  const block = buf.slice(0, headerEnd).toString('latin1');
  const lines = block.split('\r\n');
  const reqLine = (lines.shift() || '').split(' ');
  if (reqLine.length < 3) return { bad: true };
  const headerPairs = [];
  let cl = 0;
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const name  = line.slice(0, idx);
    const value = line.slice(idx + 1).trim();
    headerPairs.push([name, value]);
    if (name.trim().toLowerCase() === 'content-length') {
      const n = parseInt(value, 10);
      if (Number.isFinite(n) && n >= 0) cl = n;
    }
    // Transfer-Encoding is intentionally NOT consulted. That is the bug.
  }
  const total = headerEnd + 4 + cl;
  if (buf.length < total) return null;
  return {
    method: reqLine[0], path: reqLine[1], httpVer: reqLine[2],
    headerPairs,
    body: buf.slice(headerEnd + 4, total),
    raw:  buf.slice(0, total),
    rest: buf.slice(total),
    cl
  };
}

function parseResponse(buf) {
  const headerEnd = buf.indexOf('\r\n\r\n');
  if (headerEnd < 0) return null;
  const block = buf.slice(0, headerEnd).toString('latin1');
  const lines = block.split('\r\n');
  const statusLine = lines.shift() || '';
  const m = /^HTTP\/1\.[01] (\d{3})/.exec(statusLine);
  if (!m) return { bad: true };
  const status = parseInt(m[1], 10);
  const headers = {};
  for (const line of lines) {
    const idx = line.indexOf(':');
    if (idx < 0) continue;
    const n = line.slice(0, idx).trim().toLowerCase();
    const v = line.slice(idx + 1).trim();
    headers[n] = headers[n] === undefined ? v : headers[n] + ', ' + v;
  }
  if (headers['transfer-encoding']) return { bad: true };
  if (status === 204 || status === 304 || (status >= 100 && status < 200)) {
    return { total: headerEnd + 4, status, headers, raw: buf.slice(0, headerEnd + 4) };
  }
  const cl = parseInt(headers['content-length'] || '0', 10) || 0;
  const total = headerEnd + 4 + cl;
  if (buf.length < total) return null;
  return { total, status, headers, raw: buf.slice(0, total) };
}

// ---------------------------------------------------------------------------
// Request forwarding.

function buildForward(parsed, clientIp) {
  const reqId = crypto.randomBytes(4).toString('hex');
  const out = [];
  out.push(parsed.method + ' ' + parsed.path + ' ' + parsed.httpVer);
  for (const [name, value] of parsed.headerPairs) {
    if (STRIP_INBOUND.has(name.trim().toLowerCase())) continue;
    out.push(name + ': ' + value);
  }
  out.push('X-Forwarded-For: ' + clientIp);
  out.push('X-Forwarded-Proto: http');
  out.push('X-Request-ID: ' + reqId);
  out.push('X-Internal-Auth: ' + INTERNAL_TOKEN);
  const head = Buffer.from(out.join('\r\n') + '\r\n\r\n', 'latin1');
  return Buffer.concat([head, parsed.body]);
}

function cacheKeyFor(parsed) {
  if (parsed.method !== 'GET') return null;
  if (parsed.path === '/' ||
      parsed.path.startsWith('/article/') ||
      parsed.path.startsWith('/category/') ||
      parsed.path.startsWith('/static/')) {
    return parsed.method + ' ' + parsed.path;
  }
  return null;
}

function writeError(client, code, body) {
  if (client.destroyed) return;
  const b = Buffer.from(body || '', 'utf8');
  const head =
    'HTTP/1.1 ' + code + ' edge\r\n' +
    'Server: Argus-Edge/0.7\r\n' +
    'Content-Type: text/plain; charset=utf-8\r\n' +
    'Content-Length: ' + b.length + '\r\n' +
    'Connection: keep-alive\r\n\r\n';
  client.write(Buffer.from(head, 'latin1'));
  client.write(b);
}

const NULL_SINK = Object.freeze({ destroyed: true, write() {} });

// ---------------------------------------------------------------------------
// Client handler.

function handleClient(client) {
  let buf = Buffer.alloc(0);
  const clientIp = (client.remoteAddress || '0.0.0.0').replace('::ffff:', '');
  client.on('data', (chunk) => {
    buf = Buffer.concat([buf, chunk]);
    while (true) {
      const parsed = parseRequest(buf);
      if (!parsed) return;
      if (parsed.bad) { client.destroy(); return; }
      buf = parsed.rest;
      dispatch(client, parsed, clientIp);
    }
  });
  client.on('error', () => {});
}

function dispatch(client, parsed, clientIp) {
  // 1) Public-ingress path ACL.
  for (const pfx of BLOCKED_PREFIXES) {
    if (parsed.path === pfx || parsed.path.startsWith(pfx + '/') ||
        parsed.path.startsWith(pfx + '?')) {
      return writeError(client, 403,
        'Forbidden by Argus Edge.\n' +
        'Path ' + parsed.path + ' is reserved for internal traffic.\n');
    }
  }

  // 2) Cache hit?
  const ckey = cacheKeyFor(parsed);
  if (ckey) {
    const hit = cache.get(ckey);
    if (hit && hit.expires > Date.now()) {
      if (!client.destroyed) client.write(hit.bytes);
      return;
    }
  }

  // 3) Forward to upstream.
  const slot = getOrConnectSlot(pickSlotIdx());
  const fwd  = buildForward(parsed, clientIp);

  // Response-queue desync: any orphan response from the previous round is
  // delivered to THIS client first. The user's own request is still
  // forwarded; its real response will become the next orphan.
  if (slot.orphanQueue.length) {
    const orphan = slot.orphanQueue.shift();
    if (!client.destroyed) client.write(orphan);
    slot.waiting.push({ client: NULL_SINK, cacheKey: null });
  } else {
    slot.waiting.push({ client, cacheKey: ckey });
  }
  if (slot.connected && slot.sock && slot.sock.writable) {
    slot.sock.write(fwd);
  } else {
    slot.pendingForwards.push(fwd);
  }
}

// ---------------------------------------------------------------------------

net.createServer(handleClient).listen(PORT, HOST, () => {
  console.log('[gateway] Argus Edge ' + HOST + ':' + PORT + ' -> ' + UP_HOST + ':' + UP_PORT);
  console.log('[gateway] pool size: ' + POOL_SIZE + '   cache ttl: ' + CACHE_TTL_MS + ' ms');
  console.log('[gateway] CL-only parser. Transfer-Encoding is NOT honoured.');
});
