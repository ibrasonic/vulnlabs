// routes/integrity.js -- A08 Software supply-chain / data-integrity sinks.
//
// The bank ships an internal "extension marketplace" that lets staff drop a
// new module into the running server without a redeploy. It accepts
// JavaScript source -- pasted directly OR fetched from a URL -- writes it to
// disk and require()s it. There is no signature, no checksum, no allow-list
// of publishers, no SBOM. The bank runs third-party code whose provenance it
// never verified: the software-supply-chain failure made concrete. Anyone who
// reaches the endpoint controls the server.
//
// In a real codebase this same pattern is the "auto-update" path: a CI/CD
// process (or a package registry) hands the app a new build artefact, the app
// fetches it, writes it to disk and loads it. Missing signature + missing
// checksum = remote code execution from any party who can influence the source.

const express = require('express');
const fs = require('fs');
const path = require('path');
const fetch = require('node-fetch');

const router = express.Router();

const PLUGIN_DIR = path.join(__dirname, '..', 'data', 'plugins');
if (!fs.existsSync(PLUGIN_DIR)) fs.mkdirSync(PLUGIN_DIR, { recursive: true });

// The core sink: trust the bytes, write them, run them. No signature check,
// no checksum, no provenance check -- just require() the supplied source.
function installPlugin(name, code) {
  if (!/^[A-Za-z0-9_-]{1,40}$/.test(name)) throw new Error('invalid plugin name');
  if (!code) throw new Error('empty code');
  const filePath = path.join(PLUGIN_DIR, name + '.js');
  fs.writeFileSync(filePath, code, 'utf8');
  delete require.cache[require.resolve(filePath)];   // reload on re-install
  const plugin = require(filePath);                  // <-- executes attacker code
  let initOutput = null;
  if (typeof plugin.init === 'function') {
    try { initOutput = plugin.init(); } catch (e) { initOutput = '(init threw: ' + e.message + ')'; }
  }
  return initOutput;
}

function listPlugins() {
  return fs.readdirSync(PLUGIN_DIR).filter(f => f.endsWith('.js'));
}

function wantsJson(req) {
  return req.is('application/json') || (req.get('accept') || '').includes('application/json');
}

// UI ENTRY POINT (discoverable from the admin panel): the extension marketplace.
router.get('/', (req, res) => {
  res.render('integrity', {
    plugins: listPlugins(),
    result: req.query.out !== undefined ? { name: req.query.installed || '', output: req.query.out } : null,
    error: req.query.err || ''
  });
});

// VULN (B-INT-001): unsigned code install. Serves the JSON API *and* the
// marketplace "paste code" form (the global body parsers handle both shapes).
router.post('/install', (req, res) => {
  const name = (req.body && req.body.name) || '';
  const code = (req.body && req.body.code) || '';
  let out;
  try {
    out = installPlugin(name, code);
  } catch (e) {
    if (wantsJson(req)) return res.status(400).json({ error: e.message });
    return res.redirect('/admin/integrity/?err=' + encodeURIComponent(e.message));
  }
  if (wantsJson(req)) return res.json({ installed: name, init: out });
  return res.redirect('/admin/integrity/?installed=' + encodeURIComponent(name) +
                      '&out=' + encodeURIComponent(String(out)));
});

// VULN (B-INT-002): fetch a plugin from a URL and run it -- no scheme/host
// allow-list, no TLS pinning, no checksum. This is the "auto-update from the
// registry / CI artefact URL" path: whoever controls (or spoofs) that URL runs
// code on the bank.
router.post('/install-url', async (req, res) => {
  const name = (req.body && req.body.name) || '';
  const url = (req.body && req.body.url) || '';
  try {
    const r = await fetch(url, { timeout: 5000 });
    const code = await r.text();                       // trust whatever bytes come back
    const out = installPlugin(name, code);
    if (wantsJson(req)) return res.json({ installed: name, source: url, init: out });
    return res.redirect('/admin/integrity/?installed=' + encodeURIComponent(name) +
                        '&out=' + encodeURIComponent(String(out)));
  } catch (e) {
    if (wantsJson(req)) return res.status(500).json({ error: e.message });
    return res.redirect('/admin/integrity/?err=' + encodeURIComponent(e.message));
  }
});

// List installed extensions.
router.get('/list', (req, res) => {
  res.json({ plugins: listPlugins() });
});

module.exports = router;
