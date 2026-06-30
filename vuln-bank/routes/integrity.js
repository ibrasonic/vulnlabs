// routes/integrity.js -- A08 Software & Data Integrity Failures sinks.
//
// The bank ships an internal "plugin install" facility that lets admins
// drop new modules into the running server without restarting. The
// facility accepts arbitrary JavaScript source over HTTP and require()s
// the saved file -- no signature, no checksum, no allow-list of
// publishers. Anyone who reaches the endpoint controls the server.

const express = require('express');
const fs = require('fs');
const path = require('path');

const router = express.Router();

const PLUGIN_DIR = path.join(__dirname, '..', 'data', 'plugins');
if (!fs.existsSync(PLUGIN_DIR)) fs.mkdirSync(PLUGIN_DIR, { recursive: true });

// VULN (B-INT-001): no signature verification on incoming code.
//   POST /admin/integrity/install
//   body: { "name": "hello-plugin", "code": "module.exports = { init: () => 42 };" }
// The bank trusts the supplied code, writes it to disk and `require()`s
// it. Plugins are expected to export an `init` function whose return
// value is sent back in the response, so the attacker gets a clean
// stdout channel for arbitrary code.
//
// In a real codebase this same pattern is the "auto-update" path: an
// external CI/CD process pushes a new build artefact, the application
// fetches it, writes it to disk and loads it. Missing signature +
// missing checksum = remote code execution from any party that can
// reach the update endpoint.
router.post('/install', express.json({ limit: '256kb' }), (req, res) => {
  const name = (req.body && req.body.name) || '';
  const code = (req.body && req.body.code) || '';
  if (!/^[A-Za-z0-9_-]{1,40}$/.test(name)) {
    return res.status(400).json({ error: 'invalid plugin name' });
  }
  if (!code) {
    return res.status(400).json({ error: 'empty code' });
  }
  const filePath = path.join(PLUGIN_DIR, name + '.js');
  fs.writeFileSync(filePath, code, 'utf8');
  // Bust the require cache so a re-install of the same name reloads.
  delete require.cache[require.resolve(filePath)];
  let plugin;
  try {
    plugin = require(filePath);
  } catch (e) {
    return res.status(500).json({ error: 'load failed: ' + e.message });
  }
  let initOutput = null;
  if (typeof plugin.init === 'function') {
    try {
      initOutput = plugin.init();
    } catch (e) {
      initOutput = '(init threw: ' + e.message + ')';
    }
  }
  res.json({ installed: name, init: initOutput });
});

// VULN (B-INT-002): "fetch a remote plugin by URL" -- no scheme or host
// allow-list, no certificate pinning, no checksum check.
router.get('/list', (req, res) => {
  const files = fs.readdirSync(PLUGIN_DIR).filter(f => f.endsWith('.js'));
  res.json({ plugins: files });
});

module.exports = router;
