// routes/components.js -- A06 Vulnerable & Outdated Components sinks.
//
// The social lab bundles `js-yaml@3.13.0`. In 3.x the default `load()`
// function honours custom YAML types including `!!js/function`, which
// deserialises a JavaScript function from a string. If the parsed object
// has a function on a known property and the application later calls it,
// the attacker has remote code execution.

const express = require('express');
const yaml = require('js-yaml');

const router = express.Router();

// POST /components/import-profile
//
// Body: raw YAML (Content-Type: text/yaml or application/x-yaml).
// The lab "imports" a profile by parsing the YAML and immediately
// calling `bio()` (if it's a function) to render a personalised greeting.
router.post('/import-profile', express.text({ type: '*/*', limit: '32kb' }), (req, res) => {
  let profile;
  try {
    // VULN: `yaml.load()` (unsafe) -- accepts `!!js/function`, `!!js/regexp`,
    // `!!js/undefined` types. `safeLoad()` would have rejected them.
    profile = yaml.load(req.body || '');
  } catch (e) {
    return res.status(400).json({ error: 'YAML parse failed: ' + e.message });
  }
  if (!profile || typeof profile !== 'object') {
    return res.status(400).json({ error: 'YAML root must be an object' });
  }
  let greeting = 'Welcome';
  // VULN: blindly calls the function returned by yaml.load.
  if (typeof profile.bio === 'function') {
    try {
      greeting = String(profile.bio());
    } catch (e) {
      greeting = '(bio threw: ' + e.message + ')';
    }
  } else if (typeof profile.bio === 'string') {
    greeting = profile.bio;
  }
  res.type('text/plain').send(greeting + '\n');
});

// GET /components/version exposes the dependency tree.
router.get('/version', (req, res) => {
  const pkg = require('../package.json');
  res.json({
    app: 'Pulse Social',
    version: pkg.version,
    dependencies: pkg.dependencies,
    node: process.version,
  });
});

module.exports = router;
