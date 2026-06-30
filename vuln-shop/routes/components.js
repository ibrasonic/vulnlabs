// routes/components.js -- A06 Vulnerable & Outdated Components sinks.
//
// The shop bundles `marked@0.3.6` which has multiple known XSS issues
// (CVE-2017-1000427 style, raw-HTML pass-through, and the `sanitize: true`
// flag does not catch every vector). Anything we feed to marked is
// trusted by the browser as authored HTML.

const express = require('express');
const marked = require('marked');

const router = express.Router();

// Render the user's markdown to HTML for "live preview" while they
// compose a product description. Returned as text/html so a browser
// fetch renders it inline. VULN: marked() is called with the user's
// input and returns raw HTML; the lab does not call any sanitiser.
//   POST /components/preview-description
//   body: { markdown: "..." }
router.post('/preview-description', express.json(), (req, res) => {
  const md = (req.body && req.body.markdown) || '';
  const html = marked(md);
  res.type('text/html').send(`<!doctype html>
<html lang="en-US"><head><meta charset="utf-8">
<title>Description preview</title></head>
<body>
<h1>Live preview</h1>
<div class="preview">${html}</div>
</body></html>`);
});

// GET wrapper for trivial demos: /components/preview?md=...
router.get('/preview-description', (req, res) => {
  const md = (req.query.md || '').toString();
  const html = marked(md);
  res.type('text/html').send(`<!doctype html>
<html lang="en-US"><head><meta charset="utf-8">
<title>Description preview</title></head>
<body>
<h1>Live preview</h1>
<div class="preview">${html}</div>
</body></html>`);
});

// /components/version exposes the installed library versions. Real apps
// often expose this through /debug or in a server header.
router.get('/version', (req, res) => {
  const pkg = require('../package.json');
  res.json({
    app: 'Northwind Outfitters',
    version: pkg.version,
    dependencies: pkg.dependencies,
    node: process.version,
  });
});

module.exports = router;
