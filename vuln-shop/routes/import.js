// routes/import.js — bulk product import via XML (XXE sink) and CSV.
const express = require('express');
const router = express.Router();
const fs = require('fs');
const fetch = require('node-fetch');
const xml2js = require('xml2js');
const db = require('../lib/db');
const { requireSession } = require('../lib/auth');

router.use(requireSession);
// VULN: NO admin check.

router.get('/', (req, res) => {
  res.render('import', { msg: req.query.msg || '', error: null, parsed: null });
});

// VULN: XXE — DTD entity resolver same as bank's.
router.post('/xml', async (req, res) => {
  const xml = req.body && typeof req.body === 'string' ? req.body : '';
  let expanded = xml;
  const entityRe = /<!ENTITY\s+(\w+)\s+SYSTEM\s+["']([^"']+)["']\s*>/g;
  const entities = {};
  let m;
  while ((m = entityRe.exec(xml))) entities[m[1]] = m[2];
  for (const [name, uri] of Object.entries(entities)) {
    let value = '';
    try {
      if (uri.startsWith('file://')) {
        let fp = uri.replace(/^file:\/\//, '');
        if (process.platform === 'win32' && /^\/[A-Za-z]:\//.test(fp)) fp = fp.slice(1);
        value = fs.readFileSync(fp, 'utf8');
      } else if (uri.startsWith('http://') || uri.startsWith('https://')) {
        const r = await fetch(uri, { timeout: 5000 });
        value = await r.text();
      }
    } catch (e) { value = '[xxe-error: ' + e.message + ']'; }
    expanded = expanded.split('&' + name + ';').join(value);
  }
  const parser = new xml2js.Parser({ explicitArray: false });
  parser.parseString(expanded, (err, result) => {
    if (err) return res.status(400).type('text/plain').send('parse error: ' + err.message + '\n---\n' + expanded);
    res.json(result);
  });
});

module.exports = router;
