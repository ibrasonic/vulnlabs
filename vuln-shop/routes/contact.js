// routes/contact.js — contact form that calls Flask email-service for rendering.
// VULNS: subject + body are sent untrusted to the email service which uses
// Jinja2 render_template_string -> server-side template injection (SSTI).
// The email service also returns the rendered template back to us, so a
// successful SSTI is visible in the HTTP response.
const express = require('express');
const router = express.Router();
const fetch = require('node-fetch');
const db = require('../lib/db');

router.get('/', (req, res) => {
  res.render('contact', { msg: '', error: null });
});

router.post('/', async (req, res) => {
  const { name, email, subject, body } = req.body;
  const userId = req.session && req.session.userId ? req.session.userId : null;
  db.prepare(
    `INSERT INTO support_messages (user_id, subject, body) VALUES (?, ?, ?)`
  ).run(userId, subject || '', body || '');
  const url = req.app.locals.EMAIL_SERVICE + '/render';
  try {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        // VULN: subject and body fields are passed as Jinja templates.
        template: 'Hello {{name}}!\n\nSubject: ' + (subject || '') + '\n\n' + (body || ''),
        context: { name: name || 'customer', email: email || '' }
      })
    });
    const txt = await r.text();
    res.render('contact', { msg: 'Email queued. Render preview:\n' + txt, error: null });
  } catch (e) {
    res.render('contact', { msg: 'Message saved.', error: 'email-service unreachable: ' + e.message });
  }
});

module.exports = router;
