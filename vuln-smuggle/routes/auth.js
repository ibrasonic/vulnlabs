// routes/auth.js - login / logout / register for NovaPress.
const express = require('express');
const router = express.Router();
const db = require('../lib/db');
const { md5 } = require('../lib/auth');

router.get('/login', (req, res) => {
  res.render('login', { error: null, next: req.query.next || '/' });
});

router.post('/login', (req, res) => {
  const { username, password } = req.body;
  const next = req.body.next || '/';
  const user = db.prepare('SELECT * FROM users WHERE username = ? LIMIT 1').get(username);
  if (!user || user.password_md5 !== md5(password || '')) {
    return res.status(401).render('login', { error: 'Wrong username or password.', next });
  }
  req.session.userId = user.id;
  req.session.username = user.username;
  req.session.display = user.display_name;
  req.session.tier = user.tier;
  res.redirect(next);
});

router.get('/logout', (req, res) => {
  req.session.destroy(() => res.redirect('/'));
});

router.get('/register', (req, res) => {
  res.render('register', { error: null });
});

router.post('/register', (req, res) => {
  const { username, password, email, display_name } = req.body;
  if (!username || !password) {
    return res.status(400).render('register', { error: 'Username and password are required.' });
  }
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) {
    return res.status(400).render('register', { error: 'That username is taken.' });
  }
  const r = db.prepare(`
    INSERT INTO users (username, password_md5, email, display_name, tier)
    VALUES (?, ?, ?, ?, 'reader')
  `).run(
    username, md5(password),
    email || (username + '@reader.test'),
    display_name || username
  );
  req.session.userId = r.lastInsertRowid;
  req.session.username = username;
  req.session.display = display_name || username;
  req.session.tier = 'reader';
  res.redirect('/account');
});

router.get('/account', (req, res) => {
  if (!req.session || !req.session.userId) return res.redirect('/login?next=/account');
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.session.userId);
  res.render('account', { user });
});

module.exports = router;
