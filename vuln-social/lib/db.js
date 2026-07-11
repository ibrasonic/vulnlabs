// lib/db.js — SQLite via Node's built-in node:sqlite.
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'social.db');

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');
db.pragma = (s) => db.exec('PRAGMA ' + s + ';');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_md5 TEXT NOT NULL,            -- VULN: unsalted MD5
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    bio TEXT DEFAULT '',                   -- VULN: rendered raw on /u/:name
    avatar TEXT DEFAULT '/static/img/avatars/default.svg',
    role TEXT NOT NULL DEFAULT 'user',     -- VULN: mass-assignable
    profile_json TEXT DEFAULT '{}',         -- VULN: deep-merge sink
    is_private INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS posts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,                    -- VULN: rendered with <%- %> in feed
    image_url TEXT,
    flagged INTEGER DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    post_id INTEGER NOT NULL REFERENCES posts(id),
    user_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,                    -- VULN: rendered with <%- %>
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS follows (
    follower_id INTEGER NOT NULL REFERENCES users(id),
    followee_id INTEGER NOT NULL REFERENCES users(id),
    PRIMARY KEY (follower_id, followee_id)
  );

  CREATE TABLE IF NOT EXISTS dms (
    id INTEGER PRIMARY KEY,
    sender_id INTEGER NOT NULL REFERENCES users(id),
    recipient_id INTEGER NOT NULL REFERENCES users(id),
    body TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS reports (
    id INTEGER PRIMARY KEY,
    post_id INTEGER NOT NULL REFERENCES posts(id),
    reporter_id INTEGER REFERENCES users(id),
    reason TEXT,
    status TEXT DEFAULT 'open',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS ai_logs (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    prompt TEXT NOT NULL,
    response TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    filename TEXT NOT NULL,                -- VULN: arbitrary extension
    purpose TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS kb_docs (
    id INTEGER PRIMARY KEY,
    title TEXT NOT NULL,
    content TEXT NOT NULL,                 -- VULN: retrieved + concatenated into LLM prompt
    tags TEXT DEFAULT '',
    visibility TEXT DEFAULT 'public',      -- VULN: 'internal' never enforced at retrieval
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- Ch23 prototype-pollution feature: an isolated platform-broadcast log.
  -- Nothing else in the app reads or writes it, so exercising it can never
  -- disturb another chapter's data.
  CREATE TABLE IF NOT EXISTS broadcasts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(id),
    body TEXT NOT NULL,
    reach INTEGER NOT NULL DEFAULT 0,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

module.exports = db;
