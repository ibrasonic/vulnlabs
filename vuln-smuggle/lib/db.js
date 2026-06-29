// lib/db.js - SQLite via Node's built-in node:sqlite for NovaPress newsroom.
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'novapress.db');

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    password_md5 TEXT NOT NULL,
    email TEXT NOT NULL,
    display_name TEXT NOT NULL,
    bio TEXT DEFAULT '',
    tier TEXT NOT NULL DEFAULT 'reader',   -- reader | subscriber | author | editor | admin
    avatar TEXT DEFAULT '/static/img/default.svg',
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS articles (
    id INTEGER PRIMARY KEY,
    slug TEXT UNIQUE NOT NULL,
    title TEXT NOT NULL,
    deck TEXT DEFAULT '',                  -- subtitle
    body TEXT NOT NULL,                    -- HTML body
    category TEXT NOT NULL,                -- politics|business|tech|sport|culture|opinion
    author_id INTEGER NOT NULL REFERENCES users(id),
    status TEXT NOT NULL DEFAULT 'draft',  -- draft | scheduled | published | retracted
    paywall INTEGER NOT NULL DEFAULT 0,    -- 0 = free, 1 = subscribers-only
    hero_url TEXT DEFAULT '',
    published_at TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS comments (
    id INTEGER PRIMARY KEY,
    article_id INTEGER NOT NULL REFERENCES articles(id),
    user_id INTEGER REFERENCES users(id),  -- nullable for anonymous
    author_label TEXT NOT NULL,            -- captured display name at post time
    body TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY,
    actor TEXT,
    action TEXT NOT NULL,
    detail TEXT,
    at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS api_tokens (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token TEXT UNIQUE NOT NULL,
    label TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );
`);

module.exports = db;
