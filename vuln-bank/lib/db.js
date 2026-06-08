// lib/db.js — SQLite wrapper. Intentionally exposes a raw `db.exec` so route
// handlers can concatenate user input directly into SQL strings (SQLi).
// Uses Node's built-in node:sqlite (stable in Node 22.5+) so the lab needs no
// native compile toolchain.
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'bank.db');

const db = new DatabaseSync(DB_PATH);
db.exec('PRAGMA journal_mode = WAL;');
db.exec('PRAGMA foreign_keys = ON;');
// Shim for better-sqlite3-style `db.pragma()` calls.
db.pragma = (s) => db.exec('PRAGMA ' + s + ';');

function init() {
  db.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY,
      username TEXT UNIQUE NOT NULL,
      password_md5 TEXT NOT NULL,            -- VULN: MD5 unsalted (A02)
      email TEXT NOT NULL,
      full_name TEXT NOT NULL,
      phone TEXT,
      address TEXT,
      ssn TEXT,
      dob TEXT,
      role TEXT NOT NULL DEFAULT 'customer', -- 'customer' | 'admin'
      mfa_enabled INTEGER DEFAULT 0,
      otp_attempts INTEGER DEFAULT 0,         -- VULN: not actually enforced (A07)
      reset_token TEXT,                       -- VULN: 6-digit numeric (A04)
      reset_expires INTEGER,
      profile_json TEXT DEFAULT '{}',         -- VULN: lodash.merge sink (A08)
      avatar_url TEXT
    );

    CREATE TABLE IF NOT EXISTS accounts (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      account_number TEXT UNIQUE NOT NULL,
      account_type TEXT NOT NULL,            -- 'checking' | 'savings'
      balance_cents INTEGER NOT NULL DEFAULT 0,
      currency TEXT NOT NULL DEFAULT 'USD',
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS transfers (
      id INTEGER PRIMARY KEY,
      from_account TEXT NOT NULL,
      to_account TEXT NOT NULL,
      amount_cents INTEGER NOT NULL,
      memo TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS statements (
      id INTEGER PRIMARY KEY,
      account_id INTEGER NOT NULL REFERENCES accounts(id),
      filename TEXT NOT NULL,                -- VULN: served via path-traversal (A01/A05)
      uploaded_by INTEGER REFERENCES users(id),
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS support_messages (
      id INTEGER PRIMARY KEY,
      user_id INTEGER REFERENCES users(id),
      subject TEXT NOT NULL,                 -- VULN: rendered unescaped (stored XSS)
      body TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY,
      user_id INTEGER,
      action TEXT NOT NULL,
      details TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS webhooks (
      id INTEGER PRIMARY KEY,
      user_id INTEGER NOT NULL REFERENCES users(id),
      url TEXT NOT NULL,                     -- VULN: SSRF (A10)
      event TEXT NOT NULL,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );
  `);
}

init();

module.exports = db;
