// lib/db.js — SQLite via Node's built-in node:sqlite (no native compile).
const { DatabaseSync } = require('node:sqlite');
const path = require('path');
const fs = require('fs');

const DATA_DIR = path.join(__dirname, '..', 'data');
if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
const DB_PATH = path.join(DATA_DIR, 'shop.db');

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
    full_name TEXT NOT NULL,
    address TEXT,
    role TEXT NOT NULL DEFAULT 'customer', -- VULN: mass-assignable
    profile_json TEXT DEFAULT '{}',         -- VULN: deep-merge sink
    cc_last4 TEXT,                          -- demo only
    credits_cents INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS products (
    id INTEGER PRIMARY KEY,
    sku TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    description TEXT,
    price_cents INTEGER NOT NULL,
    stock INTEGER NOT NULL DEFAULT 0,
    image_url TEXT,
    category TEXT
  );

  CREATE TABLE IF NOT EXISTS reviews (
    id INTEGER PRIMARY KEY,
    product_id INTEGER NOT NULL REFERENCES products(id),
    user_id INTEGER REFERENCES users(id),
    rating INTEGER NOT NULL,
    body TEXT NOT NULL,                    -- VULN: rendered with <%- %>
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS carts (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS cart_items (
    id INTEGER PRIMARY KEY,
    cart_id INTEGER NOT NULL REFERENCES carts(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    qty INTEGER NOT NULL DEFAULT 1,
    price_cents INTEGER NOT NULL           -- VULN: client-supplied -> price tampering
  );

  CREATE TABLE IF NOT EXISTS coupons (
    code TEXT PRIMARY KEY,
    percent_off INTEGER NOT NULL,
    max_uses INTEGER NOT NULL DEFAULT 1000,
    used INTEGER NOT NULL DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS cart_coupons (
    id INTEGER PRIMARY KEY,
    cart_id INTEGER NOT NULL REFERENCES carts(id),
    code TEXT NOT NULL,
    percent_off INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS orders (
    id INTEGER PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    total_cents INTEGER NOT NULL,
    coupon TEXT,
    status TEXT NOT NULL DEFAULT 'placed',
    shipping_address TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS order_items (
    id INTEGER PRIMARY KEY,
    order_id INTEGER NOT NULL REFERENCES orders(id),
    product_id INTEGER NOT NULL REFERENCES products(id),
    qty INTEGER NOT NULL,
    price_cents INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS support_messages (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    subject TEXT NOT NULL,                 -- VULN: rendered unescaped on admin
    body TEXT NOT NULL,
    created_at TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS uploads (
    id INTEGER PRIMARY KEY,
    user_id INTEGER REFERENCES users(id),
    filename TEXT NOT NULL,                -- VULN: arbitrary extension allowed
    purpose TEXT,
    created_at TEXT DEFAULT (datetime('now'))
  );

  -- Ch23 prototype-pollution feature: an isolated store-credit rewards wallet.
  -- Nothing else in the app reads or writes it, so exercising it can never
  -- disturb another chapter's data.
  CREATE TABLE IF NOT EXISTS reward_wallet (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    credit_cents INTEGER NOT NULL DEFAULT 0
  );
`);

module.exports = db;
