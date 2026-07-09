// seed.js — create the MySQL schema and populate it with realistic data.
//
// DDL is MySQL-flavoured (InnoDB + AUTO_INCREMENT + utf8mb4).  Index lengths
// on string columns are 191 chars so the indexes fit under InnoDB's
// historical 767-byte limit even on legacy MySQL.
const db = require('./lib/db');
const { md5 } = require('./lib/auth');

console.log('[seed] resetting vuln-bank schema...');

// Drop in reverse FK-order so re-seeding always succeeds.
db.exec(`
  DROP TABLE IF EXISTS login_codes;
  DROP TABLE IF EXISTS pending_transfers;
  DROP TABLE IF EXISTS otp_challenges;
  DROP TABLE IF EXISTS gift_cards;
  DROP TABLE IF EXISTS webhooks;
  DROP TABLE IF EXISTS audit_log;
  DROP TABLE IF EXISTS support_messages;
  DROP TABLE IF EXISTS statements;
  DROP TABLE IF EXISTS transfers;
  DROP TABLE IF EXISTS accounts;
  DROP TABLE IF EXISTS users;
`);

db.exec(`
  CREATE TABLE users (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    username        VARCHAR(191) UNIQUE NOT NULL,
    password_md5    VARCHAR(64)  NOT NULL,           -- VULN: MD5 unsalted (A02)
    email           VARCHAR(191) NOT NULL,
    full_name       VARCHAR(191) NOT NULL,
    phone           VARCHAR(64),
    address         VARCHAR(255),
    ssn             VARCHAR(32),
    dob             VARCHAR(32),
    role            VARCHAR(32)  NOT NULL DEFAULT 'customer',
    mfa_enabled     TINYINT      NOT NULL DEFAULT 0,
    otp_attempts    INT          NOT NULL DEFAULT 0, -- VULN: not enforced (A07)
    reset_token     VARCHAR(64),                     -- VULN: 4-digit numeric (A04)
    reset_expires   BIGINT,
    profile_json    TEXT,                            -- VULN: lodash.merge sink (A08)
    avatar_url      VARCHAR(512)
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

db.exec(`
  CREATE TABLE accounts (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT NOT NULL,
    account_number  VARCHAR(64) UNIQUE NOT NULL,
    account_type    VARCHAR(32) NOT NULL,
    balance_cents   BIGINT      NOT NULL DEFAULT 0,
    currency        VARCHAR(8)  NOT NULL DEFAULT 'USD',
    created_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

db.exec(`
  CREATE TABLE transfers (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    from_account    VARCHAR(64) NOT NULL,
    to_account      VARCHAR(64) NOT NULL,
    amount_cents    BIGINT      NOT NULL,
    memo            VARCHAR(512),
    created_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

db.exec(`
  CREATE TABLE statements (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    account_id      INT NOT NULL,
    filename        VARCHAR(255) NOT NULL,           -- VULN: served via path-traversal (A01/A05)
    uploaded_by     INT,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

db.exec(`
  CREATE TABLE support_messages (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT,
    subject         VARCHAR(255) NOT NULL,           -- VULN: rendered unescaped (stored XSS)
    body            TEXT         NOT NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

db.exec(`
  CREATE TABLE audit_log (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT,
    action          VARCHAR(64) NOT NULL,
    details         TEXT,
    created_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

db.exec(`
  CREATE TABLE webhooks (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT NOT NULL,
    url             VARCHAR(512) NOT NULL,           -- VULN: SSRF (A10)
    event           VARCHAR(64)  NOT NULL,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

// Promotional reward / gift-card codes. Each is meant to be redeemed ONCE and
// credits the redeemer's checking account. VULN (Ch 21): redemption is a
// read-check-write with no atomicity, so N concurrent redemptions of the same
// code all pass the `redeemed = 0` check and each credit the account -> limit
// overrun (a single-use card minted many times over).
db.exec(`
  CREATE TABLE gift_cards (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    code            VARCHAR(64) UNIQUE NOT NULL,
    amount_cents    BIGINT      NOT NULL,
    redeemed        TINYINT     NOT NULL DEFAULT 0,
    redeemed_by     INT,
    redeemed_at     TIMESTAMP   NULL
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

// Step-up security codes (SMS/authenticator OTP for a sensitive action).
// VULN (Ch 21, rate-limit bypass by race): verification reads attempts, checks
// attempts < 5, waits, then either verifies or increments attempts. The check
// and the increment are non-atomic, so N concurrent guesses all pass the
// "under the limit" gate before the counter catches up -> the 5-try
// anti-brute-force lock never trips and the whole code space is guessable.
db.exec(`
  CREATE TABLE otp_challenges (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT NOT NULL,
    purpose         VARCHAR(48) NOT NULL DEFAULT 'step_up',
    code            VARCHAR(8)  NOT NULL,
    attempts        INT         NOT NULL DEFAULT 0,
    status          VARCHAR(16) NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

// Two-step confirmation for large transfers. VULN (Ch 21, multi-endpoint
// race): /transfer/initiate creates a pending row; /transfer/confirm checks
// status='pending', waits, then debits + marks executed. Racing the confirm
// endpoint executes ONE authorised transfer many times.
db.exec(`
  CREATE TABLE pending_transfers (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    user_id         INT NOT NULL,
    from_account    VARCHAR(64) NOT NULL,
    to_account      VARCHAR(64) NOT NULL,
    amount_cents    BIGINT      NOT NULL,
    memo            VARCHAR(512),
    status          VARCHAR(16) NOT NULL DEFAULT 'pending',
    created_at      TIMESTAMP   NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

// Passwordless "email me a login code". VULN (Ch 21, time-sensitive): the code
// is derived from the current second, so two requests made in the same second
// receive the SAME code. An attacker requests a code for the victim AND for
// their own address at the same instant, reads their own code, and uses it to
// log in as the victim.
db.exec(`
  CREATE TABLE login_codes (
    id              INT AUTO_INCREMENT PRIMARY KEY,
    email           VARCHAR(191) NOT NULL,
    code            VARCHAR(8)   NOT NULL,
    used            TINYINT      NOT NULL DEFAULT 0,
    created_at      TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP
  ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;
`);

console.log('[seed] inserting users + accounts + transfers...');

const users = [
  { username: 'alice.chen',    password: 'Password123!',  email: 'alice.chen@gmail.com',     full_name: 'Alice Chen',          phone: '+1-415-555-0148', address: '221 Mission St, San Francisco, CA',     ssn: '538-12-9942', dob: '1989-04-12', role: 'customer' },
  { username: 'bob.martinez',  password: 'Sunshine99',    email: 'b.martinez@outlook.com',    full_name: 'Robert Martinez',     phone: '+1-718-555-0199', address: '88 Wyckoff Ave, Brooklyn, NY',           ssn: '044-71-3382', dob: '1976-09-30', role: 'customer' },
  { username: 'carol.singh',   password: 'autumn2023',    email: 'carolsingh@yahoo.com',      full_name: 'Carol Singh',         phone: '+1-312-555-0117', address: '410 Adams Blvd, Chicago, IL',            ssn: '299-58-7711', dob: '1992-11-02', role: 'customer' },
  { username: 'david.okafor',  password: 'Letmein2024',   email: 'd.okafor@protonmail.com',   full_name: 'David Okafor',        phone: '+1-617-555-0153', address: '12 Beacon St, Boston, MA',                ssn: '671-04-2288', dob: '1984-02-19', role: 'customer' },
  { username: 'eva.lindstrom', password: 'fika4life',     email: 'eva.l@hotmail.com',          full_name: 'Eva Lindström',       phone: '+1-206-555-0184', address: '900 Pike St, Seattle, WA',                ssn: '821-19-0461', dob: '1995-07-23', role: 'customer' },
  { username: 'julie.morgan',  password: 'Admin2024!',    email: 'j.morgan@vulnbank.test',    full_name: 'Julie Morgan',        phone: '+1-202-555-0140', address: 'HQ — 100 Pennsylvania Ave NW',           ssn: '111-22-3333', dob: '1978-06-15', role: 'admin'    },
  { username: 'finance_audit', password: 'AuditTeam2024', email: 'audit@vulnbank.test',        full_name: 'Internal Audit Team', phone: '+1-202-555-0124', address: 'HQ',                                       ssn: '000-00-0000', dob: '1970-01-01', role: 'admin'    },
];

const insertUser = db.prepare(`
  INSERT INTO users (username, password_md5, email, full_name, phone, address, ssn, dob, role, profile_json)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const userIds = {};
for (const u of users) {
  const info = insertUser.run(
    u.username, md5(u.password), u.email, u.full_name, u.phone,
    u.address, u.ssn, u.dob, u.role,
    JSON.stringify({ theme: 'light', notifications: { email: true, sms: false } })
  );
  userIds[u.username] = info.lastInsertRowid;
}

const insertAccount = db.prepare(`
  INSERT INTO accounts (user_id, account_number, account_type, balance_cents)
  VALUES (?, ?, ?, ?)
`);

const accounts = [
  ['alice.chen',    '4002-1188-0001', 'checking',  1248750],
  ['alice.chen',    '4002-1188-0002', 'savings',   9215600],
  ['bob.martinez',  '4002-2244-0001', 'checking',   389400],
  ['bob.martinez',  '4002-2244-0002', 'savings',   3200000],
  ['carol.singh',   '4002-3315-0001', 'checking',   655000],
  ['david.okafor',  '4002-4421-0001', 'checking',  1890200],
  ['david.okafor',  '4002-4421-0002', 'savings',  12450000],
  ['eva.lindstrom', '4002-5588-0001', 'checking',   442100],
  ['julie.morgan',  '4002-6601-0001', 'checking',    75000],
  ['finance_audit', '4002-9999-0001', 'checking', 100000000],
];

for (const [u, acct, type, bal] of accounts) {
  insertAccount.run(userIds[u], acct, type, bal);
}

const insertTransfer = db.prepare(`
  INSERT INTO transfers (from_account, to_account, amount_cents, memo, created_at)
  VALUES (?, ?, ?, ?, ?)
`);

const transfers = [
  ['4002-1188-0001', '4002-2244-0001',  50000, 'Concert tickets - splitting',         '2025-12-12 14:22:01'],
  ['4002-1188-0001', '4002-3315-0001',  18000, 'Coffee + brunch Sunday',               '2025-12-22 11:08:55'],
  ['4002-1188-0002', '4002-1188-0001', 100000, 'savings -> checking, december rent',   '2026-01-01 09:00:00'],
  ['4002-2244-0001', '4002-4421-0001',  35000, 'Camera lens',                          '2026-02-04 19:42:30'],
  ['4002-4421-0001', '4002-1188-0001',  12500, 'Lunch friday',                         '2026-03-15 13:01:18'],
  ['4002-5588-0001', '4002-1188-0001',  44000, 'splitting airbnb',                     '2026-04-01 08:30:01'],
  ['4002-3315-0001', '4002-5588-0001',  12000, 'thanks for the book',                  '2026-04-20 21:11:44'],
  ['4002-4421-0002', '4002-4421-0001', 200000, 'monthly transfer',                     '2026-05-01 06:00:00'],
  ['4002-9999-0001', '4002-6601-0001',   5000, 'payroll: J. Morgan',                   '2026-05-15 00:01:00'],
];

for (const t of transfers) insertTransfer.run(...t);

const insertMsg = db.prepare(`
  INSERT INTO support_messages (user_id, subject, body, created_at) VALUES (?, ?, ?, ?)
`);
insertMsg.run(userIds['alice.chen'],   'Card not working at pump',        'My Visa was declined at Shell on Mission. Tried 3 times.', '2026-05-20 18:11:00');
insertMsg.run(userIds['bob.martinez'], 'Wire transfer pending too long',  'Sent $1200 to Mexico City branch 4 days ago, still pending.', '2026-05-22 09:30:00');
insertMsg.run(userIds['carol.singh'],  'Statements not downloading',      'When I open May statement I get a 500 error.', '2026-05-28 12:14:00');

db.prepare('INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)')
  .run(userIds['julie.morgan'], 'login', 'admin login from 10.0.0.5');

db.prepare('INSERT INTO webhooks (user_id, url, event) VALUES (?, ?, ?)')
  .run(userIds['alice.chen'], 'https://hooks.example.com/alice-mobile', 'transfer.completed');

const insertCard = db.prepare('INSERT INTO gift_cards (code, amount_cents, redeemed, redeemed_by) VALUES (?, ?, ?, ?)');
// Single-use promo codes worth real credit; NOVA-WELCOME-50 is the one the
// walkthrough races. NOVA-USED-10 is already spent (shows the honest path).
insertCard.run('NOVA-WELCOME-50', 5000, 0, null);
insertCard.run('NOVA-BONUS-25',   2500, 0, null);
insertCard.run('NOVA-USED-10',    1000, 1, userIds['bob.martinez']);

console.log('[seed] complete. Test credentials:');
for (const u of users) console.log(`  ${u.username.padEnd(18)} / ${u.password.padEnd(16)}  (${u.role})`);

// Allow `node seed.js` to terminate cleanly even though lib/db.js owns a
// persistent connection.
process.exit(0);
