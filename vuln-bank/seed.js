// seed.js — populate the bank DB with realistic data.
const db = require('./lib/db');
const { md5 } = require('./lib/auth');

console.log('Seeding vuln-bank database...');

// Wipe and re-seed deterministically.
db.exec(`
  DELETE FROM webhooks;
  DELETE FROM audit_log;
  DELETE FROM support_messages;
  DELETE FROM statements;
  DELETE FROM transfers;
  DELETE FROM accounts;
  DELETE FROM users;
`);

const users = [
  {
    username: 'alice.chen', password: 'Password123!', email: 'alice.chen@gmail.com',
    full_name: 'Alice Chen', phone: '+1-415-555-0148', address: '221 Mission St, San Francisco, CA',
    ssn: '538-12-9942', dob: '1989-04-12', role: 'customer'
  },
  {
    username: 'bob.martinez', password: 'Sunshine99', email: 'b.martinez@outlook.com',
    full_name: 'Robert Martinez', phone: '+1-718-555-0199', address: '88 Wyckoff Ave, Brooklyn, NY',
    ssn: '044-71-3382', dob: '1976-09-30', role: 'customer'
  },
  {
    username: 'carol.singh', password: 'autumn2023', email: 'carolsingh@yahoo.com',
    full_name: 'Carol Singh', phone: '+1-312-555-0117', address: '410 Adams Blvd, Chicago, IL',
    ssn: '299-58-7711', dob: '1992-11-02', role: 'customer'
  },
  {
    username: 'david.okafor', password: 'Letmein2024', email: 'd.okafor@protonmail.com',
    full_name: 'David Okafor', phone: '+1-617-555-0153', address: '12 Beacon St, Boston, MA',
    ssn: '671-04-2288', dob: '1984-02-19', role: 'customer'
  },
  {
    username: 'eva.lindstrom', password: 'fika4life', email: 'eva.l@hotmail.com',
    full_name: 'Eva Lindström', phone: '+1-206-555-0184', address: '900 Pike St, Seattle, WA',
    ssn: '821-19-0461', dob: '1995-07-23', role: 'customer'
  },
  {
    username: 'julie.morgan', password: 'Admin2024!', email: 'j.morgan@vulnbank.test',
    full_name: 'Julie Morgan', phone: '+1-202-555-0140', address: 'HQ — 100 Pennsylvania Ave NW',
    ssn: '111-22-3333', dob: '1978-06-15', role: 'admin'
  },
  {
    username: 'finance_audit', password: 'AuditTeam2024', email: 'audit@vulnbank.test',
    full_name: 'Internal Audit Team', phone: '+1-202-555-0124', address: 'HQ',
    ssn: '000-00-0000', dob: '1970-01-01', role: 'admin'
  }
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
  ['alice.chen',      '4002-1188-0001', 'checking', 1248750],
  ['alice.chen',      '4002-1188-0002', 'savings',  9215600],
  ['bob.martinez',    '4002-2244-0001', 'checking',  389400],
  ['bob.martinez',    '4002-2244-0002', 'savings',  3200000],
  ['carol.singh',     '4002-3315-0001', 'checking',  655000],
  ['david.okafor',    '4002-4421-0001', 'checking', 1890200],
  ['david.okafor',    '4002-4421-0002', 'savings', 12450000],
  ['eva.lindstrom',   '4002-5588-0001', 'checking',  442100],
  ['julie.morgan',    '4002-6601-0001', 'checking',   75000],
  ['finance_audit',   '4002-9999-0001', 'checking', 100000000] // master operations account
];

for (const [u, acct, type, bal] of accounts) {
  insertAccount.run(userIds[u], acct, type, bal);
}

const insertTransfer = db.prepare(`
  INSERT INTO transfers (from_account, to_account, amount_cents, memo, created_at)
  VALUES (?, ?, ?, ?, ?)
`);

const transfers = [
  ['4002-1188-0001', '4002-2244-0001',  50000, 'Concert tickets - splitting',          '2025-12-12 14:22:01'],
  ['4002-1188-0001', '4002-3315-0001',  18000, 'Coffee + brunch Sunday',                '2025-12-22 11:08:55'],
  ['4002-1188-0002', '4002-1188-0001', 100000, 'savings -> checking, december rent',    '2026-01-01 09:00:00'],
  ['4002-2244-0001', '4002-4421-0001',  35000, 'Camera lens',                           '2026-02-04 19:42:30'],
  ['4002-4421-0001', '4002-1188-0001',  12500, 'Lunch friday',                          '2026-03-15 13:01:18'],
  ['4002-5588-0001', '4002-1188-0001',  44000, 'splitting airbnb',                      '2026-04-01 08:30:01'],
  ['4002-3315-0001', '4002-5588-0001',  12000, 'thanks for the book',                   '2026-04-20 21:11:44'],
  ['4002-4421-0002', '4002-4421-0001', 200000, 'monthly transfer',                       '2026-05-01 06:00:00'],
  ['4002-9999-0001', '4002-6601-0001',   5000, 'payroll: J. Morgan',                    '2026-05-15 00:01:00']
];

for (const t of transfers) insertTransfer.run(...t);

// Support messages — used by stored XSS demo on admin panel.
const insertMsg = db.prepare(`
  INSERT INTO support_messages (user_id, subject, body, created_at) VALUES (?, ?, ?, ?)
`);
insertMsg.run(userIds['alice.chen'], 'Card not working at pump', 'My Visa was declined at Shell on Mission. Tried 3 times.', '2026-05-20 18:11:00');
insertMsg.run(userIds['bob.martinez'], 'Wire transfer pending too long', 'Sent $1200 to Mexico City branch 4 days ago, still pending.', '2026-05-22 09:30:00');
insertMsg.run(userIds['carol.singh'], 'Statements not downloading',     'When I click May statement I get a 500 error.', '2026-05-28 12:14:00');

// A single audit log row so admin pages have content.
db.prepare(`INSERT INTO audit_log (user_id, action, details) VALUES (?, ?, ?)`)
  .run(userIds['julie.morgan'], 'login', 'admin login from 10.0.0.5');

// Webhook example (used to demo SSRF target).
db.prepare(`INSERT INTO webhooks (user_id, url, event) VALUES (?, ?, ?)`)
  .run(userIds['alice.chen'], 'https://hooks.example.com/alice-mobile', 'transfer.completed');

console.log('Seed complete. Test credentials:');
for (const u of users) console.log(`  ${u.username.padEnd(18)} / ${u.password.padEnd(16)}  (${u.role})`);
