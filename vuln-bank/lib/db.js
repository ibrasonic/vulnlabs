// lib/db.js — MySQL adapter.
//
// The lab keeps a synchronous-looking API (`db.prepare(sql).get/all/run`,
// `db.exec(sql)`) so the existing 70+ call sites do not change.  Internally
// every call drives mysql2 via deasync so the Express handlers stay
// synchronous, exactly the way better-sqlite3 / node:sqlite handlers do.
//
// VULNS deliberately baked in here so Chapter 11 has the full SQLi surface:
//   - multipleStatements: true  → every template-literal sink is ALSO a
//     stacked-query sink (DROP/INSERT/UPDATE chained onto a SELECT).
//   - The bank app is granted FILE privilege at seed time
//     (see seed.js + docker-compose.yml's --secure-file-priv flag), so
//     LOAD_FILE and SELECT … INTO OUTFILE work for out-of-band SQLi demos.
//
// Connection bootstrap retries for up to 120s so `docker compose up -d`
// (which starts the bank container before MySQL finishes initialising) works
// from a single command with no user intervention.

const mysql = require('mysql2');
const deasync = require('deasync');

const config = {
  host:     process.env.MYSQL_HOST     || '127.0.0.1',
  port:     parseInt(process.env.MYSQL_PORT || '3306', 10),
  user:     process.env.MYSQL_USER     || 'bank',
  password: process.env.MYSQL_PASSWORD || 'bankpw',
  database: process.env.MYSQL_DATABASE || 'vulnbank',
  multipleStatements: true,
  dateStrings: true,
  charset: 'utf8mb4',
};

let connection = null;

function connectSync() {
  const deadline = Date.now() + 120000;
  let lastErr = null;
  while (Date.now() < deadline) {
    let done = false, ok = null;
    const c = mysql.createConnection(config);
    c.connect((err) => {
      if (err) { lastErr = err; try { c.destroy(); } catch (_) {} done = true; }
      else     { ok = c; done = true; }
    });
    deasync.loopWhile(() => !done);
    if (ok) {
      connection = ok;
      connection.on('error', (err) => {
        console.error('[db] mysql connection error:', err.code || err.message);
        if (err.fatal || err.code === 'PROTOCOL_CONNECTION_LOST') {
          connection = null;
        }
      });
      return;
    }
    let wait = false;
    setTimeout(() => { wait = true; }, 1000);
    deasync.loopWhile(() => !wait);
  }
  throw new Error('[db] could not connect to MySQL after 120s: ' + (lastErr && lastErr.message));
}

connectSync();

function reconnectIfNeeded() {
  if (!connection) connectSync();
}

function runSync(sql, params) {
  reconnectIfNeeded();
  let done = false, error = null, result = null;
  connection.query(sql, params || [], (err, res) => {
    error = err; result = res; done = true;
  });
  deasync.loopWhile(() => !done);
  if (error) throw error;
  return result;
}

// With multipleStatements on, mysql2 returns either a single rows array, a
// single OkPacket, or an array of those (one element per statement).  Collapse
// multi-statement responses down to the FIRST sub-result so the legitimate
// query's row shape stays compatible with SQLite-era render code; the stacked
// side-effect still runs.
function isResultArray(x) {
  return Array.isArray(x) && x.length > 0 &&
    (Array.isArray(x[0]) || (x[0] && x[0].constructor && x[0].constructor.name === 'OkPacket'));
}

function pickFirstRowset(res) {
  if (res == null) return [];
  if (isResultArray(res)) return pickFirstRowset(res[0]);
  return Array.isArray(res) ? res : [];
}

function pickFirstResult(res) {
  if (res == null) return null;
  if (isResultArray(res)) return pickFirstResult(res[0]);
  return res;
}

const db = {
  exec(sql) { runSync(sql); },

  prepare(sql) {
    return {
      all(...args) {
        return pickFirstRowset(runSync(sql, args));
      },
      get(...args) {
        return pickFirstRowset(runSync(sql, args))[0];
      },
      run(...args) {
        const first = pickFirstResult(runSync(sql, args));
        return {
          lastInsertRowid: first && first.insertId    !== undefined ? first.insertId    : 0,
          changes:         first && first.affectedRows !== undefined ? first.affectedRows : 0,
        };
      },
    };
  },

  // SQLite-parity no-op.  Some routes still call db.pragma('foreign_keys=on').
  pragma() {},
};

module.exports = db;
