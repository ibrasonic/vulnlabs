// routes/staff.js — corporate SSO staff directory (Northwind Outfitters).
//
// VULN (S-INJ-002): LDAP injection.
//
// Northwind's staff directory is backed by an in-memory LDAP-style tree. Both
// the search box and the SSO login build an RFC-4515 filter STRING by
// concatenating user input, then evaluate it against the directory. Because
// the input is spliced into the filter unescaped, an attacker can inject
// filter syntax — parentheses, the `*` wildcard, and `&`/`|`/`!` operators:
//
//   search ?uid=*                         -> every staff entry
//   search ?uid=*)(mail=*                 -> breaks out of the AND clause
//   login  uid=admin  password=*          -> wildcard password (presence match)
//   login  uid=*)(uid=*))(|(uid=*  pwd=*  -> classic filter break-out
//
// The fix is a parameterised filter API (or RFC-4515 escaping of `* ( ) \ NUL`)
// so the user value can never change the structure of the filter. See Ch 12.
const express = require('express');
const router = express.Router();

// In-memory directory entries (a flat ou=people subtree).
const DIRECTORY = [
  { uid: 'admin',        cn: 'Directory Administrator', mail: 'sso-admin@northwind.test', title: 'IT Administrator',    department: 'IT',       employeeType: 'staff', userPassword: 'Sup3rSecretLDAP!' },
  { uid: 'kate.h',       cn: 'Kate Holloway',           mail: 'kate@northwind.test',      title: 'Head of Retail',      department: 'Retail',   employeeType: 'staff', userPassword: 'AdminKate!1' },
  { uid: 'brandon.o',    cn: 'Brandon Ortega',          mail: 'brandon@northwind.test',   title: 'Warehouse Lead',      department: 'Ops',      employeeType: 'staff', userPassword: 'OpsB!2024' },
  { uid: 'lin.t',        cn: 'Lin Tran',                mail: 'lin@northwind.test',       title: 'Support Engineer',    department: 'Support',  employeeType: 'staff', userPassword: 'SupportLin#9' },
  { uid: 'svc-reports',  cn: 'Reporting Service',       mail: 'svc-reports@northwind.test', title: 'Automation',        department: 'IT',       employeeType: 'service', userPassword: 'r3p0rts-sa-key-7741' },
];

// --- Minimal RFC-4515 filter parser + evaluator --------------------------
function parseFilter(str) {
  let i = 0;
  function parseExpr() {
    if (str[i] !== '(') throw new Error('expected "(" at position ' + i);
    i++; // consume '('
    const c = str[i];
    let node;
    if (c === '&' || c === '|') {
      i++; // consume operator
      const kids = [];
      while (str[i] === '(') kids.push(parseExpr());
      node = { op: c, kids };
    } else if (c === '!') {
      i++;
      node = { op: '!', kids: [parseExpr()] };
    } else {
      const close = str.indexOf(')', i);
      if (close === -1) throw new Error('unterminated filter item');
      const item = str.slice(i, close);
      const eq = item.indexOf('=');
      if (eq === -1) throw new Error('filter item missing "=": ' + item);
      node = { op: '=', attr: item.slice(0, eq).trim(), val: item.slice(eq + 1) };
      i = close;
    }
    if (str[i] !== ')') throw new Error('expected ")" at position ' + i);
    i++; // consume ')'
    return node;
  }
  const ast = parseExpr();
  if (i !== str.length) throw new Error('trailing characters after filter');
  return ast;
}

function escapeRegExp(s) { return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'); }

function evalFilter(node, entry) {
  if (node.op === '&') return node.kids.every((k) => evalFilter(k, entry));
  if (node.op === '|') return node.kids.some((k) => evalFilter(k, entry));
  if (node.op === '!') return !evalFilter(node.kids[0], entry);
  // leaf equality / presence / substring
  const key = Object.keys(entry).find((k) => k.toLowerCase() === node.attr.toLowerCase());
  if (key === undefined) return false;
  const actual = String(entry[key]);
  const val = node.val;
  if (val === '*') return true; // presence
  if (val.indexOf('*') !== -1) {
    const re = new RegExp('^' + val.split('*').map(escapeRegExp).join('.*') + '$', 'i');
    return re.test(actual);
  }
  return actual.toLowerCase() === val.toLowerCase();
}

function search(filterStr) {
  const ast = parseFilter(filterStr);
  return DIRECTORY.filter((e) => evalFilter(ast, e));
}

function publicView(e) {
  return { uid: e.uid, cn: e.cn, mail: e.mail, title: e.title, department: e.department };
}

// Landing page.
router.get('/', (req, res) => {
  res.render('staff', { filter: null, error: null, results: null, mode: null });
});

// VULN: ?uid= spliced into an AND filter.
router.get('/search', (req, res) => {
  const uid = (req.query.uid !== undefined) ? String(req.query.uid) : '';
  let filter = null, error = null, results = null;
  if (req.query.uid !== undefined) {
    filter = `(&(uid=${uid})(employeeType=staff))`;
    try {
      results = search(filter).map(publicView);
    } catch (e) { error = e.message; }
  }
  res.render('staff', { filter, error, results, mode: 'search' });
});

// VULN: SSO login filter built from uid + password — wildcard password and
// filter break-out both bypass authentication.
router.post('/login', (req, res) => {
  const uid = String(req.body.uid !== undefined ? req.body.uid : '');
  const password = String(req.body.password !== undefined ? req.body.password : '');
  const filter = `(&(uid=${uid})(userPassword=${password}))`;
  let error = null, results = null;
  try {
    const matches = search(filter);
    if (matches.length) {
      const e = matches[0];
      req.session.staffUid = e.uid;
      req.session.staffDept = e.department;
      results = [publicView(e)];
      return res.render('staff', { filter, error: null, results, mode: 'login-ok' });
    }
    error = 'Authentication failed.';
  } catch (e) { error = e.message; }
  return res.status(401).render('staff', { filter, error, results: null, mode: 'login-fail' });
});

module.exports = router;
