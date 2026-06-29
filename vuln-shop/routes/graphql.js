// routes/graphql.js — V-SHOP-035 — real GraphQL endpoint, every classic bug:
//   - introspection enabled (default)
//   - no depth / complexity / cost limit -> nested-DoS
//   - batching enabled (array body) -> rate-limit bypass
//   - GET supported (?query=) -> CSRF-able for queries
//   - field-level disclosure of passwordMd5 and ccLast4
//   - BOLA on user(id) / order(id) — no ownership check
//   - mass-assignment on register(role)
//   - unauthenticated promoteUser mutation -> admin escalation
//   - applyCoupon enumerates existing codes via "No such coupon" error
//   - errors include did-you-mean field suggestions (graphql default)
const express = require('express');
const router = express.Router();
const { buildSchema, graphql } = require('graphql');
const db = require('../lib/db');
const { md5, signToken, verifyToken } = require('../lib/auth');

const schemaSource = `
  type User {
    id: Int!
    username: String!
    email: String
    fullName: String
    role: String!
    passwordMd5: String
    ccLast4: String
    creditsCents: Int
    orders: [Order!]!
    reviews: [Review!]!
  }

  type Product {
    id: Int!
    sku: String!
    name: String!
    description: String
    priceCents: Int!
    stock: Int!
    category: String
    reviews: [Review!]!
  }

  type Review {
    id: Int!
    rating: Int!
    body: String!
    author: User
    product: Product
  }

  type Order {
    id: Int!
    totalCents: Int!
    status: String!
    shippingAddress: String
    coupon: String
    user: User
    items: [OrderItem!]!
  }

  type OrderItem {
    id: Int!
    qty: Int!
    priceCents: Int!
    product: Product
    order: Order
  }

  type Coupon {
    code: String!
    percentOff: Int!
    maxUses: Int!
    used: Int!
  }

  type AuthPayload {
    token: String!
    user: User!
  }

  type Query {
    me: User
    user(id: Int!): User
    users: [User!]!
    product(id: Int!): Product
    products(category: String): [Product!]!
    order(id: Int!): Order
    orders: [Order!]!
    coupon(code: String!): Coupon
  }

  type Mutation {
    login(username: String!, password: String!): AuthPayload
    register(username: String!, password: String!, email: String!, role: String): User
    promoteUser(id: Int!): User
    applyCoupon(code: String!): Coupon
  }
`;

const schema = buildSchema(schemaSource);

function userById(id) {
  return db.prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function shape(row, type) {
  if (!row) return null;
  if (type === 'user') {
    return {
      id: row.id,
      username: row.username,
      email: row.email,
      fullName: row.full_name,
      role: row.role,
      passwordMd5: row.password_md5,
      ccLast4: row.cc_last4,
      creditsCents: row.credits_cents,
      orders: () => db.prepare('SELECT * FROM orders WHERE user_id = ?').all(row.id).map(o => shape(o, 'order')),
      reviews: () => db.prepare('SELECT * FROM reviews WHERE user_id = ?').all(row.id).map(r => shape(r, 'review'))
    };
  }
  if (type === 'product') {
    return {
      id: row.id, sku: row.sku, name: row.name, description: row.description,
      priceCents: row.price_cents, stock: row.stock, category: row.category,
      reviews: () => db.prepare('SELECT * FROM reviews WHERE product_id = ?').all(row.id).map(r => shape(r, 'review'))
    };
  }
  if (type === 'review') {
    return {
      id: row.id, rating: row.rating, body: row.body,
      author: () => row.user_id ? shape(userById(row.user_id), 'user') : null,
      product: () => shape(db.prepare('SELECT * FROM products WHERE id = ?').get(row.product_id), 'product')
    };
  }
  if (type === 'order') {
    return {
      id: row.id, totalCents: row.total_cents, status: row.status,
      shippingAddress: row.shipping_address, coupon: row.coupon,
      user: () => shape(userById(row.user_id), 'user'),
      items: () => db.prepare('SELECT * FROM order_items WHERE order_id = ?').all(row.id).map(i => shape(i, 'orderItem'))
    };
  }
  if (type === 'orderItem') {
    return {
      id: row.id, qty: row.qty, priceCents: row.price_cents,
      product: () => shape(db.prepare('SELECT * FROM products WHERE id = ?').get(row.product_id), 'product'),
      order: () => shape(db.prepare('SELECT * FROM orders WHERE id = ?').get(row.order_id), 'order')
    };
  }
  return row;
}

const root = {
  me: (args, ctx) => ctx.user ? shape(userById(ctx.user.sub), 'user') : null,
  user: ({ id }) => shape(userById(id), 'user'),
  users: () => db.prepare('SELECT * FROM users').all().map(u => shape(u, 'user')),
  product: ({ id }) => shape(db.prepare('SELECT * FROM products WHERE id = ?').get(id), 'product'),
  products: ({ category }) => {
    const rows = category
      ? db.prepare('SELECT * FROM products WHERE category = ?').all(category)
      : db.prepare('SELECT * FROM products').all();
    return rows.map(p => shape(p, 'product'));
  },
  order: ({ id }) => shape(db.prepare('SELECT * FROM orders WHERE id = ?').get(id), 'order'),
  orders: () => db.prepare('SELECT * FROM orders').all().map(o => shape(o, 'order')),
  coupon: ({ code }) => {
    const c = db.prepare('SELECT * FROM coupons WHERE code = ?').get(code);
    return c ? { code: c.code, percentOff: c.percent_off, maxUses: c.max_uses, used: c.used } : null;
  },

  login: ({ username, password }) => {
    const u = db.prepare('SELECT * FROM users WHERE username = ? AND password_md5 = ?').get(username, md5(password));
    if (!u) throw new Error('bad credentials');
    return { token: signToken(u), user: shape(u, 'user') };
  },
  register: ({ username, password, email, role }) => {
    const r = db.prepare(
      'INSERT INTO users (username, password_md5, email, full_name, role) VALUES (?, ?, ?, ?, ?)'
    ).run(username, md5(password), email, username, role || 'customer');
    return shape(userById(r.lastInsertRowid), 'user');
  },
  promoteUser: ({ id }) => {
    db.prepare("UPDATE users SET role = 'admin' WHERE id = ?").run(id);
    return shape(userById(id), 'user');
  },
  applyCoupon: ({ code }) => {
    const c = db.prepare('SELECT * FROM coupons WHERE code = ?').get(code);
    if (!c) throw new Error(`No such coupon: ${code}`);
    db.prepare('UPDATE coupons SET used = used + 1 WHERE code = ?').run(code);
    const updated = db.prepare('SELECT * FROM coupons WHERE code = ?').get(code);
    return { code: updated.code, percentOff: updated.percent_off, maxUses: updated.max_uses, used: updated.used };
  }
};

function ctxFromReq(req) {
  const auth = req.headers.authorization || '';
  const m = auth.match(/^Bearer\s+(.+)$/i);
  if (m) {
    try { return { user: verifyToken(m[1]) }; } catch (_) { /* anonymous */ }
  }
  return { user: null };
}

async function runOne(op, ctx) {
  return graphql({
    schema,
    source: op.query || '',
    variableValues: op.variables || {},
    operationName: op.operationName,
    rootValue: root,
    contextValue: ctx
  });
}

router.all('/', async (req, res) => {
  try {
    const ctx = ctxFromReq(req);
    if (req.method === 'GET') {
      const vars = req.query.variables ? JSON.parse(req.query.variables) : {};
      const result = await runOne({ query: req.query.query, variables: vars }, ctx);
      return res.json(result);
    }
    if (req.method !== 'POST') return res.status(405).json({ error: 'method not allowed' });
    const body = req.body;
    if (Array.isArray(body)) {
      const results = [];
      for (const op of body) results.push(await runOne(op, ctx));
      return res.json(results);
    }
    const result = await runOne(body || {}, ctx);
    res.json(result);
  } catch (e) {
    res.status(500).json({ errors: [{ message: e.message, stack: e.stack }] });
  }
});

module.exports = router;
