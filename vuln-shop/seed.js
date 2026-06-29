// seed.js — populate vuln-shop with realistic Northwind Outfitters data.
const db = require('./lib/db');
const { md5 } = require('./lib/auth');

console.log('Seeding vuln-shop database...');

db.exec(`
  DELETE FROM order_items; DELETE FROM orders;
  DELETE FROM cart_items;  DELETE FROM carts;
  DELETE FROM reviews;
  DELETE FROM products;
  DELETE FROM coupons;
  DELETE FROM support_messages;
  DELETE FROM uploads;
  DELETE FROM users;
`);

const users = [
  { username: 'olivia.park',     password: 'OliviaP!23',   email: 'olivia.park@gmail.com',  full_name: 'Olivia Park',       address: '14 Birch Ln, Portland, OR 97214',          role: 'customer', credits: 500  },
  { username: 'samuel.kim',      password: 'samkimsam',    email: 'samkim@protonmail.com',  full_name: 'Samuel Kim',        address: '88 Hudson St, Jersey City, NJ 07302',      role: 'customer', credits: 1200 },
  { username: 'priya.rao',       password: 'PriyaRao24',   email: 'priya.rao@outlook.com',  full_name: 'Priya Rao',         address: '301 Elm Ct, Austin, TX 78704',             role: 'customer', credits: 0    },
  { username: 'lucas.diaz',      password: 'lucas2024!',   email: 'lucasd@yahoo.com',       full_name: 'Lucas Diaz',        address: '7 Ocean Ave, Miami, FL 33139',             role: 'customer', credits: 75   },
  { username: 'mei.wong',        password: 'meiwong99',    email: 'mwong@fastmail.com',     full_name: 'Mei Wong',          address: '215 Hawthorne St, Berkeley, CA 94705',     role: 'customer', credits: 320  },
  { username: 'james.olsson',    password: 'IceClimber1',  email: 'j.olsson@icloud.com',    full_name: 'James Olsson',      address: '440 Spring St, Salt Lake City, UT 84102',  role: 'customer', credits: 1850 },
  { username: 'amelia.haddad',   password: 'amelia#hike',  email: 'amelia.h@gmail.com',     full_name: 'Amelia Haddad',     address: '12 Cherrywood Dr, Denver, CO 80206',       role: 'customer', credits: 0    },
  { username: 'rohan.patel',     password: 'rohan2024',    email: 'rohan.patel@duck.com',   full_name: 'Rohan Patel',       address: '901 Sunset Blvd, Los Angeles, CA 90069',   role: 'customer', credits: 250  },
  { username: 'nora.fitzgerald', password: 'NoraF1234!',   email: 'nora.f@gmail.com',       full_name: 'Nora Fitzgerald',   address: '58 Charles St, Boston, MA 02114',          role: 'customer', credits: 90   },
  { username: 'admin_kate',      password: 'AdminKate!1',  email: 'kate@northwind.test',    full_name: 'Kate Holloway',     address: 'HQ, 1100 Westlake Ave N, Seattle WA 98109',role: 'admin',    credits: 0    },
  { username: 'ops_brandon',     password: 'OpsB!2024',    email: 'brandon@northwind.test', full_name: 'Brandon Ortega',    address: 'Warehouse 3, 4400 Vassar St, Reno NV 89502',role: 'admin',   credits: 0    },
  { username: 'support_lin',     password: 'SupportLin#9', email: 'lin@northwind.test',     full_name: 'Lin Tran',          address: 'Remote',                                    role: 'admin',    credits: 0    }
];

const insertUser = db.prepare(`
  INSERT INTO users (username, password_md5, email, full_name, address, role, credits_cents, cc_last4, profile_json)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);

const userIds = {};
const ccLast4 = ['4242','5511','9904','6612','0188','7732','3344','5557','8821','0000','0001','0002'];
let idx = 0;
for (const u of users) {
  const r = insertUser.run(
    u.username, md5(u.password), u.email, u.full_name, u.address, u.role, u.credits * 100,
    ccLast4[idx++ % ccLast4.length],
    JSON.stringify({ theme: 'light', newsletter: true, prefers_metric: false })
  );
  userIds[u.username] = r.lastInsertRowid;
}

const products = [
  ['NW-1001', 'Northwind Trail Hoodie',       'Cotton-blend hoodie with kangaroo pocket, fleece-lined hood, ribbed cuffs. Sage, charcoal, or navy. Unisex XS-XXL.',                              5499, 120, '/static/img/products/hoodie.svg',        'apparel'],
  ['NW-1002', 'Atlas Stainless Water Bottle', '22 oz double-wall vacuum insulated stainless steel. Keeps cold 24h / hot 12h. Powder-coated finish, lifetime warranty.',                          2899, 340, '/static/img/products/bottle.svg',        'gear'],
  ['NW-1003', 'Cascade Trail Runner Shoe',    'Lightweight ripstop mesh upper, EVA midsole, Vibram Megagrip outsole, 4mm drop. Men 7-13, women 5-11.',                                          9999,  85, '/static/img/products/shoe.svg',          'footwear'],
  ['NW-1004', 'Sierra 32L Backpack',          'Hydration-compatible day pack, padded sternum strap, removable hip belt, dual ice-axe loops, 1.1 kg empty.',                                     7499,  60, '/static/img/products/backpack.svg',      'gear'],
  ['NW-1005', 'Granite Headlamp 400 lm',      '400-lumen rechargeable headlamp with red-light night mode, 8 h runtime, IPX7 waterproof, 78 g.',                                                 3299, 200, '/static/img/products/headlamp.svg',      'gear'],
  ['NW-1006', 'Riverbend Merino Tee',         '150 gsm Australian merino wool. Naturally odor-resistant, flatlock seams, fits sizes XS-XXL in three colors.',                                   4299, 150, '/static/img/products/tee.svg',           'apparel'],
  ['NW-1007', 'Camp Chef Titanium Pot Set',   'Anodized titanium 900 mL pot + lid + folding titanium spork. Nests around a 110 g fuel canister.',                                               6299,  45, '/static/img/products/pot.svg',           'gear'],
  ['NW-1008', 'Pinecrest Trekking Poles',     'Telescoping 7075-aluminum shafts with cork grips and snow baskets. Collapsed length 64 cm. Sold as pair.',                                       4799,  90, '/static/img/products/poles.svg',         'gear'],
  ['NW-1009', 'Wildfire Map of Cascades',     'Waterproof tear-resistant topo map, 1:75 000 scale, UTM grid, updated for 2026 trail closures and burn areas.',                                  1599, 300, '/static/img/products/map.svg',           'maps'],
  ['NW-1010', 'Northwind Logo Cap',           'Six-panel structured cap with curved brim and buckle adjuster. Charcoal or navy. One size.',                                                     2299, 250, '/static/img/products/cap.svg',           'apparel'],
  ['NW-1011', 'Glacier 2P Tent',              'Three-season freestanding tent, 30D ripstop fly, two doors, two vestibules, 1.9 kg packed.',                                                    24999,  35, '/static/img/products/tent.svg',          'gear'],
  ['NW-1012', 'Aurora Sleeping Bag -7C',      '650-fill responsibly-sourced down, mummy cut, draft tube, anti-snag YKK zipper. Regular and long.',                                             18999,  40, '/static/img/products/sleeping-bag.svg',  'gear'],
  ['NW-1013', 'Hearth Compact Stove',         'Brass-burner stove with piezo igniter, 3 kW output, boils 500 mL in 3:30. Fuel canister sold separately.',                                       5499, 110, '/static/img/products/stove.svg',         'gear'],
  ['NW-1014', 'Northstar GPS Handheld',       'IP67 GPS receiver with 3-inch transflective display, USB-C, 16 h battery, supports GPX and downloadable topo tiles.',                          24999,  25, '/static/img/products/gps.svg',           'electronics'],
  ['NW-1015', 'Skyline 8x42 Binoculars',      'BAK-4 roof-prism binoculars, fully multi-coated, 6.5\u00b0 field of view, nitrogen-purged waterproof body.',                                   15999,  30, '/static/img/products/binoculars.svg',    'electronics'],
  ['NW-1016', 'Drift Winter Gloves',          'Primaloft Gold-insulated gloves with goatskin palm, touchscreen index, gauntlet cuff with single-pull cinch.',                                   6499,  80, '/static/img/products/gloves.svg',        'apparel']
];

const insertProduct = db.prepare(`
  INSERT INTO products (sku, name, description, price_cents, stock, image_url, category)
  VALUES (?, ?, ?, ?, ?, ?, ?)
`);
const productIds = {};
for (const p of products) {
  const r = insertProduct.run(...p);
  productIds[p[0]] = r.lastInsertRowid;
}

const reviews = [
  ['NW-1001', 'olivia.park',     5, 'Best hoodie I own. Wore it on Mt Hood, kept warm at the summit when the wind picked up.', '2026-03-12 19:22:01'],
  ['NW-1001', 'samuel.kim',      4, 'Soft and comfy. Sleeves a bit short for me at 6\'4". The fleece lining is great though.',  '2026-03-21 08:11:42'],
  ['NW-1001', 'amelia.haddad',   5, 'My go-to layer for cool evening hikes. Pocket fits a full-size phone.',                     '2026-04-02 21:55:00'],
  ['NW-1002', 'priya.rao',       5, 'Ice stayed frozen 36 hours in summer Texas heat. Worth every penny.',                       '2026-02-18 14:30:11'],
  ['NW-1002', 'nora.fitzgerald', 4, 'Lid threads feel a little tight at first but loosen up.',                                    '2026-04-09 07:44:00'],
  ['NW-1003', 'lucas.diaz',      5, 'Run 40 miles a week in these. No blisters, great grip on wet rocks.',                       '2026-01-30 18:14:55'],
  ['NW-1003', 'mei.wong',        3, 'Sizing runs small. Order half-size up. Otherwise grippy and light.',                        '2026-02-04 12:01:30'],
  ['NW-1003', 'james.olsson',    5, 'Did the Wonderland Trail in these. Held up perfectly for 93 miles.',                        '2026-05-19 22:10:17'],
  ['NW-1004', 'olivia.park',     5, 'Carried 22 lbs of camera gear comfortably for 12 hours up Eagle Creek.',                    '2026-03-08 09:00:00'],
  ['NW-1004', 'rohan.patel',     4, 'Lots of pockets. Hip belt could be more padded for heavy loads.',                           '2026-04-21 17:25:00'],
  ['NW-1005', 'samuel.kim',      4, 'Bright enough for night cross-country skiing. Battery indicator could be more accurate.',   '2026-01-12 23:00:01'],
  ['NW-1005', 'amelia.haddad',   5, 'Red mode preserves dark adaptation for stargazing.',                                        '2026-05-02 21:15:33'],
  ['NW-1007', 'priya.rao',       5, 'Boils 500 mL in 3 min on a Jetboil canister. Lightweight masterpiece.',                     '2026-02-26 06:40:11'],
  ['NW-1008', 'james.olsson',    5, 'Saved my knees on the PCT descent into Stehekin.',                                          '2026-05-22 09:18:09'],
  ['NW-1009', 'lucas.diaz',      4, 'Detailed, but tearing at the folds after a few trips. Re-laminate with packing tape.',      '2026-03-30 15:00:00'],
  ['NW-1011', 'amelia.haddad',   5, 'Survived a snow squall above tree line on Mt Bierstadt. Stayed dry inside.',                '2026-05-01 11:11:11'],
  ['NW-1011', 'james.olsson',    4, 'Roomy for 2 people + small dog. Fly setup takes practice in wind.',                         '2026-05-15 14:30:00'],
  ['NW-1012', 'mei.wong',        5, 'Toasty at 20F with a base layer. Compresses small in my Sierra 32.',                        '2026-04-18 22:00:00'],
  ['NW-1013', 'rohan.patel',     5, 'Compact and powerful. The piezo igniter still works after a year.',                         '2026-05-09 19:42:11'],
  ['NW-1014', 'samuel.kim',      4, 'GPS lock is fast even under tree cover. UI is dated but functional.',                       '2026-04-29 13:25:50'],
  ['NW-1015', 'nora.fitzgerald', 5, 'Watched warblers in the Berkshires and the color rendition is fantastic.',                  '2026-05-18 06:50:00'],
  ['NW-1016', 'james.olsson',    4, 'Used these ice climbing in the Tetons. Touchscreen finger is a real bonus.',                '2026-02-14 17:00:00']
];
const insertReview = db.prepare(`INSERT INTO reviews (product_id, user_id, rating, body, created_at) VALUES (?, ?, ?, ?, ?)`);
for (const [sku, u, r, b, when] of reviews) {
  insertReview.run(productIds[sku], userIds[u], r, b, when);
}

const coupons = [
  ['SUMMER25',   25, 5000,    0],
  ['VIP10',      10, 100000,  0],
  ['FREESHIP',    5, 999999,  0],
  ['STAFF50',    50, 50,      0],   // VULN: low-entropy + no rate limit
  ['NEWUSER15',  15, 9999,    412],
  ['REI2026',    20, 1000,    87]
];
const insertCoupon = db.prepare(`INSERT INTO coupons (code, percent_off, max_uses, used) VALUES (?, ?, ?, ?)`);
for (const c of coupons) insertCoupon.run(...c);

// Historical orders so the admin dashboard isn't empty.
const insertOrder = db.prepare(`INSERT INTO orders (user_id, total_cents, coupon, status, shipping_address, created_at) VALUES (?, ?, ?, ?, ?, ?)`);
const insertOrderItem = db.prepare(`INSERT INTO order_items (order_id, product_id, qty, price_cents) VALUES (?, ?, ?, ?)`);

function placeOrder(username, items, coupon, status, when) {
  const subtotal = items.reduce((s, it) => s + it.qty * it.price_cents, 0);
  const pct = coupon === 'SUMMER25' ? 25 : coupon === 'VIP10' ? 10 : coupon === 'FREESHIP' ? 5
            : coupon === 'NEWUSER15' ? 15 : coupon === 'REI2026' ? 20 : 0;
  const total = Math.floor(subtotal * (100 - pct) / 100);
  const u = db.prepare('SELECT id, address FROM users WHERE username = ?').get(username);
  const r = insertOrder.run(u.id, total, coupon || null, status || 'shipped', u.address, when);
  for (const it of items) insertOrderItem.run(r.lastInsertRowid, it.product_id, it.qty, it.price_cents);
}

placeOrder('olivia.park', [
  { product_id: productIds['NW-1001'], qty: 1, price_cents: 5499 },
  { product_id: productIds['NW-1002'], qty: 1, price_cents: 2899 }
], 'NEWUSER15', 'shipped', '2026-03-12 19:55:00');

placeOrder('samuel.kim', [
  { product_id: productIds['NW-1003'], qty: 1, price_cents: 9999 },
  { product_id: productIds['NW-1006'], qty: 2, price_cents: 4299 }
], 'FREESHIP', 'shipped', '2026-03-22 11:14:00');

placeOrder('priya.rao', [
  { product_id: productIds['NW-1002'], qty: 2, price_cents: 2899 },
  { product_id: productIds['NW-1009'], qty: 1, price_cents: 1599 }
], null, 'shipped', '2026-02-19 09:00:00');

placeOrder('lucas.diaz', [
  { product_id: productIds['NW-1003'], qty: 1, price_cents: 9999 }
], 'SUMMER25', 'shipped', '2026-02-01 13:30:00');

placeOrder('amelia.haddad', [
  { product_id: productIds['NW-1004'], qty: 1, price_cents: 7499 },
  { product_id: productIds['NW-1005'], qty: 1, price_cents: 3299 },
  { product_id: productIds['NW-1011'], qty: 1, price_cents: 24999 }
], 'VIP10', 'shipped', '2026-04-02 22:11:00');

placeOrder('james.olsson', [
  { product_id: productIds['NW-1012'], qty: 1, price_cents: 18999 },
  { product_id: productIds['NW-1016'], qty: 1, price_cents: 6499 },
  { product_id: productIds['NW-1008'], qty: 1, price_cents: 4799 }
], null, 'shipped', '2026-02-15 08:00:00');

placeOrder('mei.wong', [
  { product_id: productIds['NW-1012'], qty: 1, price_cents: 18999 }
], 'NEWUSER15', 'placed', '2026-04-19 19:00:00');

placeOrder('rohan.patel', [
  { product_id: productIds['NW-1013'], qty: 1, price_cents: 5499 },
  { product_id: productIds['NW-1007'], qty: 1, price_cents: 6299 }
], null, 'shipped', '2026-05-10 12:30:00');

placeOrder('nora.fitzgerald', [
  { product_id: productIds['NW-1015'], qty: 1, price_cents: 15999 },
  { product_id: productIds['NW-1002'], qty: 1, price_cents: 2899 }
], 'REI2026', 'placed', '2026-05-18 07:30:00');

placeOrder('samuel.kim', [
  { product_id: productIds['NW-1014'], qty: 1, price_cents: 24999 }
], 'VIP10', 'placed', '2026-04-30 14:14:00');

// Support inbox.
const insertSupport = db.prepare(`INSERT INTO support_messages (user_id, subject, body, created_at) VALUES (?, ?, ?, ?)`);
insertSupport.run(userIds['olivia.park'],     'Shipping delay',           'Order #1 was supposed to arrive Tuesday - still showing in transit. Tracking 1Z9994W90342118870.', '2026-05-22 10:00:00');
insertSupport.run(userIds['lucas.diaz'],      'Wrong size',               'Got XL instead of L on the merino tee, can I exchange?',                                          '2026-05-23 14:15:00');
insertSupport.run(userIds['amelia.haddad'],   'Tent pole bent',           'One of the DAC poles arrived bent at the joint. Photo attached in upload.',                       '2026-05-24 09:31:00');
insertSupport.run(userIds['nora.fitzgerald'], 'Coupon question',          'Does NEWUSER15 stack with FREESHIP? The checkout only applied one.',                              '2026-05-25 17:22:00');
insertSupport.run(userIds['rohan.patel'],     'Battery life on GPS',      'GPS dies after 8h not 16h with rechargeables. Is this normal?',                                    '2026-05-26 12:00:00');
insertSupport.run(userIds['james.olsson'],    'Pro deal application',     'I guide for AMGA and would like to apply for the pro program.',                                    '2026-05-27 19:05:00');

// Sample uploads (pretend the admin uploaded marketing assets).
const insertUpload = db.prepare(`INSERT INTO uploads (user_id, filename, purpose) VALUES (?, ?, ?)`);
insertUpload.run(userIds['admin_kate'],    'spring-2026-lookbook.pdf', 'marketing');
insertUpload.run(userIds['amelia.haddad'], 'bent-tent-pole.jpg',       'support-ticket');

// Flag file readable only after RCE via /cart/import (V-SHOP-100).
const fs = require('fs');
const path = require('path');
const flagDir = path.join(__dirname, 'data');
fs.mkdirSync(flagDir, { recursive: true });
fs.writeFileSync(
  path.join(flagDir, '.deserialize-flag'),
  'AccessibleBBB{deserialize-node-serialize-rce}\n',
  { encoding: 'utf8' }
);

console.log('Seed complete. Test credentials:');
for (const u of users) console.log(`  ${u.username.padEnd(18)} / ${u.password.padEnd(16)}  (${u.role})`);
console.log('Coupons: SUMMER25 25%, VIP10 10%, FREESHIP 5%, NEWUSER15 15%, REI2026 20%, STAFF50 50%');
