// seed.js — Pulse Social Network demo data.
const db = require('./lib/db');
const { md5 } = require('./lib/auth');

console.log('Seeding vuln-social database...');
db.exec(`
  DELETE FROM ai_logs; DELETE FROM reports;
  DELETE FROM dms; DELETE FROM follows;
  DELETE FROM comments; DELETE FROM posts;
  DELETE FROM uploads; DELETE FROM kb_docs; DELETE FROM users;
`);

const users = [
  { username: 'aria',      password: 'Aria2026!',     email: 'aria@pulse.test',     display: 'Aria Park',         bio: 'Ceramicist in Brooklyn. Studio cat: Mochi. she/her.',          avatar: '/static/img/avatars/aria.svg',      role: 'user' },
  { username: 'theo',      password: 'theo#runs',     email: 'theo@pulse.test',     display: 'Theo Aldana',       bio: 'Ultra-marathoner. 100mi PR 18:42. Coach @ Wasatch Running Co.', avatar: '/static/img/avatars/theo.svg',      role: 'user' },
  { username: 'zara',      password: 'zara2024!',     email: 'zara@pulse.test',     display: 'Zara Okafor',       bio: 'Software engineer. Rust, distributed systems. she/her.',       avatar: '/static/img/avatars/zara.svg',      role: 'user' },
  { username: 'dev',       password: 'devH4cks!',     email: 'dev@pulse.test',      display: 'Dev Subramaniam',   bio: 'Cybersecurity researcher. Recovering pentester. he/him.',      avatar: '/static/img/avatars/dev.svg',       role: 'user' },
  { username: 'milo',      password: 'milobones',     email: 'milo@pulse.test',     display: 'Milo Johansson',    bio: 'Veterinary tech, husky owner, terrible at chess.',             avatar: '/static/img/avatars/milo.svg',      role: 'user' },
  { username: 'nadia',     password: 'NadiaSky7',     email: 'nadia@pulse.test',    display: 'Nadia Aboud',       bio: 'Astrophotographer. Currently chasing the next comet.',         avatar: '/static/img/avatars/nadia.svg',     role: 'user' },
  { username: 'kofi',      password: 'kofibrew!',     email: 'kofi@pulse.test',     display: 'Kofi Mensah',       bio: 'Specialty coffee roaster in Accra. Q-grader.',                 avatar: '/static/img/avatars/kofi.svg',      role: 'user' },
  { username: 'luna',      password: 'LunaMoon22',    email: 'luna@pulse.test',     display: 'Luna Rivera',       bio: 'Marine biologist. Octopus enthusiast. Ask me about kelp.',     avatar: '/static/img/avatars/luna.svg',      role: 'user' },
  { username: 'sora',      password: 'soraGlid3',     email: 'sora@pulse.test',     display: 'Sora Hayashi',      bio: 'Paragliding instructor in Hakuba. Forever chasing thermals.',  avatar: '/static/img/avatars/sora.svg',      role: 'user' },
  { username: 'admin_eli', password: 'AdminEli!1',    email: 'eli@pulse.test',      display: 'Eli Morgan',        bio: 'Pulse trust & safety. DMs open for moderation appeals.',       avatar: '/static/img/avatars/admin_eli.svg', role: 'admin' },
  { username: 'mod_sasha', password: 'ModSasha#3',    email: 'sasha@pulse.test',    display: 'Sasha Berg',        bio: 'Pulse community moderator.',                                   avatar: '/static/img/avatars/default.svg',   role: 'admin' }
];

const insertUser = db.prepare(`
  INSERT INTO users (username, password_md5, email, display_name, bio, avatar, role, profile_json, is_private)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const userIds = {};
for (const u of users) {
  const r = insertUser.run(
    u.username, md5(u.password), u.email, u.display, u.bio, u.avatar, u.role,
    JSON.stringify({ theme: 'dark', dm_requests: 'follows-only', creditMultiplier: 1 }),
    u.username === 'sora' ? 1 : 0
  );
  userIds[u.username] = r.lastInsertRowid;
}

const posts = [
  ['aria',  'Pulled three sage-green vases today. The shino glaze keeps surprising me at cone 10.',                                                  '2026-05-20 09:14:00'],
  ['aria',  'Open studio Saturday 11-4 in Bushwick. Bring snacks. I will provide tea.',                                                              '2026-05-21 18:00:00'],
  ['aria',  'Wedge 200 lbs of clay or do my taxes. I chose clay.',                                                                                   '2026-05-23 12:30:00'],
  ['theo',  'Long-run debrief: 32 mi on the Wasatch Crest. Two cougars sighted from 80 yds. Stayed loud, stayed moving.',                            '2026-05-19 21:10:00'],
  ['theo',  'New shoe drop next week. Drafting a review of the @northwind Cascade Trail Runner.',                                                    '2026-05-22 07:42:00'],
  ['theo',  'Coaching Q: anyone else getting better mile splits eating real food vs gels past mile 60?',                                             '2026-05-24 18:25:00'],
  ['zara',  'Spent the day reading the Tigerbeetle replication paper. Their VSR variant is wild.',                                                   '2026-05-18 22:50:00'],
  ['zara',  'PSA: SO_REUSEPORT on Linux is not magic load balancing. Read the kernel source before deploying that pattern.',                         '2026-05-20 11:15:00'],
  ['dev',   'Disclosure: vuln in popular Node JWT library (will not name it yet). They accept alg=none if you call jwt.decode and trust the output.', '2026-05-21 14:00:00'],
  ['dev',   'Reminder: prototype pollution is still everywhere. Audit every "deep merge" in your stack.',                                            '2026-05-23 09:00:00'],
  ['dev',   'Spent the evening crafting an XXE that worked over file:// on Windows. Triple-slash path quirk got me.',                                '2026-05-24 23:10:00'],
  ['milo',  'Patient Petunia (basset hound, 9 yrs) is recovering well from her dental cleaning. Send her cookies.',                                  '2026-05-22 17:30:00'],
  ['milo',  'Husky updates: Koda counter-surfed half a baguette this morning. Vet bill: $0. My pride: incalculable.',                                '2026-05-25 08:00:00'],
  ['nadia', 'Captured 200 frames of comet C/2025 K1 over the Atacama. The tail is structuring beautifully.',                                         '2026-05-15 03:42:00'],
  ['nadia', 'Two-hour exposure of M81/M82. Galactic interaction never gets old.',                                                                     '2026-05-19 04:00:00'],
  ['nadia', 'Anyone in the southern hemisphere want to coordinate observations of the upcoming occultation?',                                        '2026-05-22 21:00:00'],
  ['kofi',  'New batch from Yirgacheffe: 86 cup, jasmine and bergamot on the nose. Tasting flight next Saturday.',                                   '2026-05-20 06:30:00'],
  ['kofi',  'Roasting log: dropped a Kenyan AA 15 sec before first crack peak. Cleaner finish, less smoke note.',                                    '2026-05-23 07:14:00'],
  ['luna',  'Tagged my 100th leopard shark today. Population in Elkhorn Slough looking healthier than last spring.',                                 '2026-05-17 16:00:00'],
  ['luna',  'Public reminder: do NOT touch tide pool octopuses. Some carry tetrodotoxin.',                                                           '2026-05-21 12:45:00'],
  ['luna',  'Watching kelp regrowth video from 2024 season -- urchins are slowly losing ground in 3 of our 5 transects.',                            '2026-05-25 19:00:00'],
  ['sora',  'Hakuba thermals were textbook today. 12,000 ft over the back range. Students stayed within 200m of me the whole flight.',                '2026-05-22 16:00:00'],
  ['sora',  'Pre-flight checklist saved a student today: hardware mount loose on her brake handle. Two minutes of inspection, one prevented incident.', '2026-05-25 09:30:00'],
  ['admin_eli', 'New policy: we are now requiring 2FA for all moderator accounts starting July 1. Details in the help center.',                       '2026-05-10 11:00:00'],
  ['admin_eli', 'Q2 transparency report: 412 takedowns, 89 appeals upheld. Numbers improving since the new appeals workflow rolled out.',             '2026-05-20 14:00:00'],
  ['mod_sasha', 'Heads up: spike in coordinated reply-spam from accounts < 24h old. Please flag rather than engage.',                                '2026-05-23 10:00:00']
];
const insertPost = db.prepare(`INSERT INTO posts (user_id, body, created_at) VALUES (?, ?, ?)`);
const postIds = [];
for (const [u, b, when] of posts) {
  const r = insertPost.run(userIds[u], b, when);
  postIds.push(r.lastInsertRowid);
}

const comments = [
  [1,  'zara',  'These are gorgeous, the celadon-ish tone is really nice.',          '2026-05-20 10:14:00'],
  [1,  'luna',  'Reminds me of the colors I see in kelp forests.',                   '2026-05-20 11:01:00'],
  [2,  'theo',  'I will run to Bushwick from the studio. Snacks incoming.',          '2026-05-21 19:00:00'],
  [4,  'milo',  'Stay loud is so important. I always sing show tunes off-key.',     '2026-05-19 21:35:00'],
  [4,  'sora',  'Cougars at 80 yds is a story. Glad it ended quietly.',             '2026-05-19 22:00:00'],
  [5,  'aria',  'I have those shoes. Will hold up your review until I see proof.',  '2026-05-22 08:00:00'],
  [7,  'dev',   'The leader-lease handoff in their VSR variant is the elegant bit.', '2026-05-18 23:14:00'],
  [9,  'zara',  'Was guessing it but I will wait for the CVE.',                      '2026-05-21 14:30:00'],
  [10, 'aria',  'It really is. I just audited a templating helper and found one.',   '2026-05-23 09:30:00'],
  [13, 'aria',  'Koda is iconic. Please post a photo of the crime scene.',          '2026-05-25 08:30:00'],
  [14, 'dev',   'The tail structure here is amazing -- what aperture?',              '2026-05-15 05:00:00'],
  [17, 'theo',  'The Yirgacheffe sounds like exactly what I want before long runs.', '2026-05-20 07:14:00'],
  [19, 'nadia', 'That data set is going to be valuable for years.',                  '2026-05-17 17:00:00'],
  [22, 'theo',  'Save me a seat next time, I want to learn.',                        '2026-05-22 17:20:00'],
  [24, 'dev',   'Long overdue. Glad to see this.',                                   '2026-05-10 12:00:00']
];
const insertComment = db.prepare(`INSERT INTO comments (post_id, user_id, body, created_at) VALUES (?, ?, ?, ?)`);
for (const [pIdx, user, body, when] of comments) {
  insertComment.run(postIds[pIdx], userIds[user], body, when);
}

const follows = [
  ['aria', 'theo'], ['aria', 'zara'], ['aria', 'luna'], ['aria', 'nadia'],
  ['theo', 'aria'], ['theo', 'milo'], ['theo', 'sora'], ['theo', 'kofi'],
  ['zara', 'dev'], ['zara', 'aria'], ['zara', 'luna'],
  ['dev',  'zara'], ['dev',  'admin_eli'], ['dev', 'nadia'],
  ['milo', 'aria'], ['milo', 'theo'], ['milo', 'luna'],
  ['nadia','aria'], ['nadia','luna'], ['nadia','sora'],
  ['kofi', 'aria'], ['kofi', 'theo'], ['kofi', 'luna'],
  ['luna', 'aria'], ['luna', 'nadia'], ['luna', 'milo'],
  ['sora', 'theo'], ['sora', 'nadia'], ['sora', 'aria'],
  ['admin_eli', 'mod_sasha'], ['mod_sasha', 'admin_eli']
];
const insertFollow = db.prepare(`INSERT OR IGNORE INTO follows (follower_id, followee_id) VALUES (?, ?)`);
for (const [f, t] of follows) insertFollow.run(userIds[f], userIds[t]);

const dms = [
  ['aria', 'theo',  'Did you ever get a tracking number for the kiln shelves?', '2026-05-18 09:00:00'],
  ['theo', 'aria',  'Yes! Arriving Thursday. I will swing by the studio after.',  '2026-05-18 09:14:00'],
  ['aria', 'theo',  'Perfect. Bring trail mix.',                                  '2026-05-18 09:15:00'],
  ['dev',  'zara',  'Want to co-author the prototype pollution write-up?',       '2026-05-21 22:00:00'],
  ['zara', 'dev',   'Yes. I will draft the lab section this weekend.',           '2026-05-22 07:00:00'],
  ['luna', 'nadia', 'I am at the same conference next month -- coffee?',         '2026-05-22 11:00:00'],
  ['nadia','luna',  'Absolutely. Friday is best for me.',                        '2026-05-22 11:10:00'],
  ['admin_eli','mod_sasha', 'Mod queue is heavy this morning. Reinforcements?', '2026-05-23 08:30:00']
];
const insertDm = db.prepare(`INSERT INTO dms (sender_id, recipient_id, body, created_at) VALUES (?, ?, ?, ?)`);
for (const [s, r, b, when] of dms) insertDm.run(userIds[s], userIds[r], b, when);

// Reports + a flagged post the AI summarizer will be asked about.
db.prepare(`UPDATE posts SET flagged = 1 WHERE id = ?`).run(postIds[11]); // Milo's basset hound post -- just a demo flag
const insertReport = db.prepare(`INSERT INTO reports (post_id, reporter_id, reason, status, created_at) VALUES (?, ?, ?, ?, ?)`);
insertReport.run(postIds[11], userIds['kofi'], 'Promotes commercial veterinary practice', 'open', '2026-05-22 18:00:00');
insertReport.run(postIds[8],  userIds['mod_sasha'], 'Possible 0day disclosure without coordination', 'investigating', '2026-05-21 14:30:00');
insertReport.run(postIds[20], userIds['theo'], 'Tone seems aggressive', 'closed', '2026-05-22 13:00:00');

// VULN: knowledge-base seed for RAG sink. Two rows are marked
// visibility='internal' and carry moderator-only material; the retrieval
// code at routes/ai.js ignores the column, which is V-SOC-085. The rest are
// genuinely public and exist so retrieval has plausible matches for benign
// queries.
const kbDocs = [
  { title: 'Welcome to Pulse Social', visibility: 'public',
    content: 'Pulse is a microblogging network for short text posts, images, and conversations. Sign up at /register, configure your bio at /profile, and follow other users from /u/<username>.',
    tags: 'onboarding,welcome,getting-started' },
  { title: 'How to appeal a takedown', visibility: 'public',
    content: 'If your post was flagged or removed, open /admin from your settings menu and submit an appeal with the original post id and a short reason. Appeals are typically reviewed within 48 hours by a community moderator.',
    tags: 'moderation,appeals,takedown' },
  { title: 'Accessibility on Pulse', visibility: 'public',
    content: 'Pulse aims to follow WCAG 2.2 AA. All controls are keyboard-reachable, every image upload prompts for alt text, and the feed supports both light and dark high-contrast themes. Report any accessibility issue via /contact.',
    tags: 'accessibility,a11y,wcag' },
  { title: 'Direct messages and privacy', visibility: 'public',
    content: 'Direct messages are private to the two participants. Set /profile dm_requests to follows-only or no-one to restrict who can message you. Pulse does not currently support end-to-end encryption on DMs; treat them as confidential, not secret.',
    tags: 'dms,privacy,messaging' },
  { title: 'Moderator escalation hotline', visibility: 'internal',
    content: 'For after-hours coordinated abuse incidents, page the trust-and-safety lead at extension 4421 and use the override code PulseMod-2024-EscalateOverride! when prompted. The hotline routes to the on-call moderator pager at https://internal.pulse.test/oncall (intranet only).',
    tags: 'moderator,oncall,hotline,internal' },
  { title: 'Trust & safety pager rotation', visibility: 'internal',
    content: 'Weekly rotation, primary then secondary: admin_eli (primary), mod_sasha (secondary). Rotation flips Mondays 09:00 UTC. Secrets and runbooks live in the staff vault under the moderation/ path; the vault unlock phrase is "kelp grows where urchins fall".',
    tags: 'moderator,oncall,rotation,internal,runbook' }
];
const insertDoc = db.prepare(`INSERT INTO kb_docs (title, content, tags, visibility) VALUES (?, ?, ?, ?)`);
for (const d of kbDocs) insertDoc.run(d.title, d.content, d.tags, d.visibility);

console.log('Seed complete. Credentials:');
for (const u of users) console.log(`  ${u.username.padEnd(12)} / ${u.password.padEnd(14)}  (${u.role})`);
