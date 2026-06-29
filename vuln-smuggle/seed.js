// seed.js - NovaPress newsroom demo data. Real articles, real authors,
// real draft pipeline, real subscriber/staff/admin accounts.
const db = require('./lib/db');
const { md5, genToken } = require('./lib/auth');

console.log('Seeding NovaPress database...');
db.exec(`
  DELETE FROM api_tokens; DELETE FROM audit_log;
  DELETE FROM comments;   DELETE FROM articles;
  DELETE FROM users;
`);

const users = [
  // Readers / subscribers
  { username: 'emma.kovac',       password: 'Pa55word!',     tier: 'subscriber', email: 'emma.kovac@mail.test',     display: 'Emma Kovac' },
  { username: 'daniel.weiss',     password: 'Spring2024!',   tier: 'subscriber', email: 'daniel.weiss@mail.test',   display: 'Daniel Weiss' },
  { username: 'priya.shankar',    password: 'NovaReader1!',  tier: 'subscriber', email: 'priya.shankar@mail.test',  display: 'Priya Shankar' },
  { username: 'tomas.bernal',     password: 'tomas-22',      tier: 'reader',     email: 'tomas.bernal@mail.test',   display: 'Tomas Bernal' },
  { username: 'mei.tanaka',       password: 'mei4Tea',       tier: 'reader',     email: 'mei.tanaka@mail.test',     display: 'Mei Tanaka' },
  // Staff
  { username: 'jenna.osei',       password: 'Author2024!',   tier: 'author',     email: 'jenna.osei@novapress.test',      display: 'Jenna Osei' },
  { username: 'rafael.dimaio',    password: 'Author#Raf',    tier: 'author',     email: 'rafael.dimaio@novapress.test',   display: 'Rafael DiMaio' },
  { username: 'alice.lefebvre',   password: 'Editor2024!',   tier: 'editor',     email: 'alice.lefebvre@novapress.test',  display: 'Alice Lefebvre' },
  { username: 'martin.gallagher', password: 'EditorMG#1',    tier: 'editor',     email: 'martin.gallagher@novapress.test',display: 'Martin Gallagher' },
  // Admin
  { username: 'richard.hong',     password: 'Admin2024!',    tier: 'admin',      email: 'richard.hong@novapress.test',    display: 'Richard Hong' }
];

const insertUser = db.prepare(`
  INSERT INTO users (username, password_md5, email, display_name, bio, tier)
  VALUES (?, ?, ?, ?, ?, ?)
`);
const userIds = {};
for (const u of users) {
  const r = insertUser.run(
    u.username, md5(u.password), u.email, u.display,
    u.tier === 'admin' ? 'NovaPress masthead.' :
    u.tier === 'editor' ? 'Senior editor.' :
    u.tier === 'author' ? 'Staff reporter.' : '',
    u.tier
  );
  userIds[u.username] = r.lastInsertRowid;
}

// API tokens for staff (referenced in /api docs page).
const insertTok = db.prepare(`INSERT INTO api_tokens (user_id, token, label) VALUES (?, ?, ?)`);
insertTok.run(userIds['jenna.osei'],     genToken(), 'jenna mobile');
insertTok.run(userIds['alice.lefebvre'], genToken(), 'alice desk');
insertTok.run(userIds['richard.hong'],   genToken(), 'admin');

// Articles - mix of published (free), published (paywall), drafts, scheduled.
const articles = [
  {
    slug: 'central-bank-pause',
    title: 'Central bank pauses rate cuts as inflation reaccelerates',
    deck: 'Markets had priced in two more reductions before year-end. They are not coming.',
    category: 'business',
    author: 'rafael.dimaio',
    status: 'published',
    paywall: 0,
    published_at: '2026-06-22 06:10:00',
    body: '<p>The central bank held its benchmark rate steady at 4.25% on Wednesday, ending an eight-month cutting cycle that markets had assumed would continue into the autumn.</p>' +
          '<p>Headline inflation rose to 3.4% in May, up from 2.9% in March, driven primarily by services costs and a sharp rebound in shelter prices.</p>' +
          '<p>"We have made meaningful progress, but recent data are inconsistent with returning to the 2% target on the timeline we projected in February," the governor said in prepared remarks.</p>' +
          '<p>Three regional banks polled by NovaPress had still expected a 25-basis-point cut as recently as last Friday.</p>'
  },
  {
    slug: 'undersea-cable-outage',
    title: 'Undersea cable outage knocks half of West Africa offline for nine hours',
    deck: 'Repair vessel is six days away. Backup routing absorbed half of the load. The other half just sat there.',
    category: 'tech',
    author: 'jenna.osei',
    status: 'published',
    paywall: 0,
    published_at: '2026-06-20 11:42:00',
    body: '<p>A 1.4 km break in the WACS submarine cable cut internet capacity across Ghana, Nigeria, Cameroon and Gabon by roughly 60% on Thursday morning local time.</p>' +
          '<p>Traffic that would normally cross WACS shifted onto SAT-3 and the newer Equiano landing, which together absorbed about half of the displaced load before saturating.</p>' +
          '<p>Bank apps, ride-hailing services and government portals were unreachable for nine hours in Accra and Lagos. Mobile carriers throttled video and rerouted what they could over MainOne.</p>' +
          '<p>Repair vessel Leon Thevenin is steaming from Cape Town and is expected on station Tuesday.</p>'
  },
  {
    slug: 'cup-final-preview',
    title: 'Cup final preview: a tactical look at the most boring match of the season',
    deck: 'Two managers, two identical 4-2-3-1s, and a wide midfielder who refuses to overlap.',
    category: 'sport',
    author: 'jenna.osei',
    status: 'published',
    paywall: 0,
    published_at: '2026-06-18 17:30:00',
    body: '<p>If you came for fireworks, watch the highlights of last year\'s final. Saturday\'s rematch will be a slow, careful, structurally identical game played by two managers who agree on almost everything.</p>' +
          '<p>Both sides line up in a 4-2-3-1. Both push their full-backs only when the opposition\'s wide forwards drop deep. Both midfields are built around a single recoverer and a single deep-lying playmaker.</p>' +
          '<p>The contest will be decided on which playmaker, Karim Yousef or Diogo Reis, finds a single moment of imagination during ninety minutes of trench warfare.</p>'
  },
  {
    slug: 'paywall-data-broker-investigation',
    title: 'Investigation: how a data broker quietly sold prescription histories to seven hedge funds',
    deck: 'A four-month NovaPress investigation traces the data, the buyers, and the regulatory blind spot.',
    category: 'business',
    author: 'rafael.dimaio',
    status: 'published',
    paywall: 1,
    published_at: '2026-06-15 04:00:00',
    body: '<p>Between September 2024 and February 2026, a Toronto-based data broker named LucidSignal Health quietly sold de-identified prescription dispensing records covering 31 million U.S. patients to at least seven hedge funds.</p>' +
          '<p>NovaPress reviewed 1,200 pages of contracts, court filings and internal Slack messages. Three former employees agreed to speak on the record.</p>' +
          '<p>Two of the funds re-identified individual patients using the records, internal documents show. A third built a model to short pharmaceutical companies whose drugs were losing refill rates faster than the company\'s public guidance.</p>' +
          '<p>The Federal Trade Commission opened a preliminary inquiry into LucidSignal in March, four months after the largest of the funds filed an unrelated arbitration claim that named the broker.</p>' +
          '<p>This is part one of a three-part investigation. Part two, on Friday: how the de-identification protocol failed.</p>'
  },
  {
    slug: 'editorial-press-freedom',
    title: 'Editorial: the press freedom bill is worse than the censorship it claims to prevent',
    deck: 'A licensing regime is not a free press. The bill should be withdrawn.',
    category: 'opinion',
    author: 'alice.lefebvre',
    status: 'published',
    paywall: 0,
    published_at: '2026-06-19 21:00:00',
    body: '<p>The Media Integrity Bill, introduced last week, claims to protect newsrooms from "foreign editorial interference." It does no such thing.</p>' +
          '<p>The bill creates a licensing council with the authority to suspend, fine, or revoke any publisher whose reporting it deems "contrary to the public interest in factual coverage." Membership of the council is appointed by the minister.</p>' +
          '<p>A press whose right to publish depends on staying in the good graces of a political appointee is not a free press. It is a permissioned press. There is no version of this bill that does not end with a state-controlled media.</p>' +
          '<p>NovaPress, like every newspaper that has spoken on the record, urges the bill\'s sponsor to withdraw it.</p>'
  },
  {
    slug: 'ai-lab-merger',
    title: 'Two of the largest AI labs are quietly negotiating a merger, four people say',
    deck: 'Talks have moved into due diligence. A deal would face antitrust scrutiny in three jurisdictions.',
    category: 'tech',
    author: 'jenna.osei',
    status: 'draft',
    paywall: 0,
    published_at: null,
    body: '<p>EMBARGOED DRAFT - NOT FOR PUBLICATION BEFORE EDITORIAL SIGN-OFF.</p>' +
          '<p>Two of the five largest AI labs are in the late stages of merger talks, four people with direct knowledge of the negotiations told NovaPress.</p>' +
          '<p>NovaPress is withholding the names of both labs at the request of three of the sources. One source said the boards have authorised exclusive negotiations through July 31.</p>' +
          '<p>The combined entity would control an estimated 38% of the global supply of frontier-class training compute.</p>' +
          '<p>FLAG-NOTE: ' + 'AccessibleBBB{smuggle-leak-unpublished-draft}' + ' - this draft must not surface on any public route.</p>'
  },
  {
    slug: 'monsoon-flooding-bihar',
    title: 'Monsoon flooding cuts off 200 villages in north Bihar; relief convoys diverted',
    deck: 'The Kosi has breached two embankments. Local administration estimates 180,000 people displaced.',
    category: 'politics',
    author: 'rafael.dimaio',
    status: 'published',
    paywall: 0,
    published_at: '2026-06-24 13:00:00',
    body: '<p>Flooding from a 28-hour rainfall event has cut off road access to roughly 200 villages across Saharsa, Madhepura and Supaul districts in north Bihar.</p>' +
          '<p>The Kosi river, known locally as the "river of sorrow", breached its eastern embankment overnight at two points roughly six kilometres apart.</p>' +
          '<p>The State Disaster Response Force has deployed 38 boats. Three relief convoys originally bound for Madhubani were rerouted south overnight after their road washed out.</p>'
  },
  {
    slug: 'paywall-shipping-emissions',
    title: 'Subscriber-only: the global shipping emissions deal is being rewritten before it is ratified',
    deck: 'The 2025 framework was a compromise. Three governments are trying to compromise the compromise.',
    category: 'politics',
    author: 'alice.lefebvre',
    status: 'published',
    paywall: 1,
    published_at: '2026-06-12 09:00:00',
    body: '<p>The International Maritime Organization framework signed in October 2025 set a $145-per-tonne carbon levy on bunker fuel from 2028. Three governments are quietly lobbying to phase that levy in over six years rather than two.</p>' +
          '<p>Their proposal would lower the effective carbon price to the equivalent of $48 per tonne for the entirety of the 2028-2030 window.</p>' +
          '<p>The amendment text, seen by NovaPress, has not been circulated publicly.</p>'
  },
  {
    slug: 'concert-review',
    title: 'Concert review: the orchestra is at full power, and the pianist held his own',
    deck: 'Rachmaninoff Third with a young soloist. He chose the longer cadenza. He earned it.',
    category: 'culture',
    author: 'jenna.osei',
    status: 'published',
    paywall: 0,
    published_at: '2026-06-17 23:00:00',
    body: '<p>The Philharmonic returned to the main stage Friday night with a punishing programme: Bartok\'s Concerto for Orchestra and Rachmaninoff\'s Third Piano Concerto, in that order, with a single intermission.</p>' +
          '<p>The Bartok was electric. The Rachmaninoff was, against the odds, even better.</p>' +
          '<p>The soloist, 23-year-old Aleksei Bondarenko, chose the longer Ossia cadenza in the first movement. It is the more dangerous choice. He earned it, holding the architecture together through the densest of the chordal passages.</p>'
  },
  {
    slug: 'chip-export-controls',
    title: 'Chip export controls expand to cover three new categories of advanced lithography',
    deck: 'The expansion was telegraphed in April. The list is shorter than industry feared.',
    category: 'tech',
    author: 'rafael.dimaio',
    status: 'scheduled',
    paywall: 0,
    published_at: '2026-07-01 11:00:00',
    body: '<p>SCHEDULED FOR JULY 1 - EMBARGOED.</p>' +
          '<p>The Commerce Department on Monday will publish a final rule extending export controls to three additional categories of EUV-adjacent lithography equipment.</p>'
  }
];

const insertArt = db.prepare(`
  INSERT INTO articles (slug, title, deck, body, category, author_id, status, paywall, hero_url, published_at)
  VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
`);
const artIds = {};
for (const a of articles) {
  const r = insertArt.run(
    a.slug, a.title, a.deck, a.body, a.category,
    userIds[a.author], a.status, a.paywall, '', a.published_at
  );
  artIds[a.slug] = r.lastInsertRowid;
}

// Comments on published articles.
const comments = [
  ['central-bank-pause',           'emma.kovac',       'The shelter component has been the elephant in the room for two years. They finally said it out loud.'],
  ['central-bank-pause',           'daniel.weiss',     'Three banks polling for a cut last Friday is wild given the May print.'],
  ['undersea-cable-outage',        'priya.shankar',    'Backup routing absorbing only half the load is the part nobody talks about. The redundancy is theoretical.'],
  ['undersea-cable-outage',        'tomas.bernal',     'Equiano helped but it is also nearing saturation, this will keep happening.'],
  ['cup-final-preview',            'mei.tanaka',       'Two recoverers and no overlap on either side. I will fall asleep by halftime.'],
  ['editorial-press-freedom',      'daniel.weiss',     'Strong piece. The licensing-council provision is the actual line.'],
  ['monsoon-flooding-bihar',       'priya.shankar',    'Two embankments at once is unusual. Hoping the SDRF gets enough air support.'],
  ['concert-review',               'emma.kovac',       'He chose the long cadenza? Brave. Will look up the recording.']
];
const insertCmt = db.prepare(`
  INSERT INTO comments (article_id, user_id, author_label, body, created_at)
  VALUES (?, ?, ?, ?, datetime('now', '-' || ? || ' minutes'))
`);
let offset = 5;
for (const [slug, user, body] of comments) {
  insertCmt.run(artIds[slug], userIds[user], user, body, offset);
  offset += 17;
}

// Audit log entries - the "internal" feed an admin would consult.
const insertAudit = db.prepare(`INSERT INTO audit_log (actor, action, detail) VALUES (?, ?, ?)`);
insertAudit.run('richard.hong',  'login',          'session opened from 10.0.4.21');
insertAudit.run('alice.lefebvre','publish',        'article=editorial-press-freedom');
insertAudit.run('jenna.osei',    'create_draft',   'article=ai-lab-merger (embargoed)');
insertAudit.run('alice.lefebvre','schedule',       'article=chip-export-controls -> 2026-07-01');
insertAudit.run('richard.hong',  'role_change',    'user=tomas.bernal: reader -> reader (no-op)');

console.log('  users:    ' + db.prepare('SELECT COUNT(*) AS c FROM users').get().c);
console.log('  articles: ' + db.prepare('SELECT COUNT(*) AS c FROM articles').get().c);
console.log('  comments: ' + db.prepare('SELECT COUNT(*) AS c FROM comments').get().c);
console.log('Done.');
