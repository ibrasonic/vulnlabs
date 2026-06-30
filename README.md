# vulnlabs

> **Deliberately vulnerable practice labs.** Self-contained, seeded with
> realistic data, end-to-end exploit harness, and a per-app vulnerability
> inventory you can read straight through.

![status: lab use only](https://img.shields.io/badge/use-lab%20only-red)
![node](https://img.shields.io/badge/node-24%20LTS-339933?logo=node.js&logoColor=white)
![docker](https://img.shields.io/badge/docker-compose-2496ED?logo=docker&logoColor=white)
![license](https://img.shields.io/badge/license-MIT-blue)

These apps are companion practice targets for the book *Web Application
Penetration Testing — Accessibility-First, Terminal-First*. Each one is
intentionally insecure across an entire OWASP-Top-10-and-then-some
checklist, so the same lab covers half the curriculum without any extra
setup.

> [!WARNING]
> The default bind is `0.0.0.0:<port>` so each app is reachable from your
> lab network. **Do not expose any port to the public internet.** Do not
> run on a corporate network without written permission. See
> [`SECURITY.md`](SECURITY.md).

## What's in the box

| Lab           | Theme                        | App port | Side service             | Stack                                                                  |
| ------------- | ---------------------------- | -------- | ------------------------ | ---------------------------------------------------------------------- |
| `vuln-bank`   | Online banking + admin       | 3001     | MySQL 8 (`mysql:3306`)   | Node 24 + Express + EJS + MySQL 8 (`mysql2` + `deasync`)               |
| `vuln-shop`   | E-commerce + admin + GraphQL | 3002     | 5002 (Flask)             | Node 24 + Express + EJS + GraphQL + `node:sqlite` &nbsp;·&nbsp; Python 3 + Flask (Jinja2 SSTI sink) |
| `vuln-social` | Social network + DMs + LLM   | 3003     | —                        | Node 24 + Express + EJS + Socket.IO + `node:sqlite` &nbsp;·&nbsp; Google Gemini |

Every app ships:

- `server.js` — the Express entry point.
- `seed.js` — realistic seed data, run automatically on first start.
- `routes/`, `lib/`, `views/`, `public/` — the actual app.
- `Dockerfile` + `docker-compose.yml` — one-shot containerised run.
- `run.ps1` — one-shot Windows launcher (checks Node, runs `npm install`
  on first run, seeds the DB, starts the server, prints credentials).
- `smoke-test.ps1` — end-to-end exploit harness that walks the full
  vulnerability inventory.
- `VULNERABILITIES.txt` — every sink, exploitation recipe, and intended
  mitigation. Read this top-to-bottom for any one app and you have a
  guided tour of dozens of vuln classes.

## Combined vulnerability coverage

All ten OWASP Top 10 categories plus the modern adjacent classes:

- **A01 Broken Access Control** — IDOR / BOLA, GET-based privilege
  escalation, missing function-level auth, force-browsing admin paths.
- **A02 Cryptographic Failures** — MD5 password storage, JWT `alg=none`,
  weak HS256 secrets, predictable session tokens, secrets in JS bundles.
- **A03 Injection** — SQL injection (login, search, admin), reflected /
  stored / DOM XSS, server-side template injection (Jinja2), GraphQL
  injection, prototype pollution sinks.
- **A04 Insecure Design** — coupon-stacking race, mass assignment on
  register, multi-step checkout bypass, business-logic skips.
- **A05 Security Misconfiguration** — `/debug` routes, CORS reflection
  with credentials, missing security headers, clickjackable admin,
  shipped source maps, default creds, secrets in client bundles.
- **A06 Vulnerable Components** — jQuery 1.12.4 (CVE-2019-11358) and
  lodash-style merge sinks.
- **A07 Auth Failures** — no rate limiting, weak reset, user enumeration,
  JWT misuse.
- **A08 Software/Data Integrity** — `jQuery.extend(true, …)` prototype
  pollution, deep-merge pollution in profile JSON.
- **A09 Logging Failures** — sensitive data (passwords, JWTs, LLM
  prompts) written to logs.
- **A10 SSRF** — webhook callback + image proxy.
- **Beyond Top 10** — file-upload RCE, path traversal / LFI, GraphQL
  no-auth dump + BOLA, WebSocket CSWSH + no-auth `read_dm` +
  unauthenticated broadcast, LLM prompt-injection via `/ai-summary`,
  CSRF (GET-based follow / DM / report / promote), open redirect,
  header injection, cache-poisoning patterns.

The exact location, recipe, and intended fix for each sink lives in the
app's `VULNERABILITIES.txt`.

## Requirements

| Need                | Version                                              |
| ------------------- | ---------------------------------------------------- |
| Node.js             | **24 LTS or newer** (`vuln-shop` and `vuln-social` need `node:sqlite`; `vuln-bank` needs `deasync` native bindings) |
| Docker Desktop      | **Required for `vuln-bank`** (bundled MySQL 8 sidecar); optional for the other two |
| PowerShell          | 5.1+ (Windows) — used by `run.ps1` and `smoke-test.ps1` |
| Python 3.11+        | Optional — only if you run `vuln-shop`'s email service outside Docker |
| `GEMINI_API_KEY`    | Optional — only `vuln-social` uses it; falls back to a stub |

`run.ps1` will offer to install Node via `winget` if it can't find it.
## Quick start — PowerShell, three terminals

```powershell
# Terminal 1
cd vuln-bank
.\run.ps1            # http://localhost:3001/

# Terminal 2
cd vuln-shop
.\run.ps1            # http://localhost:3002/  (email service on :5002)

# Terminal 3
cd vuln-social
.\run.ps1            # http://localhost:3003/
```

Each `run.ps1`:

1. checks Node.js (offers `winget install` if missing),
2. for `vuln-bank`, brings up the MySQL 8 sidecar + bank container via `docker compose up -d --build` and tails the bank logs (no separate `npm install` step — the image owns its deps),
3. for `vuln-shop` and `vuln-social`, runs `npm install` if `node_modules/` is absent, seeds the SQLite database on first run (idempotent on later runs), then starts the Express server on the port shown above,
4. prints every relevant URL and the seeded credentials.

`vuln-social` additionally reads `GEMINI_API_KEY` (optional
`GEMINI_MODEL`, default `gemini-2.0-flash`). With no key, `/ai-summary`
falls back to a deterministic stub that still echoes the user's prompt —
enough to demonstrate prompt injection end-to-end without leaving the box.

## Quick start — Docker Compose

Each app ships its own compose file (independent services, independent
named volumes for storage durability — SQLite WAL safety on Windows for
`vuln-shop`/`vuln-social`; MySQL data directory for `vuln-bank`).

```powershell
cd vuln-bank   ; docker compose up --build -d
cd vuln-shop   ; docker compose up --build -d
cd vuln-social ; docker compose up --build -d
docker ps --format 'table {{.Names}}\t{{.Status}}\t{{.Ports}}'
```

For `vuln-social`, copy `vuln-social\.env.example` to `vuln-social\.env`
and fill in `GEMINI_API_KEY` before `docker compose up` if you want the
real LLM path. (The `.env` is `.gitignore`d.)

To tear everything down:

```powershell
cd vuln-bank   ; docker compose down
cd vuln-shop   ; docker compose down
cd vuln-social ; docker compose down
```

Convenience scripts for WSL / Linux are at the repo root:

```bash
./.up.sh        # docker compose up -d for all three
./.rebuild.sh   # docker compose up --build -d for all three
```

## Default test credentials

Each app's `VULNERABILITIES.txt` carries the complete seeded account
table. Quick reference for the accounts the smoke tests drive:

| App           | Customer / member             | Admin                              |
| ------------- | ----------------------------- | ---------------------------------- |
| `vuln-bank`   | `alice.chen / Password123!`   | printed by the server banner       |
| `vuln-shop`   | `olivia.park / OliviaP!23`    | `admin_kate / AdminKate!1`         |
| `vuln-social` | `aria / Aria2026!`            | `admin_eli / AdminEli!1`           |

## Verify every sink still exploits cleanly

Each app has an end-to-end harness that walks the full vulnerability
inventory and asserts every sink is reachable. Run it **after** starting
the app:

```powershell
powershell -ExecutionPolicy Bypass -File vuln-bank\smoke-test.ps1
powershell -ExecutionPolicy Bypass -File vuln-shop\smoke-test.ps1
powershell -ExecutionPolicy Bypass -File vuln-social\smoke-test.ps1
```

Expected results on a clean checkout:

| App           | Checks  |
| ------------- | ------- |
| `vuln-bank`   | 40 / 40 |
| `vuln-shop`   | 48 / 48 |
| `vuln-social` | 43 / 43 |

A non-zero failure means a route changed and a sink accidentally got
fixed — open the failing check, then either restore the vulnerability
(the lab's whole point) or update the harness.

## Layout of a single lab

```
<app>/
├── run.ps1                # one-shot Windows launcher
├── docker-compose.yml     # alternative: docker compose up --build
├── Dockerfile
├── package.json
├── server.js              # Express entry point
├── seed.js                # realistic seed data
├── smoke-test.ps1         # full exploit harness — must pass 100 %
├── VULNERABILITIES.txt    # every sink + recipe + intended mitigation
├── lib/                   # db, auth, llm helpers
├── routes/                # express route modules
├── views/                 # EJS templates
├── public/                # static frontend + per-item images
└── data/                  # SQLite file or MySQL volume + uploads (gitignored)
```

`vuln-shop` additionally has `email-service/` (Python 3 + Flask) which
provides the Jinja2 SSTI sink on port 5002.

## Repository layout

```
vulnlabs/
├── README.md              # this file
├── LICENSE                # MIT + safe-use notice
├── SECURITY.md            # "deliberately vulnerable, no CVEs, lab-only"
├── .gitignore
├── .up.sh                 # WSL convenience: bring all three up
├── .rebuild.sh            # WSL convenience: --build all three
├── vuln-bank/
├── vuln-shop/
└── vuln-social/
```

## Sanity check (manual)

After starting each app, hit the home page in a browser:

- **bank**   — http://localhost:3001/ → login page renders.
- **shop**   — http://localhost:3002/ → storefront renders, products have per-item SVG art.
- **social** — http://localhost:3003/ → feed renders, avatars are per-user SVG.

Then open the app's `VULNERABILITIES.txt` and follow the recipes top to
bottom.

## Reset a lab to a fresh seed

`vuln-shop` and `vuln-social` reseed when their SQLite file is absent;
`vuln-bank` reseeds when the MySQL volume is removed.

PowerShell (host run):

```powershell
Remove-Item .\vuln-shop\data\shop.db*     -Force -ErrorAction SilentlyContinue
Remove-Item .\vuln-social\data\social.db* -Force -ErrorAction SilentlyContinue
cd vuln-bank ; docker compose down -v ; docker compose up --build -d
```

Docker (named volume — same effect):

```powershell
cd vuln-bank   ; docker compose down -v ; docker compose up --build -d
cd vuln-shop   ; docker compose down -v ; docker compose up --build -d
cd vuln-social ; docker compose down -v ; docker compose up --build -d
```

## Troubleshooting

- **`node:sqlite` not found / `DatabaseSync is not a constructor`** —
  you are on Node ≤ 22. Upgrade to Node 24 LTS or use the Docker path.
- **`run.ps1` blocked by execution policy** — run as
  `powershell -ExecutionPolicy Bypass -File <app>\run.ps1` or
  `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`.
- **Port already in use** — set `PORT` in the environment before
  launching, or `docker compose down` any previous instance.
- **WAL files growing forever on Windows bind mounts** — that's why the
  compose files use a named volume; don't bind-mount `data/` on
  Windows DrvFs.
- **`/ai-summary` returns a deterministic stub** — `GEMINI_API_KEY` was
  not set. Either set it and restart, or accept the stub (still good
  enough to teach prompt injection).
- **Smoke test fails immediately on auth** — you probably reseeded the
  DB mid-run; restart the app so the new seed takes effect.

## Contributing

Yes, please. Useful PRs include:

- A new deliberately-vulnerable feature in an existing app, with an
  entry in `VULNERABILITIES.txt` and a matching `smoke-test.ps1` check.
- Better seeded data (more realistic transaction history, product
  catalogue, social graph).
- A new full app under the same conventions (`run.ps1`, `Dockerfile`,
  `smoke-test.ps1`, `VULNERABILITIES.txt`).

Please *don't* open issues asking for fixes to the documented sinks —
those are the curriculum. See [`SECURITY.md`](SECURITY.md) for the kind
of issues that **are** wanted.

## License

[MIT](LICENSE). The MIT permissions cover the source; the safe-use
notice in `LICENSE` and `SECURITY.md` is an operational guideline, not
an additional licensing restriction.

## Author

Built by **Ibrahim Badawy** as the lab companion for the *Web Application
Penetration Testing — Accessibility-First, Terminal-First* book and the
[reqlore](https://github.com/ibrasonic/reqlore) accessible pentesting
toolkit.
