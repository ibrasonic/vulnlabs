# Security policy

## The whole point of this repository

Every application here is **deliberately vulnerable**. The defects are
intentional, documented, and required for the training material in the
companion book *Web Application Penetration Testing — Accessibility-First,
Terminal-First*.

## Please do not file CVEs or vulnerability reports

Reports of "this app has SQL injection" / "JWT alg=none works" / "the
admin panel has no auth" are accurate and intended. Each app ships a
`VULNERABILITIES.txt` enumerating every sink with its exploitation recipe.

## What I do want to hear about

Open a GitHub issue if:

- A documented sink **no longer reaches** (a fix slipped in by accident
  and broke the lesson).
- The smoke-test harness (`smoke-test.ps1`) reports a failure on a clean
  checkout.
- A dependency upgrade introduced a *new* unintended sink that interferes
  with the curriculum.
- Setup instructions don't reproduce on a supported platform
  (Windows 10/11 + PowerShell 5.1+, or Docker Desktop).

## Safe-use rules

1. Run on a private lab machine, a VM, or inside a CTF environment.
2. Do **not** expose any port to the public internet.
3. Do **not** run on a corporate network without written permission.
4. Do **not** reuse the seeded passwords, JWT secrets, or API keys
   anywhere real. They are documented in `VULNERABILITIES.txt` so an
   attacker who finds your exposed instance owns it instantly.
5. Use a throwaway `GEMINI_API_KEY` for `vuln-social`. Treat any key
   that ever sat in a `.env` here as compromised once you're done.

## License

MIT — see [`LICENSE`](LICENSE). The MIT permissions apply to the source;
the safe-use guidance above is a separate operational notice.
