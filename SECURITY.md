# Security Policy

## What this project is

**XSS Automator** is an offensive-leaning web application security testing tool. It
scans for XSS, SQL injection, and local file inclusion, and generates exploit
payloads. Its purpose is **authorised security testing**: finding flaws in systems
you own or have explicit written permission to assess.

**Only test systems you own or have explicit, written permission to assess.** A
scanning tool run against a third party's infrastructure without authorisation is
illegal in most jurisdictions regardless of intent, and it is not the use this
project exists to support.

If you find a vulnerability in a system you do not own, report it to that system's
owner following their disclosure policy. Do not publish it first.

---

## Security issues in this project

Report vulnerabilities **privately** via
[GitHub private vulnerability reporting](https://docs.github.com/en/code-security/security-advisories/guidance-on-reporting-and-writing-information-about-vulnerabilities/privately-reporting-a-security-vulnerability)
("Security" → "Report a vulnerability").

Please do not open a public issue for a vulnerability report.

### Disclosure history

Two issues were found by an audit of the public repository on 2026-10-20 and have
been fixed in this repository. They are documented here rather than hidden, because
the fix is only meaningful if the reasoning is on the record.

#### 1. Hard-coded default admin password (CWE-798 / CWE-1188) — FIXED

`artifacts/api-server/src/routes/admin.ts` previously contained:

```ts
const expected = process.env.SESSION_SECRET ?? "admin";
```

Any deployment that did not set `SESSION_SECRET` shipped with the admin password
`"admin"`. Combined with the absence of rate limiting on `POST /admin/login`, that
gave any unauthenticated caller who could reach the API the ability to list, mint,
revoke, and delete license keys.

**Remediation applied:**

- The default password is gone. The server now **fails closed**: with no
  `ADMIN_PASSWORD` configured, the admin surface is disabled and login returns
  `503 Service Unavailable`.
- The admin password now comes from a dedicated `ADMIN_PASSWORD` environment
  variable rather than reusing `SESSION_SECRET`, removing the secret-reuse smell.
- Password comparison is constant-time (`sha256` + `timingSafeEqual`).
- `POST /admin/login` is rate limited: 5 failures locks a client out, with
  exponential backoff up to 15 minutes. The lockout is per client address, so one
  attacker cannot lock out everyone.

**Action required if you are deploying this:**

```bash
export ADMIN_PASSWORD="<a long random string>"
# e.g.  openssl rand -base64 32
```

Without it, admin login is disabled. That is intentional.

#### 2. Live license keys committed to a public repository — FIXED

`artifacts/api-server/data/licenses.json` was committed to this repository while
it was public. It contained two **active** `lifetime` license keys, including the
owner's key.

**Remediation applied:**

- The file is now in `.gitignore` and has been removed from version control.
- The app recreates the store (empty) on first run, so this is safe. Seed the
  server with a key, or mint one through the admin panel.
- **Both previously published keys must be treated as compromised.** The
  architecture deliberately stores keys in plaintext, so anyone with repository
  access had the ability to read and reuse them. Rotate any deployment still
  using them.

**Known remaining weakness (not yet fixed):** license keys are stored in plaintext
and compared without a signature, so `licenses.json` is the entire trust root.
Anyone who can write to that file can mint themselves any license. Signing keys
with an HMAC and verifying offline is the correct fix and is tracked as future work.

---

## Deployment checklist

Before running this anywhere reachable:

- [ ] Set `ADMIN_PASSWORD` to a long random value.
- [ ] Set `DATABASE_URL` to your PostgreSQL connection string.
- [ ] Confirm `artifacts/api-server/data/licenses.json` is not in version control.
- [ ] Do not expose the admin routes without a reverse proxy that adds
      authentication, IP allow-listing, and rate limiting.
- [ ] Understand that the scanner sends attack payloads at the target. Point it at
      systems you are authorised to test, and agree a test window and scope with
      the owner first.
- [ ] Keep the license store and any admin tokens out of logs and backups.

## Supported versions

Only the latest `main` branch is supported. There are no releases yet.

## Security-relevant design notes

- Admin session tokens are 32 random bytes, expire after 4 hours, and are held
  in memory only (so they are lost on restart, which is intentional).
- The scanner's payloads are used against targets you specify. There is no
  built-in scope allowlist yet — that is a known gap, and it is the main reason
  this section exists.
