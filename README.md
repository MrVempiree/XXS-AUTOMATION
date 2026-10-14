# XXS-AUTOMATION

A learning/prototype web security testing toolkit (TypeScript + Node.js). This project provides an Express-based API used to drive automated tests of web application input reflection (XSS-focused) and related scanning helpers. It is a research/proof-of-concept repository — not production-ready.

Status: Learning / Prototype

Why this exists
- Security tooling and experimentation: provides a small, modular API that can drive automated payload testing against URL parameters and return structured results for analysis.
- Educational: a prototype to explore automated detection and evidence capture (reflection type, evidence, severity estimation).

Verified features (evidence-based)
- Express API server (artifacts/api-server) — app mounts routes under /api and uses pino-http for structured logs.
- /api/scan — implemented handler that:
  - Accepts JSON body { "url": "<url>", "timeout": <ms> }.
  - Validates URL format and scheme (http/https only).
  - Extracts query parameters and, for each parameter, calls a scanner function (scanParameter) to test payloads and returns a JSON summary of results.
  - Enforces a bounded timeout (clamped between 3000 and 30000 ms) before scanning.
- TypeScript-based code with typecheck scripts.
- pnpm workspace (pnpm-workspace.yaml, root package.json) — the repo enforces pnpm usage in preinstall.

What this project is not
- Not production-ready; no security guarantees. Use for research and controlled testing only.
- Not a turnkey vulnerability scanner — payload libraries, environment isolation, sandboxing, and safe networking controls must be added before real-world use.

Technology stack
- Node.js (ES modules), TypeScript
- Express (v5 style imports), cors
- Logging: pino / pino-http
- Build/tools: pnpm workspace, esbuild (dev), TypeScript, prettier

Repository structure (high level)
- artifacts/api-server/        Express server package (primary runnable component)
  - src/index.ts               server entry (requires PORT env variable)
  - src/app.ts                 express app configuration
  - src/routes/*.ts            route handlers (scan, health, admin, etc.)
  - package.json               package scripts (dev, build, start, typecheck)
- scripts/                     small workspace scripts (typecheck example)
- package.json                 workspace root (pnpm-only enforcer)
- pnpm-workspace.yaml, pnpm-lock.yaml, tsconfig*.json

Quickstart (verified)
1. Install (pnpm required)
   - pnpm install

2. Run the API server (example)
   - cd artifacts/api-server
   - PORT=3000 pnpm run dev
   - The server will throw at startup if PORT is not set.

3. Typecheck / build
   - From repo root:
     - pnpm run typecheck
     - pnpm run build
   - From artifacts/api-server:
     - pnpm run typecheck
     - pnpm run build

Notes & security cautions (must-read)
- The /api/scan endpoint accepts a URL to test. Running scans against external or internal targets can have legal, ethical, and security implications — only scan systems you own or are authorized to test.
- Because the scanner performs outgoing HTTP(S) requests to user-supplied hosts, there is a risk of SSRF, internal network access, DNS exfiltration, or other unintended interactions. Do not run this against non-consented targets and run scans from isolated networks or containers.
- There are no automated tests included in the inspected package.jsons; I recommend adding unit tests and integration tests before relying on the toolkit.

Next steps (suggested, optional)
- Add a CONTRIBUTING.md that states responsible disclosure and acceptable use.
- Add automated dependency scanning (Dependabot), code scanning, and a GitHub Actions workflow that runs typecheck and lint on PRs.
- Add sandboxing/network isolation for outgoing scan requests and an allowlist for target hosts/IP ranges.

If you want, I can:
- Open PR(s) that add the README.md, SECURITY.md, and SECURITY-REVIEW.md files (exact contents below).
- Add a minimal GitHub Actions job to run pnpm typecheck on PRs.
