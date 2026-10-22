import { Router, type IRouter } from "express";
import { randomBytes, timingSafeEqual, createHash } from "crypto";
import {
  listLicenses,
  generateLicense,
  revokeLicense,
  deleteLicense,
  type LicensePlan,
} from "../lib/license";

const router: IRouter = Router();

// In-memory admin session tokens  { token → expiresAt }
const adminTokens = new Map<string, number>();

// ---------------------------------------------------------------------------
// Admin password
//
// SECURITY: this used to fall back to the literal string "admin" when
// SESSION_SECRET was unset:
//
//     const expected = process.env.SESSION_SECRET ?? "admin";
//
// That is CWE-798 (use of hard-coded credentials) and CWE-1188 (insecure
// default initialisation). Any deployment that forgot to set the env var
// shipped a publicly known admin password, giving anyone who reached
// POST /admin/login the ability to list, mint, revoke and delete licenses.
//
// The server now FAILS CLOSED: with no ADMIN_PASSWORD configured, the admin
// surface is disabled and login returns 503. There is no default password.
// ---------------------------------------------------------------------------

const ADMIN_PASSWORD_ENV = "ADMIN_PASSWORD";

/** Returns the configured admin password, or null when unconfigured. */
function adminPassword(): string | null {
  const raw = process.env[ADMIN_PASSWORD_ENV];
  if (raw === undefined || raw.trim() === "") return null;
  return raw;
}

/**
 * Constant-time string comparison.
 *
 * A plain `===` leaks length and prefix information through timing, which is
 * enough to make online password guessing meaningfully cheaper. Hashing both
 * sides first also keeps the comparison length-independent.
 */
function safeEqual(a: string, b: string): boolean {
  const hashA = createHash("sha256").update(a, "utf8").digest();
  const hashB = createHash("sha256").update(b, "utf8").digest();
  return timingSafeEqual(hashA, hashB);
}

// ---------------------------------------------------------------------------
// Login throttling
//
// The admin password is a single shared secret, so without throttling it can
// be brute-forced over the network. Attempts are counted per client address
// and the lockout grows with each failure.
// ---------------------------------------------------------------------------

const MAX_ATTEMPTS = 5;
const BASE_LOCKOUT_MS = 30_000;
const MAX_LOCKOUT_MS = 15 * 60_000;

const loginAttempts = new Map<string, { count: number; lockedUntil: number }>();

function clientKey(req: import("express").Request): string {
  return req.ip ?? req.socket.remoteAddress ?? "unknown";
}

function lockoutRemaining(key: string): number {
  const record = loginAttempts.get(key);
  if (record === undefined) return 0;
  // The lockout only engages once the attempt threshold is reached. Below it
  // the client keeps getting 401 so it can correct a typo.
  if (record.count < MAX_ATTEMPTS) return 0;
  return Math.max(0, record.lockedUntil - Date.now());
}

function registerFailure(key: string): void {
  const record = loginAttempts.get(key) ?? { count: 0, lockedUntil: 0 };
  record.count += 1;
  const lockout = Math.min(
    BASE_LOCKOUT_MS * 2 ** (record.count - 1),
    MAX_LOCKOUT_MS,
  );
  record.lockedUntil = Date.now() + lockout;
  loginAttempts.set(key, record);
}

function clearFailures(key: string): void {
  loginAttempts.delete(key);
}

function pruneAttempts(): void {
  const now = Date.now();
  for (const [key, record] of loginAttempts) {
    if (record.lockedUntil <= now && now - record.lockedUntil > MAX_LOCKOUT_MS) {
      loginAttempts.delete(key);
    }
  }
}

function pruneTokens() {
  const now = Date.now();
  for (const [t, exp] of adminTokens) {
    if (exp < now) adminTokens.delete(t);
  }
}

function isValidAdminToken(token?: string): boolean {
  if (!token) return false;
  pruneTokens();
  return adminTokens.has(token) && (adminTokens.get(token) ?? 0) > Date.now();
}

function requireAdmin(req: import("express").Request, res: import("express").Response, next: import("express").NextFunction): void {
  const token = req.headers["x-admin-token"] as string | undefined;
  if (!isValidAdminToken(token)) {
    res.status(401).json({ error: "Unauthorized" });
    return;
  }
  next();
}

// POST /admin/login
router.post("/admin/login", (req, res): void => {
  pruneAttempts();

  const key = clientKey(req);
  const remaining = lockoutRemaining(key);
  if (remaining > 0) {
    res
      .status(429)
      .json({ error: "Too many failed attempts. Try again later." });
    return;
  }

  const expected = adminPassword();
  if (expected === null) {
    // Fail closed. Do not reveal whether a password is configured.
    res.status(503).json({ error: "Admin login is not configured on this server" });
    return;
  }

  const { password } = req.body as { password?: string };
  if (typeof password !== "string" || !safeEqual(password, expected)) {
    registerFailure(key);
    res.status(401).json({ error: "Invalid admin password" });
    return;
  }

  clearFailures(key);
  const token = randomBytes(32).toString("hex");
  adminTokens.set(token, Date.now() + 4 * 60 * 60 * 1000); // 4 hours
  res.json({ token });
});

// GET /admin/licenses
router.get("/admin/licenses", requireAdmin, (_req, res): void => {
  res.json({ licenses: listLicenses() });
});

// POST /admin/licenses/generate
router.post("/admin/licenses/generate", requireAdmin, (req, res): void => {
  const { plan, owner, note } = req.body as {
    plan?: string;
    owner?: string;
    note?: string;
  };

  const validPlans: LicensePlan[] = ["trial", "professional", "lifetime"];
  if (!plan || !validPlans.includes(plan as LicensePlan)) {
    res.status(400).json({ error: "plan must be trial | professional | lifetime" });
    return;
  }

  const license = generateLicense(plan as LicensePlan, owner ?? "Unnamed", note);
  res.json({ license });
});

// POST /admin/licenses/:key/revoke
router.post("/admin/licenses/:key/revoke", requireAdmin, (req, res): void => {
  const ok = revokeLicense(String(req.params.key));
  if (!ok) { res.status(404).json({ error: "License not found" }); return; }
  res.json({ success: true });
});

// DELETE /admin/licenses/:key
router.delete("/admin/licenses/:key", requireAdmin, (req, res): void => {
  const ok = deleteLicense(String(req.params.key));
  if (!ok) { res.status(404).json({ error: "License not found" }); return; }
  res.json({ success: true });
});

export default router;
