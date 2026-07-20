import { Router, type IRouter } from "express";
import { randomBytes } from "crypto";
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
  const { password } = req.body as { password?: string };
  const expected = process.env.SESSION_SECRET ?? "admin";

  if (!password || password !== expected) {
    res.status(401).json({ error: "Invalid admin password" });
    return;
  }

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
