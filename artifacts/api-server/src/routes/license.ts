import { Router, type IRouter } from "express";
import { verifyLicense } from "../lib/license";

const router: IRouter = Router();

// POST /license/verify
router.post("/license/verify", (req, res): void => {
  const { key } = req.body as { key?: string };
  const result = verifyLicense(key ?? "");
  if (!result.valid) {
    res.status(403).json({ valid: false, reason: result.reason });
    return;
  }
  res.json({ valid: true, license: result.license });
});

export default router;
