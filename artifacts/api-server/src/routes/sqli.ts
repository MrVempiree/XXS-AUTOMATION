// ─── SQLi routes ──────────────────────────────────────────────────────────────
import { Router } from "express";
import type { Request, Response } from "express";
import {
  scanSqlParam, scanSqlBulk,
  generateDumpPayloads, WAF_BYPASSES, DUMP_TARGETS,
  SQLI_PROBES,
  type DbType,
} from "../lib/sqli.js";

const router = Router();

// ── POST /sqli/stream — SSE streaming single-URL SQLi scan ────────────────────
router.post("/sqli/stream", async (req: Request, res: Response): Promise<void> => {
  const { url, fastMode } = req.body as { url?: string; fastMode?: boolean };
  if (!url) { res.status(400).json({ error: "url required" }); return; }

  let parsedUrl: URL;
  try { parsedUrl = new URL(url); }
  catch { res.status(400).json({ error: "Invalid URL" }); return; }

  const params = [...parsedUrl.searchParams.entries()];
  if (params.length === 0) {
    res.status(400).json({ error: "No query parameters found in URL" });
    return;
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });

  const send = (data: unknown) => res.write(`data: ${JSON.stringify(data)}\n\n`);
  const probeCount = fastMode ? SQLI_PROBES.filter(p => p.fast).length : SQLI_PROBES.length;

  send({ type: "scan_start", totalParams: params.length, url, probeCount });

  const startTime = Date.now();
  let totalHits = 0;
  let vulnParams = 0;

  for (const [paramName, originalValue] of params) {
    send({ type: "param_start", param: paramName, totalProbes: probeCount });

    try {
      const result = await scanSqlParam(
        parsedUrl, paramName, originalValue,
        (hit) => {
          totalHits++;
          send({
            type: "sqli_hit",
            param: paramName,
            technique: hit.technique,
            dbType: hit.dbType,
            severity: hit.severity,
            evidence: hit.evidence.slice(0, 400),
            payload: hit.probe.payload,
            responseTime: hit.responseTime,
            baselineTime: hit.baselineTime,
            wafDetected: hit.wafDetected,
          });
        },
        fastMode ?? false,
        (done, total) => send({ type: "param_progress", param: paramName, done, total }),
      );

      if (result.vulnerable) vulnParams++;

      send({
        type: "param_done",
        param: paramName,
        vulnerable: result.vulnerable,
        severity: result.severity,
        dbType: result.dbType,
        techniques: result.techniques,
        hitsCount: result.hits.length,
        columnCount: result.columnCount,
        totalTested: result.totalTested,
        wafDetected: result.wafDetected,
        hits: result.hits.map(h => ({
          technique: h.technique,
          dbType: h.dbType,
          severity: h.severity,
          evidence: h.evidence.slice(0, 400),
          payload: h.probe.payload,
          responseTime: h.responseTime,
          wafDetected: h.wafDetected,
        })),
      });
    } catch (err) {
      send({ type: "param_error", param: paramName, error: (err as Error).message });
    }
  }

  send({
    type: "scan_done",
    duration: Date.now() - startTime,
    summary: { totalParams: params.length, vulnerableParams: vulnParams, safeParams: params.length - vulnParams, totalHits },
  });

  res.end();
});

// ── POST /sqli/bulk/stream — SSE mass URL bulk scanning ───────────────────────
router.post("/sqli/bulk/stream", async (req: Request, res: Response): Promise<void> => {
  const {
    urls,
    concurrency = 3,
    fastMode = true,
  } = req.body as {
    urls?: string[];
    concurrency?: number;
    fastMode?: boolean;
  };

  if (!Array.isArray(urls) || urls.length === 0) {
    res.status(400).json({ error: "urls array required" });
    return;
  }

  if (urls.length > 500) {
    res.status(400).json({ error: "Maximum 500 URLs per batch" });
    return;
  }

  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });

  const send = (data: unknown) => {
    if (!res.writableEnded) res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  // Abort when client disconnects
  const ctrl = new AbortController();
  req.on("close", () => ctrl.abort());

  try {
    await scanSqlBulk(
      urls,
      Math.max(1, Math.min(concurrency, 15)),
      fastMode,
      (event) => send(event),
      ctrl.signal,
    );
  } catch (err) {
    send({ type: "bulk_error", error: (err as Error).message });
  }

  if (!res.writableEnded) res.end();
});

// ── POST /sqli/dump — generate dump payloads ──────────────────────────────────
router.post("/sqli/dump", (req: Request, res: Response): void => {
  const {
    paramName, baseUrl, dbType, columnCount, dumpTarget, wafBypass, customTable, customColumn,
  } = req.body as {
    paramName: string; baseUrl: string; dbType: DbType;
    columnCount: number; dumpTarget: string; wafBypass: string;
    customTable?: string; customColumn?: string;
  };

  if (!paramName || !baseUrl || !dbType || !columnCount || !dumpTarget) {
    res.status(400).json({ error: "Missing required fields" });
    return;
  }

  const payloads = generateDumpPayloads(
    paramName, baseUrl, dbType, columnCount, dumpTarget, wafBypass ?? 'None (Raw)',
    customTable ?? 'users', customColumn ?? 'username,password',
  );

  res.json({ payloads, wafBypasses: WAF_BYPASSES.map(b => b.name), dumpTargets: DUMP_TARGETS });
});

// ── GET /sqli/meta — return WAF bypasses + dump targets + probe stats ─────────
router.get("/sqli/meta", (_req: Request, res: Response): void => {
  const stats = {
    total: SQLI_PROBES.length,
    fast: SQLI_PROBES.filter(p => p.fast).length,
    byTechnique: SQLI_PROBES.reduce((acc, p) => {
      acc[p.technique] = (acc[p.technique] ?? 0) + 1;
      return acc;
    }, {} as Record<string, number>),
    wafBypasses: WAF_BYPASSES.length,
  };
  res.json({
    wafBypasses: WAF_BYPASSES.map(b => ({ name: b.name, description: b.description })),
    dumpTargets: DUMP_TARGETS,
    probeStats: stats,
  });
});

export default router;
