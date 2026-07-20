// ─── SQLi routes ──────────────────────────────────────────────────────────────
import { Router } from "express";
import type { Request, Response } from "express";
import { scanSqlParam, generateDumpPayloads, WAF_BYPASSES, DUMP_TARGETS, type DbType } from "../lib/sqli.js";

const router = Router();

// POST /sqli/stream — SSE streaming SQLi scan
router.post("/sqli/stream", async (req: Request, res: Response): Promise<void> => {
  const { url } = req.body as { url?: string };
  if (!url) { res.status(400).json({ error: "url required" }); return; }

  let parsedUrl: URL;
  try {
    parsedUrl = new URL(url);
  } catch {
    res.status(400).json({ error: "Invalid URL" });
    return;
  }

  const params = [...parsedUrl.searchParams.entries()];
  if (params.length === 0) {
    res.status(400).json({ error: "No query parameters found in URL" });
    return;
  }

  // SSE headers
  res.writeHead(200, {
    "Content-Type": "text/event-stream",
    "Cache-Control": "no-cache",
    "Connection": "keep-alive",
    "Access-Control-Allow-Origin": "*",
  });

  const send = (data: unknown) => {
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  };

  send({ type: "scan_start", totalParams: params.length, url });

  const startTime = Date.now();
  let totalHits = 0;
  let vulnParams = 0;

  for (const [paramName, originalValue] of params) {
    send({ type: "param_start", param: paramName, totalProbes: 75 });

    try {
      const result = await scanSqlParam(
        parsedUrl,
        paramName,
        originalValue,
        (hit) => {
          totalHits++;
          send({
            type: "sqli_hit",
            param: paramName,
            technique: hit.technique,
            dbType: hit.dbType,
            severity: hit.severity,
            evidence: hit.evidence.slice(0, 300),
            payload: hit.probe.payload,
            responseTime: hit.responseTime,
            baselineTime: hit.baselineTime,
            wafDetected: hit.wafDetected,
          });
        }
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
          evidence: h.evidence.slice(0, 300),
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
    summary: {
      totalParams: params.length,
      vulnerableParams: vulnParams,
      safeParams: params.length - vulnParams,
      totalHits,
    },
  });

  res.end();
});

// POST /sqli/dump — generate dump payloads for a known-vulnerable param
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

  res.json({
    payloads,
    wafBypasses: WAF_BYPASSES.map(b => b.name),
    dumpTargets: DUMP_TARGETS,
  });
});

// GET /sqli/meta — return WAF bypasses + dump targets
router.get("/sqli/meta", (_req: Request, res: Response): void => {
  res.json({ wafBypasses: WAF_BYPASSES.map(b => ({ name: b.name, description: b.description })), dumpTargets: DUMP_TARGETS });
});

export default router;
