import { Router, type IRouter } from "express";
import { scanParameter, DETECTION_PAYLOADS } from "../lib/scanner";

const router: IRouter = Router();

// SSE helper — silently swallows write errors (client disconnected)
function sendEvent(res: import("express").Response, data: unknown): void {
  try { res.write(`data: ${JSON.stringify(data)}\n\n`); } catch { /* client gone */ }
}

router.post("/scan/stream", async (req, res): Promise<void> => {
  const { url, timeout } = req.body as { url?: string; timeout?: number };

  if (!url || typeof url !== "string") {
    res.status(400).json({ error: "url is required" });
    return;
  }

  const timeoutMs = typeof timeout === "number" ? Math.min(Math.max(timeout, 3000), 30000) : 12000;

  let targetUrl: URL;
  try {
    targetUrl = new URL(url);
  } catch {
    res.status(400).json({ error: "Invalid URL — include http:// or https://" });
    return;
  }

  if (!["http:", "https:"].includes(targetUrl.protocol)) {
    res.status(400).json({ error: "Only HTTP and HTTPS URLs are supported" });
    return;
  }

  const params = [...targetUrl.searchParams.entries()];

  // ── Set up SSE ────────────────────────────────────────────────────────────
  res.setHeader("Content-Type",  "text/event-stream");
  res.setHeader("Cache-Control", "no-cache, no-transform");
  res.setHeader("Connection",    "keep-alive");
  res.setHeader("X-Accel-Buffering", "no");
  res.setHeader("Transfer-Encoding", "chunked");
  res.flushHeaders();

  const startTime = Date.now();

  // Keep-alive heartbeat every 15 s so proxies don't close the connection
  const heartbeat = setInterval(() => {
    try { res.write(": ping\n\n"); } catch { clearInterval(heartbeat); }
  }, 15_000);

  // Handle client disconnect
  let clientGone = false;
  req.on("close", () => { clientGone = true; clearInterval(heartbeat); });

  try {
    if (params.length === 0) {
      sendEvent(res, {
        type: "scan_done", duration: 0,
        summary: { totalParams: 0, vulnerableParams: 0, safeParams: 0, totalPayloadsTested: 0, totalHits: 0 },
        parameters: [],
      });
      clearInterval(heartbeat);
      res.end();
      return;
    }

    sendEvent(res, {
      type: "scan_start",
      target: url,
      totalParams: params.length,
      totalPayloadsPerParam: DETECTION_PAYLOADS.length,
    });

    const allResults = [];

    for (let i = 0; i < params.length; i++) {
      if (clientGone) break;
      const [paramName, originalValue] = params[i];

      sendEvent(res, { type: "param_start", param: paramName, index: i, total: params.length });

      let hitsFound = 0;

      const result = await scanParameter(
        targetUrl, paramName, originalValue, timeoutMs,
        (hit) => {
          if (clientGone) return;
          hitsFound++;
          sendEvent(res, {
            type: "payload_hit",
            param: paramName,
            payload:          hit.payload,
            reflectionType:   hit.reflectionType,
            evidence:         hit.evidence,
            severity:         hit.severity,
            injectionContext: hit.injectionContext,
            pocUrl:           hit.pocUrl,
          });
        }
      );

      allResults.push(result);

      sendEvent(res, {
        type:             "param_done",
        param:            paramName,
        vulnerable:       result.vulnerable,
        severity:         result.severity,
        totalTested:      result.totalTested,
        hitsCount:        result.payloadsHit.length,
        injectionContext: result.injectionContext,
        exploitScenarios: result.exploitScenarios,
        bestPocUrl:       result.bestPocUrl,
      });
    }

    const duration = Date.now() - startTime;
    const vulnerableParams = allResults.filter((p) => p.vulnerable).length;
    const totalHits = allResults.reduce((s, p) => s + p.payloadsHit.length, 0);

    sendEvent(res, {
      type: "scan_done", duration,
      summary: {
        totalParams:          params.length,
        vulnerableParams,
        safeParams:           params.length - vulnerableParams,
        totalPayloadsTested:  params.length * DETECTION_PAYLOADS.length,
        totalHits,
      },
      parameters: allResults,
    });
  } catch (err) {
    // Send the error over SSE instead of crashing the stream
    const msg = err instanceof Error ? err.message : String(err);
    sendEvent(res, { type: "scan_error", message: msg });
  } finally {
    clearInterval(heartbeat);
    try { res.end(); } catch { /* already ended */ }
  }
});

export default router;
