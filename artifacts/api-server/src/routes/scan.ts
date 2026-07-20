import { Router, type IRouter } from "express";
import { scanParameter, DETECTION_PAYLOADS, worstSeverity } from "../lib/scanner.js";

const router: IRouter = Router();

router.post("/scan", async (req, res): Promise<void> => {
  const { url, timeout } = req.body as { url?: string; timeout?: number };

  if (!url || typeof url !== "string") {
    res.status(400).json({ error: "url is required" });
    return;
  }

  const timeoutMs = typeof timeout === "number" ? Math.min(Math.max(timeout, 3000), 30000) : 8000;

  let targetUrl: URL;
  try {
    targetUrl = new URL(url);
  } catch {
    res.status(400).json({ error: "Invalid URL format. Include http:// or https://" });
    return;
  }

  if (!["http:", "https:"].includes(targetUrl.protocol)) {
    res.status(400).json({ error: "Only HTTP and HTTPS URLs are supported" });
    return;
  }

  const params = [...targetUrl.searchParams.entries()];

  if (params.length === 0) {
    res.json({
      target: url,
      scanDuration: 0,
      parameters: [],
      summary: {
        totalParams: 0,
        vulnerableParams: 0,
        safeParams: 0,
        totalPayloadsTested: 0,
        totalHits: 0,
      },
    });
    return;
  }

  const startTime = Date.now();
  req.log.info({ target: url, paramCount: params.length }, "Starting XSS scan");

  const paramResults = [];
  for (const [paramName, originalValue] of params) {
    const result = await scanParameter(targetUrl, paramName, originalValue, timeoutMs);
    paramResults.push({
      name: result.name,
      originalValue: result.originalValue,
      vulnerable: result.vulnerable,
      severity: result.severity,
      totalTested: result.totalTested,
      payloadsHit: result.payloadsHit.map((h) => ({
        payload: h.payload,
        reflectionType: h.reflectionType,
        evidence: h.evidence,
      })),
    });
  }

  const scanDuration = Date.now() - startTime;
  const vulnerableParams = paramResults.filter((p) => p.vulnerable).length;
  const totalHits = paramResults.reduce((s, p) => s + p.payloadsHit.length, 0);

  res.json({
    target: url,
    scanDuration,
    parameters: paramResults,
    summary: {
      totalParams: params.length,
      vulnerableParams,
      safeParams: params.length - vulnerableParams,
      totalPayloadsTested: params.length * DETECTION_PAYLOADS.length,
      totalHits,
    },
  });
});

export default router;
