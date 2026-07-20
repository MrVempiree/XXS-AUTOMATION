import { useState, useMemo, useRef, useCallback } from 'react';
import {
  ScanLine, Target, AlertTriangle, CheckCircle, XCircle,
  Copy, Download, ChevronRight, ChevronDown, ChevronUp,
  Shield, Terminal, Activity, Zap, Clock, Ban, Eye
} from 'lucide-react';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'framer-motion';
import { buildExploits, assessAccessLevel, type InjectionContext, type ExploitPayload, type AccessLevel } from '../lib/exploits';
import AttackGoalWizard from '../components/AttackGoalWizard';

// ── Types ──────────────────────────────────────────────────────────────────────
type ReflectionType = 'raw' | 'html_encoded' | 'partial';

interface LiveHit {
  param: string;
  payload: string;
  reflectionType: ReflectionType;
  evidence: string;
  severity: string;
  injectionContext: InjectionContext;
  pocUrl: string;
}

interface LiveParam {
  name: string;
  status: 'pending' | 'scanning' | 'done';
  vulnerable: boolean;
  severity: string;
  hitsCount: number;
  hits: LiveHit[];
  injectionContext: InjectionContext | null;
  exploitScenarios: string[];
  bestPocUrl: string;
  totalTested: number;
}

interface ScanSummary {
  totalParams: number;
  vulnerableParams: number;
  safeParams: number;
  totalPayloadsTested: number;
  totalHits: number;
}

type ScanPhase = 'idle' | 'scanning' | 'done' | 'error';

// ── Helpers ────────────────────────────────────────────────────────────────────
const CONTEXT_LABELS: Record<InjectionContext, string> = {
  script_block:            'Inside a <script> block — JavaScript execution context',
  css_block:               'Inside a <style> block — CSS context',
  html_attribute_double:   'Inside a double-quoted HTML attribute',
  html_attribute_single:   'Inside a single-quoted HTML attribute',
  html_attribute_unquoted: 'Inside an unquoted HTML attribute',
  html_body:               'Inside the HTML body — direct HTML injection',
  html_comment:            'Inside an HTML comment',
  url_href:                'Inside an href URL attribute',
  url_src:                 'Inside a src URL attribute',
  unknown:                 'Context unclear — manual verification needed',
};

const SEV_RANK: Record<string, number> = { none: 0, low: 1, medium: 2, high: 3, critical: 4 };

function sevColor(s: string) {
  switch (s.toLowerCase()) {
    case 'critical': return 'text-red-500 border-red-500/30 bg-red-500/10';
    case 'high':     return 'text-orange-400 border-orange-400/30 bg-orange-400/10';
    case 'medium':   return 'text-yellow-400 border-yellow-400/30 bg-yellow-400/10';
    case 'low':      return 'text-blue-400 border-blue-400/30 bg-blue-400/10';
    default:         return 'text-primary border-primary/20 bg-primary/10';
  }
}

function cvssScore(severity: string): string {
  switch (severity) {
    case 'critical': return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H — Score: 9.6 (Critical)';
    case 'high':     return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:H/A:N — Score: 7.5 (High)';
    case 'medium':   return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N — Score: 6.1 (Medium)';
    default:         return 'CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N — Score: 4.3 (Medium)';
  }
}

// ── SSE stream ─────────────────────────────────────────────────────────────────
async function runScanStream(
  url: string,
  signal: AbortSignal,
  onEvent: (e: Record<string, unknown>) => void
): Promise<void> {
  const resp = await fetch('/api/scan/stream', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ url }),
    signal,
  });
  if (!resp.ok) {
    const err = await resp.json().catch(() => ({ error: 'Scan failed' }));
    throw new Error((err as { error?: string }).error ?? 'Scan request failed');
  }
  if (!resp.body) throw new Error('No response body');

  const reader = resp.body.getReader();
  const decoder = new TextDecoder();
  let buffer = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    buffer += decoder.decode(value, { stream: true });
    const chunks = buffer.split('\n\n');
    buffer = chunks.pop() ?? '';
    for (const chunk of chunks) {
      const line = chunk.trim();
      if (line.startsWith('data: ')) {
        try { onEvent(JSON.parse(line.slice(6))); } catch { /* skip */ }
      }
    }
  }
}

// ── Report ─────────────────────────────────────────────────────────────────────
function buildReport(targetUrl: string, params: LiveParam[], summary: ScanSummary, duration: number): string {
  const date = new Date().toISOString().split('T')[0];
  const vulnParams = params.filter(p => p.vulnerable);
  const worstSev = vulnParams.reduce((best, p) =>
    (SEV_RANK[p.severity] ?? 0) > (SEV_RANK[best] ?? 0) ? p.severity : best, 'low');

  const affectedTable = vulnParams.map(p =>
    `| \`${p.name}\` | ${p.severity.toUpperCase()} | ${p.injectionContext ? CONTEXT_LABELS[p.injectionContext] : 'Unknown'} | ${p.hitsCount} |`
  ).join('\n');

  const exploitDetails = vulnParams.map(p => {
    const ctx = p.injectionContext ?? 'unknown';
    const access = assessAccessLevel(ctx as InjectionContext, p.severity, p.hitsCount, p.exploitScenarios);
    return `
### Parameter: \`${p.name}\`

**Severity:** ${p.severity.toUpperCase()}  
**Injection Context:** ${p.injectionContext ? CONTEXT_LABELS[p.injectionContext] : 'Unknown'}  
**Access Level:** ${access.headline}  
**Payloads Triggered:** ${p.hitsCount}

**Proof of Concept URL:**
\`\`\`
${p.bestPocUrl}
\`\`\`

**What an attacker can do:**
${p.exploitScenarios.map(s => `- ${s}`).join('\n')}

**Access Assessment:**
${access.details.map(d => `- ${d}`).join('\n')}

**Payload Evidence:**
${p.hits.slice(0, 3).map((h, i) => `
**Hit #${i + 1}** — ${h.reflectionType} reflection, ${h.severity} severity
- Payload: \`${h.payload}\`
- Evidence: \`${h.evidence}\`
`).join('')}
`;
  }).join('\n---\n');

  return `# XSS Vulnerability Report

**Target:** ${targetUrl}
**Date:** ${date}
**Overall Severity:** ${worstSev.toUpperCase()}
**CWE:** CWE-79 — Improper Neutralization of Input During Web Page Generation
**Scan Duration:** ${(duration / 1000).toFixed(2)}s | **Payloads Tested:** ${summary.totalPayloadsTested}

---

## Executive Summary

A reflected Cross-Site Scripting (XSS) vulnerability was identified in **${summary.vulnerableParams}** of ${summary.totalParams} tested parameter(s). Unencoded user input is reflected in the HTTP response. An attacker who tricks a victim into visiting a crafted URL can execute arbitrary JavaScript in the victim's browser session.

---

## Affected Parameters

| Parameter | Severity | Injection Context | Hits |
|-----------|----------|-------------------|------|
${affectedTable}

---

## Technical Details & Exploit Scenarios
${exploitDetails}

---

## Impact

Depending on the injection context and victim's privilege level, a successful attack enables:

- **Session Hijacking** — Steal cookies to impersonate the victim
- **Account Takeover** — Change email/password via CSRF using victim's session
- **Credential Theft** — Phishing overlay or keylogger to harvest passwords
- **Data Exfiltration** — Steal localStorage tokens, API keys, personal data
- **Admin Panel Access** — If victim is an admin, attacker gains admin privileges
- **Persistent Foothold** — Service Worker registration for long-term access

---

## Remediation

1. **HTML Encode Output** — Use context-appropriate encoding before inserting user data into HTML
2. **Content Security Policy** — Deploy strict CSP to block inline script execution
3. **HttpOnly Cookies** — Mark session cookies HttpOnly to prevent cookie theft via XSS
4. **CSRF Tokens** — Protect all state-changing endpoints against CSRF
5. **Framework Auto-Escaping** — Use React/Angular/Vue and avoid \`dangerouslySetInnerHTML\`
6. **Input Validation** — Allowlist-validate all query parameters server-side

---

## CVSS Score

${cvssScore(worstSev)}

---

## References

- OWASP XSS Prevention: https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- PortSwigger XSS Labs: https://portswigger.net/web-security/cross-site-scripting
- HackerOne Disclosure: https://hackerone.com/reports?filter=keyword%3Axss
`;
}

// ── Exploit Arsenal Panel ──────────────────────────────────────────────────────
const CATEGORY_LABELS: Record<string, string> = {
  cookie_theft: '🍪 Cookie & Token Theft',
  keylogger:    '⌨️  Keyloggers',
  csrf:         '🔄 CSRF Attacks',
  phishing:     '🎭 Phishing Overlays',
  recon:        '🔍 Recon & Probing',
  persistence:  '👾 Persistence',
};

const SEV_BADGE: Record<string, string> = {
  critical: 'text-red-500 border-red-500/30 bg-red-500/10',
  high:     'text-orange-400 border-orange-400/30 bg-orange-400/10',
  medium:   'text-yellow-400 border-yellow-400/30 bg-yellow-400/10',
};

function ExploitCard({ exploit }: { exploit: ExploitPayload }) {
  const [open, setOpen] = useState(false);
  const [showPayload, setShowPayload] = useState(false);

  const copy = (text: string, label: string) => {
    navigator.clipboard.writeText(text);
    toast.success(label);
  };

  return (
    <div className={`border rounded-lg overflow-hidden transition-colors ${
      exploit.severity === 'critical' ? 'border-red-500/25' :
      exploit.severity === 'high'     ? 'border-orange-400/25' :
                                        'border-yellow-400/20'
    }`}>
      <button
        onClick={() => setOpen(o => !o)}
        className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors hover:bg-secondary/30 ${
          exploit.severity === 'critical' ? 'bg-red-500/5' :
          exploit.severity === 'high'     ? 'bg-orange-400/5' :
                                            'bg-yellow-400/4'
        }`}
      >
        <span className="text-lg shrink-0">{exploit.icon}</span>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <span className="font-bold text-sm">{exploit.title}</span>
            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase shrink-0 ${SEV_BADGE[exploit.severity]}`}>
              {exploit.severity}
            </span>
          </div>
          <p className="text-[11px] text-muted-foreground mt-0.5 truncate">{exploit.description.slice(0, 80)}…</p>
        </div>
        {open ? <ChevronUp className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />}
      </button>

      <AnimatePresence>
        {open && (
          <motion.div
            initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
            className="overflow-hidden border-t border-border/50"
          >
            <div className="p-4 space-y-4 bg-background/60">
              <p className="text-xs text-foreground/80 leading-relaxed">{exploit.description}</p>

              <div className="p-3 bg-red-500/8 border border-red-500/20 rounded-lg space-y-1">
                <div className="text-[10px] text-red-400 uppercase tracking-widest font-bold">What attacker gains</div>
                <p className="text-xs text-foreground/80">{exploit.what_attacker_gains}</p>
              </div>

              <div className="space-y-1.5">
                <div className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">Usage</div>
                <p className="text-[11px] text-muted-foreground font-mono leading-relaxed">{exploit.pocUsage}</p>
              </div>

              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <div className="text-[10px] text-muted-foreground uppercase tracking-widest font-bold">Exploit Payload</div>
                  <div className="flex items-center gap-2">
                    <button
                      onClick={() => setShowPayload(v => !v)}
                      className="text-[10px] text-muted-foreground hover:text-foreground flex items-center gap-1 transition-colors font-mono"
                    >
                      <Eye className="w-3 h-3" /> {showPayload ? 'Hide' : 'Reveal'}
                    </button>
                    <button
                      onClick={() => copy(exploit.payload, `${exploit.title} payload copied`)}
                      className="text-[10px] text-primary hover:text-primary/80 flex items-center gap-1 transition-colors font-mono"
                    >
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                  </div>
                </div>
                {showPayload ? (
                  <code className="block text-[10px] font-mono bg-black/60 border border-border rounded px-3 py-2 text-orange-300/90 break-all whitespace-pre-wrap max-h-48 overflow-y-auto">
                    {exploit.payload}
                  </code>
                ) : (
                  <div className="flex items-center justify-center h-10 border border-dashed border-border rounded text-[11px] text-muted-foreground/40 font-mono">
                    Click Reveal to show payload
                  </div>
                )}
              </div>
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}

function ExploitArsenal({ param, targetUrl }: { param: LiveParam; targetUrl: string }) {
  const ctx = (param.injectionContext ?? 'unknown') as InjectionContext;
  const exploits = buildExploits(param.name, targetUrl, ctx);
  const access   = assessAccessLevel(ctx, param.severity, param.hitsCount, param.exploitScenarios);

  const byCategory = exploits.reduce<Record<string, ExploitPayload[]>>((acc, e) => {
    (acc[e.category] ??= []).push(e);
    return acc;
  }, {});

  return (
    <div className="space-y-5">
      {/* Access Level Meter */}
      <div className={`p-4 rounded-xl border space-y-3 ${
        access.level === 'FULL_ACCOUNT_TAKEOVER' ? 'border-red-500/30 bg-red-500/5' :
        access.level === 'SESSION_HIJACK'         ? 'border-orange-400/30 bg-orange-400/5' :
        access.level === 'DOM_MANIPULATION'        ? 'border-yellow-400/30 bg-yellow-400/5' :
                                                     'border-blue-400/30 bg-blue-400/5'
      }`}>
        <div className="flex items-center justify-between">
          <div>
            <div className={`text-sm font-black ${access.color}`}>{access.headline}</div>
            <div className="text-[11px] text-muted-foreground font-mono mt-0.5">{access.urgency}</div>
          </div>
          <div className="text-right">
            <div className={`text-3xl font-black font-mono ${access.color}`}>{access.score}</div>
            <div className="text-[9px] text-muted-foreground uppercase tracking-widest">risk score</div>
          </div>
        </div>

        {/* Bar */}
        <div className="h-2 bg-secondary rounded-full overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${
              access.score >= 80 ? 'bg-red-500' : access.score >= 60 ? 'bg-orange-400' : access.score >= 40 ? 'bg-yellow-400' : 'bg-blue-400'
            }`}
            style={{ width: `${access.score}%` }}
          />
        </div>

        <ul className="space-y-1">
          {access.details.map((d, i) => (
            <li key={i} className="flex items-start gap-2 text-[11px] text-foreground/70">
              <ChevronRight className="w-3 h-3 text-current shrink-0 mt-0.5" />
              {d}
            </li>
          ))}
        </ul>
      </div>

      {/* Exploit payloads by category */}
      {Object.entries(byCategory).map(([cat, items]) => (
        <div key={cat} className="space-y-2">
          <div className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
            {CATEGORY_LABELS[cat] ?? cat}
          </div>
          <div className="space-y-2">
            {items.map(e => <ExploitCard key={e.title} exploit={e} />)}
          </div>
        </div>
      ))}

      <p className="text-[10px] text-muted-foreground/50 font-mono leading-relaxed border-t border-border/50 pt-3">
        ⚠ These payloads are generated for authorized bug bounty research only. Replace collector URLs with your own Burp Collaborator / webhook.site endpoint. Never use against sites you don't have written permission to test.
      </p>
    </div>
  );
}

// ── Component ──────────────────────────────────────────────────────────────────
export default function Scanner() {
  const [targetUrl, setTargetUrl]         = useState('');
  const [phase, setPhase]                 = useState<ScanPhase>('idle');
  const [errorMsg, setErrorMsg]           = useState('');
  const [params, setParams]               = useState<LiveParam[]>([]);
  const [liveHits, setLiveHits]           = useState<LiveHit[]>([]);
  const [currentParam, setCurrentParam]   = useState('');
  const [payloadsFired, setPayloadsFired] = useState(0);
  const [summary, setSummary]             = useState<ScanSummary | null>(null);
  const [duration, setDuration]           = useState(0);
  const [expanded, setExpanded]           = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab]         = useState<Record<string, 'hits' | 'exploits' | 'goals'>>({});
  const [showReport, setShowReport]       = useState(false);
  const abortRef                          = useRef<AbortController | null>(null);
  const hitsEndRef                        = useRef<HTMLDivElement>(null);

  const detectedParams = useMemo(() => {
    try {
      if (!targetUrl.startsWith('http://') && !targetUrl.startsWith('https://')) return [];
      return [...new URL(targetUrl).searchParams.entries()];
    } catch { return []; }
  }, [targetUrl]);

  const handleEvent = useCallback((e: Record<string, unknown>) => {
    const type = e.type as string;

    if (type === 'param_start') {
      const name = e.param as string;
      setCurrentParam(name);
      setParams(prev => {
        if (prev.find(p => p.name === name)) return prev.map(p => p.name === name ? { ...p, status: 'scanning' } : p);
        return [...prev, { name, status: 'scanning', vulnerable: false, severity: 'none', hitsCount: 0, hits: [], injectionContext: null, exploitScenarios: [], bestPocUrl: '', totalTested: 0 }];
      });
      setPayloadsFired(0);
    }

    if (type === 'payload_hit') {
      setPayloadsFired(n => n + 1);
      const hit: LiveHit = {
        param: e.param as string, payload: e.payload as string,
        reflectionType: e.reflectionType as ReflectionType, evidence: e.evidence as string,
        severity: e.severity as string, injectionContext: e.injectionContext as InjectionContext,
        pocUrl: e.pocUrl as string,
      };
      setLiveHits(prev => [...prev.slice(-7), hit]);
      setParams(prev => prev.map(p => p.name === hit.param ? { ...p, hitsCount: p.hitsCount + 1, hits: [...p.hits, hit] } : p));
      setTimeout(() => hitsEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
    }

    if (type === 'param_done') {
      const name = e.param as string;
      setParams(prev => prev.map(p => p.name === name ? {
        ...p, status: 'done', vulnerable: e.vulnerable as boolean, severity: e.severity as string,
        hitsCount: e.hitsCount as number, injectionContext: e.injectionContext as InjectionContext | null,
        exploitScenarios: e.exploitScenarios as string[], bestPocUrl: e.bestPocUrl as string,
        totalTested: e.totalTested as number,
      } : p));
      if (e.vulnerable) {
        setExpanded(prev => new Set([...prev, name]));
        setActiveTab(prev => ({ ...prev, [name]: 'goals' }));
      }
    }

    if (type === 'scan_done') {
      setSummary(e.summary as ScanSummary);
      setDuration(e.duration as number);
      setPhase('done');
      setCurrentParam('');
    }
  }, []);

  const startScan = async () => {
    if (!targetUrl || detectedParams.length === 0) {
      toast.error('Enter a URL with query parameters (e.g. ?id=1&q=test)');
      return;
    }
    setPhase('scanning'); setParams([]); setLiveHits([]); setSummary(null);
    setShowReport(false); setExpanded(new Set()); setErrorMsg('');
    setPayloadsFired(0); setActiveTab({});
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      await runScanStream(targetUrl, ctrl.signal, handleEvent);
    } catch (err: unknown) {
      if ((err as Error).name === 'AbortError') { setPhase('idle'); toast.info('Scan aborted'); }
      else { setPhase('error'); setErrorMsg((err as Error).message ?? 'Unknown error'); toast.error(`Scan failed: ${(err as Error).message}`); }
    }
  };

  const copyText = (text: string, label = 'Copied') => navigator.clipboard.writeText(text).then(() => toast.success(label));

  const downloadReport = () => {
    if (!summary) return;
    const text = buildReport(targetUrl, params, summary, duration);
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/markdown' }));
    a.download = `xss_report_${Date.now()}.md`;
    a.click();
    toast.success('Report downloaded');
  };

  const doneParams  = params.filter(p => p.status === 'done').length;
  const totalPCount = detectedParams.length || params.length;
  const progress    = totalPCount ? Math.round((doneParams / totalPCount) * 100) : 0;
  const vulnCount   = params.filter(p => p.vulnerable).length;
  const worstSev    = params.filter(p => p.vulnerable).reduce((best, p) =>
    (SEV_RANK[p.severity] ?? 0) > (SEV_RANK[best] ?? 0) ? p.severity : best, 'none');

  return (
    <div className="flex flex-col h-full">

      {/* ── Input bar ──────────────────────────────────────────────── */}
      <div className="shrink-0 p-4 border-b border-border bg-card/40 space-y-3">
        <div className="flex items-center gap-2">
          <Target className="w-5 h-5 text-primary" />
          <h2 className="font-bold text-base tracking-tight">Active Scanner</h2>
          <span className="text-[10px] font-mono text-muted-foreground uppercase tracking-widest ml-1">
            Real-time · Parallel · 35 payloads/param
          </span>
        </div>

        <div className="flex gap-2">
          <div className="relative flex-1">
            <ScanLine className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
            <input
              type="url"
              value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && phase === 'idle' && startScan()}
              placeholder="https://target.com/search?q=hello&page=1&id=5"
              disabled={phase === 'scanning'}
              className="w-full bg-background border border-border rounded-md pl-10 pr-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary placeholder:font-sans placeholder:text-muted-foreground/40 disabled:opacity-50"
            />
          </div>
          {phase === 'scanning' ? (
            <button onClick={() => abortRef.current?.abort()}
              className="px-5 py-2 bg-destructive/20 text-destructive border border-destructive/30 hover:bg-destructive/30 rounded-md text-sm font-bold flex items-center gap-2 transition-colors">
              <Ban className="w-4 h-4" /> ABORT
            </button>
          ) : (
            <button onClick={startScan} disabled={!targetUrl}
              className="px-5 py-2 bg-primary text-primary-foreground hover:bg-primary/90 rounded-md text-sm font-bold flex items-center gap-2 transition-colors disabled:opacity-40 disabled:cursor-not-allowed">
              <Zap className="w-4 h-4" /> RUN SCAN
            </button>
          )}
        </div>

        {detectedParams.length > 0 && (
          <div className="flex flex-wrap gap-1.5 items-center">
            {detectedParams.map(([k, v]) => (
              <span key={k} className="inline-flex items-center gap-1 px-2 py-0.5 bg-secondary/50 border border-border rounded text-[11px] font-mono">
                <span className="text-primary">{k}</span>
                <span className="text-muted-foreground/40">=</span>
                <span className="text-muted-foreground truncate max-w-[80px]">{v}</span>
              </span>
            ))}
            <span className="text-[11px] text-muted-foreground font-mono">{detectedParams.length} param{detectedParams.length !== 1 ? 's' : ''}</span>
          </div>
        )}
        {targetUrl && detectedParams.length === 0 && (
          <p className="text-[11px] text-muted-foreground font-mono">No query parameters — add ?param=value to URL</p>
        )}

        <div className="flex items-center gap-2 text-xs text-orange-400/80 bg-orange-500/8 border border-orange-500/20 px-3 py-1.5 rounded">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          Only scan targets you own or have explicit written permission to test. For authorized bug bounty research only.
        </div>
      </div>

      {/* ── Scrollable results area ─────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">

        {/* Live progress */}
        <AnimatePresence>
          {phase === 'scanning' && (
            <motion.div initial={{ opacity: 0, y: -4 }} animate={{ opacity: 1, y: 0 }} exit={{ opacity: 0 }}
              className="border border-primary/20 rounded-lg bg-card overflow-hidden">
              <div className="h-1 bg-secondary">
                <motion.div className="h-full bg-primary" animate={{ width: `${progress}%` }} transition={{ type: 'spring', stiffness: 60 }} />
              </div>
              <div className="p-3 space-y-2">
                <div className="flex items-center justify-between text-xs font-mono">
                  <span className="flex items-center gap-2 text-primary">
                    <Activity className="w-3.5 h-3.5 animate-spin" />
                    {currentParam ? <>Scanning <span className="font-bold">{currentParam}</span> ({doneParams + 1}/{totalPCount}) — {payloadsFired} payloads fired</> : 'Starting…'}
                  </span>
                  <span className="text-muted-foreground">{progress}%</span>
                </div>
                <div className="bg-background/60 border border-border/50 rounded h-28 overflow-y-auto p-2 space-y-1">
                  <AnimatePresence initial={false}>
                    {liveHits.map((h, i) => (
                      <motion.div key={`${h.param}-${i}`} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
                        className={`flex items-center gap-2 px-2 py-0.5 rounded text-[10px] font-mono ${
                          SEV_RANK[h.severity] >= 3 ? 'bg-red-500/10 border border-red-500/15' :
                          SEV_RANK[h.severity] >= 2 ? 'bg-orange-500/10 border border-orange-500/15' :
                          'bg-yellow-500/8 border border-yellow-500/10'}`}>
                        <span className={`shrink-0 uppercase font-bold px-1 py-0.5 rounded border text-[9px] ${sevColor(h.severity)}`}>{h.severity}</span>
                        <span className="text-muted-foreground shrink-0">{h.param}:</span>
                        <span className="text-foreground/80 truncate flex-1">{h.payload}</span>
                        <span className="shrink-0 text-muted-foreground/50">{h.reflectionType}</span>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                  <div ref={hitsEndRef} />
                  {liveHits.length === 0 && <span className="text-muted-foreground/30 text-[10px]">Waiting for reflection hits…</span>}
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Error */}
        {phase === 'error' && (
          <div className="border border-destructive/30 bg-destructive/10 rounded-lg p-4 text-sm text-destructive font-mono">
            Scan error: {errorMsg}
          </div>
        )}

        {/* Verdict banner */}
        <AnimatePresence>
          {phase === 'done' && summary && (
            <motion.div initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }}
              className={`rounded-lg border p-4 flex items-center justify-between ${vulnCount > 0 ? 'bg-red-500/8 border-red-500/30' : 'bg-primary/8 border-primary/30'}`}>
              <div className="flex items-center gap-3">
                {vulnCount > 0 ? <XCircle className="w-8 h-8 text-red-500 shrink-0" /> : <CheckCircle className="w-8 h-8 text-primary shrink-0" />}
                <div>
                  <div className={`text-lg font-black tracking-wider ${vulnCount > 0 ? 'text-red-500' : 'text-primary'}`}>
                    {vulnCount > 0 ? `VULNERABLE — ${vulnCount} PARAM${vulnCount !== 1 ? 'S' : ''} AT RISK` : 'NO VULNERABILITIES DETECTED'}
                  </div>
                  <div className="text-xs text-muted-foreground font-mono">
                    {summary.totalParams} params scanned · {summary.totalPayloadsTested} payloads · {(duration / 1000).toFixed(2)}s
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {vulnCount > 0 && <span className={`text-xs font-bold px-3 py-1 rounded border uppercase ${sevColor(worstSev)}`}>{worstSev}</span>}
                <div className="flex items-center gap-1 text-xs text-muted-foreground font-mono">
                  <Clock className="w-3.5 h-3.5" />{(duration / 1000).toFixed(2)}s
                </div>
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Parameter cards */}
        {params.length > 0 && (
          <div className="space-y-3">
            <AnimatePresence>
              {params.map((p, i) => {
                const isOpen  = expanded.has(p.name);
                const tab     = activeTab[p.name] ?? 'hits';
                const setTab  = (t: 'hits' | 'exploits' | 'goals') => setActiveTab(prev => ({ ...prev, [p.name]: t }));

                return (
                  <motion.div key={p.name} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                    className={`border rounded-lg overflow-hidden ${
                      p.status === 'scanning' ? 'border-primary/40' :
                      p.vulnerable ? 'border-red-500/30' : 'border-border'}`}>

                    {/* Header */}
                    <button className={`w-full flex items-center justify-between px-4 py-3 text-left transition-colors ${
                      p.status === 'scanning' ? 'bg-primary/5' :
                      p.vulnerable ? 'bg-red-500/5 hover:bg-red-500/8' : 'bg-card hover:bg-secondary/30'}`}
                      onClick={() => p.status === 'done' && setExpanded(prev => {
                        const n = new Set(prev); n.has(p.name) ? n.delete(p.name) : n.add(p.name); return n;
                      })}>
                      <div className="flex items-center gap-3">
                        {p.status === 'scanning' ? <Activity className="w-4 h-4 text-primary animate-spin" />
                          : p.vulnerable ? <XCircle className="w-4 h-4 text-red-500" />
                          : <CheckCircle className="w-4 h-4 text-primary" />}
                        <div>
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-mono font-bold text-sm">{p.name}</span>
                            {p.status === 'done' && (
                              <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${p.vulnerable ? sevColor(p.severity) : 'text-primary border-primary/20 bg-primary/10'}`}>
                                {p.vulnerable ? p.severity : 'safe'}
                              </span>
                            )}
                            {p.vulnerable && <span className="text-[10px] font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">{p.hitsCount} hit{p.hitsCount !== 1 ? 's' : ''}</span>}
                          </div>
                          <div className="text-[11px] text-muted-foreground font-mono mt-0.5">
                            {p.status === 'scanning' && 'Scanning…'}
                            {p.status === 'done' && (p.vulnerable
                              ? (p.injectionContext ? CONTEXT_LABELS[p.injectionContext] : 'Vulnerable')
                              : `${p.totalTested} payloads tested — no reflection`)}
                          </div>
                        </div>
                      </div>
                      {p.status === 'done' && (isOpen ? <ChevronUp className="w-4 h-4 text-muted-foreground shrink-0" /> : <ChevronDown className="w-4 h-4 text-muted-foreground shrink-0" />)}
                    </button>

                    {/* Expanded body */}
                    <AnimatePresence>
                      {isOpen && p.vulnerable && (
                        <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                          className="overflow-hidden border-t border-border/50">

                          {/* Tab bar */}
                          <div className="flex border-b border-border bg-secondary/20 overflow-x-auto">
                            {([
                              { id: 'goals',   label: '🎯 Attack Goals' },
                              { id: 'exploits', label: '💥 Exploit Arsenal' },
                              { id: 'hits',    label: `📡 Payload Hits (${p.hits.length})` },
                            ] as const).map(t => (
                              <button key={t.id} onClick={() => setTab(t.id)}
                                className={`px-4 py-2 text-xs font-bold whitespace-nowrap transition-colors shrink-0 ${
                                  tab === t.id ? 'text-primary border-b-2 border-primary bg-primary/5' : 'text-muted-foreground hover:text-foreground'}`}>
                                {t.label}
                              </button>
                            ))}
                          </div>

                          <div className="p-4 bg-background/50">
                            {tab === 'hits' && (
                              <div className="space-y-4">
                                {/* WHERE */}
                                <section className="space-y-1">
                                  <div className="text-[10px] uppercase tracking-widest text-primary font-bold flex items-center gap-1">
                                    <Shield className="w-3 h-3" /> WHERE IS IT REFLECTED
                                  </div>
                                  <div className="text-sm font-mono bg-card border border-border rounded px-3 py-2 text-foreground/80">
                                    {p.injectionContext ? CONTEXT_LABELS[p.injectionContext] : 'Unknown context'}
                                  </div>
                                </section>

                                {/* PoC */}
                                {p.bestPocUrl && (
                                  <section className="space-y-1">
                                    <div className="text-[10px] uppercase tracking-widest text-primary font-bold flex items-center gap-1">
                                      <Zap className="w-3 h-3" /> PROOF OF CONCEPT URL
                                    </div>
                                    <div className="relative">
                                      <code className="block text-[11px] font-mono bg-black/60 border border-border rounded px-3 py-2 text-yellow-300/90 break-all pr-10">
                                        {p.bestPocUrl}
                                      </code>
                                      <button onClick={() => copyText(p.bestPocUrl, 'PoC URL copied')}
                                        className="absolute top-1.5 right-1.5 p-1.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition-colors">
                                        <Copy className="w-3.5 h-3.5" />
                                      </button>
                                    </div>
                                  </section>
                                )}

                                {/* What attacker can do */}
                                {p.exploitScenarios.length > 0 && (
                                  <section className="space-y-1">
                                    <div className="text-[10px] uppercase tracking-widest text-primary font-bold flex items-center gap-1">
                                      <Terminal className="w-3 h-3" /> WHAT AN ATTACKER CAN DO
                                    </div>
                                    <ul className="space-y-1">
                                      {p.exploitScenarios.map((s, i) => (
                                        <li key={i} className="flex items-start gap-2 text-xs text-foreground/80 font-mono">
                                          <ChevronRight className="w-3.5 h-3.5 text-primary shrink-0 mt-0.5" />{s}
                                        </li>
                                      ))}
                                    </ul>
                                  </section>
                                )}

                                {/* Payload hits */}
                                <section className="space-y-2">
                                  <div className="text-[10px] uppercase tracking-widest text-muted-foreground font-bold">Payload Hits</div>
                                  {p.hits.map((h, i) => (
                                    <div key={i} className="border border-border rounded bg-card p-3 space-y-2">
                                      <div className="flex items-center gap-2">
                                        <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${sevColor(h.severity)}`}>{h.severity}</span>
                                        <span className="text-[10px] px-1.5 py-0.5 border border-primary/20 bg-primary/10 text-primary rounded font-mono uppercase">{h.reflectionType}</span>
                                      </div>
                                      <code className="block text-[11px] font-mono text-red-400 bg-black/40 rounded px-2 py-1.5 break-all">{h.payload}</code>
                                      <div>
                                        <div className="text-[10px] text-muted-foreground uppercase tracking-wider mb-1">Evidence</div>
                                        <code className="block text-[11px] font-mono text-muted-foreground bg-secondary/40 rounded px-2 py-1.5 break-all border border-border/40 whitespace-pre-wrap">{h.evidence}</code>
                                      </div>
                                    </div>
                                  ))}
                                </section>
                              </div>
                            )}

                            {tab === 'exploits' && (
                              <ExploitArsenal param={p} targetUrl={targetUrl} />
                            )}

                            {tab === 'goals' && (
                              <AttackGoalWizard
                                paramName={p.name}
                                targetUrl={targetUrl}
                                injectionContext={(p.injectionContext ?? 'unknown') as InjectionContext}
                              />
                            )}
                          </div>
                        </motion.div>
                      )}
                    </AnimatePresence>
                  </motion.div>
                );
              })}
            </AnimatePresence>
          </div>
        )}

        {/* Bug Bounty Report */}
        {phase === 'done' && vulnCount > 0 && (
          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ delay: 0.3 }}
            className="border border-border rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 bg-card border-b border-border">
              <div className="flex items-center gap-2">
                <Terminal className="w-4 h-4 text-primary" />
                <span className="font-bold text-sm">Bug Bounty Report</span>
                <span className="text-[10px] text-muted-foreground font-mono">CWE-79 · Markdown</span>
              </div>
              <div className="flex items-center gap-2">
                {!showReport ? (
                  <button onClick={() => setShowReport(true)}
                    className="px-3 py-1.5 border border-primary text-primary hover:bg-primary/10 rounded text-xs font-bold transition-colors">
                    Generate Report
                  </button>
                ) : (
                  <>
                    <button onClick={() => summary && copyText(buildReport(targetUrl, params, summary, duration), 'Report copied')}
                      className="px-3 py-1.5 border border-border hover:border-primary text-muted-foreground hover:text-primary rounded text-xs font-bold flex items-center gap-1.5 transition-colors">
                      <Copy className="w-3 h-3" /> Copy
                    </button>
                    <button onClick={downloadReport}
                      className="px-3 py-1.5 bg-primary text-primary-foreground hover:bg-primary/90 rounded text-xs font-bold flex items-center gap-1.5 transition-colors">
                      <Download className="w-3 h-3" /> Download .md
                    </button>
                  </>
                )}
              </div>
            </div>
            {showReport && summary && (
              <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} className="overflow-hidden">
                <textarea readOnly
                  className="w-full h-96 bg-[#080808] text-primary/80 font-mono text-[11px] p-4 resize-y focus:outline-none selection:bg-primary/20 leading-relaxed"
                  value={buildReport(targetUrl, params, summary, duration)} />
              </motion.div>
            )}
          </motion.div>
        )}

        {/* Empty state */}
        {phase === 'idle' && params.length === 0 && (
          <div className="flex flex-col items-center justify-center py-20 text-center">
            <ScanLine className="w-10 h-10 text-primary/20 mb-4" />
            <p className="text-muted-foreground font-mono text-sm">Paste a target URL with query parameters</p>
            <p className="text-muted-foreground/40 font-mono text-xs mt-1">e.g. https://example.com/search?q=test&amp;id=5</p>
          </div>
        )}
      </div>
    </div>
  );
}
