import { useState, useRef, useCallback } from 'react';
import {
  Database, Upload, Play, Square, Download, Copy, ChevronDown, ChevronUp,
  AlertTriangle, CheckCircle, XCircle, Clock, Shield, Zap, Filter,
  FileText, BarChart2, RefreshCw, Eye
} from 'lucide-react';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'framer-motion';

// ── Types ──────────────────────────────────────────────────────────────────────
type Phase = 'idle' | 'scanning' | 'done' | 'stopped';
type UrlStatus = 'pending' | 'scanning' | 'vuln' | 'clean' | 'error' | 'skipped';

interface ParamResult {
  param: string;
  originalValue: string;
  vulnerable: boolean;
  severity: string;
  dbType: string;
  techniques: string[];
  hitsCount: number;
  columnCount: number | null;
  totalTested: number;
  wafDetected: boolean;
}

interface LiveHit {
  param: string;
  technique: string;
  dbType: string;
  severity: string;
  evidence: string;
  payload: string;
  wafDetected: boolean;
}

interface UrlEntry {
  url: string;
  status: UrlStatus;
  paramResults: ParamResult[];
  hits: LiveHit[];
  error?: string;
  duration?: number;
  wafDetected?: boolean;
}

// ── Helpers ────────────────────────────────────────────────────────────────────
const API = `${window.location.origin}/api`;

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-500 border-red-500/30 bg-red-500/8',
  high:     'text-orange-400 border-orange-400/30 bg-orange-400/8',
  medium:   'text-yellow-400 border-yellow-400/30 bg-yellow-400/8',
  low:      'text-blue-400 border-blue-400/30 bg-blue-400/8',
  none:     'text-muted-foreground border-border bg-secondary/30',
};
const TECH_COLOR: Record<string, string> = {
  'Error-Based':         'text-red-400 bg-red-500/10 border-red-500/20',
  'Boolean-Based Blind': 'text-orange-400 bg-orange-500/10 border-orange-500/20',
  'Time-Based Blind':    'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  'UNION-Based':         'text-purple-400 bg-purple-500/10 border-purple-500/20',
  'Stacked Queries':     'text-pink-400 bg-pink-500/10 border-pink-500/20',
};
const DB_ICON: Record<string, string> = {
  MySQL: '🐬', PostgreSQL: '🐘', MSSQL: '🪟', Oracle: '🔴', SQLite: '🗄️', Unknown: '❓',
};
const STATUS_ICON: Record<UrlStatus, React.ReactNode> = {
  pending:  <Clock className="w-3.5 h-3.5 text-muted-foreground/50" />,
  scanning: <RefreshCw className="w-3.5 h-3.5 text-primary animate-spin" />,
  vuln:     <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
  clean:    <CheckCircle className="w-3.5 h-3.5 text-green-400" />,
  error:    <XCircle className="w-3.5 h-3.5 text-muted-foreground" />,
  skipped:  <XCircle className="w-3.5 h-3.5 text-muted-foreground/40" />,
};

function fmtMs(ms: number) {
  return ms >= 1000 ? `${(ms / 1000).toFixed(1)}s` : `${ms}ms`;
}

function parseUrls(raw: string): string[] {
  return raw.split(/[\n,]+/).map(s => s.trim()).filter(s => s.length > 0 && s.startsWith('http'));
}

function copyText(text: string) {
  navigator.clipboard.writeText(text).then(() => toast.success('Copied'));
}

// ── Export helpers ─────────────────────────────────────────────────────────────
function exportCSV(entries: UrlEntry[]) {
  const rows = [
    ['URL', 'Status', 'Vuln Params', 'DB Types', 'Techniques', 'Hits', 'WAF', 'Duration'].join(','),
    ...entries.map(e => [
      `"${e.url}"`,
      e.status,
      e.paramResults.filter(p => p.vulnerable).length,
      `"${[...new Set(e.paramResults.map(p => p.dbType))].join('|')}"`,
      `"${[...new Set(e.paramResults.flatMap(p => p.techniques))].join('|')}"`,
      e.hits.length,
      e.wafDetected ? 'Yes' : 'No',
      e.duration ? fmtMs(e.duration) : '',
    ].join(','))
  ].join('\n');
  const blob = new Blob([rows], { type: 'text/csv' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `sqli-bulk-${Date.now()}.csv`; a.click();
}

function exportMarkdown(entries: UrlEntry[]) {
  const vuln = entries.filter(e => e.status === 'vuln');
  const lines = [
    '# SQLi Mass Scan Report',
    `**Generated:** ${new Date().toISOString()}`,
    `**Total URLs:** ${entries.length} | **Vulnerable:** ${vuln.length} | **Clean:** ${entries.filter(e => e.status === 'clean').length}`,
    '',
    '---',
    '',
    '## Vulnerable Targets',
    '',
    ...vuln.flatMap(e => {
      const vulnParams = e.paramResults.filter(p => p.vulnerable);
      return [
        `### ${e.url}`,
        `- **DB:** ${[...new Set(vulnParams.map(p => p.dbType))].join(', ')}`,
        `- **Techniques:** ${[...new Set(vulnParams.flatMap(p => p.techniques))].join(', ')}`,
        `- **WAF:** ${e.wafDetected ? 'Detected' : 'None'}`,
        `- **Duration:** ${e.duration ? fmtMs(e.duration) : 'N/A'}`,
        '',
        '#### Vulnerable Parameters',
        ...vulnParams.map(p =>
          `- **\`${p.param}\`** — ${p.techniques.join(', ')} | DB: ${p.dbType} | Severity: ${p.severity}`
        ),
        '',
        '#### Sample Payloads',
        ...e.hits.slice(0, 5).map(h =>
          `\`\`\`\n[${h.technique}] ${h.payload}\n# Evidence: ${h.evidence.slice(0, 120)}\n\`\`\``
        ),
        '',
        '---',
        '',
      ];
    }),
  ];
  const blob = new Blob([lines.join('\n')], { type: 'text/markdown' });
  const a = document.createElement('a'); a.href = URL.createObjectURL(blob);
  a.download = `sqli-bulk-${Date.now()}.md`; a.click();
}

// ── URL Result Card ────────────────────────────────────────────────────────────
function UrlCard({ entry, showOnly }: { entry: UrlEntry; showOnly: 'all' | 'vuln' }) {
  const [expanded, setExpanded] = useState(entry.status === 'vuln');
  const [expandedParams, setExpandedParams] = useState<Set<string>>(new Set());

  if (showOnly === 'vuln' && entry.status !== 'vuln') return null;

  const vulnParams = entry.paramResults.filter(p => p.vulnerable);
  const isVuln = entry.status === 'vuln';

  const toggleParam = (name: string) => {
    setExpandedParams(prev => {
      const next = new Set(prev);
      next.has(name) ? next.delete(name) : next.add(name);
      return next;
    });
  };

  return (
    <motion.div
      layout
      initial={{ opacity: 0, y: 6 }}
      animate={{ opacity: 1, y: 0 }}
      className={`border rounded-md overflow-hidden ${
        isVuln ? 'border-red-500/25 bg-red-500/3' :
        entry.status === 'scanning' ? 'border-primary/20 bg-primary/3' :
        entry.status === 'error' || entry.status === 'skipped' ? 'border-border/40 bg-secondary/10 opacity-60' :
        'border-border/50 bg-secondary/10'
      }`}
    >
      {/* Header row */}
      <button
        onClick={() => setExpanded(e => !e)}
        className="w-full flex items-center gap-3 px-4 py-2.5 hover:bg-white/3 transition-colors text-left"
      >
        {STATUS_ICON[entry.status]}

        <span className="flex-1 font-mono text-xs text-foreground truncate min-w-0">{entry.url}</span>

        {/* Badges */}
        <div className="flex items-center gap-2 shrink-0">
          {entry.wafDetected && (
            <span className="text-[9px] font-black px-1.5 py-0.5 rounded border bg-orange-500/10 border-orange-500/30 text-orange-400 uppercase tracking-wider">WAF</span>
          )}
          {isVuln && vulnParams.length > 0 && (
            <span className="text-[9px] font-black px-1.5 py-0.5 rounded border bg-red-500/10 border-red-500/30 text-red-400 uppercase">
              {vulnParams.length} PARAM{vulnParams.length > 1 ? 'S' : ''}
            </span>
          )}
          {isVuln && (
            <div className="flex gap-1">
              {[...new Set(vulnParams.flatMap(p => p.techniques))].slice(0, 3).map(t => (
                <span key={t} className={`text-[8px] font-bold px-1 py-0.5 rounded border ${TECH_COLOR[t] ?? 'text-primary bg-primary/10 border-primary/20'}`}>
                  {t.split('-')[0].trim()}
                </span>
              ))}
            </div>
          )}
          {isVuln && (
            <div className="flex gap-1">
              {[...new Set(vulnParams.map(p => p.dbType))].map(db => (
                <span key={db} className="text-[9px]">{DB_ICON[db] ?? '❓'}</span>
              ))}
            </div>
          )}
          {entry.duration && (
            <span className="text-[10px] text-muted-foreground font-mono">{fmtMs(entry.duration)}</span>
          )}
          {entry.status === 'error' && (
            <span className="text-[10px] text-muted-foreground font-mono truncate max-w-[180px]">{entry.error}</span>
          )}
          {expanded ? <ChevronUp className="w-3.5 h-3.5 text-muted-foreground/50" /> : <ChevronDown className="w-3.5 h-3.5 text-muted-foreground/50" />}
        </div>
      </button>

      {/* Expanded body */}
      <AnimatePresence>
        {expanded && (entry.paramResults.length > 0 || entry.hits.length > 0) && (
          <motion.div
            initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }}
            className="overflow-hidden border-t border-border/40"
          >
            <div className="p-3 space-y-3">
              {/* Param results */}
              {entry.paramResults.map(pr => (
                <div key={pr.param} className={`rounded border ${SEV_COLOR[pr.severity] ?? SEV_COLOR.none}`}>
                  <button
                    onClick={() => toggleParam(pr.param)}
                    className="w-full flex items-center gap-2 px-3 py-2 text-left"
                  >
                    {pr.vulnerable
                      ? <AlertTriangle className="w-3 h-3 shrink-0 text-red-400" />
                      : <CheckCircle className="w-3 h-3 shrink-0 text-green-400" />}
                    <span className="font-mono text-xs font-bold">?{pr.param}={pr.originalValue.slice(0, 30)}</span>
                    <span className="text-[9px] text-muted-foreground ml-1">({pr.totalTested} probes)</span>
                    <div className="flex-1" />
                    {pr.vulnerable && (
                      <>
                        <span className="text-[9px] font-bold uppercase tracking-wider">{pr.severity}</span>
                        <span className="text-[9px]">{DB_ICON[pr.dbType] ?? '❓'} {pr.dbType}</span>
                        {pr.columnCount && <span className="text-[9px] text-muted-foreground">{pr.columnCount} cols</span>}
                        {pr.wafDetected && <Shield className="w-3 h-3 text-orange-400" />}
                        <div className="flex gap-1">
                          {pr.techniques.map(t => (
                            <span key={t} className={`text-[8px] px-1 py-0.5 rounded border ${TECH_COLOR[t] ?? 'text-primary bg-primary/10 border-primary/20'}`}>
                              {t.replace('-Based', '').replace(' Blind', '').trim()}
                            </span>
                          ))}
                        </div>
                      </>
                    )}
                    {expandedParams.has(pr.param) ? <ChevronUp className="w-3 h-3 opacity-40" /> : <ChevronDown className="w-3 h-3 opacity-40" />}
                  </button>

                  {/* Hits for this param */}
                  <AnimatePresence>
                    {expandedParams.has(pr.param) && pr.vulnerable && (
                      <motion.div initial={{ height: 0 }} animate={{ height: 'auto' }} exit={{ height: 0 }} className="overflow-hidden">
                        <div className="px-3 pb-2 space-y-2 border-t border-border/30 pt-2">
                          {entry.hits.filter(h => h.param === pr.param).map((h, i) => (
                            <div key={i} className="rounded bg-card/50 border border-border/40 p-2 space-y-1.5">
                              <div className="flex items-center gap-2 flex-wrap">
                                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded border ${TECH_COLOR[h.technique] ?? 'text-primary bg-primary/10 border-primary/20'}`}>
                                  {h.technique}
                                </span>
                                <span className="text-[9px] font-mono text-muted-foreground">{h.dbType !== 'Unknown' ? `${DB_ICON[h.dbType]} ${h.dbType}` : ''}</span>
                                {h.wafDetected && <span className="text-[9px] text-orange-400">🛡️ WAF</span>}
                              </div>
                              <div className="flex items-start gap-2">
                                <code className="flex-1 font-mono text-[10px] text-primary/90 bg-primary/5 px-2 py-1 rounded break-all leading-relaxed">{h.payload}</code>
                                <button onClick={() => copyText(h.payload)} className="shrink-0 p-1 hover:text-primary transition-colors mt-0.5"><Copy className="w-3 h-3" /></button>
                              </div>
                              {h.evidence && (
                                <p className="font-mono text-[10px] text-muted-foreground bg-secondary/40 px-2 py-1 rounded break-all leading-relaxed">
                                  {h.evidence.slice(0, 300)}
                                </p>
                              )}
                            </div>
                          ))}
                          {/* Quick dump link */}
                          {pr.vulnerable && (
                            <div className="flex gap-2 pt-1">
                              <button
                                onClick={() => {
                                  const u = new URL(entry.url);
                                  const q = new URLSearchParams({ url: entry.url, param: pr.param, db: pr.dbType, cols: String(pr.columnCount ?? 3) });
                                  window.location.href = `/sqli?${q}`;
                                }}
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-primary/25 bg-primary/8 text-primary hover:bg-primary/15 transition-colors text-[11px] font-bold"
                              >
                                <Database className="w-3 h-3" /> Open Dumper
                              </button>
                              <button
                                onClick={() => copyText(entry.url)}
                                className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-border bg-secondary/40 text-muted-foreground hover:text-foreground transition-colors text-[11px]"
                              >
                                <Copy className="w-3 h-3" /> Copy URL
                              </button>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </div>
              ))}
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </motion.div>
  );
}

// ── Main Page ──────────────────────────────────────────────────────────────────
export default function SQLiBulk() {
  const [urlsRaw, setUrlsRaw] = useState('');
  const [concurrency, setConcurrency] = useState(4);
  const [fastMode, setFastMode] = useState(true);
  const [phase, setPhase] = useState<Phase>('idle');
  const [entries, setEntries] = useState<UrlEntry[]>([]);
  const [filter, setFilter] = useState<'all' | 'vuln'>('all');
  const [stats, setStats] = useState({ total: 0, done: 0, vuln: 0, hits: 0, duration: 0 });
  const abortRef = useRef<AbortController | null>(null);
  const esRef = useRef<EventSource | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // ── Start scan ───────────────────────────────────────────────────────────────
  const startScan = useCallback(async () => {
    const urls = parseUrls(urlsRaw);
    if (urls.length === 0) { toast.error('No valid URLs found (must start with http)'); return; }
    if (urls.length > 500) { toast.error('Maximum 500 URLs per batch'); return; }

    setPhase('scanning');
    setEntries([]);
    setStats({ total: urls.length, done: 0, vuln: 0, hits: 0, duration: 0 });

    const ab = new AbortController();
    abortRef.current = ab;

    try {
      const resp = await fetch(`${API}/sqli/bulk/stream`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ urls, concurrency, fastMode }),
        signal: ab.signal,
      });
      if (!resp.ok || !resp.body) throw new Error(`Server error: ${resp.status}`);

      const reader = resp.body.getReader();
      const dec = new TextDecoder();
      let buf = '';

      const process = (chunk: string) => {
        buf += chunk;
        const lines = buf.split('\n');
        buf = lines.pop() ?? '';
        for (const line of lines) {
          if (!line.startsWith('data: ')) continue;
          let ev: Record<string, unknown>;
          try { ev = JSON.parse(line.slice(6)); } catch { continue; }
          handleEvent(ev);
        }
      };

      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        process(dec.decode(value, { stream: true }));
      }
    } catch (err: unknown) {
      if ((err as Error)?.name !== 'AbortError') {
        toast.error('Scan failed: ' + (err as Error).message);
        setPhase('idle');
      }
    }
  }, [urlsRaw, concurrency, fastMode]);

  // ── Stop scan ────────────────────────────────────────────────────────────────
  const stopScan = () => {
    abortRef.current?.abort();
    esRef.current?.close();
    setPhase('stopped');
    toast.info('Scan stopped');
  };

  // ── Event handler ────────────────────────────────────────────────────────────
  const handleEvent = (ev: Record<string, unknown>) => {
    const type = ev.type as string;

    if (type === 'url_start') {
      const url = ev.url as string;
      setEntries(prev => {
        if (prev.some(e => e.url === url)) {
          return prev.map(e => e.url === url ? { ...e, status: 'scanning' } : e);
        }
        return [...prev, { url, status: 'scanning', paramResults: [], hits: [] }];
      });
    }

    if (type === 'param_hit') {
      const url = ev.url as string;
      const hit: LiveHit = {
        param: ev.param as string,
        technique: ev.technique as string,
        dbType: ev.dbType as string,
        severity: ev.severity as string,
        evidence: ev.evidence as string ?? '',
        payload: ev.payload as string ?? '',
        wafDetected: !!ev.wafDetected,
      };
      setEntries(prev => prev.map(e => e.url === url ? { ...e, hits: [...e.hits, hit] } : e));
    }

    if (type === 'url_done') {
      const url = ev.url as string;
      const vulnerable = !!ev.vulnerable;
      const paramResults = (ev.paramResults as ParamResult[]) ?? [];
      const wafDetected = !!ev.wafDetected;
      const duration = ev.duration as number ?? 0;

      setEntries(prev => prev.map(e =>
        e.url === url ? {
          ...e,
          status: vulnerable ? 'vuln' : 'clean',
          paramResults,
          wafDetected,
          duration,
        } : e
      ));

      setStats(prev => ({
        ...prev,
        done: prev.done + 1,
        vuln: vulnerable ? prev.vuln + 1 : prev.vuln,
        hits: prev.hits + ((ev.totalHits as number) ?? 0),
      }));
    }

    if (type === 'url_error') {
      const url = ev.url as string;
      setEntries(prev => {
        if (prev.some(e => e.url === url)) {
          return prev.map(e => e.url === url ? { ...e, status: 'error', error: ev.error as string } : e);
        }
        return [...prev, { url, status: 'error', paramResults: [], hits: [], error: ev.error as string }];
      });
      setStats(prev => ({ ...prev, done: prev.done + 1 }));
    }

    if (type === 'bulk_done') {
      setPhase('done');
      const dur = ev.duration as number ?? 0;
      setStats(prev => ({ ...prev, duration: dur }));
      toast.success(`Scan complete — ${ev.vulnUrls} vulnerable URLs found`);
    }
  };

  // ── File upload ──────────────────────────────────────────────────────────────
  const handleFile = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (ev) => {
      const text = (ev.target?.result as string) ?? '';
      setUrlsRaw(text);
      toast.success(`Loaded ${parseUrls(text).length} URLs`);
    };
    reader.readAsText(file);
    e.target.value = '';
  };

  const validUrls = parseUrls(urlsRaw);
  const pct = stats.total > 0 ? (stats.done / stats.total) * 100 : 0;
  const visibleEntries = filter === 'vuln' ? entries.filter(e => e.status === 'vuln') : entries;

  return (
    <div className="h-full flex flex-col overflow-hidden bg-background">
      {/* ── Header ── */}
      <div className="shrink-0 border-b border-border px-6 py-3 flex items-center gap-4">
        <div className="flex items-center gap-2">
          <Database className="w-4 h-4 text-primary" />
          <h1 className="font-brand text-sm font-black text-primary tracking-wide uppercase">SQLi Mass Scanner</h1>
        </div>
        <span className="text-[9px] font-bold text-muted-foreground/60 uppercase tracking-widest border border-border px-2 py-0.5 rounded font-mono">
          {SQLI_PROBES_COUNT} Payloads · 22 WAF Bypasses
        </span>
        {phase === 'scanning' && (
          <span className="text-[9px] font-black px-2 py-0.5 rounded border bg-primary/10 border-primary/30 text-primary animate-pulse uppercase tracking-wider">
            SCANNING
          </span>
        )}
        {phase === 'done' && (
          <span className="text-[9px] font-black px-2 py-0.5 rounded border bg-green-500/10 border-green-500/30 text-green-400 uppercase tracking-wider">
            DONE
          </span>
        )}
        <div className="ml-auto flex items-center gap-2">
          {(phase === 'done' || phase === 'stopped') && entries.length > 0 && (
            <>
              <button onClick={() => exportCSV(entries)} className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-border bg-secondary/50 hover:bg-secondary text-xs transition-colors">
                <Download className="w-3.5 h-3.5" /> CSV
              </button>
              <button onClick={() => exportMarkdown(entries)} className="flex items-center gap-1.5 px-3 py-1.5 rounded border border-border bg-secondary/50 hover:bg-secondary text-xs transition-colors">
                <FileText className="w-3.5 h-3.5" /> Report
              </button>
            </>
          )}
        </div>
      </div>

      <div className="flex-1 flex overflow-hidden">
        {/* ── Left Config Panel ── */}
        <div className="w-72 shrink-0 border-r border-border flex flex-col overflow-y-auto">
          <div className="p-4 space-y-5">
            {/* URL Input */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">Target URLs</label>
                <div className="flex items-center gap-1">
                  <span className={`text-[10px] font-mono ${validUrls.length > 0 ? 'text-primary' : 'text-muted-foreground/50'}`}>
                    {validUrls.length} URLs
                  </span>
                  <button
                    onClick={() => fileInputRef.current?.click()}
                    className="flex items-center gap-1 px-2 py-0.5 rounded border border-border hover:bg-secondary text-[10px] transition-colors"
                  >
                    <Upload className="w-3 h-3" /> .txt
                  </button>
                  <input ref={fileInputRef} type="file" accept=".txt,.csv" className="hidden" onChange={handleFile} />
                </div>
              </div>
              <textarea
                value={urlsRaw}
                onChange={e => setUrlsRaw(e.target.value)}
                disabled={phase === 'scanning'}
                placeholder={"https://target.com/page?id=1\nhttps://site.com/search?q=test\nhttps://example.com/item?cat=5&page=2"}
                rows={10}
                className="w-full bg-card border border-border rounded px-3 py-2 font-mono text-[11px] text-foreground placeholder:text-muted-foreground/40 resize-none focus:outline-none focus:border-primary/50 transition-colors disabled:opacity-50"
              />
              <p className="text-[9px] text-muted-foreground/50">One URL per line · Max 500 · Must have query params</p>
            </div>

            {/* Options */}
            <div className="space-y-4">
              <div className="text-[10px] font-black uppercase tracking-widest text-muted-foreground">Scan Options</div>

              {/* Concurrency */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between text-[11px]">
                  <span className="text-muted-foreground font-medium">Concurrency</span>
                  <span className="font-mono font-bold text-primary">{concurrency} URLs</span>
                </div>
                <input
                  type="range" min={1} max={15} value={concurrency}
                  onChange={e => setConcurrency(+e.target.value)}
                  disabled={phase === 'scanning'}
                  className="w-full accent-primary disabled:opacity-50"
                />
                <div className="flex justify-between text-[9px] text-muted-foreground/40 font-mono">
                  <span>1 (Safe)</span><span>8 (Fast)</span><span>15 (Max)</span>
                </div>
              </div>

              {/* Scan mode */}
              <div className="space-y-1.5">
                <div className="text-[11px] text-muted-foreground font-medium mb-1">Probe Depth</div>
                <div className="grid grid-cols-2 gap-1.5">
                  <button
                    onClick={() => setFastMode(true)}
                    disabled={phase === 'scanning'}
                    className={`flex flex-col items-center gap-1 px-2 py-2 rounded border text-[10px] transition-all ${
                      fastMode ? 'border-primary/40 bg-primary/10 text-primary' : 'border-border bg-secondary/30 text-muted-foreground hover:bg-secondary'
                    }`}
                  >
                    <Zap className="w-3.5 h-3.5" />
                    <span className="font-bold">Fast Mode</span>
                    <span className="text-[8px] opacity-70">~50 probes/param</span>
                  </button>
                  <button
                    onClick={() => setFastMode(false)}
                    disabled={phase === 'scanning'}
                    className={`flex flex-col items-center gap-1 px-2 py-2 rounded border text-[10px] transition-all ${
                      !fastMode ? 'border-primary/40 bg-primary/10 text-primary' : 'border-border bg-secondary/30 text-muted-foreground hover:bg-secondary'
                    }`}
                  >
                    <Eye className="w-3.5 h-3.5" />
                    <span className="font-bold">Full Mode</span>
                    <span className="text-[8px] opacity-70">300+ probes/param</span>
                  </button>
                </div>
                <p className="text-[9px] text-muted-foreground/50 leading-relaxed">
                  {fastMode
                    ? 'Fast: error + boolean + UNION probes with key WAF bypasses. Best for mass scanning.'
                    : 'Full: all 300+ probes including time-based, stacked, OOB. More accurate but slower.'}
                </p>
              </div>
            </div>

            {/* Payload stats */}
            <div className="rounded border border-border/50 bg-secondary/20 p-3 space-y-1.5">
              <div className="text-[9px] font-black uppercase tracking-widest text-muted-foreground/60 mb-2">Payload Arsenal</div>
              {[
                ['Error-Based', 'MySQL EXTRACTVALUE, MSSQL CONVERT, PgSQL CAST, Oracle XMLType'],
                ['Boolean Blind', 'True/false pairs, IF/CASE, substring oracles, comparison'],
                ['Time-Based', 'SLEEP, BENCHMARK, WAITFOR, pg_sleep, dbms_pipe, RANDOMBLOB'],
                ['UNION-Based', '1–10 columns, hex markers, ALL bypass, Oracle dual'],
                ['Stacked', 'CREATE, EXEC, DECLARE, xp_cmdshell, dynamic SQL'],
                ['WAF Bypasses', '22 transforms: inline comments, case, HPP, concat, encoding'],
              ].map(([label, desc]) => (
                <div key={label} className="flex items-start gap-2">
                  <span className="text-primary font-mono text-[10px] shrink-0">›</span>
                  <div>
                    <span className="text-[10px] font-bold text-foreground">{label}</span>
                    <span className="text-[9px] text-muted-foreground/60 ml-1">{desc}</span>
                  </div>
                </div>
              ))}
            </div>

            {/* Start / Stop */}
            <div className="space-y-2">
              {phase !== 'scanning' ? (
                <button
                  onClick={startScan}
                  disabled={validUrls.length === 0}
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded border border-primary/40 bg-primary/10 hover:bg-primary/20 text-primary font-bold text-sm transition-all disabled:opacity-40 disabled:cursor-not-allowed"
                >
                  <Play className="w-4 h-4" />
                  {phase === 'idle' ? `Scan ${validUrls.length} URL${validUrls.length !== 1 ? 's' : ''}` : 'Scan Again'}
                </button>
              ) : (
                <button
                  onClick={stopScan}
                  className="w-full flex items-center justify-center gap-2 py-2.5 rounded border border-red-500/30 bg-red-500/10 hover:bg-red-500/20 text-red-400 font-bold text-sm transition-all"
                >
                  <Square className="w-4 h-4" /> Stop Scan
                </button>
              )}
            </div>
          </div>
        </div>

        {/* ── Right Results Panel ── */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Stats bar */}
          <div className="shrink-0 border-b border-border px-4 py-2 flex items-center gap-4">
            {[
              { label: 'URLs', value: stats.total, color: 'text-foreground' },
              { label: 'Scanned', value: stats.done, color: 'text-foreground' },
              { label: 'Vulnerable', value: stats.vuln, color: stats.vuln > 0 ? 'text-red-400' : 'text-muted-foreground' },
              { label: 'Hits', value: stats.hits, color: stats.hits > 0 ? 'text-orange-400' : 'text-muted-foreground' },
              { label: 'Clean', value: stats.done - stats.vuln, color: 'text-green-400' },
            ].map(s => (
              <div key={s.label} className="flex items-center gap-1.5">
                <span className={`text-sm font-black font-mono ${s.color}`}>{s.value}</span>
                <span className="text-[9px] text-muted-foreground/50 uppercase tracking-wider">{s.label}</span>
              </div>
            ))}
            {stats.duration > 0 && (
              <div className="flex items-center gap-1.5">
                <Clock className="w-3 h-3 text-muted-foreground/40" />
                <span className="text-[10px] text-muted-foreground/50 font-mono">{fmtMs(stats.duration)}</span>
              </div>
            )}
            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={() => setFilter(f => f === 'all' ? 'vuln' : 'all')}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded border text-[11px] transition-all ${
                  filter === 'vuln' ? 'border-red-500/30 bg-red-500/10 text-red-400' : 'border-border text-muted-foreground hover:bg-secondary'
                }`}
              >
                <Filter className="w-3 h-3" />
                {filter === 'vuln' ? 'Vuln Only' : 'All Results'}
              </button>
              {entries.length > 0 && (
                <button onClick={() => { setEntries([]); setPhase('idle'); setStats({ total: 0, done: 0, vuln: 0, hits: 0, duration: 0 }); }}
                  className="px-2.5 py-1 rounded border border-border text-muted-foreground hover:bg-secondary text-[11px] transition-colors">
                  Clear
                </button>
              )}
            </div>
          </div>

          {/* Progress bar */}
          {phase === 'scanning' && stats.total > 0 && (
            <div className="shrink-0 px-4 py-1.5 border-b border-border/40">
              <div className="flex items-center justify-between text-[10px] text-muted-foreground mb-1">
                <span>{stats.done} / {stats.total} URLs</span>
                <span>{pct.toFixed(0)}%</span>
              </div>
              <div className="h-1 bg-secondary rounded-full overflow-hidden">
                <motion.div className="h-full bg-primary rounded-full" style={{ width: `${pct}%` }} />
              </div>
            </div>
          )}

          {/* Results list */}
          <div className="flex-1 overflow-y-auto p-3 space-y-1.5">
            {entries.length === 0 && phase === 'idle' && (
              <div className="h-full flex flex-col items-center justify-center text-center gap-4 p-8">
                <div className="w-16 h-16 rounded-full border-2 border-dashed border-border flex items-center justify-center">
                  <Database className="w-7 h-7 text-muted-foreground/30" />
                </div>
                <div>
                  <p className="text-sm font-bold text-muted-foreground">No scan results yet</p>
                  <p className="text-[11px] text-muted-foreground/50 mt-1">Paste URLs with query parameters on the left, then start the scan</p>
                </div>
                <div className="grid grid-cols-3 gap-3 max-w-sm text-[10px] text-muted-foreground/50">
                  <div className="rounded border border-border/40 px-3 py-2 text-center">
                    <BarChart2 className="w-4 h-4 mx-auto mb-1 text-primary/40" />
                    300+ payloads per param
                  </div>
                  <div className="rounded border border-border/40 px-3 py-2 text-center">
                    <Shield className="w-4 h-4 mx-auto mb-1 text-primary/40" />
                    22 WAF bypass techniques
                  </div>
                  <div className="rounded border border-border/40 px-3 py-2 text-center">
                    <Zap className="w-4 h-4 mx-auto mb-1 text-primary/40" />
                    Up to 15 concurrent URLs
                  </div>
                </div>
              </div>
            )}

            <AnimatePresence>
              {visibleEntries.map(entry => (
                <UrlCard key={entry.url} entry={entry} showOnly={filter} />
              ))}
            </AnimatePresence>

            {filter === 'vuln' && visibleEntries.length === 0 && entries.length > 0 && (
              <div className="text-center py-12 text-muted-foreground/50 text-sm">No vulnerable URLs found yet</div>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}

// Constant for display — actual probe count from backend
const SQLI_PROBES_COUNT = '300+';
