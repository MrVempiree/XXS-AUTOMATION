import { useState, useRef, useCallback } from 'react';
import {
  Database, Target, AlertTriangle, CheckCircle, XCircle,
  Copy, Download, ChevronDown, ChevronUp, Ban, Activity,
  Zap, Clock, Shield, ChevronRight, Eye, EyeOff, Search
} from 'lucide-react';
import { toast } from 'sonner';
import { motion, AnimatePresence } from 'framer-motion';

// ── Types ──────────────────────────────────────────────────────────────────────
type DbType = 'MySQL' | 'PostgreSQL' | 'MSSQL' | 'Oracle' | 'SQLite' | 'Unknown';
type ScanPhase = 'idle' | 'scanning' | 'done' | 'error';
type DbTech = 'error' | 'boolean' | 'time' | 'union' | 'stacked';

interface SqliHitEvent {
  param: string;
  technique: string;
  dbType: DbType;
  severity: 'critical' | 'high' | 'medium' | 'low';
  evidence: string;
  payload: string;
  responseTime: number;
  baselineTime: number;
  wafDetected: boolean;
}

interface LiveParam {
  name: string;
  status: 'pending' | 'scanning' | 'done';
  vulnerable: boolean;
  severity: string;
  dbType: DbType;
  techniques: string[];
  hitsCount: number;
  hits: SqliHitEvent[];
  columnCount: number | null;
  totalTested: number;
  wafDetected: boolean;
}

interface DumpPayload {
  target: string;
  dbType: DbType;
  columnCount: number;
  columnPosition: number;
  payload: string;
  description: string;
  urlEncoded: string;
  notes: string;
}

interface WafBypass { name: string; description: string; }
interface DumpTarget { label: string; description: string; }
interface Meta { wafBypasses: WafBypass[]; dumpTargets: Record<string, DumpTarget>; }

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-500 border-red-500/30 bg-red-500/10',
  high:     'text-orange-400 border-orange-400/30 bg-orange-400/10',
  medium:   'text-yellow-400 border-yellow-400/30 bg-yellow-400/10',
  low:      'text-blue-400 border-blue-400/30 bg-blue-400/10',
};

const DB_ICON: Record<string, string> = {
  MySQL: '🐬', PostgreSQL: '🐘', MSSQL: '🪟', Oracle: '🔴', SQLite: '🗄️', Unknown: '❓',
};

const TECH_COLOR: Record<string, string> = {
  'Error-Based':       'text-red-400 bg-red-500/10 border-red-500/20',
  'Boolean-Based Blind':'text-orange-400 bg-orange-500/10 border-orange-500/20',
  'Time-Based Blind':  'text-yellow-400 bg-yellow-500/10 border-yellow-500/20',
  'UNION-Based':       'text-purple-400 bg-purple-500/10 border-purple-500/20',
  'Stacked Queries':   'text-pink-400 bg-pink-500/10 border-pink-500/20',
};

// ── SSE stream ─────────────────────────────────────────────────────────────────
async function runSqliStream(
  url: string,
  signal: AbortSignal,
  onEvent: (e: Record<string, unknown>) => void
): Promise<void> {
  const resp = await fetch('/api/sqli/stream', {
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

// ── Dumper panel ──────────────────────────────────────────────────────────────
function DumperPanel({ param, targetUrl, meta }: { param: LiveParam; targetUrl: string; meta: Meta }) {
  const [wafBypass, setWafBypass]       = useState('None (Raw)');
  const [dumpTarget, setDumpTarget]     = useState('current_user');
  const [colCount, setColCount]         = useState(param.columnCount ?? 2);
  const [customTable, setCustomTable]   = useState('users');
  const [customCol, setCustomCol]       = useState('username,password');
  const [payloads, setPayloads]         = useState<DumpPayload[]>([]);
  const [loading, setLoading]           = useState(false);
  const [showPayloads, setShowPayloads] = useState<Set<number>>(new Set());

  const generate = async () => {
    setLoading(true);
    try {
      const resp = await fetch('/api/sqli/dump', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          paramName: param.name, baseUrl: targetUrl, dbType: param.dbType,
          columnCount: colCount, dumpTarget, wafBypass, customTable, customColumn: customCol,
        }),
      });
      const data = await resp.json();
      setPayloads(data.payloads ?? []);
      toast.success(`Generated ${data.payloads?.length ?? 0} dump payloads`);
    } catch (e) {
      toast.error('Failed to generate payloads');
    } finally { setLoading(false); }
  };

  const copy = (text: string, label = 'Copied') => { navigator.clipboard.writeText(text); toast.success(label); };

  const toggleShow = (i: number) => setShowPayloads(prev => {
    const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n;
  });

  const needsTable = ['list_columns', 'users_table', 'extract_data'].includes(dumpTarget);
  const needsCols  = dumpTarget === 'extract_data';

  return (
    <div className="space-y-4">
      {/* Config */}
      <div className="grid grid-cols-2 gap-3">
        {/* Dump Target */}
        <div className="col-span-2 space-y-1">
          <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">What to dump</label>
          <div className="grid grid-cols-2 gap-1.5">
            {Object.entries(meta.dumpTargets).map(([k, v]) => (
              <button
                key={k}
                onClick={() => setDumpTarget(k)}
                className={`text-left p-2.5 rounded-lg border text-[11px] transition-all ${
                  dumpTarget === k
                    ? 'border-primary bg-primary/10 text-primary'
                    : 'border-border text-muted-foreground hover:border-primary/40 hover:text-foreground'
                }`}
              >
                <div className="font-bold">{v.label}</div>
                <div className="text-[10px] opacity-70 mt-0.5 leading-snug">{v.description}</div>
              </button>
            ))}
          </div>
        </div>

        {/* Column count */}
        <div className="space-y-1">
          <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Column count</label>
          <div className="flex items-center gap-2">
            <input
              type="number" min={1} max={20} value={colCount}
              onChange={e => setColCount(Math.max(1, parseInt(e.target.value) || 1))}
              className="w-20 bg-background border border-border rounded px-2 py-1.5 text-sm font-mono text-center focus:outline-none focus:ring-1 focus:ring-primary"
            />
            {param.columnCount && (
              <span className="text-[10px] text-primary font-mono">detected: {param.columnCount}</span>
            )}
          </div>
          <p className="text-[10px] text-muted-foreground">Number of columns in the original SELECT</p>
        </div>

        {/* WAF Bypass */}
        <div className="space-y-1">
          <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">WAF Bypass</label>
          <select
            value={wafBypass}
            onChange={e => setWafBypass(e.target.value)}
            className="w-full bg-background border border-border rounded px-2 py-1.5 text-[11px] font-mono focus:outline-none focus:ring-1 focus:ring-primary"
          >
            {meta.wafBypasses.map(b => (
              <option key={b.name} value={b.name}>{b.name}</option>
            ))}
          </select>
        </div>

        {/* Custom table */}
        {needsTable && (
          <div className="space-y-1">
            <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Target table</label>
            <input
              type="text" value={customTable} onChange={e => setCustomTable(e.target.value)}
              placeholder="users"
              className="w-full bg-background border border-border rounded px-2 py-1.5 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
        )}

        {/* Custom columns */}
        {needsCols && (
          <div className="space-y-1">
            <label className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Columns to extract</label>
            <input
              type="text" value={customCol} onChange={e => setCustomCol(e.target.value)}
              placeholder="username,password,email"
              className="w-full bg-background border border-border rounded px-2 py-1.5 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary"
            />
            <p className="text-[10px] text-muted-foreground">Comma-separated column names</p>
          </div>
        )}
      </div>

      {/* WAF detected warning */}
      {param.wafDetected && (
        <div className="flex items-start gap-2 px-3 py-2 rounded-lg bg-yellow-500/8 border border-yellow-500/20 text-[11px] text-yellow-400 font-mono">
          <Shield className="w-3.5 h-3.5 shrink-0 mt-0.5" />
          WAF detected on this parameter — use a bypass technique above to evade filtering
        </div>
      )}

      <button
        onClick={generate}
        disabled={loading}
        className="w-full py-2.5 bg-primary text-primary-foreground hover:bg-primary/90 rounded-lg text-sm font-bold flex items-center justify-center gap-2 disabled:opacity-50 transition-colors"
      >
        <Database className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
        {loading ? 'Generating…' : 'Generate Dump Payloads'}
      </button>

      {/* Payload results */}
      {payloads.length > 0 && (
        <div className="space-y-3">
          <div className="text-[10px] font-bold uppercase tracking-widest text-muted-foreground">
            {payloads.length} payload{payloads.length !== 1 ? 's' : ''} generated
          </div>
          {payloads.map((p, i) => (
            <div key={i} className="border border-border rounded-lg overflow-hidden">
              <div className="flex items-start justify-between gap-2 px-3 py-2.5 bg-secondary/30">
                <div className="flex-1 min-w-0">
                  <div className="text-xs font-bold text-foreground">{p.description}</div>
                  <div className="text-[10px] text-muted-foreground font-mono mt-0.5">{p.notes}</div>
                </div>
                <div className="flex items-center gap-1.5 shrink-0">
                  <button onClick={() => toggleShow(i)}
                    className="flex items-center gap-1 px-1.5 py-1 rounded text-[10px] border border-border text-muted-foreground hover:text-foreground transition-colors font-mono">
                    {showPayloads.has(i) ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    {showPayloads.has(i) ? 'Hide' : 'Show'}
                  </button>
                  <button onClick={() => copy(p.payload, 'Payload copied')}
                    className="flex items-center gap-1 px-1.5 py-1 rounded text-[10px] border border-primary/20 bg-primary/5 text-primary hover:bg-primary/15 transition-colors font-mono">
                    <Copy className="w-3 h-3" /> Copy
                  </button>
                  <button onClick={() => copy(p.urlEncoded, 'Full URL copied')}
                    className="flex items-center gap-1 px-1.5 py-1 rounded text-[10px] border border-border text-muted-foreground hover:text-foreground transition-colors font-mono">
                    🔗 URL
                  </button>
                </div>
              </div>
              {showPayloads.has(i) && (
                <div className="border-t border-border">
                  <div className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground px-3 pt-2 pb-1">Payload</div>
                  <code className="block text-[10px] font-mono bg-black/60 text-yellow-300/90 px-3 py-2 break-all whitespace-pre-wrap">
                    {p.payload}
                  </code>
                  <div className="text-[9px] font-bold uppercase tracking-wider text-muted-foreground px-3 pt-2 pb-1">Full URL</div>
                  <code className="block text-[10px] font-mono bg-black/40 text-blue-300/70 px-3 py-2 break-all whitespace-pre-wrap border-t border-border/50">
                    {p.urlEncoded}
                  </code>
                </div>
              )}
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ── Main component ─────────────────────────────────────────────────────────────
export default function SQLi() {
  const [targetUrl, setTargetUrl]       = useState('');
  const [phase, setPhase]               = useState<ScanPhase>('idle');
  const [errorMsg, setErrorMsg]         = useState('');
  const [params, setParams]             = useState<LiveParam[]>([]);
  const [liveHits, setLiveHits]         = useState<SqliHitEvent[]>([]);
  const [currentParam, setCurrentParam] = useState('');
  const [summary, setSummary]           = useState<{ totalParams: number; vulnerableParams: number; totalHits: number } | null>(null);
  const [duration, setDuration]         = useState(0);
  const [expanded, setExpanded]         = useState<Set<string>>(new Set());
  const [activeTab, setActiveTab]       = useState<Record<string, 'hits' | 'dump'>>({});
  const [meta, setMeta]                 = useState<Meta | null>(null);
  const abortRef                        = useRef<AbortController | null>(null);
  const hitsEndRef                      = useRef<HTMLDivElement>(null);

  // Load meta once
  const loadMeta = async () => {
    if (meta) return;
    const r = await fetch('/api/sqli/meta').then(r => r.json()).catch(() => null);
    if (r) setMeta(r);
  };

  const detectedParams = (() => {
    try {
      if (!targetUrl.startsWith('http')) return [];
      return [...new URL(targetUrl).searchParams.entries()];
    } catch { return []; }
  })();

  const handleEvent = useCallback((e: Record<string, unknown>) => {
    const type = e.type as string;

    if (type === 'param_start') {
      const name = e.param as string;
      setCurrentParam(name);
      setParams(prev => {
        if (prev.find(p => p.name === name)) return prev;
        return [...prev, {
          name, status: 'scanning', vulnerable: false, severity: 'none',
          dbType: 'Unknown', techniques: [], hitsCount: 0, hits: [],
          columnCount: null, totalTested: 0, wafDetected: false,
        }];
      });
    }

    if (type === 'sqli_hit') {
      const hit = e as unknown as SqliHitEvent;
      setLiveHits(prev => [...prev.slice(-6), hit]);
      setParams(prev => prev.map(p => p.name === hit.param
        ? { ...p, hitsCount: p.hitsCount + 1, hits: [...p.hits, hit] } : p));
      setTimeout(() => hitsEndRef.current?.scrollIntoView({ behavior: 'smooth' }), 50);
    }

    if (type === 'param_done') {
      const name = e.param as string;
      setParams(prev => prev.map(p => p.name === name ? {
        ...p, status: 'done',
        vulnerable: e.vulnerable as boolean,
        severity: e.severity as string,
        dbType: e.dbType as DbType,
        techniques: e.techniques as string[],
        hitsCount: e.hitsCount as number,
        columnCount: e.columnCount as number | null,
        totalTested: e.totalTested as number,
        wafDetected: e.wafDetected as boolean,
        hits: (e.hits as SqliHitEvent[]) ?? p.hits,
      } : p));
      if (e.vulnerable) {
        setExpanded(prev => new Set([...prev, name as string]));
        setActiveTab(prev => ({ ...prev, [name]: 'dump' }));
      }
    }

    if (type === 'scan_done') {
      setSummary(e.summary as typeof summary);
      setDuration(e.duration as number);
      setPhase('done');
      setCurrentParam('');
    }
  }, []);

  const startScan = async () => {
    if (!targetUrl || detectedParams.length === 0) {
      toast.error('Enter a URL with query parameters (e.g. ?id=1&page=2)');
      return;
    }
    await loadMeta();
    setPhase('scanning'); setParams([]); setLiveHits([]); setSummary(null);
    setExpanded(new Set()); setErrorMsg(''); setActiveTab({});
    const ctrl = new AbortController();
    abortRef.current = ctrl;
    try {
      await runSqliStream(targetUrl, ctrl.signal, handleEvent);
    } catch (err: unknown) {
      if ((err as Error).name === 'AbortError') { setPhase('idle'); toast.info('Scan aborted'); }
      else { setPhase('error'); setErrorMsg((err as Error).message); toast.error(`Scan failed: ${(err as Error).message}`); }
    }
  };

  const copy = (text: string, label = 'Copied') => { navigator.clipboard.writeText(text); toast.success(label); };

  const doneCount  = params.filter(p => p.status === 'done').length;
  const totalCount = detectedParams.length || params.length;
  const progress   = totalCount ? Math.round((doneCount / totalCount) * 100) : 0;
  const vulnCount  = params.filter(p => p.vulnerable).length;
  const wafCount   = params.filter(p => p.wafDetected).length;

  return (
    <div className="flex flex-col h-full">

      {/* ── Header ─────────────────────────────────────────────────────── */}
      <div className="shrink-0 p-4 border-b border-border bg-card/40 space-y-3">
        <div className="flex items-center gap-2">
          <Database className="w-5 h-5 text-primary" />
          <h2 className="font-bold text-base tracking-tight">SQL Injection Scanner</h2>
          <span className="text-[10px] font-mono text-muted-foreground/60 uppercase tracking-widest ml-1">
            {75} probes/param · Error + Boolean + Time + UNION · WAF Bypass
          </span>
        </div>

        <div className="flex gap-2">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground pointer-events-none" />
            <input
              type="url" value={targetUrl}
              onChange={e => setTargetUrl(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && phase === 'idle' && startScan()}
              placeholder="https://target.com/page?id=1&cat=news&user=admin"
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
              className="px-5 py-2 bg-primary text-primary-foreground hover:bg-primary/90 rounded-md text-sm font-bold flex items-center gap-2 transition-colors disabled:opacity-40">
              <Zap className="w-4 h-4" /> SCAN
            </button>
          )}
        </div>

        {detectedParams.length > 0 && (
          <div className="flex flex-wrap gap-1.5 items-center">
            {detectedParams.map(([k, v]) => (
              <span key={k} className="inline-flex items-center gap-1 px-2 py-0.5 bg-secondary/50 border border-border rounded text-[11px] font-mono">
                <span className="text-primary">{k}</span>
                <span className="text-muted-foreground/40">=</span>
                <span className="text-muted-foreground truncate max-w-[60px]">{v}</span>
              </span>
            ))}
            <span className="text-[11px] text-muted-foreground font-mono">{detectedParams.length} param{detectedParams.length !== 1 ? 's' : ''} detected</span>
          </div>
        )}

        <div className="flex items-center gap-2 text-xs text-orange-400/80 bg-orange-500/8 border border-orange-500/20 px-3 py-1.5 rounded">
          <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
          Authorized bug bounty / pen-test use only. Scanning sites without written permission is illegal.
        </div>
      </div>

      {/* ── Results area ────────────────────────────────────────────────── */}
      <div className="flex-1 overflow-y-auto p-4 space-y-4">

        {/* Live scan progress */}
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
                    {currentParam ? <>Testing <span className="font-bold">{currentParam}</span> ({doneCount + 1}/{totalCount})</> : 'Initializing…'}
                  </span>
                  <span className="text-muted-foreground">{progress}%</span>
                </div>
                <div className="bg-background/60 border border-border/50 rounded h-28 overflow-y-auto p-2 space-y-1">
                  <AnimatePresence initial={false}>
                    {liveHits.map((h, i) => (
                      <motion.div key={i} initial={{ opacity: 0, x: -6 }} animate={{ opacity: 1, x: 0 }}
                        className="flex items-start gap-2 px-2 py-1 rounded text-[10px] font-mono bg-red-500/10 border border-red-500/15">
                        <span className={`shrink-0 uppercase font-bold px-1 py-0.5 rounded border text-[9px] ${SEV_COLOR[h.severity]}`}>{h.severity}</span>
                        <span className="text-purple-400 shrink-0">{h.technique}</span>
                        <span className="text-muted-foreground shrink-0">{h.param}:</span>
                        <span className="text-foreground/80 truncate flex-1">{h.payload.slice(0, 50)}…</span>
                        <span className="shrink-0 text-muted-foreground/50">{DB_ICON[h.dbType]}{h.dbType}</span>
                      </motion.div>
                    ))}
                  </AnimatePresence>
                  <div ref={hitsEndRef} />
                  {liveHits.length === 0 && <span className="text-muted-foreground/30 text-[10px]">Firing probes… waiting for SQLi indicators</span>}
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
                    {vulnCount > 0 ? `SQL INJECTABLE — ${vulnCount} PARAM${vulnCount !== 1 ? 'S' : ''} VULNERABLE` : 'NO SQLi DETECTED'}
                  </div>
                  <div className="text-xs text-muted-foreground font-mono">
                    {summary.totalParams} params · {summary.totalHits} hits · {(duration / 1000).toFixed(2)}s
                    {wafCount > 0 && <span className="text-yellow-400 ml-2">· WAF detected on {wafCount} param{wafCount !== 1 ? 's' : ''}</span>}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-1 text-xs text-muted-foreground font-mono">
                <Clock className="w-3.5 h-3.5" />{(duration / 1000).toFixed(2)}s
              </div>
            </motion.div>
          )}
        </AnimatePresence>

        {/* Technique reference */}
        {phase === 'idle' && params.length === 0 && (
          <div className="space-y-4">
            <div className="flex flex-col items-center justify-center py-10 text-center">
              <Database className="w-10 h-10 text-primary/20 mb-4" />
              <p className="text-muted-foreground font-mono text-sm">Paste a target URL with query parameters</p>
              <p className="text-muted-foreground/40 font-mono text-xs mt-1">e.g. https://example.com/item?id=5&category=2</p>
            </div>

            {/* Detection technique cards */}
            <div className="grid grid-cols-2 gap-3">
              {[
                { name: 'Error-Based', icon: '💥', color: 'border-red-500/20 bg-red-500/5', desc: 'Triggers SQL syntax errors — database reveals version, table names, structure directly in the response. Fastest technique.' },
                { name: 'Boolean Blind', icon: '🎭', color: 'border-orange-500/20 bg-orange-500/5', desc: 'Sends true/false conditions, compares response length changes to infer data one bit at a time without visible errors.' },
                { name: 'Time-Based Blind', icon: '⏱️', color: 'border-yellow-500/20 bg-yellow-500/5', desc: 'Uses SLEEP()/WAITFOR DELAY to cause deliberate response delays — confirms injection even when response content is identical.' },
                { name: 'UNION-Based', icon: '🔗', color: 'border-purple-500/20 bg-purple-500/5', desc: 'Appends a UNION SELECT to retrieve data from other tables directly in the HTTP response — most powerful for data extraction.' },
                { name: 'Stacked Queries', icon: '📚', color: 'border-pink-500/20 bg-pink-500/5', desc: 'Uses semicolons to execute multiple SQL statements — enables UPDATE, INSERT, DROP operations if the DB driver permits.' },
                { name: 'WAF Bypass', icon: '🛡️', color: 'border-blue-500/20 bg-blue-500/5', desc: '11 bypass techniques: URL encoding, case variation, comment padding, inline comments, hex values, newline injection, null bytes.' },
              ].map(t => (
                <div key={t.name} className={`p-3 rounded-lg border ${t.color} space-y-1`}>
                  <div className="flex items-center gap-2">
                    <span className="text-lg">{t.icon}</span>
                    <span className="text-xs font-bold">{t.name}</span>
                  </div>
                  <p className="text-[10px] text-muted-foreground leading-snug">{t.desc}</p>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Parameter cards */}
        {params.length > 0 && (
          <div className="space-y-3">
            {params.map((p, i) => {
              const isOpen = expanded.has(p.name);
              const tab    = activeTab[p.name] ?? 'hits';
              const setTab = (t: 'hits' | 'dump') => setActiveTab(prev => ({ ...prev, [p.name]: t }));

              return (
                <motion.div key={p.name} initial={{ opacity: 0, y: 6 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: i * 0.04 }}
                  className={`border rounded-lg overflow-hidden ${
                    p.status === 'scanning' ? 'border-primary/40' :
                    p.vulnerable ? 'border-red-500/30' : 'border-border'}`}>

                  {/* Header */}
                  <button
                    className={`w-full flex items-center justify-between px-4 py-3 text-left transition-colors ${
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
                            <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${p.vulnerable ? SEV_COLOR[p.severity] ?? SEV_COLOR.low : 'text-primary border-primary/20 bg-primary/10'}`}>
                              {p.vulnerable ? p.severity : 'safe'}
                            </span>
                          )}
                          {p.vulnerable && (
                            <span className="text-[10px] font-bold text-red-400 bg-red-500/10 px-1.5 py-0.5 rounded border border-red-500/20">
                              {DB_ICON[p.dbType]} {p.dbType}
                            </span>
                          )}
                          {p.wafDetected && (
                            <span className="text-[10px] font-bold text-yellow-400 bg-yellow-500/10 px-1.5 py-0.5 rounded border border-yellow-500/20">
                              🛡️ WAF
                            </span>
                          )}
                        </div>
                        <div className="text-[11px] text-muted-foreground font-mono mt-0.5">
                          {p.status === 'scanning' && 'Probing…'}
                          {p.status === 'done' && p.vulnerable && p.techniques.join(' + ')}
                          {p.status === 'done' && !p.vulnerable && `${p.totalTested} probes — not injectable`}
                        </div>
                      </div>
                    </div>
                    {p.status === 'done' && (
                      <div className="flex items-center gap-2 shrink-0">
                        {p.vulnerable && p.techniques.map(t => (
                          <span key={t} className={`text-[9px] font-bold px-1.5 py-0.5 rounded border uppercase ${TECH_COLOR[t] ?? ''}`}>{t.replace(' Blind', '')}</span>
                        ))}
                        {isOpen ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                      </div>
                    )}
                  </button>

                  {/* Expanded body */}
                  <AnimatePresence>
                    {isOpen && p.vulnerable && (
                      <motion.div initial={{ height: 0, opacity: 0 }} animate={{ height: 'auto', opacity: 1 }} exit={{ height: 0, opacity: 0 }}
                        className="overflow-hidden border-t border-border/50">
                        {/* Tab bar */}
                        <div className="flex border-b border-border bg-secondary/20">
                          {([
                            { id: 'dump', label: `🗄️ Database Dumper` },
                            { id: 'hits', label: `🎯 Detection Hits (${p.hits.length})` },
                          ] as const).map(t => (
                            <button key={t.id} onClick={() => setTab(t.id)}
                              className={`px-4 py-2 text-xs font-bold transition-colors ${tab === t.id ? 'text-primary border-b-2 border-primary bg-primary/5' : 'text-muted-foreground hover:text-foreground'}`}>
                              {t.label}
                            </button>
                          ))}
                        </div>

                        <div className="p-4 bg-background/50">
                          {/* Database Dumper */}
                          {tab === 'dump' && meta && (
                            <DumperPanel param={p} targetUrl={targetUrl} meta={meta} />
                          )}
                          {tab === 'dump' && !meta && (
                            <div className="text-center py-8 text-muted-foreground font-mono text-sm">Loading dumper…</div>
                          )}

                          {/* Detection Hits */}
                          {tab === 'hits' && (
                            <div className="space-y-3">
                              {/* DB info */}
                              <div className="grid grid-cols-3 gap-2">
                                {[
                                  { k: 'Database', v: `${DB_ICON[p.dbType]} ${p.dbType}` },
                                  { k: 'Techniques', v: p.techniques.join(', ') || '—' },
                                  { k: 'Column Count', v: p.columnCount ? `${p.columnCount} columns` : 'Not determined' },
                                ].map(({ k, v }) => (
                                  <div key={k} className="p-2 rounded border border-border bg-secondary/30">
                                    <div className="text-[9px] uppercase tracking-widest text-muted-foreground mb-0.5">{k}</div>
                                    <div className="text-xs font-mono text-foreground/90">{v}</div>
                                  </div>
                                ))}
                              </div>

                              {/* Hit list */}
                              {p.hits.map((h, idx) => (
                                <div key={idx} className="border border-border rounded-lg overflow-hidden">
                                  <div className="flex items-center gap-2 px-3 py-2 bg-secondary/20 flex-wrap">
                                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border uppercase ${SEV_COLOR[h.severity]}`}>{h.severity}</span>
                                    <span className={`text-[10px] font-bold px-1.5 py-0.5 rounded border ${TECH_COLOR[h.technique] ?? ''}`}>{h.technique}</span>
                                    <span className="text-[10px] text-muted-foreground font-mono">{DB_ICON[h.dbType]} {h.dbType}</span>
                                    {h.wafDetected && <span className="text-[10px] text-yellow-400 border border-yellow-500/20 bg-yellow-500/10 px-1.5 py-0.5 rounded">🛡️ WAF</span>}
                                    <span className="ml-auto text-[10px] text-muted-foreground font-mono flex items-center gap-1">
                                      <Clock className="w-3 h-3" />{h.responseTime}ms
                                    </span>
                                  </div>
                                  <div className="p-3 space-y-2">
                                    <div>
                                      <div className="text-[9px] uppercase tracking-wider text-muted-foreground mb-1 font-bold">Payload Used</div>
                                      <code className="block text-[11px] font-mono text-red-400 bg-black/40 rounded px-2 py-1.5 break-all">{h.payload}</code>
                                    </div>
                                    <div>
                                      <div className="flex items-center justify-between mb-1">
                                        <div className="text-[9px] uppercase tracking-wider text-muted-foreground font-bold">Evidence</div>
                                        <button onClick={() => copy(h.evidence, 'Evidence copied')}
                                          className="flex items-center gap-1 text-[9px] text-primary font-mono hover:text-primary/80 transition-colors">
                                          <Copy className="w-2.5 h-2.5" /> Copy
                                        </button>
                                      </div>
                                      <code className="block text-[10px] font-mono text-muted-foreground bg-secondary/40 rounded px-2 py-1.5 break-all whitespace-pre-wrap border border-border/40">
                                        {h.evidence.slice(0, 400)}
                                      </code>
                                    </div>
                                  </div>
                                </div>
                              ))}

                              {/* How to report */}
                              <div className="p-3 rounded-lg border border-primary/20 bg-primary/5 space-y-2">
                                <div className="text-[10px] font-bold uppercase tracking-wider text-primary">Bug Bounty Report Notes</div>
                                <ul className="space-y-1">
                                  {[
                                    `Parameter: ${p.name} — ${p.techniques.join(' + ')} SQLi`,
                                    `Database: ${p.dbType} (${DB_ICON[p.dbType]})`,
                                    `CWE: CWE-89 — Improper Neutralization of Special Elements in SQL Command`,
                                    `CVSS: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H — 10.0 (Critical)`,
                                    `Impact: Authentication bypass, full database exfiltration, potential RCE via INTO OUTFILE`,
                                    `Remediation: Parameterized queries / prepared statements + input validation`,
                                  ].map((s, i) => (
                                    <li key={i} className="flex items-start gap-1.5 text-[11px] font-mono text-foreground/80">
                                      <ChevronRight className="w-3 h-3 text-primary shrink-0 mt-0.5" />{s}
                                    </li>
                                  ))}
                                </ul>
                              </div>
                            </div>
                          )}
                        </div>
                      </motion.div>
                    )}
                  </AnimatePresence>
                </motion.div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
