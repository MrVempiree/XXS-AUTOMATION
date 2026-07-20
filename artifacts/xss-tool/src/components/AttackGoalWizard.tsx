// ─── Attack Goal Wizard ────────────────────────────────────────────────────────
// Interactive "What do you want to test?" panel shown after a vulnerable param
// is detected. Guides the researcher through goal-based exploitation for
// authorized bug bounty research.

import { useState } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Copy, ArrowLeft, ExternalLink, ChevronRight, Eye, EyeOff, Download } from 'lucide-react';
import { toast } from 'sonner';
import {
  ATTACK_GOALS,
  buildGoalAttack,
  type GoalId,
  type AttackGoalResult,
} from '../lib/attack-goals';
import type { InjectionContext } from '../lib/exploits';

// ── Severity badge ─────────────────────────────────────────────────────────────
function SevBadge({ s }: { s: string }) {
  const cls =
    s === 'critical' ? 'text-red-500 border-red-500/30 bg-red-500/10' :
    s === 'high'     ? 'text-orange-400 border-orange-400/30 bg-orange-400/10' :
                       'text-yellow-400 border-yellow-400/30 bg-yellow-400/10';
  return (
    <span className={`text-[10px] font-black px-1.5 py-0.5 rounded border uppercase ${cls}`}>
      {s}
    </span>
  );
}

// ── Goal selection grid ────────────────────────────────────────────────────────
function GoalGrid({ onSelect }: { onSelect: (id: GoalId) => void }) {
  return (
    <div className="space-y-3">
      <div className="space-y-1">
        <h3 className="text-sm font-black text-foreground tracking-tight">
          🎯 What do you want to assess?
        </h3>
        <p className="text-[11px] text-muted-foreground font-mono leading-relaxed">
          Select a goal — the wizard generates a ready-to-use payload, shows exactly what an attacker
          would extract, and builds your bug bounty report section.
        </p>
      </div>

      <div className="grid grid-cols-2 gap-2">
        {ATTACK_GOALS.map(goal => (
          <button
            key={goal.id}
            onClick={() => onSelect(goal.id)}
            className={`text-left p-3 rounded-lg border transition-all group hover:scale-[1.02] active:scale-[0.99] ${
              goal.severity === 'critical'
                ? 'border-red-500/20 bg-red-500/5 hover:border-red-500/40 hover:bg-red-500/10'
                : 'border-orange-400/20 bg-orange-400/5 hover:border-orange-400/40 hover:bg-orange-400/10'
            }`}
          >
            <div className="flex items-start justify-between gap-1 mb-1.5">
              <span className="text-xl leading-none">{goal.icon}</span>
              <SevBadge s={goal.severity} />
            </div>
            <div className="font-bold text-xs text-foreground">{goal.title}</div>
            <div className="text-[10px] text-muted-foreground mt-0.5 leading-snug">{goal.subtitle}</div>
          </button>
        ))}
      </div>

      <p className="text-[10px] text-muted-foreground/50 font-mono pt-1 border-t border-border/50">
        ⚠ Only run these against targets you own or have written authorization to test.
        All payloads are for authorized bug bounty research only.
      </p>
    </div>
  );
}

// ── Copy button ────────────────────────────────────────────────────────────────
function CopyBtn({ text, label = 'Copied' }: { text: string; label?: string }) {
  const [done, setDone] = useState(false);
  const copy = () => {
    navigator.clipboard.writeText(text);
    toast.success(label);
    setDone(true);
    setTimeout(() => setDone(false), 2000);
  };
  return (
    <button
      onClick={copy}
      className={`flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono transition-all border ${
        done
          ? 'text-green-400 border-green-400/30 bg-green-400/10'
          : 'text-primary border-primary/20 bg-primary/5 hover:bg-primary/15'
      }`}
    >
      <Copy className="w-3 h-3" />
      {done ? 'Copied!' : 'Copy'}
    </button>
  );
}

// ── Goal result view ───────────────────────────────────────────────────────────
function GoalResult({
  result,
  onBack,
}: {
  result: AttackGoalResult;
  onBack: () => void;
}) {
  const [showPayload, setShowPayload] = useState(false);
  const [openSection, setOpenSection] = useState<string>('how');

  const downloadPayload = () => {
    const text = [
      `# ${result.goalTitle} — XSS Exploit Payload`,
      `# Target goal: ${result.goalTitle}`,
      `# Severity: ${result.severity}`,
      `# CWE: ${result.bountyImpact.cwe}`,
      `#`,
      `# REPLACE YOUR_COLLECTOR_URL with your webhook.site / Burp Collaborator URL`,
      `# Only use against targets you have written permission to test`,
      ``,
      result.collectorPayload,
    ].join('\n');
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    a.download = `xss_${result.goalId}_payload.txt`;
    a.click();
    toast.success('Payload file downloaded');
  };

  const sections = [
    { id: 'how',       label: '⚙️ How it works' },
    { id: 'receive',   label: '📥 What you receive' },
    { id: 'collector', label: '🎣 Collector setup' },
    { id: 'report',    label: '📋 Bug bounty report' },
  ];

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center gap-3">
        <button
          onClick={onBack}
          className="p-1.5 rounded-md hover:bg-secondary/60 text-muted-foreground hover:text-foreground transition-colors"
        >
          <ArrowLeft className="w-4 h-4" />
        </button>
        <div className="flex items-center gap-2 flex-1 min-w-0">
          <span className="text-xl">{result.goalIcon}</span>
          <div>
            <div className="font-black text-sm">{result.goalTitle}</div>
            <div className="text-[10px] text-muted-foreground font-mono">{result.bountyImpact.severity}</div>
          </div>
        </div>
        <SevBadge s={result.severity} />
      </div>

      {/* Payload block */}
      <div className="rounded-lg border border-border overflow-hidden">
        <div className="flex items-center justify-between px-3 py-2 bg-secondary/40 border-b border-border">
          <div className="flex items-center gap-2">
            <span className="text-[10px] font-black uppercase tracking-wider text-muted-foreground">
              Exploit Payload
            </span>
            <span className="text-[10px] text-yellow-400/70 font-mono">
              Replace YOUR_COLLECTOR_URL before use
            </span>
          </div>
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setShowPayload(v => !v)}
              className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 transition-all"
            >
              {showPayload ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
              {showPayload ? 'Hide' : 'Reveal'}
            </button>
            <CopyBtn text={result.collectorPayload} label="Payload copied — paste your collector URL first" />
            <button
              onClick={downloadPayload}
              className="flex items-center gap-1 px-2 py-1 rounded text-[10px] font-mono border border-border text-muted-foreground hover:text-foreground hover:border-primary/30 transition-all"
            >
              <Download className="w-3 h-3" /> .txt
            </button>
          </div>
        </div>
        {showPayload ? (
          <code className="block text-[10px] font-mono bg-black/70 text-orange-300/90 px-4 py-3 break-all whitespace-pre-wrap max-h-44 overflow-y-auto leading-relaxed">
            {result.collectorPayload}
          </code>
        ) : (
          <div className="flex items-center justify-center h-12 bg-black/40 text-[11px] text-muted-foreground/30 font-mono">
            Click Reveal to show exploit payload
          </div>
        )}
      </div>

      {/* Warning */}
      <div className="flex items-start gap-2 px-3 py-2.5 rounded-lg bg-orange-500/8 border border-orange-500/25 text-[11px] text-orange-300/90 font-mono leading-relaxed">
        <span className="text-base shrink-0">⚠️</span>
        {result.warningNote}
      </div>

      {/* Tabbed sections */}
      <div className="rounded-lg border border-border overflow-hidden">
        {/* Tab bar */}
        <div className="flex border-b border-border bg-secondary/20 overflow-x-auto">
          {sections.map(s => (
            <button
              key={s.id}
              onClick={() => setOpenSection(s.id)}
              className={`px-3 py-2 text-[11px] font-bold whitespace-nowrap transition-colors shrink-0 ${
                openSection === s.id
                  ? 'text-primary border-b-2 border-primary bg-primary/5'
                  : 'text-muted-foreground hover:text-foreground'
              }`}
            >
              {s.label}
            </button>
          ))}
        </div>

        <AnimatePresence mode="wait">
          <motion.div
            key={openSection}
            initial={{ opacity: 0, y: 4 }}
            animate={{ opacity: 1, y: 0 }}
            exit={{ opacity: 0 }}
            transition={{ duration: 0.15 }}
            className="p-4 bg-background/60"
          >
            {/* How it works */}
            {openSection === 'how' && (
              <div className="space-y-3">
                {result.howItWorks.map((step, i) => (
                  <div key={i} className="flex gap-3">
                    <span className="text-base shrink-0 leading-snug">{step.icon}</span>
                    <div>
                      <div className="text-xs font-bold text-foreground">{step.title}</div>
                      <div className="text-[11px] text-muted-foreground mt-0.5 leading-relaxed font-mono">
                        {step.detail}
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            )}

            {/* What you receive */}
            {openSection === 'receive' && (
              <div className="space-y-3">
                <p className="text-[11px] text-muted-foreground font-mono leading-relaxed">
                  When you trigger this payload in an authorized test, here's what arrives at your collector:
                </p>
                {result.whatYouReceive.map((out, i) => (
                  <div key={i} className="space-y-1.5">
                    <div className="flex items-center justify-between">
                      <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">
                        {out.label}
                      </div>
                      <CopyBtn text={out.content} label="Sample data copied" />
                    </div>
                    <pre className="text-[10px] font-mono bg-black/60 border border-border rounded px-3 py-2.5 text-green-300/80 overflow-x-auto max-h-56 leading-relaxed whitespace-pre">
                      {out.content}
                    </pre>
                  </div>
                ))}
              </div>
            )}

            {/* Collector setup */}
            {openSection === 'collector' && (
              <div className="space-y-3">
                <div className="flex items-center gap-2 flex-wrap">
                  <span className="text-[11px] text-muted-foreground font-mono">Recommended collectors:</span>
                  {[
                    { label: 'webhook.site', url: 'https://webhook.site' },
                    { label: 'Burp Collaborator', url: 'https://portswigger.net/burp/documentation/collaborator' },
                    { label: 'interact.sh', url: 'https://app.interactsh.com' },
                  ].map(c => (
                    <a
                      key={c.label}
                      href={c.url}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="inline-flex items-center gap-1 text-[10px] text-primary hover:text-primary/80 font-mono border border-primary/20 hover:border-primary/40 px-2 py-0.5 rounded transition-colors"
                    >
                      {c.label} <ExternalLink className="w-2.5 h-2.5" />
                    </a>
                  ))}
                </div>
                <ol className="space-y-2">
                  {result.collectorSetup.map((step, i) => (
                    <li key={i} className="flex items-start gap-2 text-[11px] font-mono text-foreground/80 leading-relaxed">
                      <ChevronRight className="w-3 h-3 text-primary shrink-0 mt-0.5" />
                      {step}
                    </li>
                  ))}
                </ol>
              </div>
            )}

            {/* Bug bounty report */}
            {openSection === 'report' && (
              <div className="space-y-3">
                <div className="grid grid-cols-2 gap-2">
                  {[
                    { k: 'Severity', v: result.bountyImpact.severity },
                    { k: 'CWE',      v: result.bountyImpact.cwe },
                    { k: 'CVSS',     v: result.bountyImpact.cvss },
                  ].map(({ k, v }) => (
                    <div key={k} className={`p-2 rounded border border-border bg-secondary/30 ${k === 'CVSS' ? 'col-span-2' : ''}`}>
                      <div className="text-[9px] text-muted-foreground uppercase tracking-widest font-bold mb-0.5">{k}</div>
                      <div className="text-[11px] font-mono text-foreground/90 break-all">{v}</div>
                    </div>
                  ))}
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Report Title</div>
                    <CopyBtn text={result.bountyImpact.title} label="Title copied" />
                  </div>
                  <div className="text-[11px] font-mono bg-black/40 border border-border rounded px-3 py-2 text-foreground/90 leading-relaxed">
                    {result.bountyImpact.title}
                  </div>
                </div>

                <div className="space-y-1.5">
                  <div className="flex items-center justify-between">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-muted-foreground">Impact Summary</div>
                    <CopyBtn text={result.bountyImpact.summary} label="Summary copied" />
                  </div>
                  <div className="text-[11px] font-mono bg-black/40 border border-border rounded px-3 py-2.5 text-foreground/80 leading-relaxed whitespace-pre-wrap">
                    {result.bountyImpact.summary}
                  </div>
                </div>

                <div className="p-3 rounded-lg border border-primary/20 bg-primary/5 text-[11px] font-mono text-muted-foreground leading-relaxed">
                  <span className="font-bold text-primary">Tip:</span> Always include in your report: (1) crafted URL showing the XSS, (2) screenshot of payload executing, (3) collector screenshot showing data received, (4) steps to reproduce. Attach all evidence before submitting.
                </div>
              </div>
            )}
          </motion.div>
        </AnimatePresence>
      </div>
    </div>
  );
}

// ── Main export ────────────────────────────────────────────────────────────────
export default function AttackGoalWizard({
  paramName,
  targetUrl,
  injectionContext,
}: {
  paramName: string;
  targetUrl: string;
  injectionContext: InjectionContext;
}) {
  const [selectedGoal, setSelectedGoal] = useState<GoalId | null>(null);

  const result = selectedGoal
    ? buildGoalAttack(selectedGoal, paramName, targetUrl, injectionContext)
    : null;

  return (
    <AnimatePresence mode="wait">
      {result ? (
        <motion.div
          key="result"
          initial={{ opacity: 0, x: 10 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: -10 }}
          transition={{ duration: 0.2 }}
        >
          <GoalResult result={result} onBack={() => setSelectedGoal(null)} />
        </motion.div>
      ) : (
        <motion.div
          key="grid"
          initial={{ opacity: 0, x: -10 }}
          animate={{ opacity: 1, x: 0 }}
          exit={{ opacity: 0, x: 10 }}
          transition={{ duration: 0.2 }}
        >
          <GoalGrid onSelect={setSelectedGoal} />
        </motion.div>
      )}
    </AnimatePresence>
  );
}
