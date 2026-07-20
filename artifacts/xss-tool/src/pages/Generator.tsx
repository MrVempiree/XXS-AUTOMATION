import { useState } from 'react';
import { generatePayloads, InjectionContext, PayloadGoal } from '@/lib/generator';
import { Copy, Check, Terminal, Play } from 'lucide-react';
import { toast } from 'sonner';

export default function Generator() {
  const [context, setContext] = useState<InjectionContext>('html-tag');
  const [goal, setGoal] = useState<PayloadGoal>('alert');
  const [callbackUrl, setCallbackUrl] = useState('https://attacker.com/col');
  const [customJs, setCustomJs] = useState('alert(document.domain)');
  
  const [results, setResults] = useState<string[]>([]);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const handleGenerate = () => {
    const payloads = generatePayloads({
      context,
      goal,
      callbackUrl,
      customJs
    });
    setResults(payloads);
    toast.success(`Generated ${payloads.length} tailored payloads`);
  };

  const copyToClipboard = (index: number, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const contexts: {value: InjectionContext, label: string}[] = [
    { value: 'html-tag', label: 'HTML Tag Context (<div [here] >)' },
    { value: 'html-attr-quoted', label: 'Quoted Attribute (value="[here]")' },
    { value: 'html-attr-unquoted', label: 'Unquoted Attribute (value=[here])' },
    { value: 'js-string-single', label: 'JS String (Single Quote)' },
    { value: 'js-string-double', label: 'JS String (Double Quote)' },
    { value: 'js-template', label: 'JS Template Literal (`...`)' },
    { value: 'url-param', label: 'URL / HREF Parameter' },
    { value: 'css', label: 'CSS Context (<style>...)' },
    { value: 'json', label: 'JSON / JS Object Context' }
  ];

  const goals: {value: PayloadGoal, label: string}[] = [
    { value: 'alert', label: 'Alert / PoC (Proof of Concept)' },
    { value: 'cookie', label: 'Cookie Theft' },
    { value: 'keylogger', label: 'Keylogger Injection' },
    { value: 'redirect', label: 'Open Redirect' },
    { value: 'dom', label: 'DOM Manipulation / Defacement' },
    { value: 'exfil', label: 'Data Exfiltration (Local Storage)' }
  ];

  return (
    <div className="flex h-full animate-in fade-in duration-300">
      <div className="w-[350px] border-r border-border bg-card/50 flex flex-col h-full overflow-y-auto shrink-0">
        <div className="p-6 border-b border-border">
          <h2 className="text-xl font-bold tracking-tight">Context Generator</h2>
          <p className="text-sm text-muted-foreground mt-1">Build payloads optimized for specific injection points.</p>
        </div>
        
        <div className="p-6 space-y-6 flex-1">
          <div className="space-y-3">
            <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Injection Context</label>
            <div className="grid gap-2">
              {contexts.map(c => (
                <label key={c.value} className={`flex items-center gap-3 p-2.5 rounded-md border cursor-pointer transition-colors ${context === c.value ? 'bg-primary/10 border-primary text-foreground' : 'bg-background border-border text-muted-foreground hover:border-primary/50'}`}>
                  <input 
                    type="radio" 
                    name="context" 
                    value={c.value} 
                    checked={context === c.value} 
                    onChange={() => setContext(c.value as InjectionContext)}
                    className="mt-0.5 accent-primary h-3.5 w-3.5"
                  />
                  <span className="text-sm font-mono leading-none">{c.label}</span>
                </label>
              ))}
            </div>
          </div>

          <div className="space-y-3">
            <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Payload Goal</label>
            <select 
              value={goal} 
              onChange={e => setGoal(e.target.value as PayloadGoal)}
              className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary font-mono"
            >
              {goals.map(g => <option key={g.value} value={g.value}>{g.label}</option>)}
            </select>
          </div>

          {(goal === 'cookie' || goal === 'keylogger' || goal === 'redirect' || goal === 'exfil') && (
            <div className="space-y-3 animate-in fade-in slide-in-from-top-2">
              <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Attacker Server URL</label>
              <input 
                type="text" 
                value={callbackUrl} 
                onChange={e => setCallbackUrl(e.target.value)}
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                placeholder="https://attacker.com/col"
              />
            </div>
          )}

          {goal === 'alert' && (
            <div className="space-y-3 animate-in fade-in slide-in-from-top-2">
              <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Custom JS Execution</label>
              <input 
                type="text" 
                value={customJs} 
                onChange={e => setCustomJs(e.target.value)}
                className="w-full bg-background border border-border rounded-md px-3 py-2 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary"
                placeholder="alert(1)"
              />
            </div>
          )}
        </div>

        <div className="p-6 border-t border-border bg-card">
          <button 
            onClick={handleGenerate}
            className="w-full bg-primary text-primary-foreground hover:bg-primary/90 py-3 rounded-md font-bold uppercase tracking-wider text-sm flex items-center justify-center gap-2 transition-colors active:scale-[0.98]"
          >
            <Terminal className="w-4 h-4" />
            Generate Payloads
          </button>
        </div>
      </div>

      <div className="flex-1 bg-background p-8 overflow-y-auto">
        {results.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-muted-foreground opacity-50">
            <Play className="w-16 h-16 mb-4 stroke-1" />
            <p className="font-mono text-sm uppercase tracking-widest">Awaiting Parameters</p>
          </div>
        ) : (
          <div className="max-w-4xl mx-auto space-y-6">
            <div className="flex items-center justify-between mb-8 pb-4 border-b border-border">
              <h3 className="text-xl font-mono text-primary flex items-center gap-2">
                <Terminal className="w-5 h-5" /> 
                Generated Results
              </h3>
              <span className="text-xs font-mono text-muted-foreground">{results.length} PAYLOADS READY</span>
            </div>

            <div className="grid gap-4">
              {results.map((res, i) => (
                <div key={i} className="group relative border border-border bg-card rounded-md overflow-hidden hover:border-primary/50 transition-colors">
                  <div className="absolute left-0 top-0 bottom-0 w-1 bg-primary opacity-0 group-hover:opacity-100 transition-opacity" />
                  <div className="p-4 flex items-center gap-4">
                    <code className="flex-1 font-mono text-sm text-foreground break-all whitespace-pre-wrap selection:bg-primary/30">
                      {res}
                    </code>
                    <button
                      onClick={() => copyToClipboard(i, res)}
                      className="p-2 rounded-md hover:bg-secondary border border-transparent hover:border-border text-muted-foreground hover:text-foreground transition-all shrink-0 active:scale-95"
                      title="Copy payload"
                    >
                      {copiedIndex === i ? <Check className="w-4 h-4 text-primary" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}