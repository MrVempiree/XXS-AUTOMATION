import { useState } from 'react';
import { generateFuzzVariants, FuzzOption } from '@/lib/fuzzer';
import { Download, Play, Copy, Check, Settings2, Shield } from 'lucide-react';
import { toast } from 'sonner';

export default function Fuzzer() {
  const [baseInput, setBaseInput] = useState('<script>alert("XSS")</script>');
  const [count, setCount] = useState(20);
  const [modes, setModes] = useState<FuzzOption[]>(['case', 'tag-swap', 'attr-swap', 'whitespace']);
  const [results, setResults] = useState<string[]>([]);
  const [copiedIndex, setCopiedIndex] = useState<number | null>(null);

  const fuzzOptions: {value: FuzzOption, label: string, desc: string}[] = [
    { value: 'case', label: 'Case Mutation', desc: 'Randomly upper/lowercase characters' },
    { value: 'tag-swap', label: 'Tag Substitution', desc: 'Swap <script> for <img>, <svg>, etc.' },
    { value: 'attr-swap', label: 'Attribute Swap', desc: 'Swap onerror for onload, etc.' },
    { value: 'whitespace', label: 'Whitespace Injection', desc: 'Insert random tabs/newlines' },
    { value: 'comment', label: 'Comment Obfuscation', desc: 'Insert /* */ randomly' },
    { value: 'null-byte', label: 'Null Byte Injection', desc: 'Insert \\0 characters' },
    { value: 'double-encode', label: 'Double Encoding', desc: 'Randomly double encode parts' }
  ];

  const toggleMode = (mode: FuzzOption) => {
    setModes(prev => 
      prev.includes(mode) 
        ? prev.filter(m => m !== mode)
        : [...prev, mode]
    );
  };

  const handleFuzz = (): void => {
    if (!baseInput) { toast.error('Enter a base payload first'); return; }
    if (modes.length === 0) { toast.error('Select at least one mutation strategy'); return; }
    const variants = generateFuzzVariants({ base: baseInput, modes, count });
    setResults(variants);
    toast.success(`Generated ${variants.length} mutations`);
  };

  const copyResult = (index: number, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedIndex(index);
    setTimeout(() => setCopiedIndex(null), 2000);
  };

  const downloadWordlist = () => {
    if (results.length === 0) return;
    const blob = new Blob([results.join('\n')], { type: 'text/plain' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `xss_fuzz_${Date.now()}.txt`;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex h-full bg-background animate-in fade-in duration-300">
      
      {/* Settings Panel */}
      <div className="w-[350px] border-r border-border bg-card/50 flex flex-col h-full shrink-0 overflow-y-auto">
        <div className="p-6 border-b border-border">
          <h2 className="text-xl font-bold tracking-tight flex items-center gap-2">
            <Settings2 className="w-5 h-5 text-primary" /> Fuzzer Engine
          </h2>
          <p className="text-sm text-muted-foreground mt-1">Generate mutated wordlists for automated scanning.</p>
        </div>

        <div className="p-6 space-y-6 flex-1">
          <div className="space-y-3">
            <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Base Payload</label>
            <textarea
              value={baseInput}
              onChange={e => setBaseInput(e.target.value)}
              className="w-full min-h-[100px] bg-background border border-border rounded-md p-3 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-primary resize-none"
              placeholder="<script>alert(1)</script>"
            />
          </div>

          <div className="space-y-3">
            <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex justify-between">
              <span>Mutations</span>
              <span className="text-primary font-mono">{count}</span>
            </label>
            <input 
              type="range" 
              min="1" 
              max="100" 
              value={count} 
              onChange={e => setCount(parseInt(e.target.value))}
              className="w-full accent-primary h-1 bg-secondary rounded-lg appearance-none cursor-pointer"
            />
          </div>

          <div className="space-y-3">
            <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Mutation Strategies</label>
            <div className="grid gap-2">
              {fuzzOptions.map(opt => (
                <label key={opt.value} className="flex items-start gap-3 p-3 rounded-md border bg-background border-border cursor-pointer hover:border-primary/50 transition-colors">
                  <input 
                    type="checkbox" 
                    checked={modes.includes(opt.value)}
                    onChange={() => toggleMode(opt.value)}
                    className="mt-0.5 accent-primary w-4 h-4 rounded border-border"
                  />
                  <div>
                    <div className="text-sm font-semibold font-mono">{opt.label}</div>
                    <div className="text-[10px] text-muted-foreground mt-0.5 opacity-80">{opt.desc}</div>
                  </div>
                </label>
              ))}
            </div>
          </div>
        </div>

        <div className="p-6 border-t border-border bg-card">
          <button 
            onClick={handleFuzz}
            className="w-full bg-primary text-primary-foreground hover:bg-primary/90 py-3 rounded-md font-bold uppercase tracking-wider text-sm flex items-center justify-center gap-2 transition-colors active:scale-[0.98]"
          >
            <Play className="w-4 h-4 fill-current" />
            Engage Fuzzer
          </button>
        </div>
      </div>

      {/* Results Panel */}
      <div className="flex-1 flex flex-col h-full overflow-hidden">
        <div className="p-6 border-b border-border bg-card/30 flex items-center justify-between">
          <div className="flex flex-col">
            <span className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Generated Wordlist</span>
            {results.length > 0 && <span className="text-[10px] font-mono text-primary mt-1">{results.length} VARIANTS READY</span>}
          </div>
          {results.length > 0 && (
            <button 
              onClick={downloadWordlist}
              className="flex items-center gap-2 px-4 py-2 border border-border hover:border-primary text-xs font-bold uppercase tracking-wider rounded bg-secondary hover:bg-secondary/80 transition-colors"
            >
              <Download className="w-4 h-4" /> Download .txt
            </button>
          )}
        </div>

        <div className="flex-1 overflow-y-auto p-6 bg-background">
          {results.length === 0 ? (
            <div className="h-full flex flex-col items-center justify-center text-muted-foreground opacity-30">
              <Shield className="w-24 h-24 mb-6 stroke-1" />
              <p className="font-mono text-sm uppercase tracking-widest">Awaiting Input</p>
            </div>
          ) : (
            <div className="space-y-1.5 max-w-4xl mx-auto">
              {results.map((res, i) => (
                <div key={i} className="group flex items-center gap-3 bg-secondary/30 hover:bg-secondary border border-transparent hover:border-border rounded p-2 transition-colors">
                  <span className="w-6 text-right text-[10px] font-mono text-muted-foreground opacity-50 select-none">{(i+1).toString().padStart(2, '0')}</span>
                  <code className="flex-1 font-mono text-sm text-primary/80 break-all selection:bg-primary/30">{res}</code>
                  <button
                    onClick={() => copyResult(i, res)}
                    className="p-1.5 rounded hover:bg-background border border-transparent hover:border-border text-muted-foreground hover:text-foreground opacity-0 group-hover:opacity-100 transition-all shrink-0 active:scale-95"
                  >
                    {copiedIndex === i ? <Check className="w-3.5 h-3.5 text-primary" /> : <Copy className="w-3.5 h-3.5" />}
                  </button>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

    </div>
  );
}