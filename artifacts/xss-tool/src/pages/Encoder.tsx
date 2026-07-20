import { useState, useMemo } from 'react';
import { encodePayload, EncodingMode } from '@/lib/encoder';
import { Copy, Check, ArrowRightLeft, Trash2 } from 'lucide-react';

export default function Encoder() {
  const [input, setInput] = useState('<script>alert(1)</script>');
  const [modes, setModes] = useState<EncodingMode[]>([]);
  const [copied, setCopied] = useState(false);

  const output = useMemo(() => {
    if (!input) return '';
    return encodePayload(input, modes);
  }, [input, modes]);

  const toggleMode = (mode: EncodingMode) => {
    setModes(prev => 
      prev.includes(mode) 
        ? prev.filter(m => m !== mode)
        : [...prev, mode]
    );
  };

  const copyOutput = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const clearModes = () => setModes([]);

  const encodingOptions: {value: EncodingMode, label: string, desc: string}[] = [
    { value: 'url-encode', label: 'URL Encode', desc: '%3Cscript%3E...' },
    { value: 'double-url-encode', label: 'Double URL Encode', desc: '%253Cscript%253E...' },
    { value: 'html-entity-dec', label: 'HTML Entity (Dec)', desc: '&#60;script&#62;...' },
    { value: 'html-entity-hex', label: 'HTML Entity (Hex)', desc: '&#x3C;script&#x3E;...' },
    { value: 'unicode-escape', label: 'Unicode Escape', desc: '\\u003cscript\\u003e...' },
    { value: 'hex-escape', label: 'Hex Escape (JS)', desc: '\\x3cscript\\x3e...' },
    { value: 'base64-eval', label: 'Base64 Eval Wrapper', desc: 'eval(atob("..."))' },
    { value: 'char-code', label: 'fromCharCode', desc: 'String.fromCharCode(...)' }
  ];

  return (
    <div className="flex flex-col h-full bg-background p-6 space-y-6 overflow-y-auto animate-in fade-in duration-300">
      <div>
        <h2 className="text-2xl font-bold tracking-tight">Encoder / Obfuscator</h2>
        <p className="text-sm text-muted-foreground mt-1">Chain multiple encoding methods to bypass WAFs and filters.</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 flex-1 max-w-[1400px]">
        
        {/* Left Column - Input & Controls */}
        <div className="flex flex-col gap-6">
          <div className="space-y-3 flex-1 flex flex-col">
            <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex justify-between">
              <span>Raw Payload</span>
              <span className="font-mono text-[10px]">{input.length} chars</span>
            </label>
            <textarea
              value={input}
              onChange={e => setInput(e.target.value)}
              className="w-full flex-1 min-h-[200px] bg-card border border-border rounded-md p-4 font-mono text-sm focus:outline-none focus:ring-1 focus:ring-primary resize-none"
              placeholder="Enter your payload here..."
            />
          </div>

          <div className="bg-card border border-border rounded-md p-4">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-xs font-bold uppercase tracking-wider text-muted-foreground">Encoding Chain</h3>
              <button 
                onClick={clearModes}
                disabled={modes.length === 0}
                className="text-xs font-mono flex items-center gap-1 text-muted-foreground hover:text-destructive disabled:opacity-50 transition-colors"
              >
                <Trash2 className="w-3 h-3" /> CLEAR
              </button>
            </div>
            
            <div className="grid grid-cols-2 gap-3">
              {encodingOptions.map(opt => {
                const isActive = modes.includes(opt.value);
                const orderIndex = modes.indexOf(opt.value);
                
                return (
                  <button
                    key={opt.value}
                    onClick={() => toggleMode(opt.value)}
                    className={`relative p-3 rounded border text-left transition-all ${
                      isActive 
                        ? 'bg-primary/10 border-primary shadow-[0_0_10px_rgba(0,255,65,0.05)]' 
                        : 'bg-background border-border hover:border-primary/50'
                    }`}
                  >
                    {isActive && (
                      <span className="absolute top-2 right-2 w-4 h-4 rounded-full bg-primary text-primary-foreground text-[10px] font-bold flex items-center justify-center shadow-sm">
                        {orderIndex + 1}
                      </span>
                    )}
                    <div className={`font-mono text-sm font-semibold ${isActive ? 'text-primary' : 'text-foreground'}`}>
                      {opt.label}
                    </div>
                    <div className="text-[10px] text-muted-foreground mt-1 truncate font-mono opacity-60">
                      {opt.desc}
                    </div>
                  </button>
                );
              })}
            </div>
          </div>
        </div>

        {/* Right Column - Output */}
        <div className="flex flex-col gap-3 h-full">
          <label className="text-xs font-bold uppercase tracking-wider text-muted-foreground flex justify-between items-center">
            <div className="flex items-center gap-2">
              <span>Encoded Output</span>
              {modes.length > 0 && <span className="bg-primary text-primary-foreground px-1.5 py-0.5 rounded text-[9px] font-bold">{modes.length} LAYERS</span>}
            </div>
            <span className="font-mono text-[10px]">{output.length} chars</span>
          </label>
          
          <div className="relative flex-1 group">
            <textarea
              readOnly
              value={output}
              className="w-full h-full min-h-[300px] bg-secondary border border-border rounded-md p-4 font-mono text-sm text-primary focus:outline-none focus:ring-1 focus:ring-primary resize-none selection:bg-primary/30 shadow-inner"
              placeholder="Output will appear here..."
            />
            {output && (
              <button
                onClick={copyOutput}
                className="absolute top-4 right-4 bg-background border border-border p-2 rounded hover:bg-primary hover:text-primary-foreground hover:border-primary transition-all opacity-0 group-hover:opacity-100 active:scale-95 shadow-md"
              >
                {copied ? <Check className="w-4 h-4" /> : <Copy className="w-4 h-4" />}
              </button>
            )}
          </div>
          
          {modes.length > 0 && (
            <div className="bg-card border border-border rounded-md p-3 text-xs font-mono text-muted-foreground flex items-center gap-2 animate-in fade-in slide-in-from-bottom-2">
              <ArrowRightLeft className="w-4 h-4 text-primary shrink-0" />
              <span className="truncate">
                Chain: <span className="text-foreground">{modes.map(m => encodingOptions.find(o => o.value === m)?.label).join(' → ')}</span>
              </span>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}