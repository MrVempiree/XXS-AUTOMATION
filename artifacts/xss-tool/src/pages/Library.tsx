import { useState, useMemo } from 'react';
import { PAYLOADS, Category } from '@/lib/payloads';
import { Search, Copy, Check, Filter } from 'lucide-react';
import { toast } from 'sonner';

export default function Library() {
  const [search, setSearch] = useState('');
  const [selectedCategory, setSelectedCategory] = useState<Category | 'All'>('All');
  const [copiedId, setCopiedId] = useState<string | null>(null);

  const categories = ['All', ...Array.from(new Set(PAYLOADS.map(p => p.category)))];

  const filteredPayloads = useMemo(() => {
    return PAYLOADS.filter(p => {
      const matchSearch = p.content.toLowerCase().includes(search.toLowerCase()) || 
                          p.description.toLowerCase().includes(search.toLowerCase());
      const matchCategory = selectedCategory === 'All' || p.category === selectedCategory;
      return matchSearch && matchCategory;
    });
  }, [search, selectedCategory]);

  const copyToClipboard = (id: string, text: string) => {
    navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success('Payload copied to clipboard');
    setTimeout(() => setCopiedId(null), 2000);
  };

  const getSeverityColor = (sev: string) => {
    switch(sev) {
      case 'critical': return 'text-red-500 border-red-500/20 bg-red-500/10';
      case 'high': return 'text-orange-500 border-orange-500/20 bg-orange-500/10';
      case 'medium': return 'text-yellow-500 border-yellow-500/20 bg-yellow-500/10';
      case 'low': return 'text-blue-500 border-blue-500/20 bg-blue-500/10';
      default: return 'text-muted-foreground';
    }
  };

  return (
    <div className="flex flex-col h-full animate-in fade-in duration-300">
      <div className="p-6 border-b border-border bg-card/50 flex flex-col gap-4">
        <div>
          <h2 className="text-2xl font-bold tracking-tight">Payload Library</h2>
          <p className="text-sm text-muted-foreground mt-1">Browse, search, and copy battle-tested XSS payloads.</p>
        </div>
        
        <div className="flex items-center gap-4">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
            <input 
              type="text" 
              placeholder="Search payloads or descriptions..." 
              value={search}
              onChange={e => setSearch(e.target.value)}
              className="w-full bg-background border border-border rounded-md pl-10 pr-4 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary font-mono placeholder:font-sans"
            />
          </div>
          <div className="flex items-center gap-2 overflow-x-auto pb-1 no-scrollbar max-w-[60%]">
            <Filter className="w-4 h-4 text-muted-foreground shrink-0" />
            {categories.map(cat => (
              <button
                key={cat}
                onClick={() => setSelectedCategory(cat as any)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium whitespace-nowrap transition-colors border ${
                  selectedCategory === cat 
                    ? 'bg-primary text-primary-foreground border-primary' 
                    : 'bg-secondary text-secondary-foreground border-transparent hover:border-border'
                }`}
              >
                {cat}
                {cat !== 'All' && (
                  <span className="ml-2 opacity-60 font-mono text-[10px]">
                    {PAYLOADS.filter(p => p.category === cat).length}
                  </span>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      <div className="flex-1 overflow-y-auto p-6 bg-background">
        <div className="grid gap-4 max-w-5xl">
          {filteredPayloads.map(payload => (
            <div key={payload.id} className="group border border-border rounded-lg bg-card overflow-hidden hover:border-primary/50 transition-colors">
              <div className="flex items-center justify-between px-4 py-2 border-b border-border/50 bg-secondary/50">
                <div className="flex items-center gap-3">
                  <span className="text-xs font-bold text-muted-foreground uppercase tracking-wider">{payload.category}</span>
                  <span className={`text-[10px] px-2 py-0.5 rounded uppercase font-bold border ${getSeverityColor(payload.severity)}`}>
                    {payload.severity}
                  </span>
                </div>
                <span className="text-xs text-muted-foreground">{payload.description}</span>
              </div>
              <div className="p-4 flex items-start gap-4">
                <code className="flex-1 font-mono text-sm text-primary/90 break-all whitespace-pre-wrap selection:bg-primary/30">
                  {payload.content}
                </code>
                <button
                  onClick={() => copyToClipboard(payload.id, payload.content)}
                  className="p-2 rounded-md border border-transparent hover:border-border hover:bg-secondary text-muted-foreground hover:text-foreground transition-all shrink-0 active:scale-95"
                  title="Copy payload"
                >
                  {copiedId === payload.id ? <Check className="w-4 h-4 text-primary" /> : <Copy className="w-4 h-4" />}
                </button>
              </div>
            </div>
          ))}
          {filteredPayloads.length === 0 && (
            <div className="text-center p-12 text-muted-foreground border border-dashed border-border rounded-lg max-w-5xl">
              <Search className="w-8 h-8 mx-auto mb-4 opacity-20" />
              <p className="font-mono text-sm">No payloads match your search criteria.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}