import { useState, useEffect } from 'react';
import { TerminalSquare, Key, ShieldCheck, ShieldX, Loader } from 'lucide-react';
import { toast } from 'sonner';

const LS_KEY = 'xssforge_license';

export type LicenseInfo = {
  key: string;
  plan: string;
  owner: string;
  expiresAt: string | null;
};

async function verifyKey(key: string): Promise<{ valid: boolean; license?: LicenseInfo; reason?: string }> {
  const res = await fetch('/api/license/verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ key }),
  });
  return res.json();
}

export function useLicense() {
  const saved = localStorage.getItem(LS_KEY);
  return saved ? (JSON.parse(saved) as LicenseInfo) : null;
}

export function clearLicense() {
  localStorage.removeItem(LS_KEY);
  window.location.reload();
}

interface Props { children: React.ReactNode }

export default function LicenseGate({ children }: Props) {
  const [phase, setPhase]     = useState<'checking' | 'unlocked' | 'locked'>('checking');
  const [keyInput, setKey]    = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError]     = useState('');

  useEffect(() => {
    const saved = localStorage.getItem(LS_KEY);
    if (!saved) { setPhase('locked'); return; }
    const info = JSON.parse(saved) as LicenseInfo;
    verifyKey(info.key).then(r => {
      if (r.valid) setPhase('unlocked');
      else { localStorage.removeItem(LS_KEY); setPhase('locked'); }
    }).catch(() => {
      // Network error — allow offline use if key was previously valid
      setPhase('unlocked');
    });
  }, []);

  const handleActivate = async () => {
    const trimmed = keyInput.trim().toUpperCase();
    if (!trimmed) { setError('Enter a license key'); return; }
    setLoading(true); setError('');
    try {
      const r = await verifyKey(trimmed);
      if (r.valid && r.license) {
        localStorage.setItem(LS_KEY, JSON.stringify(r.license));
        toast.success(`Activated — ${r.license.plan.toUpperCase()} license for ${r.license.owner}`);
        setPhase('unlocked');
      } else {
        setError(r.reason ?? 'Invalid license key');
      }
    } catch {
      setError('Cannot reach server');
    } finally {
      setLoading(false);
    }
  };

  if (phase === 'checking') {
    return (
      <div className="h-screen w-full bg-background flex items-center justify-center dark">
        <Loader className="w-6 h-6 text-primary animate-spin" />
      </div>
    );
  }

  if (phase === 'unlocked') return <>{children}</>;

  return (
    <div className="h-screen w-full bg-background dark flex items-center justify-center p-6">
      <div className="w-full max-w-md space-y-8">
        {/* Logo */}
        <div className="text-center space-y-2">
          <div className="flex items-center justify-center gap-3 text-primary">
            <TerminalSquare className="w-10 h-10" />
          </div>
          <h1 className="font-brand text-2xl font-black text-primary tracking-wider">ALCAME</h1>
          <div className="font-brand text-[11px] font-bold text-muted-foreground tracking-[0.25em]">AUTOMATION</div>
          <p className="text-[10px] text-muted-foreground font-mono uppercase tracking-widest mt-1">
            Security Research Toolkit · License Required
          </p>
        </div>

        {/* Card */}
        <div className="border border-border bg-card rounded-xl p-6 space-y-5">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <Key className="w-4 h-4 text-primary" />
            Activate License
          </div>

          <div className="space-y-2">
            <input
              type="text"
              value={keyInput}
              onChange={e => { setKey(e.target.value.toUpperCase()); setError(''); }}
              onKeyDown={e => e.key === 'Enter' && handleActivate()}
              placeholder="XSSF-XXXX-XXXX-XXXX-XXXX"
              className="w-full bg-background border border-border rounded-lg px-4 py-3 text-sm font-mono tracking-widest focus:outline-none focus:ring-1 focus:ring-primary placeholder:text-muted-foreground/30 placeholder:tracking-normal"
              autoFocus
              autoComplete="off"
              spellCheck={false}
            />
            {error && (
              <div className="flex items-center gap-2 text-xs text-destructive font-mono">
                <ShieldX className="w-3.5 h-3.5" /> {error}
              </div>
            )}
          </div>

          <button
            onClick={handleActivate}
            disabled={loading || !keyInput.trim()}
            className="w-full py-3 bg-primary text-primary-foreground font-bold rounded-lg flex items-center justify-center gap-2 hover:bg-primary/90 transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
          >
            {loading ? <Loader className="w-4 h-4 animate-spin" /> : <ShieldCheck className="w-4 h-4" />}
            {loading ? 'Verifying...' : 'Activate'}
          </button>

          <p className="text-center text-[11px] text-muted-foreground font-mono">
            Contact your administrator to obtain a license key
          </p>
        </div>

        {/* Admin hint */}
        <p className="text-center text-[10px] text-muted-foreground/40 font-mono">
          Administrators:{' '}
          <a href="/admin" className="underline underline-offset-2 hover:text-muted-foreground">
            open admin panel
          </a>
        </p>
      </div>
    </div>
  );
}
