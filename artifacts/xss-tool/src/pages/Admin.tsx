import { useState, useEffect, useCallback } from 'react';
import {
  TerminalSquare, Key, LogIn, Plus, Trash2, ShieldOff,
  Copy, CheckCircle, XCircle, Clock, Crown, Loader,
  RefreshCw, LogOut, Shield
} from 'lucide-react';
import { toast } from 'sonner';

// ── Types ──────────────────────────────────────────────────────────────────────
interface License {
  key: string;
  plan: 'trial' | 'professional' | 'lifetime';
  owner: string;
  createdAt: string;
  expiresAt: string | null;
  active: boolean;
  note?: string;
}

// ── Helpers ────────────────────────────────────────────────────────────────────
const PLAN_COLORS = {
  trial:        'text-yellow-400 border-yellow-400/30 bg-yellow-400/10',
  professional: 'text-blue-400 border-blue-400/30 bg-blue-400/10',
  lifetime:     'text-primary border-primary/30 bg-primary/10',
};

const PLAN_ICON = {
  trial:        Clock,
  professional: Shield,
  lifetime:     Crown,
};

function isExpired(lic: License) {
  if (!lic.expiresAt) return false;
  return new Date(lic.expiresAt) < new Date();
}

function statusLabel(lic: License) {
  if (!lic.active) return { label: 'REVOKED', cls: 'text-red-500 bg-red-500/10 border-red-500/30' };
  if (isExpired(lic)) return { label: 'EXPIRED', cls: 'text-orange-400 bg-orange-400/10 border-orange-400/30' };
  return { label: 'ACTIVE', cls: 'text-primary bg-primary/10 border-primary/30' };
}

function fmtDate(d: string | null) {
  if (!d) return 'Never';
  return new Date(d).toLocaleDateString('en-US', { year: 'numeric', month: 'short', day: 'numeric' });
}

// ── API ────────────────────────────────────────────────────────────────────────
async function apiPost(path: string, body: object, token?: string) {
  const res = await fetch(`/api${path}`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { 'x-admin-token': token } : {}),
    },
    body: JSON.stringify(body),
  });
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).error ?? `HTTP ${res.status}`);
  return res.json();
}

async function apiGet(path: string, token: string) {
  const res = await fetch(`/api${path}`, {
    headers: { 'x-admin-token': token },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

async function apiDelete(path: string, token: string) {
  const res = await fetch(`/api${path}`, {
    method: 'DELETE',
    headers: { 'x-admin-token': token },
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}`);
  return res.json();
}

// ── Login ──────────────────────────────────────────────────────────────────────
function LoginScreen({ onLogin }: { onLogin: (token: string) => void }) {
  const [pw, setPw]         = useState('');
  const [loading, setLoading] = useState(false);
  const [err, setErr]       = useState('');

  const handleLogin = async () => {
    if (!pw) return;
    setLoading(true); setErr('');
    try {
      const r = await apiPost('/admin/login', { password: pw });
      sessionStorage.setItem('xssforge_admin_token', r.token);
      onLogin(r.token);
    } catch {
      setErr('Invalid admin password');
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="h-screen w-full bg-background dark flex items-center justify-center p-6">
      <div className="w-full max-w-sm space-y-8">
        <div className="text-center space-y-2">
          <TerminalSquare className="w-10 h-10 text-primary mx-auto" />
          <h1 className="text-xl font-black tracking-tight text-foreground">Admin Panel</h1>
          <p className="text-xs text-muted-foreground font-mono uppercase tracking-widest">XSS Forge · Restricted Access</p>
        </div>

        <div className="border border-border bg-card rounded-xl p-6 space-y-4">
          <div className="flex items-center gap-2 text-sm font-semibold">
            <LogIn className="w-4 h-4 text-primary" /> Administrator Login
          </div>
          <input
            type="password"
            value={pw}
            onChange={e => { setPw(e.target.value); setErr(''); }}
            onKeyDown={e => e.key === 'Enter' && handleLogin()}
            placeholder="Admin password"
            className="w-full bg-background border border-border rounded-lg px-4 py-3 text-sm font-mono focus:outline-none focus:ring-1 focus:ring-primary placeholder:text-muted-foreground/40"
            autoFocus
          />
          {err && <p className="text-xs text-destructive font-mono">{err}</p>}
          <button
            onClick={handleLogin}
            disabled={loading || !pw}
            className="w-full py-3 bg-primary text-primary-foreground font-bold rounded-lg flex items-center justify-center gap-2 hover:bg-primary/90 transition-colors disabled:opacity-40"
          >
            {loading ? <Loader className="w-4 h-4 animate-spin" /> : <LogIn className="w-4 h-4" />}
            {loading ? 'Authenticating...' : 'Login'}
          </button>
        </div>

        <p className="text-center text-[10px] text-muted-foreground/40 font-mono">
          <a href="/" className="underline hover:text-muted-foreground">← Back to app</a>
        </p>
      </div>
    </div>
  );
}

// ── Generate Modal ─────────────────────────────────────────────────────────────
function GenerateModal({
  token, onClose, onGenerated,
}: { token: string; onClose: () => void; onGenerated: (lic: License) => void }) {
  const [plan, setPlan]   = useState<'trial' | 'professional' | 'lifetime'>('professional');
  const [owner, setOwner] = useState('');
  const [note, setNote]   = useState('');
  const [loading, setLoading] = useState(false);

  const generate = async () => {
    setLoading(true);
    try {
      const r = await apiPost('/admin/licenses/generate', { plan, owner, note }, token);
      onGenerated(r.license as License);
      toast.success('License generated!');
    } catch (e: unknown) {
      toast.error((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <div className="fixed inset-0 bg-black/70 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="w-full max-w-md bg-card border border-border rounded-xl shadow-2xl">
        <div className="flex items-center justify-between p-5 border-b border-border">
          <div className="flex items-center gap-2 font-bold">
            <Key className="w-4 h-4 text-primary" /> Generate License
          </div>
          <button onClick={onClose} className="text-muted-foreground hover:text-foreground">
            <XCircle className="w-5 h-5" />
          </button>
        </div>

        <div className="p-5 space-y-4">
          {/* Plan */}
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground font-mono uppercase tracking-wider">Plan</label>
            <div className="grid grid-cols-3 gap-2">
              {(['trial', 'professional', 'lifetime'] as const).map(p => {
                const Icon = PLAN_ICON[p];
                return (
                  <button
                    key={p}
                    onClick={() => setPlan(p)}
                    className={`p-3 rounded-lg border text-xs font-bold flex flex-col items-center gap-1.5 transition-all ${
                      plan === p ? PLAN_COLORS[p] : 'border-border text-muted-foreground hover:border-primary/40'
                    }`}
                  >
                    <Icon className="w-4 h-4" />
                    {p.charAt(0).toUpperCase() + p.slice(1)}
                    <span className="font-normal text-[10px] opacity-70">
                      {p === 'trial' ? '14 days' : p === 'professional' ? '1 year' : 'Forever'}
                    </span>
                  </button>
                );
              })}
            </div>
          </div>

          {/* Owner */}
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground font-mono uppercase tracking-wider">Owner / Name</label>
            <input
              type="text"
              value={owner}
              onChange={e => setOwner(e.target.value)}
              placeholder="e.g. Lavish"
              className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>

          {/* Note */}
          <div className="space-y-1.5">
            <label className="text-xs text-muted-foreground font-mono uppercase tracking-wider">Note (optional)</label>
            <input
              type="text"
              value={note}
              onChange={e => setNote(e.target.value)}
              placeholder="e.g. Personal use"
              className="w-full bg-background border border-border rounded-lg px-3 py-2 text-sm focus:outline-none focus:ring-1 focus:ring-primary"
            />
          </div>
        </div>

        <div className="flex gap-2 p-5 border-t border-border">
          <button onClick={onClose} className="flex-1 py-2.5 border border-border rounded-lg text-sm text-muted-foreground hover:text-foreground transition-colors">
            Cancel
          </button>
          <button
            onClick={generate}
            disabled={loading}
            className="flex-1 py-2.5 bg-primary text-primary-foreground rounded-lg text-sm font-bold flex items-center justify-center gap-2 hover:bg-primary/90 transition-colors disabled:opacity-40"
          >
            {loading ? <Loader className="w-4 h-4 animate-spin" /> : <Key className="w-4 h-4" />}
            Generate
          </button>
        </div>
      </div>
    </div>
  );
}

// ── New Key Banner ─────────────────────────────────────────────────────────────
function NewKeyBanner({ license, onDismiss }: { license: License; onDismiss: () => void }) {
  const [copied, setCopied] = useState(false);

  const copy = () => {
    navigator.clipboard.writeText(license.key);
    setCopied(true);
    toast.success('License key copied!');
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="border border-primary/40 bg-primary/5 rounded-xl p-5 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2 text-primary font-bold text-sm">
          <CheckCircle className="w-4 h-4" /> New License Generated
        </div>
        <button onClick={onDismiss} className="text-muted-foreground hover:text-foreground">
          <XCircle className="w-4 h-4" />
        </button>
      </div>

      <div className="flex items-center gap-2">
        <code className="flex-1 font-mono text-sm bg-black/40 px-4 py-3 rounded-lg border border-border text-primary tracking-widest select-all">
          {license.key}
        </code>
        <button
          onClick={copy}
          className="p-3 border border-border rounded-lg hover:border-primary hover:text-primary text-muted-foreground transition-colors"
        >
          {copied ? <CheckCircle className="w-4 h-4 text-primary" /> : <Copy className="w-4 h-4" />}
        </button>
      </div>

      <p className="text-[11px] text-muted-foreground font-mono">
        {license.plan.toUpperCase()} · {license.owner} ·{' '}
        {license.expiresAt ? `Expires ${fmtDate(license.expiresAt)}` : 'Lifetime'}
      </p>
    </div>
  );
}

// ── Main Admin Panel ───────────────────────────────────────────────────────────
function AdminDashboard({ token, onLogout }: { token: string; onLogout: () => void }) {
  const [licenses, setLicenses] = useState<License[]>([]);
  const [loading, setLoading]   = useState(true);
  const [showModal, setShowModal] = useState(false);
  const [newLicense, setNewLicense] = useState<License | null>(null);

  const loadLicenses = useCallback(async () => {
    setLoading(true);
    try {
      const r = await apiGet('/admin/licenses', token);
      setLicenses(r.licenses as License[]);
    } catch {
      toast.error('Failed to load licenses — session may have expired');
    } finally {
      setLoading(false);
    }
  }, [token]);

  useEffect(() => { loadLicenses(); }, [loadLicenses]);

  const handleRevoke = async (key: string) => {
    if (!confirm('Revoke this license? The user will lose access.')) return;
    try {
      await apiPost(`/admin/licenses/${key}/revoke`, {}, token);
      toast.success('License revoked');
      loadLicenses();
    } catch (e: unknown) { toast.error((e as Error).message); }
  };

  const handleDelete = async (key: string) => {
    if (!confirm('Permanently delete this license?')) return;
    try {
      await apiDelete(`/admin/licenses/${key}`, token);
      toast.success('License deleted');
      loadLicenses();
      if (newLicense?.key === key) setNewLicense(null);
    } catch (e: unknown) { toast.error((e as Error).message); }
  };

  const handleGenerated = (lic: License) => {
    setNewLicense(lic);
    setShowModal(false);
    loadLicenses();
  };

  const handleLogout = () => {
    sessionStorage.removeItem('xssforge_admin_token');
    onLogout();
  };

  const active    = licenses.filter(l => l.active && !isExpired(l)).length;
  const expired   = licenses.filter(l => isExpired(l)).length;
  const revoked   = licenses.filter(l => !l.active).length;

  return (
    <div className="min-h-screen bg-background dark text-foreground">
      {/* Top bar */}
      <div className="border-b border-border bg-card px-6 py-4 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <TerminalSquare className="w-6 h-6 text-primary" />
          <div>
            <span className="font-bold text-sm">XSS Forge</span>
            <span className="text-muted-foreground text-xs font-mono ml-2">Admin Panel</span>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <a href="/" className="px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground border border-border rounded-lg transition-colors font-mono">
            ← App
          </a>
          <button
            onClick={handleLogout}
            className="px-3 py-1.5 text-xs text-muted-foreground hover:text-destructive border border-border rounded-lg flex items-center gap-1.5 transition-colors font-mono"
          >
            <LogOut className="w-3.5 h-3.5" /> Logout
          </button>
        </div>
      </div>

      <div className="max-w-5xl mx-auto p-6 space-y-6">
        {/* Stats */}
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total', value: licenses.length, cls: 'text-foreground' },
            { label: 'Active', value: active, cls: 'text-primary' },
            { label: 'Expired', value: expired, cls: 'text-orange-400' },
            { label: 'Revoked', value: revoked, cls: 'text-red-500' },
          ].map(s => (
            <div key={s.label} className="border border-border bg-card rounded-xl p-4 space-y-1">
              <div className="text-xs text-muted-foreground font-mono uppercase tracking-wider">{s.label}</div>
              <div className={`text-3xl font-black font-mono ${s.cls}`}>{s.value}</div>
            </div>
          ))}
        </div>

        {/* New key banner */}
        {newLicense && (
          <NewKeyBanner license={newLicense} onDismiss={() => setNewLicense(null)} />
        )}

        {/* Header row */}
        <div className="flex items-center justify-between">
          <h2 className="font-bold text-sm flex items-center gap-2">
            <Key className="w-4 h-4 text-primary" /> License Keys
            <span className="text-muted-foreground font-normal font-mono">({licenses.length})</span>
          </h2>
          <div className="flex items-center gap-2">
            <button
              onClick={loadLicenses}
              className="p-2 border border-border rounded-lg text-muted-foreground hover:text-primary hover:border-primary/40 transition-colors"
            >
              <RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />
            </button>
            <button
              onClick={() => setShowModal(true)}
              className="px-4 py-2 bg-primary text-primary-foreground rounded-lg text-sm font-bold flex items-center gap-2 hover:bg-primary/90 transition-colors"
            >
              <Plus className="w-4 h-4" /> Generate License
            </button>
          </div>
        </div>

        {/* Table */}
        <div className="border border-border rounded-xl overflow-hidden">
          {loading ? (
            <div className="flex items-center justify-center py-16 text-muted-foreground">
              <Loader className="w-5 h-5 animate-spin mr-2" /> Loading...
            </div>
          ) : licenses.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-muted-foreground font-mono text-sm space-y-2">
              <Key className="w-8 h-8 opacity-20" />
              <p>No licenses yet. Generate one to get started.</p>
            </div>
          ) : (
            <table className="w-full text-sm">
              <thead className="bg-secondary/40 text-xs text-muted-foreground font-mono uppercase tracking-wider">
                <tr>
                  <th className="px-4 py-3 text-left">Key</th>
                  <th className="px-4 py-3 text-left">Owner</th>
                  <th className="px-4 py-3 text-left">Plan</th>
                  <th className="px-4 py-3 text-left">Status</th>
                  <th className="px-4 py-3 text-left">Expires</th>
                  <th className="px-4 py-3 text-left">Created</th>
                  <th className="px-4 py-3 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {licenses.map(lic => {
                  const { label, cls } = statusLabel(lic);
                  const PlanIcon = PLAN_ICON[lic.plan];
                  return (
                    <tr key={lic.key} className="hover:bg-secondary/20 transition-colors">
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <code className="font-mono text-xs text-primary tracking-wider">{lic.key}</code>
                          <button
                            onClick={() => { navigator.clipboard.writeText(lic.key); toast.success('Copied'); }}
                            className="text-muted-foreground hover:text-primary opacity-0 group-hover:opacity-100 transition-opacity"
                          >
                            <Copy className="w-3 h-3" />
                          </button>
                        </div>
                        {lic.note && <p className="text-[10px] text-muted-foreground/60 font-mono mt-0.5">{lic.note}</p>}
                      </td>
                      <td className="px-4 py-3 font-medium">{lic.owner}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center gap-1 text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${PLAN_COLORS[lic.plan]}`}>
                          <PlanIcon className="w-3 h-3" />
                          {lic.plan}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-[10px] font-bold px-2 py-0.5 rounded border uppercase ${cls}`}>{label}</span>
                      </td>
                      <td className="px-4 py-3 text-xs text-muted-foreground font-mono">{fmtDate(lic.expiresAt)}</td>
                      <td className="px-4 py-3 text-xs text-muted-foreground font-mono">{fmtDate(lic.createdAt)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center justify-end gap-1">
                          <button
                            onClick={() => { navigator.clipboard.writeText(lic.key); toast.success('Key copied'); }}
                            className="p-1.5 text-muted-foreground hover:text-primary rounded transition-colors" title="Copy key"
                          >
                            <Copy className="w-3.5 h-3.5" />
                          </button>
                          {lic.active && !isExpired(lic) && (
                            <button
                              onClick={() => handleRevoke(lic.key)}
                              className="p-1.5 text-muted-foreground hover:text-orange-400 rounded transition-colors" title="Revoke"
                            >
                              <ShieldOff className="w-3.5 h-3.5" />
                            </button>
                          )}
                          <button
                            onClick={() => handleDelete(lic.key)}
                            className="p-1.5 text-muted-foreground hover:text-destructive rounded transition-colors" title="Delete"
                          >
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {showModal && (
        <GenerateModal token={token} onClose={() => setShowModal(false)} onGenerated={handleGenerated} />
      )}
    </div>
  );
}

// ── Page ───────────────────────────────────────────────────────────────────────
export default function Admin() {
  const [token, setToken] = useState<string | null>(
    () => sessionStorage.getItem('xssforge_admin_token')
  );

  if (!token) return <LoginScreen onLogin={setToken} />;
  return <AdminDashboard token={token} onLogout={() => setToken(null)} />;
}
