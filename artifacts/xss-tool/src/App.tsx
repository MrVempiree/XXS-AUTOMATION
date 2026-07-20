import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { Toaster } from 'sonner';
import { TooltipProvider } from '@/components/ui/tooltip';
import { Route, Switch, Router as WouterRouter, useLocation } from 'wouter';
import { Code2, Search, Shield, Zap, Target, Database, Activity, List, Crosshair } from 'lucide-react';
import Library from './pages/Library';
import Generator from './pages/Generator';
import Encoder from './pages/Encoder';
import Fuzzer from './pages/Fuzzer';
import Scanner from './pages/Scanner';
import SQLi from './pages/SQLi';
import Admin from './pages/Admin';
import BulkScanner from './pages/BulkScanner';
import ExploitEngine from './pages/ExploitEngine';
import NotFound from './pages/not-found';
import LicenseGate, { useLicense, clearLicense } from './components/LicenseGate';

const queryClient = new QueryClient();

function Sidebar() {
  const [location, setLocation] = useLocation();
  const license = useLicense();

  const xssItems = [
    { href: '/',        icon: Search,    label: 'Payload Library' },
    { href: '/gen',     icon: Zap,       label: 'Generator' },
    { href: '/encoder', icon: Code2,     label: 'Encoder' },
    { href: '/scanner', icon: Target,    label: 'XSS Scanner' },
    { href: '/bulk',    icon: List,      label: 'Bulk Scanner' },
    { href: '/exploit', icon: Crosshair, label: 'Exploit Engine', badge: 'LIVE' },
    { href: '/fuzzer',  icon: Shield,    label: 'Fuzzer' },
  ];

  const sqliItems = [
    { href: '/sqli', icon: Database, label: 'SQLi Scanner' },
  ];

  const NavBtn = ({ href, icon: Icon, label, badge }: {
    href: string; icon: typeof Target; label: string; badge?: string;
  }) => {
    const isActive = location === href;
    return (
      <button
        onClick={() => setLocation(href)}
        className={`w-full flex items-center gap-3 px-3 py-2 rounded-md text-sm font-semibold transition-all duration-150 ${
          isActive
            ? 'bg-primary/10 text-primary border border-primary/20 shadow-[inset_2px_0_0_0_hsl(var(--primary))]'
            : 'text-muted-foreground hover:bg-secondary hover:text-foreground border border-transparent'
        }`}
      >
        <Icon className={`w-4 h-4 shrink-0 ${isActive ? 'text-primary' : 'opacity-60'}`} />
        <span className="flex-1 text-left">{label}</span>
        {badge && (
          <span className={`text-[8px] font-black px-1.5 py-0.5 rounded uppercase tracking-wider shrink-0 ${
            badge === 'LIVE' ? 'bg-red-500/20 text-red-400 border border-red-500/30 animate-pulse' :
            'bg-primary/20 text-primary'
          }`}>
            {badge}
          </span>
        )}
      </button>
    );
  };

  return (
    <div className="w-60 border-r border-border bg-card h-screen flex flex-col shrink-0">
      {/* Brand */}
      <div className="px-4 py-4 border-b border-border">
        <div className="flex items-center gap-2.5 mb-0.5">
          <Activity className="w-5 h-5 text-primary shrink-0" />
          <h1 className="font-brand text-[15px] font-black leading-none text-primary tracking-wide">ALCAME</h1>
        </div>
        <div className="font-brand text-[10px] font-bold text-muted-foreground tracking-[0.22em] ml-7">AUTOMATION</div>
        <div className="text-[9px] font-mono-hack text-primary/50 uppercase tracking-widest mt-1.5 ml-7">Security Research Toolkit</div>
      </div>

      <nav className="flex-1 p-3 space-y-4 overflow-y-auto">
        <div>
          <div className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/50 px-3 mb-1.5">XSS MODULE</div>
          <div className="space-y-0.5">
            {xssItems.map(item => <NavBtn key={item.href} {...item} />)}
          </div>
        </div>
        <div>
          <div className="text-[9px] font-black uppercase tracking-[0.2em] text-muted-foreground/50 px-3 mb-1.5">SQL INJECTION</div>
          <div className="space-y-0.5">
            {sqliItems.map(item => <NavBtn key={item.href} {...item} />)}
          </div>
        </div>
      </nav>

      <div className="p-3 border-t border-border bg-secondary/20 space-y-2">
        {license && (
          <div className="flex items-center justify-between px-2 py-1.5 rounded-md bg-primary/5 border border-primary/15">
            <div className="text-[10px] font-mono text-primary uppercase tracking-wider">{license.plan}</div>
            <div className="text-[10px] text-muted-foreground font-mono truncate max-w-[100px]">{license.owner}</div>
          </div>
        )}
        <div className="flex items-center justify-between px-2">
          <button onClick={() => setLocation('/admin')} className="text-[10px] text-muted-foreground hover:text-foreground font-mono uppercase tracking-wider transition-colors">Admin</button>
          <button onClick={clearLicense} className="text-[10px] text-muted-foreground hover:text-destructive font-mono uppercase tracking-wider transition-colors">Logout</button>
        </div>
        <div className="text-[9px] text-muted-foreground/30 font-mono px-2">v2.0 · Bug Bounty Edition</div>
      </div>
    </div>
  );
}

function Layout({ children }: { children: React.ReactNode }) {
  return (
    <div className="flex h-screen bg-background overflow-hidden">
      <Sidebar />
      <main className="flex-1 overflow-hidden">{children}</main>
    </div>
  );
}

function Router() {
  return (
    <Switch>
      <Route path="/"        component={() => <Layout><Library /></Layout>} />
      <Route path="/gen"     component={() => <Layout><Generator /></Layout>} />
      <Route path="/encoder" component={() => <Layout><Encoder /></Layout>} />
      <Route path="/scanner" component={() => <Layout><Scanner /></Layout>} />
      <Route path="/bulk"    component={() => <Layout><BulkScanner /></Layout>} />
      <Route path="/exploit" component={() => <Layout><ExploitEngine /></Layout>} />
      <Route path="/fuzzer"  component={() => <Layout><Fuzzer /></Layout>} />
      <Route path="/sqli"    component={() => <Layout><SQLi /></Layout>} />
      <Route path="/admin"   component={Admin} />
      <Route component={NotFound} />
    </Switch>
  );
}

function App() {
  return (
    <QueryClientProvider client={queryClient}>
      <TooltipProvider>
        <WouterRouter base={import.meta.env.BASE_URL.replace(/\/$/, '')}>
          <LicenseGate>
            <Router />
          </LicenseGate>
        </WouterRouter>
        <Toaster
          theme="dark"
          toastOptions={{
            classNames: {
              toast: 'bg-card border-border text-foreground font-mono text-xs',
              title: 'text-foreground',
              description: 'text-muted-foreground',
            },
          }}
        />
      </TooltipProvider>
    </QueryClientProvider>
  );
}

export default App;
