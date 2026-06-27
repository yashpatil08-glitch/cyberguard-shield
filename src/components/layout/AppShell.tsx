import { Link, useRouterState } from "@tanstack/react-router";
import { motion } from "framer-motion";
import {
  LayoutDashboard,
  Globe,
  KeyRound,
  ShieldCheck,
  Fish,
  FileText,
  Info,
  Mail,
  Settings,
  ShieldHalf,
  Menu,
  X,
} from "lucide-react";
import { useState, type ReactNode } from "react";
import { Toaster } from "@/components/ui/sonner";
import { cn } from "@/lib/utils";

type NavItem = {
  to: string;
  label: string;
  icon: typeof LayoutDashboard;
  exact?: boolean;
};

const NAV: NavItem[] = [
  { to: "/", label: "Dashboard", icon: LayoutDashboard, exact: true },
  { to: "/url-analyzer", label: "URL Analyzer", icon: Globe },
  { to: "/password", label: "Password Strength", icon: KeyRound },
  { to: "/headers", label: "Security Headers", icon: ShieldCheck },
  { to: "/phishing", label: "Phishing Detector", icon: Fish },
  { to: "/reports", label: "Reports", icon: FileText },
];

const SECONDARY: NavItem[] = [
  { to: "/about", label: "About", icon: Info },
  { to: "/contact", label: "Contact", icon: Mail },
  { to: "/settings", label: "Settings", icon: Settings },
];

export function AppShell({ children }: { children: ReactNode }) {
  const [open, setOpen] = useState(false);
  const pathname = useRouterState({ select: (s) => s.location.pathname });

  const isActive = (to: string, exact?: boolean) =>
    exact ? pathname === to : pathname === to || pathname.startsWith(to + "/");

  return (
    <div className="flex min-h-screen w-full">
      <aside
        className={cn(
          "fixed inset-y-0 left-0 z-40 w-64 transform border-r border-border bg-sidebar/80 backdrop-blur-xl transition-transform md:static md:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-16 items-center gap-2 px-5 border-b border-border">
          <div className="flex h-9 w-9 items-center justify-center rounded-lg glow-neon">
            <ShieldHalf className="h-5 w-5 text-neon" />
          </div>
          <div className="leading-tight">
            <div className="font-semibold tracking-tight text-gradient-cyber">CyberGuard</div>
            <div className="text-[10px] uppercase tracking-[0.18em] text-muted-foreground">
              Security Suite
            </div>
          </div>
        </div>

        <nav className="flex flex-col gap-1 p-3">
          <div className="px-3 pb-2 pt-3 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Tools
          </div>
          {NAV.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.to, item.exact);
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setOpen(false)}
                className={cn(
                  "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition",
                  active
                    ? "bg-secondary text-foreground"
                    : "text-muted-foreground hover:bg-secondary/60 hover:text-foreground",
                )}
              >
                {active && (
                  <motion.span
                    layoutId="nav-active"
                    className="absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r bg-neon"
                  />
                )}
                <Icon className={cn("h-4 w-4", active && "text-neon")} />
                <span>{item.label}</span>
              </Link>
            );
          })}

          <div className="px-3 pb-2 pt-5 text-[10px] font-semibold uppercase tracking-[0.18em] text-muted-foreground">
            Workspace
          </div>
          {SECONDARY.map((item) => {
            const Icon = item.icon;
            const active = isActive(item.to);
            return (
              <Link
                key={item.to}
                to={item.to}
                onClick={() => setOpen(false)}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-sm transition",
                  active
                    ? "bg-secondary text-foreground"
                    : "text-muted-foreground hover:bg-secondary/60 hover:text-foreground",
                )}
              >
                <Icon className="h-4 w-4" />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="absolute inset-x-3 bottom-3 rounded-lg border border-border p-3 text-xs text-muted-foreground">
          <div className="font-mono text-[10px] uppercase tracking-widest text-neon">
            System status
          </div>
          <div className="mt-1 flex items-center gap-2">
            <span className="h-2 w-2 animate-pulse rounded-full bg-neon shadow-[0_0_8px] shadow-neon" />
            All systems operational
          </div>
        </div>
      </aside>

      <div className="flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-background/60 px-4 backdrop-blur-xl md:px-8">
          <button
            onClick={() => setOpen((v) => !v)}
            className="md:hidden inline-flex h-9 w-9 items-center justify-center rounded-md border border-border"
            aria-label="Toggle navigation"
          >
            {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
          <div className="flex flex-1 items-center gap-3">
            <div className="hidden md:flex items-center gap-2 rounded-md border border-border bg-card/60 px-3 py-1.5 text-xs font-mono text-muted-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-neon" />
              <span>secure.session</span>
              <span className="text-muted-foreground/50">·</span>
              <span>v1.0.0</span>
            </div>
          </div>
          <Link
            to="/settings"
            className="hidden md:inline-flex items-center gap-2 rounded-md border border-border bg-card/60 px-3 py-1.5 text-xs text-muted-foreground hover:text-foreground"
          >
            <Settings className="h-3.5 w-3.5" /> Configure backend
          </Link>
        </header>
        <main className="flex-1 px-4 py-6 md:px-8 md:py-10">{children}</main>
        <footer className="border-t border-border px-4 py-4 text-xs text-muted-foreground md:px-8">
          CyberGuard · For authorized security testing and educational use only.
        </footer>
      </div>
      <Toaster />
    </div>
  );
}