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
          "fixed inset-y-0 left-0 z-40 w-64 transform border-r border-sidebar-border bg-sidebar/85 backdrop-blur-xl transition-transform md:sticky md:top-0 md:h-screen md:translate-x-0",
          open ? "translate-x-0" : "-translate-x-full",
        )}
      >
        <div className="flex h-16 items-center gap-3 border-b border-sidebar-border px-5">
          <div className="relative flex h-9 w-9 items-center justify-center rounded-xl bg-gradient-to-br from-primary to-accent shadow-[0_8px_24px_-8px] shadow-primary/60">
            <ShieldHalf className="h-4 w-4 text-primary-foreground" />
          </div>
          <div className="leading-tight">
            <div className="text-[15px] font-semibold tracking-tight text-foreground">CyberGuard</div>
            <div className="text-[10px] font-medium uppercase tracking-[0.22em] text-muted-foreground">
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
                to={item.to as never}
                onClick={() => setOpen(false)}
                className={cn(
                  "group relative flex items-center gap-3 rounded-lg px-3 py-2 text-[13.5px] font-medium transition-all duration-200",
                  active
                    ? "bg-sidebar-accent text-foreground shadow-sm"
                    : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
                )}
              >
                {active && (
                  <motion.span
                    layoutId="nav-active"
                    className="absolute left-0 top-1/2 h-6 w-[3px] -translate-y-1/2 rounded-r bg-gradient-to-b from-primary to-accent shadow-[0_0_12px] shadow-primary/60"
                  />
                )}
                <Icon className={cn("h-[17px] w-[17px] transition", active ? "text-primary" : "group-hover:text-foreground")} />
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
                to={item.to as never}
                onClick={() => setOpen(false)}
                className={cn(
                  "flex items-center gap-3 rounded-lg px-3 py-2 text-[13.5px] font-medium transition",
                  active
                    ? "bg-sidebar-accent text-foreground"
                    : "text-muted-foreground hover:bg-sidebar-accent/60 hover:text-foreground",
                )}
              >
                <Icon className={cn("h-[17px] w-[17px]", active && "text-primary")} />
                <span>{item.label}</span>
              </Link>
            );
          })}
        </nav>

        <div className="absolute inset-x-3 bottom-3 rounded-xl border border-sidebar-border bg-sidebar-accent/40 p-3 text-xs">
          <div className="text-[10px] font-medium uppercase tracking-[0.2em] text-muted-foreground">
            System status
          </div>
          <div className="mt-1.5 flex items-center gap-2 text-foreground/90">
            <span className="relative flex h-2 w-2">
              <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-success opacity-70" />
              <span className="relative inline-flex h-2 w-2 rounded-full bg-success" />
            </span>
            All systems operational
          </div>
        </div>
      </aside>

      <div className="flex min-h-screen flex-1 flex-col">
        <header className="sticky top-0 z-30 flex h-16 items-center gap-3 border-b border-border bg-background/70 px-4 backdrop-blur-xl md:px-8">
          <button
            onClick={() => setOpen((v) => !v)}
            className="md:hidden inline-flex h-9 w-9 items-center justify-center rounded-lg border border-border bg-card/50"
            aria-label="Toggle navigation"
          >
            {open ? <X className="h-4 w-4" /> : <Menu className="h-4 w-4" />}
          </button>
          <div className="flex flex-1 items-center gap-3">
            <div className="hidden md:flex items-center gap-2.5 rounded-full border border-border bg-card/50 px-3.5 py-1.5 text-xs text-muted-foreground">
              <span className="h-1.5 w-1.5 rounded-full bg-success shadow-[0_0_8px] shadow-success/60" />
              <span className="font-mono">secure.session</span>
              <span className="text-muted-foreground/40">·</span>
              <span className="font-mono">v1.0.0</span>
            </div>
          </div>
          <Link
            to="/settings"
            className="hidden md:inline-flex items-center gap-2 rounded-full border border-border bg-card/50 px-3.5 py-1.5 text-xs text-muted-foreground transition hover:border-primary/40 hover:text-foreground"
          >
            <Settings className="h-3.5 w-3.5" /> Configure backend
          </Link>
        </header>
        <main className="flex-1 px-4 py-8 md:px-10 md:py-12">
          <div className="mx-auto w-full max-w-7xl">{children}</div>
        </main>
        <footer className="border-t border-border/60 px-4 py-6 md:px-10">
          <div className="mx-auto flex w-full max-w-7xl flex-col items-start justify-between gap-2 text-xs text-muted-foreground md:flex-row md:items-center">
            <div>© {new Date().getFullYear()} CyberGuard — Security Analysis Suite.</div>
            <div className="font-mono">For authorized security testing and educational use only.</div>
          </div>
        </footer>
      </div>
      <Toaster />
    </div>
  );
}