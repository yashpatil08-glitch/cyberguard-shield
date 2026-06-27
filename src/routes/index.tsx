import { createFileRoute, Link } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import {
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Tooltip,
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
} from "recharts";
import {
  Globe,
  KeyRound,
  ShieldCheck,
  Fish,
  FileText,
  Activity,
  TrendingUp,
  AlertTriangle,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";
import { listReports, type ReportEntry } from "@/lib/reports";
import { cn } from "@/lib/utils";

export const Route = createFileRoute("/")({
  head: () => ({
    meta: [
      { title: "Dashboard — CyberGuard" },
      { name: "description", content: "Overview of scans, reports, and risk distribution across your CyberGuard security toolkit." },
    ],
  }),
  component: Dashboard,
});

const QUICK = [
  { to: "/url-analyzer", label: "URL Security", icon: Globe, desc: "HTTPS, SSL, DNS, WHOIS" },
  { to: "/password", label: "Password Strength", icon: KeyRound, desc: "Entropy & crack-time" },
  { to: "/headers", label: "Security Headers", icon: ShieldCheck, desc: "HSTS, CSP, X-Frame" },
  { to: "/phishing", label: "Phishing Detector", icon: Fish, desc: "Risk indicators" },
] as const;

function useReports(): ReportEntry[] {
  const [reports, setReports] = useState<ReportEntry[]>([]);
  useEffect(() => {
    const sync = () => setReports(listReports());
    sync();
    window.addEventListener("cyberguard:reports-changed", sync);
    return () => window.removeEventListener("cyberguard:reports-changed", sync);
  }, []);
  return reports;
}

function Dashboard() {
  const reports = useReports();
  const totalScans = reports.length;
  const totalReports = reports.length;

  const buckets = { low: 0, medium: 0, high: 0, critical: 0 };
  reports.forEach((r) => {
    const inverted = r.kind === "url" || r.kind === "phishing";
    const sev = inverted ? r.score : 100 - r.score;
    if (sev >= 75) buckets.critical++;
    else if (sev >= 50) buckets.high++;
    else if (sev >= 25) buckets.medium++;
    else buckets.low++;
  });

  const pieData = [
    { name: "Low", value: buckets.low, color: "var(--neon)" },
    { name: "Medium", value: buckets.medium, color: "var(--cyber)" },
    { name: "High", value: buckets.high, color: "var(--warn)" },
    { name: "Critical", value: buckets.critical, color: "var(--danger)" },
  ];
  const hasData = totalScans > 0;

  const trend = buildTrend(reports);

  const stats = [
    { label: "Total scans", value: totalScans, icon: Activity, accent: "neon" as const },
    { label: "Reports generated", value: totalReports, icon: FileText, accent: "cyber" as const },
    { label: "High-risk findings", value: buckets.high + buckets.critical, icon: AlertTriangle, accent: "warn" as const },
    { label: "Avg score", value: totalScans ? Math.round(reports.reduce((a, r) => a + r.score, 0) / totalScans) : 0, icon: TrendingUp, accent: "neon" as const },
  ];

  return (
    <AppShell>
      <PageHeader
        eyebrow="Mission control"
        title={<span className="text-gradient-cyber">Security Dashboard</span>}
        description="Live overview of your security posture, recent scans, and risk distribution across CyberGuard tools."
      />

      <div className="grid grid-cols-2 gap-4 lg:grid-cols-4">
        {stats.map((s, i) => (
          <motion.div
            key={s.label}
            initial={{ opacity: 0, y: 12 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: i * 0.05 }}
            className="glass rounded-xl p-5"
          >
            <div className="flex items-center justify-between">
              <span className="text-xs uppercase tracking-widest text-muted-foreground">{s.label}</span>
              <s.icon
                className={cn(
                  "h-4 w-4",
                  s.accent === "neon" && "text-neon",
                  s.accent === "cyber" && "text-cyber",
                  s.accent === "warn" && "text-warn",
                )}
              />
            </div>
            <div className="mt-3 text-3xl font-semibold tabular-nums">{s.value}</div>
          </motion.div>
        ))}
      </div>

      <div className="mt-8 grid gap-4 lg:grid-cols-3">
        <div className="glass rounded-xl p-6 lg:col-span-2">
          <div className="mb-4 flex items-center justify-between">
            <h3 className="font-semibold">Scan activity</h3>
            <span className="text-xs text-muted-foreground">Last 7 days</span>
          </div>
          <div className="h-56">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trend}>
                <defs>
                  <linearGradient id="grad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="var(--neon)" stopOpacity={0.5} />
                    <stop offset="100%" stopColor="var(--neon)" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="var(--border)" />
                <XAxis dataKey="day" stroke="var(--muted-foreground)" fontSize={11} />
                <YAxis stroke="var(--muted-foreground)" fontSize={11} allowDecimals={false} />
                <Tooltip
                  contentStyle={{
                    background: "var(--card)",
                    border: "1px solid var(--border)",
                    borderRadius: 8,
                  }}
                />
                <Area type="monotone" dataKey="scans" stroke="var(--neon)" fill="url(#grad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="glass rounded-xl p-6">
          <h3 className="mb-4 font-semibold">Risk distribution</h3>
          {hasData ? (
            <div className="h-56">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={pieData} dataKey="value" innerRadius={45} outerRadius={75} stroke="none">
                    {pieData.map((d) => (
                      <Cell key={d.name} fill={d.color} />
                    ))}
                  </Pie>
                  <Tooltip
                    contentStyle={{
                      background: "var(--card)",
                      border: "1px solid var(--border)",
                      borderRadius: 8,
                    }}
                  />
                </PieChart>
              </ResponsiveContainer>
            </div>
          ) : (
            <div className="flex h-56 items-center justify-center text-sm text-muted-foreground">
              Run a scan to see distribution
            </div>
          )}
          <div className="mt-3 grid grid-cols-2 gap-2 text-xs">
            {pieData.map((d) => (
              <div key={d.name} className="flex items-center gap-2">
                <span className="h-2 w-2 rounded-full" style={{ background: d.color }} />
                <span className="text-muted-foreground">{d.name}</span>
                <span className="ml-auto tabular-nums">{d.value}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <div className="mt-8">
        <h3 className="mb-4 text-sm font-semibold uppercase tracking-widest text-muted-foreground">
          Quick actions
        </h3>
        <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-4">
          {QUICK.map((q) => (
            <Link
              key={q.to}
              to={q.to as never}
              className="group glass relative overflow-hidden rounded-xl p-5 transition hover:glow-neon"
            >
              <q.icon className="h-6 w-6 text-neon transition group-hover:scale-110" />
              <div className="mt-4 font-semibold">{q.label}</div>
              <div className="text-xs text-muted-foreground">{q.desc}</div>
              <div className="absolute -bottom-8 -right-8 h-24 w-24 rounded-full bg-neon/10 blur-2xl transition group-hover:bg-neon/20" />
            </Link>
          ))}
        </div>
      </div>

      <div className="mt-8 glass rounded-xl">
        <div className="flex items-center justify-between border-b border-border px-6 py-4">
          <h3 className="font-semibold">Recent activity</h3>
          <Link to="/reports" className="text-xs text-neon hover:underline">
            View all reports →
          </Link>
        </div>
        {reports.length === 0 ? (
          <div className="px-6 py-12 text-center text-sm text-muted-foreground">
            No scans yet. Run your first analysis to populate the timeline.
          </div>
        ) : (
          <ul className="divide-y divide-border">
            {reports.slice(0, 6).map((r) => (
              <li key={r.id} className="flex items-center gap-4 px-6 py-3">
                <KindBadge kind={r.kind} />
                <div className="min-w-0 flex-1">
                  <div className="truncate text-sm font-medium">{r.title}</div>
                  <div className="truncate text-xs text-muted-foreground">{r.target}</div>
                </div>
                <div className="text-xs text-muted-foreground">
                  {new Date(r.createdAt).toLocaleString()}
                </div>
                <div
                  className="font-mono text-sm tabular-nums"
                  style={{ color: scoreColor(r.score, r.kind) }}
                >
                  {r.score}
                </div>
              </li>
            ))}
          </ul>
        )}
      </div>
    </AppShell>
  );
}

function KindBadge({ kind }: { kind: ReportEntry["kind"] }) {
  const map = {
    url: { label: "URL", color: "var(--cyber)" },
    password: { label: "PASS", color: "var(--neon)" },
    headers: { label: "HDRS", color: "var(--warn)" },
    phishing: { label: "PHISH", color: "var(--danger)" },
  } as const;
  const m = map[kind];
  return (
    <span
      className="rounded border px-2 py-0.5 text-[10px] font-mono uppercase tracking-widest"
      style={{ color: m.color, borderColor: `color-mix(in oklch, ${m.color} 40%, transparent)` }}
    >
      {m.label}
    </span>
  );
}

function scoreColor(score: number, kind: ReportEntry["kind"]): string {
  const inverted = kind === "url" || kind === "phishing";
  const v = inverted ? 100 - score : score;
  if (v >= 75) return "var(--neon)";
  if (v >= 50) return "var(--cyber)";
  if (v >= 25) return "var(--warn)";
  return "var(--danger)";
}

function buildTrend(reports: ReportEntry[]) {
  const days: { day: string; scans: number }[] = [];
  const now = new Date();
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now);
    d.setDate(d.getDate() - i);
    d.setHours(0, 0, 0, 0);
    const next = d.getTime() + 86400000;
    const count = reports.filter((r) => r.createdAt >= d.getTime() && r.createdAt < next).length;
    days.push({ day: d.toLocaleDateString(undefined, { weekday: "short" }), scans: count });
  }
  return days;
}