import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { motion, AnimatePresence } from "framer-motion";
import { Globe, Loader2, Lock, ShieldAlert, CheckCircle2, XCircle, FileDown } from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";
import { ScoreGauge } from "@/components/cg/ScoreGauge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { api, type UrlAnalysisResult } from "@/lib/api";
import { saveReport } from "@/lib/reports";

export const Route = createFileRoute("/url-analyzer")({
  head: () => ({
    meta: [
      { title: "URL Security Analyzer — CyberGuard" },
      { name: "description", content: "Analyze a URL for HTTPS, SSL, DNS, WHOIS, redirects and overall risk score." },
    ],
  }),
  component: UrlAnalyzerPage,
});

function UrlAnalyzerPage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<UrlAnalysisResult | null>(null);

  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const r = await api.analyzeUrl(url.trim());
      setResult(r);
      saveReport({
        kind: "url",
        title: `URL scan — ${new URL(r.url).hostname}`,
        target: r.url,
        score: r.risk_score,
        summary: `${r.findings.length} findings`,
        data: r,
      });
      toast.success("Analysis complete");
    } catch (e: unknown) {
      toast.error((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AppShell>
      <PageHeader
        eyebrow="Recon"
        title="URL Security Analyzer"
        description="Inspect HTTPS, SSL/TLS, DNS, WHOIS, redirects, and compute a risk score with recommendations."
      />

      <form onSubmit={run} className="glass flex flex-col gap-3 rounded-xl p-4 md:flex-row">
        <div className="flex flex-1 items-center gap-2 rounded-lg border border-border bg-background/50 px-3">
          <Globe className="h-4 w-4 text-muted-foreground" />
          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="https://example.com"
            className="border-0 bg-transparent shadow-none focus-visible:ring-0"
          />
        </div>
        <Button type="submit" disabled={loading} className="bg-neon text-primary-foreground hover:bg-neon/90">
          {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : null}
          Analyze
        </Button>
      </form>

      <AnimatePresence mode="wait">
        {loading && (
          <motion.div
            key="loading"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            className="mt-6 grid gap-4 md:grid-cols-3"
          >
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="glass h-32 animate-pulse rounded-xl" />
            ))}
          </motion.div>
        )}
        {result && (
          <motion.div
            key="result"
            initial={{ opacity: 0, y: 16 }}
            animate={{ opacity: 1, y: 0 }}
            className="mt-6 space-y-6"
          >
            <div className="grid gap-6 lg:grid-cols-3">
              <div className="glass flex flex-col items-center justify-center rounded-xl p-6">
                <ScoreGauge value={result.risk_score} label="Risk score" inverted />
                <p className="mt-3 text-center text-xs text-muted-foreground">
                  Lower is safer · 0–100 scale
                </p>
              </div>
              <div className="glass rounded-xl p-6 lg:col-span-2">
                <h3 className="mb-4 font-semibold">Connection</h3>
                <div className="grid gap-3 sm:grid-cols-2">
                  <Fact ok={result.is_https} label="HTTPS" value={result.is_https ? "Enabled" : "Not enabled"} icon={Lock} />
                  <Fact
                    ok={result.ssl?.valid}
                    label="SSL certificate"
                    value={
                      result.ssl
                        ? result.ssl.valid
                          ? `Valid · ${result.ssl.days_remaining ?? "?"}d remaining`
                          : "Invalid"
                        : "Unavailable"
                    }
                  />
                  <Fact
                    label="Issuer"
                    value={result.ssl?.issuer ?? "—"}
                    info
                  />
                  <Fact
                    label="Expires"
                    value={result.ssl?.expires ?? "—"}
                    info
                  />
                </div>
              </div>
            </div>

            <div className="grid gap-6 md:grid-cols-2">
              <div className="glass rounded-xl p-6">
                <h3 className="mb-4 font-semibold">DNS records</h3>
                <RecordList label="A" items={result.dns?.a} />
                <RecordList label="MX" items={result.dns?.mx} />
                <RecordList label="NS" items={result.dns?.ns} />
              </div>
              <div className="glass rounded-xl p-6">
                <h3 className="mb-4 font-semibold">WHOIS</h3>
                <KV k="Registrar" v={result.whois?.registrar} />
                <KV k="Created" v={result.whois?.created} />
                <KV k="Expires" v={result.whois?.expires} />
                <KV k="Country" v={result.whois?.country} />
              </div>
            </div>

            {result.redirects && result.redirects.length > 0 && (
              <div className="glass rounded-xl p-6">
                <h3 className="mb-3 font-semibold">Redirect chain</h3>
                <ol className="space-y-2 font-mono text-xs">
                  {result.redirects.map((r, i) => (
                    <li key={i} className="flex items-center gap-2">
                      <span className="text-neon">{i + 1}.</span>
                      <span className="truncate">{r}</span>
                    </li>
                  ))}
                </ol>
              </div>
            )}

            <FindingsList findings={result.findings} />
            <RecommendationsList items={result.recommendations} />

            <ReportActions payload={{ kind: "url", target: result.url, data: result }} />
          </motion.div>
        )}
      </AnimatePresence>
    </AppShell>
  );
}

function Fact({
  ok,
  label,
  value,
  icon: Icon,
  info,
}: {
  ok?: boolean;
  label: string;
  value: string;
  icon?: typeof Lock;
  info?: boolean;
}) {
  const IconCmp = info ? null : ok ? CheckCircle2 : XCircle;
  const color = info ? "text-muted-foreground" : ok ? "text-neon" : "text-danger";
  return (
    <div className="flex items-start gap-3 rounded-lg border border-border bg-background/40 p-3">
      {Icon ? <Icon className={`mt-0.5 h-4 w-4 ${color}`} /> : IconCmp ? <IconCmp className={`mt-0.5 h-4 w-4 ${color}`} /> : null}
      <div className="min-w-0">
        <div className="text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
        <div className="truncate text-sm">{value}</div>
      </div>
    </div>
  );
}
function RecordList({ label, items }: { label: string; items?: string[] }) {
  return (
    <div className="mb-3">
      <div className="mb-1 text-[10px] font-mono uppercase tracking-widest text-muted-foreground">{label}</div>
      {items && items.length ? (
        <ul className="space-y-1 font-mono text-xs">
          {items.map((it, i) => <li key={i} className="truncate">{it}</li>)}
        </ul>
      ) : (
        <div className="text-xs text-muted-foreground">—</div>
      )}
    </div>
  );
}
function KV({ k, v }: { k: string; v?: string }) {
  return (
    <div className="flex justify-between gap-3 border-b border-border/50 py-2 text-sm last:border-0">
      <span className="text-muted-foreground">{k}</span>
      <span className="truncate font-mono text-xs">{v ?? "—"}</span>
    </div>
  );
}

export function FindingsList({ findings }: { findings: { severity: string; message: string }[] }) {
  if (!findings.length) return null;
  return (
    <div className="glass rounded-xl p-6">
      <h3 className="mb-3 flex items-center gap-2 font-semibold">
        <ShieldAlert className="h-4 w-4 text-warn" /> Findings ({findings.length})
      </h3>
      <ul className="space-y-2">
        {findings.map((f, i) => {
          const colors: Record<string, string> = {
            high: "var(--danger)",
            medium: "var(--warn)",
            low: "var(--cyber)",
            info: "var(--muted-foreground)",
          };
          const c = colors[f.severity] ?? "var(--muted-foreground)";
          return (
            <li key={i} className="flex items-start gap-3 rounded-md border border-border p-3 text-sm">
              <span
                className="rounded px-1.5 py-0.5 text-[10px] font-mono uppercase"
                style={{ color: c, border: `1px solid color-mix(in oklch, ${c} 40%, transparent)` }}
              >
                {f.severity}
              </span>
              <span>{f.message}</span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}

export function RecommendationsList({ items }: { items: string[] }) {
  if (!items.length) return null;
  return (
    <div className="glass rounded-xl p-6">
      <h3 className="mb-3 font-semibold">Recommendations</h3>
      <ul className="space-y-2 text-sm">
        {items.map((it, i) => (
          <li key={i} className="flex items-start gap-2">
            <span className="mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-neon" />
            <span>{it}</span>
          </li>
        ))}
      </ul>
    </div>
  );
}

export function ReportActions({ payload }: { payload: unknown }) {
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true);
    try {
      const blob = await api.generateReport(payload);
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cyberguard-report-${Date.now()}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
      toast.success("Report downloaded");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <div className="flex justify-end">
      <Button variant="outline" onClick={download} disabled={busy}>
        {busy ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <FileDown className="mr-2 h-4 w-4" />}
        Generate PDF report
      </Button>
    </div>
  );
}