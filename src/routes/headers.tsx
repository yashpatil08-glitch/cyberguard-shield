import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { motion } from "framer-motion";
import { Globe, Loader2, ShieldCheck, CheckCircle2, XCircle } from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";
import { ScoreGauge } from "@/components/cg/ScoreGauge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { api, type HeadersResult, type HeaderFinding } from "@/lib/api";
import { saveReport } from "@/lib/reports";
import { RecommendationsList, ReportActions } from "./url-analyzer";

export const Route = createFileRoute("/headers")({
  head: () => ({
    meta: [
      { title: "Security Headers — CyberGuard" },
      { name: "description", content: "Audit HSTS, CSP, X-Frame-Options, Referrer-Policy, Permissions-Policy and more." },
    ],
  }),
  component: HeadersPage,
});

function HeadersPage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<HeadersResult | null>(null);

  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const r = await api.checkHeaders(url.trim());
      setResult(r);
      const findings = r.findings ?? [];
      const present = findings.filter((f) => f.present).length;
      saveReport({
        kind: "headers",
        title: `Headers audit — Grade ${r.grade ?? "?"}`,
        target: r.url,
        score: r.score ?? 0,
        summary: `${present}/${findings.length} present`,
        data: r,
      });
      toast.success("Headers checked");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AppShell>
      <PageHeader
        eyebrow="Hardening"
        title="Security Headers Checker"
        description="Inspect the response headers of any URL and grade their security posture."
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
          {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />}
          Check headers
        </Button>
      </form>

      {result && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="mt-6 space-y-6">
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="glass flex flex-col items-center justify-center rounded-xl p-6">
              <ScoreGauge value={result.score ?? 0} label={`Grade ${result.grade ?? "?"}`} />
              <p className="mt-2 text-sm">
                Level: <span className="font-semibold">{result.risk_level ?? "—"}</span>
              </p>
            </div>
            <div className="glass rounded-xl p-6 lg:col-span-2">
              <h3 className="mb-4 font-semibold">Header status</h3>
              <ul className="grid gap-2 sm:grid-cols-2">
                {(result.findings ?? []).map((h: HeaderFinding) => {
                  const present = !!h.present;
                  return (
                    <li
                      key={h.header}
                      className="flex items-start gap-3 rounded-lg border border-border bg-background/40 p-3 text-sm"
                    >
                      {present ? (
                        <CheckCircle2 className={`mt-0.5 h-4 w-4 flex-shrink-0 ${h.status === "weak" ? "text-warn" : "text-neon"}`} />
                      ) : (
                        <XCircle className="mt-0.5 h-4 w-4 flex-shrink-0 text-danger" />
                      )}
                      <div className="min-w-0 flex-1">
                        <div className="flex items-center justify-between gap-2">
                          <span className="truncate font-medium">{h.header}</span>
                          {typeof h.score === "number" && typeof h.max_score === "number" && (
                            <span className="font-mono text-[10px] text-muted-foreground">
                              {h.score}/{h.max_score}
                            </span>
                          )}
                        </div>
                        <div className="truncate font-mono text-xs text-muted-foreground" title={h.value ?? ""}>
                          {h.value ?? "missing"}
                        </div>
                        {h.note && (
                          <div className="mt-1 text-xs text-muted-foreground">{h.note}</div>
                        )}
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>

          {(() => {
            const missing = (result.findings ?? []).filter((f) => !f.present);
            if (!missing.length) return null;
            return (
              <div className="glass rounded-xl p-6">
                <h3 className="mb-3 font-semibold">Missing headers</h3>
                <div className="flex flex-wrap gap-2">
                  {missing.map((m) => (
                    <span
                      key={m.header}
                      className="rounded-md border border-danger/40 px-2 py-1 font-mono text-xs text-danger"
                    >
                      {m.header}
                    </span>
                  ))}
                </div>
              </div>
            );
          })()}

          <RecommendationsList items={result.recommendations ?? []} />
          <ReportActions payload={{ kind: "headers", target: result.url, data: result }} />
        </motion.div>
      )}
    </AppShell>
  );
}