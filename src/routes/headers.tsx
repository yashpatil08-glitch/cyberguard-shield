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
import { api, type HeadersResult } from "@/lib/api";
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

const KEY_HEADERS = [
  { key: "strict-transport-security", label: "HSTS" },
  { key: "content-security-policy", label: "Content-Security-Policy" },
  { key: "x-frame-options", label: "X-Frame-Options" },
  { key: "x-content-type-options", label: "X-Content-Type-Options" },
  { key: "referrer-policy", label: "Referrer-Policy" },
  { key: "permissions-policy", label: "Permissions-Policy" },
];

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
      saveReport({
        kind: "headers",
        title: `Headers audit — Grade ${r.grade}`,
        target: r.url,
        score: r.score,
        summary: `${r.present.length}/${r.present.length + r.missing.length} present`,
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
              <ScoreGauge value={result.score} label={`Grade ${result.grade}`} />
            </div>
            <div className="glass rounded-xl p-6 lg:col-span-2">
              <h3 className="mb-4 font-semibold">Header status</h3>
              <ul className="grid gap-2 sm:grid-cols-2">
                {KEY_HEADERS.map((h) => {
                  const present = Boolean(result.headers[h.key]);
                  return (
                    <li
                      key={h.key}
                      className="flex items-center gap-3 rounded-lg border border-border bg-background/40 p-3 text-sm"
                    >
                      {present ? (
                        <CheckCircle2 className="h-4 w-4 flex-shrink-0 text-neon" />
                      ) : (
                        <XCircle className="h-4 w-4 flex-shrink-0 text-danger" />
                      )}
                      <div className="min-w-0">
                        <div className="font-medium">{h.label}</div>
                        <div className="truncate font-mono text-xs text-muted-foreground">
                          {result.headers[h.key] ?? "missing"}
                        </div>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </div>
          </div>

          {result.missing.length > 0 && (
            <div className="glass rounded-xl p-6">
              <h3 className="mb-3 font-semibold">Missing headers</h3>
              <div className="flex flex-wrap gap-2">
                {result.missing.map((m) => (
                  <span
                    key={m}
                    className="rounded-md border border-danger/40 px-2 py-1 font-mono text-xs text-danger"
                  >
                    {m}
                  </span>
                ))}
              </div>
            </div>
          )}

          <RecommendationsList items={result.recommendations.map((r) => `${r.header}: ${r.message}`)} />
          <ReportActions payload={{ kind: "headers", target: result.url, data: result }} />
        </motion.div>
      )}
    </AppShell>
  );
}