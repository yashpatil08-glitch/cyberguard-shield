import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { motion } from "framer-motion";
import { Fish, Globe, Loader2, AlertTriangle, CheckCircle2, ShieldCheck } from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";
import { ScoreGauge } from "@/components/cg/ScoreGauge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { api, type PhishingResult } from "@/lib/api";
import { saveReport } from "@/lib/reports";
import { RecommendationsList, ReportActions, FindingsList } from "./url-analyzer";

export const Route = createFileRoute("/phishing")({
  head: () => ({
    meta: [
      { title: "Phishing Detector — CyberGuard" },
      { name: "description", content: "Detect suspicious URL indicators and estimate phishing risk." },
    ],
  }),
  component: PhishingPage,
});

function PhishingPage() {
  const [url, setUrl] = useState("");
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PhishingResult | null>(null);

  const run = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!url.trim()) return;
    setLoading(true);
    setResult(null);
    try {
      const r = await api.analyzePhishing(url.trim());
      setResult(r);
      saveReport({
        kind: "phishing",
        title: `Phishing scan — ${r.risk_level ?? "Unknown"}`,
        target: r.url,
        score: r.score ?? 0,
        summary: `${(r.findings ?? []).length} indicators · ${r.is_phishing ? "Likely phishing" : "Looks safe"}`,
        data: r,
      });
      toast.success("Phishing analysis complete");
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setLoading(false);
    }
  };

  return (
    <AppShell>
      <PageHeader
        eyebrow="Threat"
        title="Phishing Detector"
        description="Heuristic analysis of URL structure, domain reputation patterns, and impersonation indicators."
      />

      <form onSubmit={run} className="glass flex flex-col gap-3 rounded-xl p-4 md:flex-row">
        <div className="flex flex-1 items-center gap-2 rounded-lg border border-border bg-background/50 px-3">
          <Globe className="h-4 w-4 text-muted-foreground" />
          <Input
            value={url}
            onChange={(e) => setUrl(e.target.value)}
            placeholder="Paste suspicious URL"
            className="border-0 bg-transparent shadow-none focus-visible:ring-0"
          />
        </div>
        <Button type="submit" disabled={loading} className="bg-neon text-primary-foreground hover:bg-neon/90">
          {loading ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Fish className="mr-2 h-4 w-4" />}
          Analyze
        </Button>
      </form>

      {result && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="mt-6 space-y-6">
          <div className="grid gap-6 lg:grid-cols-3">
            <div className="glass flex flex-col items-center justify-center rounded-xl p-6">
              <ScoreGauge value={result.score ?? 0} label="Risk score" inverted />
              <div className="mt-3 text-center text-sm">
                Level: <span className="font-semibold">{result.risk_level ?? "—"}</span>
              </div>
              <div className="mt-1 text-center text-xs text-muted-foreground">
                Confidence: {result.confidence ?? "—"}
              </div>
            </div>
            <div className="glass rounded-xl p-6 lg:col-span-2">
              <h3 className="mb-3 flex items-center gap-2 font-semibold">
                {result.is_phishing ? (
                  <>
                    <AlertTriangle className="h-4 w-4 text-danger" /> Likely phishing
                  </>
                ) : (
                  <>
                    <CheckCircle2 className="h-4 w-4 text-neon" /> No phishing indicators
                  </>
                )}
              </h3>
              <p className="text-sm text-muted-foreground">{result.explanation ?? "—"}</p>
              {result.checks_performed?.length ? (
                <div className="mt-4">
                  <div className="mb-2 flex items-center gap-2 text-xs uppercase tracking-widest text-muted-foreground">
                    <ShieldCheck className="h-3 w-3" /> Checks performed ({result.checks_performed.length})
                  </div>
                  <div className="flex flex-wrap gap-1.5">
                    {result.checks_performed.map((c) => (
                      <span
                        key={c}
                        className="rounded-md border border-border bg-background/40 px-2 py-0.5 font-mono text-[10px] text-muted-foreground"
                      >
                        {c}
                      </span>
                    ))}
                  </div>
                </div>
              ) : null}
            </div>
          </div>

          <FindingsList findings={result.findings ?? []} />
          <RecommendationsList items={result.recommendations ?? []} />
          <ReportActions payload={{ kind: "phishing", target: result.url, data: result }} />
        </motion.div>
      )}
    </AppShell>
  );
}