import { createFileRoute } from "@tanstack/react-router";
import { useState } from "react";
import { motion } from "framer-motion";
import { Fish, Globe, Loader2, AlertTriangle, CheckCircle2 } from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";
import { ScoreGauge } from "@/components/cg/ScoreGauge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { api, type PhishingResult } from "@/lib/api";
import { saveReport } from "@/lib/reports";
import { RecommendationsList, ReportActions } from "./url-analyzer";

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
        title: `Phishing scan — ${r.verdict}`,
        target: r.url,
        score: r.risk_score,
        summary: `${r.indicators.filter((i) => i.triggered).length} indicators triggered`,
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
              <ScoreGauge value={result.risk_score} label="Risk score" inverted />
              <div className="mt-3 text-center text-sm">
                Verdict: <span className="font-semibold text-neon">{result.verdict}</span>
              </div>
            </div>
            <div className="glass rounded-xl p-6 lg:col-span-2">
              <h3 className="mb-4 font-semibold">Indicators</h3>
              <ul className="space-y-2">
                {result.indicators.map((ind, i) => (
                  <li
                    key={i}
                    className="flex items-start gap-3 rounded-lg border border-border bg-background/40 p-3 text-sm"
                  >
                    {ind.triggered ? (
                      <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-danger" />
                    ) : (
                      <CheckCircle2 className="mt-0.5 h-4 w-4 flex-shrink-0 text-neon" />
                    )}
                    <div className="flex-1">
                      <div className="flex items-center justify-between gap-3">
                        <span className="font-medium">{ind.name}</span>
                        <span className="font-mono text-[10px] text-muted-foreground">w={ind.weight}</span>
                      </div>
                      <div className="mt-0.5 text-xs text-muted-foreground">{ind.description}</div>
                    </div>
                  </li>
                ))}
              </ul>
            </div>
          </div>

          {result.findings.length > 0 && (
            <div className="glass rounded-xl p-6">
              <h3 className="mb-3 font-semibold">Explanation</h3>
              <ul className="space-y-2 text-sm">
                {result.findings.map((f, i) => (
                  <li key={i} className="flex gap-2">
                    <span className="mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-warn" />
                    <span>{f}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}

          <RecommendationsList items={result.recommendations} />
          <ReportActions payload={{ kind: "phishing", target: result.url, data: result }} />
        </motion.div>
      )}
    </AppShell>
  );
}