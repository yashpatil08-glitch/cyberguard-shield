import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Eye, EyeOff, KeyRound, Loader2, Shield } from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { toast } from "sonner";
import { api, type PasswordAnalysisResult } from "@/lib/api";
import { saveReport } from "@/lib/reports";

export const Route = createFileRoute("/password")({
  head: () => ({
    meta: [
      { title: "Password Strength — CyberGuard" },
      { name: "description", content: "Estimate entropy, strength tier, and crack-time for a password. Passwords are never stored." },
    ],
  }),
  component: PasswordPage,
});

function PasswordPage() {
  const [pwd, setPwd] = useState("");
  const [show, setShow] = useState(false);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<PasswordAnalysisResult | null>(null);

  // Debounced analysis
  useEffect(() => {
    if (!pwd) {
      setResult(null);
      return;
    }
    const t = setTimeout(async () => {
      setLoading(true);
      try {
        const r = await api.analyzePassword(pwd);
        setResult(r);
      } catch (e) {
        toast.error((e as Error).message);
      } finally {
        setLoading(false);
      }
    }, 400);
    return () => clearTimeout(t);
  }, [pwd]);

  const saveAsReport = () => {
    if (!result) return;
    saveReport({
      kind: "password",
      title: `Password analysis — ${result.strength}`,
      target: `${result.length} chars · ${result.entropy} bits`,
      score: result.score,
      summary: result.crack_time_estimate,
      data: { ...result },
    });
    toast.success("Saved to reports (password value not stored)");
  };

  const color = useMemo(() => {
    const s = result?.score ?? 0;
    if (s >= 80) return "var(--neon)";
    if (s >= 60) return "var(--cyber)";
    if (s >= 40) return "var(--warn)";
    return "var(--danger)";
  }, [result]);

  return (
    <AppShell>
      <PageHeader
        eyebrow="Identity"
        title="Password Strength Analyzer"
        description="Entropy, character-class coverage, common-pattern detection, and crack-time estimate. Passwords never leave the request body — nothing is stored."
      />

      <div className="glass rounded-xl p-6">
        <label className="mb-2 block text-xs uppercase tracking-widest text-muted-foreground">
          Password
        </label>
        <div className="flex gap-2">
          <div className="flex flex-1 items-center gap-2 rounded-lg border border-border bg-background/50 px-3">
            <KeyRound className="h-4 w-4 text-muted-foreground" />
            <Input
              type={show ? "text" : "password"}
              value={pwd}
              onChange={(e) => setPwd(e.target.value)}
              placeholder="Type or paste a password"
              autoComplete="new-password"
              className="border-0 bg-transparent shadow-none focus-visible:ring-0"
            />
            <button
              type="button"
              onClick={() => setShow((v) => !v)}
              className="text-muted-foreground hover:text-foreground"
              aria-label={show ? "Hide" : "Show"}
            >
              {show ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </button>
          </div>
          {loading && <Loader2 className="h-4 w-4 animate-spin self-center text-muted-foreground" />}
        </div>

        <div className="mt-6">
          <div className="mb-2 flex items-center justify-between text-xs">
            <span className="text-muted-foreground">Strength</span>
            <span className="font-mono" style={{ color }}>
              {result?.strength ?? "—"}
            </span>
          </div>
          <div className="h-3 overflow-hidden rounded-full bg-secondary">
            <motion.div
              initial={{ width: 0 }}
              animate={{ width: `${result?.score ?? 0}%` }}
              transition={{ duration: 0.6, ease: "easeOut" }}
              style={{
                background: `linear-gradient(90deg, ${color}, color-mix(in oklch, ${color} 60%, white))`,
                boxShadow: `0 0 18px ${color}`,
              }}
              className="h-full"
            />
          </div>
        </div>
      </div>

      {result && (
        <motion.div initial={{ opacity: 0, y: 12 }} animate={{ opacity: 1, y: 0 }} className="mt-6 grid gap-4 md:grid-cols-3">
          <Stat label="Length" value={result.length} unit="chars" />
          <Stat label="Entropy" value={result.entropy} unit="bits" />
          <Stat label="Crack time" value={result.crack_time_estimate} />

          <div className="glass rounded-xl p-6 md:col-span-2">
            <h3 className="mb-3 font-semibold">Character composition</h3>
            <div className="grid grid-cols-2 gap-3 text-sm sm:grid-cols-4">
              <Chip ok={result.has_uppercase} label="Uppercase" />
              <Chip ok={result.has_lowercase} label="Lowercase" />
              <Chip ok={result.has_digits} label="Digits" />
              <Chip ok={result.has_special} label="Symbols" />
              <Chip ok={!result.has_repeated_chars} label="No repeats" />
              <Chip ok={!result.has_sequential_chars} label="No sequences" />
              <Chip ok={!result.is_common_password} label="Not common" />
              <Chip ok={result.charset_size >= 70} label={`Charset ${result.charset_size}`} />
            </div>
          </div>

          <div className="glass rounded-xl p-6">
            <Shield className="mb-2 h-5 w-5 text-neon" />
            <h3 className="font-semibold">Score</h3>
            <div className="mt-1 text-4xl font-semibold tabular-nums" style={{ color }}>
              {result.score}
              <span className="text-base text-muted-foreground">/100</span>
            </div>
            <Button onClick={saveAsReport} variant="outline" size="sm" className="mt-4 w-full">
              Save to reports
            </Button>
          </div>

          {result.suggestions.length > 0 && (
            <div className="glass rounded-xl p-6 md:col-span-3">
              <h3 className="mb-3 font-semibold">Suggestions</h3>
              <ul className="space-y-2 text-sm">
                {result.suggestions.map((s, i) => (
                  <li key={i} className="flex items-start gap-2">
                    <span className="mt-1 h-1.5 w-1.5 flex-shrink-0 rounded-full bg-cyber" />
                    <span>{s}</span>
                  </li>
                ))}
              </ul>
            </div>
          )}
        </motion.div>
      )}
    </AppShell>
  );
}

function Stat({ label, value, unit }: { label: string; value: string | number; unit?: string }) {
  return (
    <div className="glass rounded-xl p-5">
      <div className="text-xs uppercase tracking-widest text-muted-foreground">{label}</div>
      <div className="mt-2 text-2xl font-semibold tabular-nums">
        {value} {unit && <span className="text-sm text-muted-foreground">{unit}</span>}
      </div>
    </div>
  );
}
function Chip({ ok, label }: { ok: boolean; label: string }) {
  return (
    <div
      className="flex items-center gap-2 rounded-md border px-3 py-2 text-xs"
      style={{
        borderColor: ok ? "color-mix(in oklch, var(--neon) 40%, transparent)" : "var(--border)",
        color: ok ? "var(--neon)" : "var(--muted-foreground)",
      }}
    >
      <span
        className="h-1.5 w-1.5 rounded-full"
        style={{ background: ok ? "var(--neon)" : "var(--muted-foreground)" }}
      />
      {label}
    </div>
  );
}