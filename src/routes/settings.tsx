import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useState } from "react";
import { motion } from "framer-motion";
import { Save, CheckCircle2, XCircle, Loader2, Server, User2, Palette } from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { loadSettings, saveSettings, API_ROUTES } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/settings")({
  head: () => ({
    meta: [
      { title: "Settings — CyberGuard" },
      { name: "description", content: "Configure your CyberGuard backend URL, profile, and theme." },
    ],
  }),
  component: SettingsPage,
});

function SettingsPage() {
  const [s, setS] = useState({ apiUrl: "", profileName: "", profileEmail: "" });
  const [status, setStatus] = useState<"idle" | "checking" | "ok" | "fail">("idle");

  useEffect(() => {
    setS(loadSettings());
  }, []);

  const save = () => {
    saveSettings(s);
    toast.success("Settings saved — API URL is active immediately.");
  };

  const test = async () => {
    if (!s.apiUrl) {
      toast.error("Enter a backend URL first");
      return;
    }
    setStatus("checking");
    try {
      const res = await fetch(`${s.apiUrl.replace(/\/$/, "")}/api/health`, { method: "GET" });
      setStatus(res.ok ? "ok" : "fail");
    } catch {
      setStatus("fail");
    }
  };

  return (
    <AppShell>
      <PageHeader
        eyebrow="Workspace"
        title="Settings"
        description="Connect your hosted FastAPI backend and configure your workspace."
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} className="glass rounded-xl p-6 lg:col-span-2">
          <div className="mb-4 flex items-center gap-2">
            <Server className="h-5 w-5 text-neon" />
            <h3 className="font-semibold">Backend API</h3>
          </div>
          <Field label="FastAPI base URL">
            <Input
              value={s.apiUrl}
              onChange={(e) => setS({ ...s, apiUrl: e.target.value })}
              placeholder="https://your-cyberguard-api.example.com"
            />
          </Field>
          <div className="mt-3 flex items-center gap-2">
            <Button onClick={test} variant="outline" size="sm" disabled={status === "checking"}>
              {status === "checking" ? (
                <Loader2 className="mr-2 h-4 w-4 animate-spin" />
              ) : status === "ok" ? (
                <CheckCircle2 className="mr-2 h-4 w-4 text-neon" />
              ) : status === "fail" ? (
                <XCircle className="mr-2 h-4 w-4 text-danger" />
              ) : null}
              Test connection
            </Button>
            <span className="text-xs text-muted-foreground">
              {status === "ok" && "Backend reachable"}
              {status === "fail" && "Could not reach backend (check CORS)"}
            </span>
          </div>

          <div className="mt-6 rounded-lg border border-border bg-background/40 p-4 text-xs">
            <div className="mb-2 font-mono uppercase tracking-widest text-muted-foreground">Expected endpoints</div>
            <ul className="space-y-1 font-mono">
              {Object.entries(API_ROUTES).map(([k, v]) => (
                <li key={k}>
                  <span className="text-neon">POST</span> {v}{" "}
                  <span className="text-muted-foreground">// {k}</span>
                </li>
              ))}
            </ul>
            <p className="mt-3 text-muted-foreground">
              Recommended: set <code className="rounded bg-secondary px-1">VITE_CYBERGUARD_API_URL</code> as a build-time
              env var, or mount a runtime config via your hosting provider. Enable CORS for this origin in FastAPI.
            </p>
          </div>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.05 }} className="glass rounded-xl p-6">
          <div className="mb-4 flex items-center gap-2">
            <User2 className="h-5 w-5 text-cyber" />
            <h3 className="font-semibold">Profile</h3>
          </div>
          <Field label="Display name">
            <Input
              value={s.profileName}
              onChange={(e) => setS({ ...s, profileName: e.target.value })}
            />
          </Field>
          <Field label="Email">
            <Input
              type="email"
              value={s.profileEmail}
              onChange={(e) => setS({ ...s, profileEmail: e.target.value })}
            />
          </Field>
        </motion.div>

        <motion.div initial={{ opacity: 0, y: 8 }} animate={{ opacity: 1, y: 0 }} transition={{ delay: 0.1 }} className="glass rounded-xl p-6 lg:col-span-3">
          <div className="mb-4 flex items-center gap-2">
            <Palette className="h-5 w-5 text-warn" />
            <h3 className="font-semibold">Theme</h3>
          </div>
          <p className="text-sm text-muted-foreground">
            CyberGuard ships with a single curated dark theme — black, dark gray, neon green, and cyber blue.
            A light mode is intentionally disabled to preserve contrast for long analysis sessions.
          </p>
        </motion.div>
      </div>

      <div className="mt-6 flex justify-end">
        <Button onClick={save} className="bg-neon text-primary-foreground hover:bg-neon/90">
          <Save className="mr-2 h-4 w-4" /> Save settings
        </Button>
      </div>
    </AppShell>
  );
}

function Field({ label, children }: { label: string; children: React.ReactNode }) {
  return (
    <label className="mt-3 block">
      <div className="mb-1.5 text-xs uppercase tracking-widest text-muted-foreground">{label}</div>
      {children}
    </label>
  );
}