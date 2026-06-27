import { createFileRoute } from "@tanstack/react-router";
import { ShieldHalf, AlertTriangle, Cpu, GitBranch } from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";

export const Route = createFileRoute("/about")({
  head: () => ({
    meta: [
      { title: "About — CyberGuard" },
      { name: "description", content: "About CyberGuard, an educational cybersecurity toolkit, and its responsible-use disclaimer." },
    ],
  }),
  component: AboutPage,
});

function AboutPage() {
  return (
    <AppShell>
      <PageHeader
        eyebrow="About"
        title={<span className="text-gradient-cyber">CyberGuard</span>}
        description="A modern, modular cybersecurity toolkit built for analysts, students, and developers who need fast, reliable surface-level security checks."
      />

      <div className="grid gap-6 lg:grid-cols-3">
        <div className="glass rounded-xl p-6">
          <ShieldHalf className="mb-3 h-6 w-6 text-neon" />
          <h3 className="mb-2 font-semibold">Mission</h3>
          <p className="text-sm text-muted-foreground">
            Make foundational security analysis accessible — URL recon, password hygiene, header
            hardening, and phishing triage — in one polished interface.
          </p>
        </div>
        <div className="glass rounded-xl p-6">
          <Cpu className="mb-3 h-6 w-6 text-cyber" />
          <h3 className="mb-2 font-semibold">Architecture</h3>
          <p className="text-sm text-muted-foreground">
            React + TanStack Start frontend talks to a FastAPI Python backend that owns all analysis
            logic — URL analyzer, password scorer, header checker, phishing detector, and PDF generator.
          </p>
        </div>
        <div className="glass rounded-xl p-6">
          <GitBranch className="mb-3 h-6 w-6 text-warn" />
          <h3 className="mb-2 font-semibold">Extensible</h3>
          <p className="text-sm text-muted-foreground">
            New tools — port scanner, hash generator, JWT decoder, threat intel — slot in as
            additional routes and FastAPI endpoints without touching existing logic.
          </p>
        </div>
      </div>

      <div className="mt-8 glass rounded-xl border-l-4 border-warn p-6">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-6 w-6 flex-shrink-0 text-warn" />
          <div>
            <h3 className="font-semibold text-warn">Responsible-use disclaimer</h3>
            <p className="mt-2 text-sm text-muted-foreground">
              This application must only be used for authorized security testing and educational
              purposes. Scanning, probing, or analyzing systems you do not own or do not have explicit
              written permission to assess is illegal in most jurisdictions. By using CyberGuard you
              accept full responsibility for your actions.
            </p>
          </div>
        </div>
      </div>

      <div className="mt-8 grid gap-6 md:grid-cols-2">
        <div className="glass rounded-xl p-6">
          <h3 className="mb-3 font-semibold">Powered by</h3>
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li>• React 19 · TanStack Start · TypeScript</li>
            <li>• TailwindCSS · shadcn/ui · Framer Motion · Recharts</li>
            <li>• Python · FastAPI (your hosted backend)</li>
          </ul>
        </div>
        <div className="glass rounded-xl p-6">
          <h3 className="mb-3 font-semibold">Roadmap</h3>
          <ul className="space-y-2 text-sm text-muted-foreground">
            <li>• Port scanner & DNS/WHOIS lookups</li>
            <li>• Hash generator & JWT decoder</li>
            <li>• Base64 / log analyzer / packet analyzer</li>
            <li>• Threat intel via VirusTotal integration</li>
          </ul>
        </div>
      </div>
    </AppShell>
  );
}