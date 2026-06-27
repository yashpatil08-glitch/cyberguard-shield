import { createFileRoute } from "@tanstack/react-router";
import {
  Github,
  Linkedin,
  Mail,
  Phone,
  Download,
  GraduationCap,
  Briefcase,
  Target,
  AlertTriangle,
  User,
} from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";

export const Route = createFileRoute("/about")({
  head: () => ({
    meta: [
      { title: "About — CyberGuard" },
      { name: "description", content: "About the developer behind CyberGuard — bio, skills, education, and contact." },
    ],
  }),
  component: AboutPage,
});

const SKILLS = [
  "Python", "FastAPI", "React", "TypeScript", "TanStack Start",
  "TailwindCSS", "PostgreSQL", "Docker", "Penetration Testing",
  "OWASP Top 10", "Network Security", "Cryptography",
];

function AboutPage() {
  return (
    <AppShell>
      <PageHeader
        eyebrow="About the developer"
        title={<span className="text-gradient-cyber">Building CyberGuard</span>}
        description="A premium personal profile of the engineer behind this security suite."
      />

      {/* Profile hero */}
      <div className="glass relative overflow-hidden rounded-2xl p-6 md:p-10">
        <div className="pointer-events-none absolute -right-20 -top-20 h-72 w-72 rounded-full bg-primary/20 blur-3xl" />
        <div className="pointer-events-none absolute -bottom-24 -left-10 h-72 w-72 rounded-full bg-accent/20 blur-3xl" />

        <div className="relative grid gap-8 md:grid-cols-[auto_1fr] md:items-center">
          <div className="relative mx-auto md:mx-0">
            <div className="relative h-36 w-36 overflow-hidden rounded-2xl border border-border bg-gradient-to-br from-primary/20 to-accent/20 md:h-44 md:w-44">
              <div className="flex h-full w-full items-center justify-center text-muted-foreground">
                <User className="h-12 w-12" />
              </div>
            </div>
            <span className="absolute -bottom-2 -right-2 rounded-full border border-border bg-card px-3 py-1 text-[10px] font-medium uppercase tracking-[0.18em] text-muted-foreground">
              Photo
            </span>
          </div>

          <div>
            <div className="text-xs font-medium uppercase tracking-[0.22em] text-primary">
              Security Engineer · Full-stack Developer
            </div>
            <h2 className="mt-2 text-3xl font-semibold tracking-tight md:text-4xl">Your Name</h2>
            <p className="mt-3 max-w-2xl text-sm leading-relaxed text-muted-foreground md:text-base">
              Short professional bio — what you build, the security problems you care about, and the
              tools you reach for. Replace this paragraph with your own story.
            </p>

            <div className="mt-6 flex flex-wrap gap-2.5">
              <a className="btn-primary-gradient inline-flex items-center gap-2 rounded-full px-4 py-2 text-sm font-medium" href="#">
                <Download className="h-4 w-4" /> Download résumé
              </a>
              <a className="inline-flex items-center gap-2 rounded-full border border-border bg-card/50 px-4 py-2 text-sm text-foreground transition hover:border-primary/40" href="#">
                <Github className="h-4 w-4" /> GitHub
              </a>
              <a className="inline-flex items-center gap-2 rounded-full border border-border bg-card/50 px-4 py-2 text-sm text-foreground transition hover:border-primary/40" href="#">
                <Linkedin className="h-4 w-4" /> LinkedIn
              </a>
            </div>
          </div>
        </div>
      </div>

      {/* Contact strip */}
      <div className="mt-6 grid gap-4 md:grid-cols-3">
        {[
          { icon: Mail, label: "Email", value: "you@example.com" },
          { icon: Phone, label: "Phone", value: "+00 0000 000 000" },
          { icon: Github, label: "Handle", value: "@your-handle" },
        ].map((c) => (
          <div key={c.label} className="glass card-hover flex items-center gap-3 rounded-xl p-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary">
              <c.icon className="h-4 w-4" />
            </div>
            <div className="min-w-0">
              <div className="text-[10px] font-medium uppercase tracking-[0.18em] text-muted-foreground">{c.label}</div>
              <div className="truncate text-sm">{c.value}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Bio sections */}
      <div className="mt-6 grid gap-6 lg:grid-cols-2">
        <div className="glass rounded-2xl p-6">
          <div className="mb-3 flex items-center gap-2 text-primary">
            <Target className="h-5 w-5" />
            <h3 className="font-semibold text-foreground">Career objective</h3>
          </div>
          <p className="text-sm leading-relaxed text-muted-foreground">
            Replace with your professional objective — the kind of teams you want to join, the
            problems you want to solve, and the impact you want to make in cybersecurity.
          </p>
        </div>

        <div className="glass rounded-2xl p-6">
          <div className="mb-3 flex items-center gap-2 text-primary">
            <GraduationCap className="h-5 w-5" />
            <h3 className="font-semibold text-foreground">Education</h3>
          </div>
          <ul className="space-y-3 text-sm text-muted-foreground">
            <li className="border-l-2 border-primary/40 pl-3">
              <div className="font-medium text-foreground">B.Tech · Computer Science</div>
              <div className="text-xs">University Name · 2022 – 2026</div>
            </li>
            <li className="border-l-2 border-border pl-3">
              <div className="font-medium text-foreground">Certifications</div>
              <div className="text-xs">CEH · CompTIA Security+ · placeholders</div>
            </li>
          </ul>
        </div>

        <div className="glass rounded-2xl p-6 lg:col-span-2">
          <div className="mb-4 flex items-center gap-2 text-primary">
            <Briefcase className="h-5 w-5" />
            <h3 className="font-semibold text-foreground">Skills</h3>
          </div>
          <div className="flex flex-wrap gap-2">
            {SKILLS.map((s) => (
              <span
                key={s}
                className="rounded-full border border-border bg-card/50 px-3 py-1 text-xs text-foreground/90"
              >
                {s}
              </span>
            ))}
          </div>
        </div>
      </div>

      {/* Disclaimer */}
      <div className="mt-6 glass relative overflow-hidden rounded-2xl p-6">
        <div className="absolute inset-y-0 left-0 w-1 bg-gradient-to-b from-warn to-danger" />
        <div className="flex items-start gap-3 pl-3">
          <AlertTriangle className="h-5 w-5 flex-shrink-0 text-warn" />
          <div>
            <h3 className="font-semibold">Responsible-use disclaimer</h3>
            <p className="mt-1.5 text-sm leading-relaxed text-muted-foreground">
              CyberGuard is for authorized security testing and educational use only. Scanning,
              probing, or analyzing systems you do not own or have written permission to assess is
              illegal in most jurisdictions.
            </p>
          </div>
        </div>
      </div>
    </AppShell>
  );
}