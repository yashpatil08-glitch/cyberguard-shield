export type ReportKind = "url" | "password" | "headers" | "phishing";

export interface ReportEntry {
  id: string;
  kind: ReportKind;
  title: string;
  target: string;
  score: number;
  createdAt: number;
  summary: string;
  data: unknown;
}

const KEY = "cyberguard:reports";

export function listReports(): ReportEntry[] {
  if (typeof window === "undefined") return [];
  try {
    const raw = window.localStorage.getItem(KEY);
    return raw ? (JSON.parse(raw) as ReportEntry[]) : [];
  } catch {
    return [];
  }
}

export function saveReport(entry: Omit<ReportEntry, "id" | "createdAt">): ReportEntry {
  const full: ReportEntry = {
    ...entry,
    id: crypto.randomUUID(),
    createdAt: Date.now(),
  };
  const all = [full, ...listReports()].slice(0, 200);
  window.localStorage.setItem(KEY, JSON.stringify(all));
  window.dispatchEvent(new Event("cyberguard:reports-changed"));
  return full;
}

export function deleteReport(id: string) {
  const all = listReports().filter((r) => r.id !== id);
  window.localStorage.setItem(KEY, JSON.stringify(all));
  window.dispatchEvent(new Event("cyberguard:reports-changed"));
}

export function clearReports() {
  window.localStorage.removeItem(KEY);
  window.dispatchEvent(new Event("cyberguard:reports-changed"));
}