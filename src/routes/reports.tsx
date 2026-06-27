import { createFileRoute } from "@tanstack/react-router";
import { useEffect, useMemo, useState } from "react";
import { motion } from "framer-motion";
import { Search, Trash2, FileDown, Eye, FileText, Loader2 } from "lucide-react";
import { AppShell } from "@/components/layout/AppShell";
import { PageHeader } from "@/components/cg/PageHeader";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
} from "@/components/ui/dialog";
import { listReports, deleteReport, clearReports, type ReportEntry } from "@/lib/reports";
import { api } from "@/lib/api";
import { toast } from "sonner";

export const Route = createFileRoute("/reports")({
  head: () => ({
    meta: [
      { title: "Reports — CyberGuard" },
      { name: "description", content: "Search, preview, download and manage your CyberGuard security reports." },
    ],
  }),
  component: ReportsPage,
});

function ReportsPage() {
  const [items, setItems] = useState<ReportEntry[]>([]);
  const [q, setQ] = useState("");
  const [viewing, setViewing] = useState<ReportEntry | null>(null);

  useEffect(() => {
    const sync = () => setItems(listReports());
    sync();
    window.addEventListener("cyberguard:reports-changed", sync);
    return () => window.removeEventListener("cyberguard:reports-changed", sync);
  }, []);

  const filtered = useMemo(
    () =>
      items.filter(
        (r) =>
          !q ||
          r.title.toLowerCase().includes(q.toLowerCase()) ||
          r.target.toLowerCase().includes(q.toLowerCase()) ||
          r.kind.includes(q.toLowerCase()),
      ),
    [items, q],
  );

  return (
    <AppShell>
      <PageHeader
        eyebrow="Archive"
        title="Reports"
        description="All scans you have run on this device. Stored locally — clear anytime."
        actions={
          items.length > 0 ? (
            <Button
              variant="outline"
              onClick={() => {
                clearReports();
                toast.success("All reports cleared");
              }}
            >
              Clear all
            </Button>
          ) : undefined
        }
      />

      <div className="glass mb-4 flex items-center gap-2 rounded-xl p-3">
        <Search className="ml-2 h-4 w-4 text-muted-foreground" />
        <Input
          value={q}
          onChange={(e) => setQ(e.target.value)}
          placeholder="Search by title, target or tool…"
          className="border-0 bg-transparent shadow-none focus-visible:ring-0"
        />
      </div>

      {filtered.length === 0 ? (
        <div className="glass flex flex-col items-center gap-3 rounded-xl py-16 text-center text-muted-foreground">
          <FileText className="h-10 w-10 opacity-50" />
          <p className="text-sm">No reports {items.length ? "match your search" : "yet"}.</p>
        </div>
      ) : (
        <div className="glass overflow-hidden rounded-xl">
          <table className="w-full text-sm">
            <thead className="border-b border-border bg-background/30 text-xs uppercase text-muted-foreground">
              <tr>
                <th className="px-4 py-3 text-left font-medium">Tool</th>
                <th className="px-4 py-3 text-left font-medium">Title</th>
                <th className="hidden px-4 py-3 text-left font-medium md:table-cell">Target</th>
                <th className="px-4 py-3 text-right font-medium">Score</th>
                <th className="hidden px-4 py-3 text-left font-medium md:table-cell">Date</th>
                <th className="px-4 py-3"></th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border">
              {filtered.map((r, i) => (
                <motion.tr
                  key={r.id}
                  initial={{ opacity: 0, y: 4 }}
                  animate={{ opacity: 1, y: 0 }}
                  transition={{ delay: i * 0.02 }}
                >
                  <td className="px-4 py-3 text-xs font-mono uppercase text-neon">{r.kind}</td>
                  <td className="px-4 py-3">{r.title}</td>
                  <td className="hidden truncate px-4 py-3 text-muted-foreground md:table-cell">
                    {r.target}
                  </td>
                  <td className="px-4 py-3 text-right tabular-nums">{r.score}</td>
                  <td className="hidden px-4 py-3 text-xs text-muted-foreground md:table-cell">
                    {new Date(r.createdAt).toLocaleString()}
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex justify-end gap-1">
                      <Button size="icon" variant="ghost" onClick={() => setViewing(r)} aria-label="View">
                        <Eye className="h-4 w-4" />
                      </Button>
                      <DownloadButton report={r} />
                      <Button
                        size="icon"
                        variant="ghost"
                        onClick={() => {
                          deleteReport(r.id);
                          toast.success("Report deleted");
                        }}
                        aria-label="Delete"
                      >
                        <Trash2 className="h-4 w-4 text-danger" />
                      </Button>
                    </div>
                  </td>
                </motion.tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <Dialog open={!!viewing} onOpenChange={(o) => !o && setViewing(null)}>
        <DialogContent className="max-w-2xl">
          <DialogHeader>
            <DialogTitle>{viewing?.title}</DialogTitle>
          </DialogHeader>
          {viewing && (
            <div className="max-h-[60vh] overflow-auto rounded-lg border border-border bg-background/50 p-4">
              <pre className="whitespace-pre-wrap break-words font-mono text-xs text-muted-foreground">
                {JSON.stringify(viewing.data, null, 2)}
              </pre>
            </div>
          )}
        </DialogContent>
      </Dialog>
    </AppShell>
  );
}

function DownloadButton({ report }: { report: ReportEntry }) {
  const [busy, setBusy] = useState(false);
  const download = async () => {
    setBusy(true);
    try {
      const blob = await api.generateReport({ kind: report.kind, target: report.target, data: report.data });
      const url = URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `cyberguard-${report.kind}-${report.id}.pdf`;
      a.click();
      URL.revokeObjectURL(url);
    } catch (e) {
      toast.error((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  return (
    <Button size="icon" variant="ghost" onClick={download} disabled={busy} aria-label="Download">
      {busy ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileDown className="h-4 w-4" />}
    </Button>
  );
}