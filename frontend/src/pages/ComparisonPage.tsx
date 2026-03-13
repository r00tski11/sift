import { useState, useEffect, useCallback } from "react";
import { Card } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { Spinner } from "@/components/ui/spinner";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import { getProjects, getProjectScans } from "@/api/projects";
import { compareScans } from "@/api/scans";
import type { Project, Scan, Finding } from "@/api/types";

interface ComparisonResult {
  new: Finding[];
  resolved: Finding[];
  unchanged: Finding[];
  summary: {
    new_count: number;
    resolved_count: number;
    unchanged_count: number;
  };
}

function FindingsSection({
  label,
  variant,
  findings,
}: {
  label: string;
  variant: "destructive" | "default" | "secondary";
  findings: Finding[];
}) {
  if (findings.length === 0) {
    return (
      <Card className="p-4">
        <div className="flex items-center gap-2 mb-3">
          <Badge variant={variant}>{label}</Badge>
          <span className="text-sm text-muted-foreground">0 findings</span>
        </div>
        <p className="text-sm text-muted-foreground">No findings in this category.</p>
      </Card>
    );
  }

  return (
    <Card className="p-4">
      <div className="flex items-center gap-2 mb-3">
        <Badge variant={variant}>{label}</Badge>
        <span className="text-sm text-muted-foreground">
          {findings.length} finding{findings.length !== 1 ? "s" : ""}
        </span>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-left text-muted-foreground">
              <th className="pb-2 pr-4">Severity</th>
              <th className="pb-2 pr-4">Title</th>
              <th className="pb-2 pr-4">Detector</th>
              <th className="pb-2">Location</th>
            </tr>
          </thead>
          <tbody>
            {findings.map((f) => (
              <tr key={f.uuid} className="border-b border-border/50">
                <td className="py-2 pr-4">
                  <SeverityBadge severity={f.severity} />
                </td>
                <td className="py-2 pr-4 font-medium">{f.title}</td>
                <td className="py-2 pr-4 text-muted-foreground">{f.detector}</td>
                <td className="py-2 text-muted-foreground max-w-[200px] truncate">
                  {f.location}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </Card>
  );
}

export function ComparisonPage() {
  const [projects, setProjects] = useState<Project[]>([]);
  const [selectedProject, setSelectedProject] = useState<string>("");
  const [scans, setScans] = useState<Scan[]>([]);
  const [scanA, setScanA] = useState<string>("");
  const [scanB, setScanB] = useState<string>("");
  const [result, setResult] = useState<ComparisonResult | null>(null);
  const [loading, setLoading] = useState(false);
  const [loadingScans, setLoadingScans] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    getProjects().then(setProjects).catch(() => {});
  }, []);

  useEffect(() => {
    if (!selectedProject) {
      setScans([]);
      setScanA("");
      setScanB("");
      setResult(null);
      return;
    }
    setLoadingScans(true);
    getProjectScans(selectedProject)
      .then((s) => {
        const completed = s.filter((scan) => scan.status === "completed");
        setScans(completed);
        setScanA("");
        setScanB("");
        setResult(null);
      })
      .catch(() => setScans([]))
      .finally(() => setLoadingScans(false));
  }, [selectedProject]);

  const handleCompare = useCallback(async () => {
    if (!scanA || !scanB) return;
    setLoading(true);
    setError(null);
    setResult(null);
    try {
      const data = await compareScans(scanA, scanB);
      setResult(data);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : "Comparison failed";
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, [scanA, scanB]);

  const formatScanLabel = (scan: Scan) => {
    const date = new Date(scan.created_at).toLocaleDateString();
    return `#${scan.id} - ${scan.input_filename} (${date}) - ${scan.risk_grade ?? "N/A"}`;
  };

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-foreground">Compare Scans</h1>
        <p className="text-muted-foreground mt-1">
          Select two scans from the same project to see what changed between them.
        </p>
      </div>

      {/* Selection controls */}
      <Card className="p-6 space-y-4">
        <div>
          <label className="block text-sm font-medium text-foreground mb-1">
            Project
          </label>
          <Select
            value={selectedProject}
            onChange={(e) => setSelectedProject(e.target.value)}
          >
            <option value="">Select a project...</option>
            {projects.map((p) => (
              <option key={p.id} value={String(p.id)}>
                {p.name}
              </option>
            ))}
          </Select>
        </div>

        {loadingScans && <Spinner size="sm" />}

        {scans.length > 0 && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-foreground mb-1">
                Scan A (baseline)
              </label>
              <Select
                value={scanA}
                onChange={(e) => setScanA(e.target.value)}
              >
                <option value="">Select scan A...</option>
                {scans.map((s) => (
                  <option key={s.id} value={String(s.id)}>
                    {formatScanLabel(s)}
                  </option>
                ))}
              </Select>
            </div>
            <div>
              <label className="block text-sm font-medium text-foreground mb-1">
                Scan B (current)
              </label>
              <Select
                value={scanB}
                onChange={(e) => setScanB(e.target.value)}
              >
                <option value="">Select scan B...</option>
                {scans.map((s) => (
                  <option key={s.id} value={String(s.id)}>
                    {formatScanLabel(s)}
                  </option>
                ))}
              </Select>
            </div>
          </div>
        )}

        {selectedProject && scans.length === 0 && !loadingScans && (
          <p className="text-sm text-muted-foreground">
            No completed scans found for this project.
          </p>
        )}

        <Button
          onClick={handleCompare}
          disabled={!scanA || !scanB || scanA === scanB || loading}
        >
          {loading ? "Comparing..." : "Compare"}
        </Button>

        {scanA && scanB && scanA === scanB && (
          <p className="text-sm text-yellow-400">Please select two different scans.</p>
        )}
      </Card>

      {/* Error */}
      {error && (
        <Card className="p-4 border-destructive">
          <p className="text-sm text-destructive">{error}</p>
        </Card>
      )}

      {/* Loading */}
      {loading && (
        <div className="flex justify-center py-12">
          <Spinner size="lg" />
        </div>
      )}

      {/* Results */}
      {result && !loading && (
        <div className="space-y-6">
          {/* Summary cards */}
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Card className="p-4 text-center">
              <p className="text-3xl font-bold text-red-400">{result.summary.new_count}</p>
              <p className="text-sm text-muted-foreground mt-1">New Findings</p>
            </Card>
            <Card className="p-4 text-center">
              <p className="text-3xl font-bold text-green-400">{result.summary.resolved_count}</p>
              <p className="text-sm text-muted-foreground mt-1">Resolved</p>
            </Card>
            <Card className="p-4 text-center">
              <p className="text-3xl font-bold text-gray-400">{result.summary.unchanged_count}</p>
              <p className="text-sm text-muted-foreground mt-1">Unchanged</p>
            </Card>
          </div>

          {/* Finding sections */}
          <FindingsSection label="New Findings" variant="destructive" findings={result.new} />
          <FindingsSection label="Resolved" variant="default" findings={result.resolved} />
          <FindingsSection label="Unchanged" variant="secondary" findings={result.unchanged} />
        </div>
      )}
    </div>
  );
}
