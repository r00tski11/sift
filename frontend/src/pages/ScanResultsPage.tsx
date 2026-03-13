import { useEffect, useState } from "react";
import { useParams, useNavigate } from "react-router-dom";
import { ArrowLeft, Download } from "lucide-react";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Spinner } from "@/components/ui/spinner";
import { RiskGauge } from "@/components/findings/RiskGauge";
import { FindingsTable } from "@/components/findings/FindingsTable";
import { SeverityBadge } from "@/components/findings/SeverityBadge";
import * as scansApi from "@/api/scans";
import type { Scan, Finding, Severity } from "@/api/types";

export function ScanResultsPage() {
  const { id } = useParams<{ id: string }>();
  const navigate = useNavigate();
  const [scan, setScan] = useState<Scan | null>(null);
  const [findings, setFindings] = useState<Finding[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!id) return;
    async function load() {
      try {
        const [scanData, findingsData] = await Promise.all([
          scansApi.getScan(id!),
          scansApi.getScanFindings(id!),
        ]);
        setScan(scanData);
        setFindings(findingsData);
      } catch (err) {
        console.error("Failed to load scan results:", err);
      } finally {
        setLoading(false);
      }
    }
    load();
  }, [id]);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <Spinner size="lg" />
      </div>
    );
  }

  if (!scan) {
    return (
      <div className="flex h-96 flex-col items-center justify-center text-muted-foreground">
        <p>Scan not found.</p>
      </div>
    );
  }

  const severityCounts = findings.reduce<Record<Severity, number>>(
    (acc, f) => {
      acc[f.severity] = (acc[f.severity] || 0) + 1;
      return acc;
    },
    { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
  );

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-4">
        <Button variant="ghost" size="icon" onClick={() => navigate(-1)}>
          <ArrowLeft className="h-5 w-5" />
        </Button>
        <div className="flex-1">
          <h2 className="text-xl font-bold text-foreground">
            Scan Results
          </h2>
          <p className="text-sm text-muted-foreground">
            {scan.input_filename} &middot; {scan.scan_type} &middot;{" "}
            {new Date(scan.created_at).toLocaleString()}
          </p>
        </div>
        <Badge
          variant={
            scan.status === "completed"
              ? "default"
              : scan.status === "failed"
              ? "destructive"
              : "outline"
          }
        >
          {scan.status}
        </Badge>
      </div>

      {/* Export Buttons */}
      {scan.status === "completed" && (
        <div className="flex flex-wrap gap-2">
          {(["json", "html", "pdf", "sarif"] as const).map((fmt) => (
            <Button
              key={fmt}
              variant="outline"
              size="sm"
              onClick={() => scansApi.downloadReport(id!, fmt)}
            >
              <Download className="mr-2 h-4 w-4" />
              {fmt.toUpperCase()}
            </Button>
          ))}
        </div>
      )}

      {/* Risk Gauge + Severity Summary */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-3">
        <Card className="lg:col-span-2">
          <CardContent className="p-6">
            <RiskGauge
              score={scan.risk_score ?? 0}
              grade={scan.risk_grade}
            />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle className="text-base">Severity Breakdown</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-3">
              {(
                ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]
              ).map((sev) => (
                <div key={sev} className="flex items-center justify-between">
                  <SeverityBadge severity={sev} />
                  <span className="font-mono text-sm font-medium text-foreground">
                    {severityCounts[sev]}
                  </span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Findings */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">
            Findings ({findings.length})
          </CardTitle>
        </CardHeader>
        <CardContent>
          <FindingsTable findings={findings} />
        </CardContent>
      </Card>
    </div>
  );
}
