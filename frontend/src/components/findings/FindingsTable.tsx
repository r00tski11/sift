import React, { useState, useMemo } from "react";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Select } from "@/components/ui/select";
import { SeverityBadge } from "./SeverityBadge";
import { Badge } from "@/components/ui/badge";
import { ChevronDown, ChevronRight } from "lucide-react";
import type { Finding, Severity, FindingStatus } from "@/api/types";
import { cn } from "@/lib/utils";

interface FindingsTableProps {
  findings: Finding[];
}

export function FindingsTable({ findings }: FindingsTableProps) {
  const [severityFilter, setSeverityFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [detectorFilter, setDetectorFilter] = useState<string>("all");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const detectors = useMemo(
    () => [...new Set(findings.map((f) => f.detector))],
    [findings]
  );

  const filtered = useMemo(() => {
    return findings.filter((f) => {
      if (severityFilter !== "all" && f.severity !== severityFilter) return false;
      if (statusFilter !== "all" && f.status !== statusFilter) return false;
      if (detectorFilter !== "all" && f.detector !== detectorFilter) return false;
      return true;
    });
  }, [findings, severityFilter, statusFilter, detectorFilter]);

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <Select
          value={severityFilter}
          onChange={(e) => setSeverityFilter(e.target.value)}
          className="w-40"
        >
          <option value="all">All Severities</option>
          {(["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"] as Severity[]).map(
            (s) => (
              <option key={s} value={s}>
                {s}
              </option>
            )
          )}
        </Select>

        <Select
          value={statusFilter}
          onChange={(e) => setStatusFilter(e.target.value)}
          className="w-40"
        >
          <option value="all">All Statuses</option>
          {(["open", "confirmed", "false_positive", "mitigated"] as FindingStatus[]).map(
            (s) => (
              <option key={s} value={s}>
                {s.replace("_", " ")}
              </option>
            )
          )}
        </Select>

        <Select
          value={detectorFilter}
          onChange={(e) => setDetectorFilter(e.target.value)}
          className="w-48"
        >
          <option value="all">All Detectors</option>
          {detectors.map((d) => (
            <option key={d} value={d}>
              {d}
            </option>
          ))}
        </Select>

        <span className="flex items-center text-sm text-muted-foreground">
          {filtered.length} findings
        </span>
      </div>

      {/* Table */}
      <Table>
        <TableHeader>
          <TableRow>
            <TableHead className="w-8" />
            <TableHead className="w-28">Severity</TableHead>
            <TableHead>Title</TableHead>
            <TableHead>Detector</TableHead>
            <TableHead>Location</TableHead>
            <TableHead>OWASP</TableHead>
            <TableHead>Status</TableHead>
          </TableRow>
        </TableHeader>
        <TableBody>
          {filtered.length === 0 ? (
            <TableRow>
              <TableCell colSpan={7} className="h-24 text-center text-muted-foreground">
                No findings match the current filters.
              </TableCell>
            </TableRow>
          ) : (
            filtered.map((finding) => (
              <React.Fragment key={finding.id}>
                <TableRow
                  className="cursor-pointer"
                  onClick={() =>
                    setExpandedId(
                      expandedId === finding.id ? null : finding.id
                    )
                  }
                >
                  <TableCell>
                    {expandedId === finding.id ? (
                      <ChevronDown className="h-4 w-4 text-muted-foreground" />
                    ) : (
                      <ChevronRight className="h-4 w-4 text-muted-foreground" />
                    )}
                  </TableCell>
                  <TableCell>
                    <SeverityBadge severity={finding.severity} />
                  </TableCell>
                  <TableCell className="font-medium">{finding.title}</TableCell>
                  <TableCell className="text-muted-foreground">
                    {finding.detector}
                  </TableCell>
                  <TableCell className="max-w-[200px] truncate font-mono text-xs text-muted-foreground">
                    {finding.location}
                  </TableCell>
                  <TableCell>
                    <Badge variant="outline" className="text-xs">
                      {finding.owasp}
                    </Badge>
                  </TableCell>
                  <TableCell className="capitalize">
                    {finding.status.replace("_", " ")}
                  </TableCell>
                </TableRow>
                {expandedId === finding.id && (
                  <TableRow key={`${finding.id}-detail`}>
                    <TableCell colSpan={7}>
                      <div
                        className={cn(
                          "rounded-md bg-muted/50 p-4 space-y-3"
                        )}
                      >
                        <div>
                          <p className="text-xs font-medium text-muted-foreground">
                            Description
                          </p>
                          <p className="mt-1 text-sm text-foreground">
                            {finding.description}
                          </p>
                        </div>
                        {finding.evidence && (
                          <div>
                            <p className="text-xs font-medium text-muted-foreground">
                              Evidence
                            </p>
                            <pre className="mt-1 overflow-x-auto rounded bg-background p-2 text-xs text-foreground">
                              {finding.evidence}
                            </pre>
                          </div>
                        )}
                        {finding.remediation && (
                          <div>
                            <p className="text-xs font-medium text-muted-foreground">
                              Recommendation
                            </p>
                            <p className="mt-1 text-sm text-foreground">
                              {finding.remediation}
                            </p>
                          </div>
                        )}
                      </div>
                    </TableCell>
                  </TableRow>
                )}
              </React.Fragment>
            ))
          )}
        </TableBody>
      </Table>
    </div>
  );
}
