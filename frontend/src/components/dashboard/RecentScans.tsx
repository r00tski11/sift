import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { Badge } from "@/components/ui/badge";
import type { Scan } from "@/api/types";

const statusVariant: Record<string, "default" | "secondary" | "destructive" | "outline"> = {
  completed: "default",
  running: "secondary",
  pending: "outline",
  failed: "destructive",
};

interface RecentScansProps {
  scans: Scan[];
}

export function RecentScans({ scans }: RecentScansProps) {
  const navigate = useNavigate();

  return (
    <Card>
      <CardHeader>
        <CardTitle className="text-base">Recent Scans</CardTitle>
      </CardHeader>
      <CardContent>
        {scans.length === 0 ? (
          <p className="py-8 text-center text-sm text-muted-foreground">
            No scans yet. Start your first scan to see results here.
          </p>
        ) : (
          <Table>
            <TableHeader>
              <TableRow>
                <TableHead>Project</TableHead>
                <TableHead>Type</TableHead>
                <TableHead>Status</TableHead>
                <TableHead>Risk Score</TableHead>
                <TableHead>Findings</TableHead>
                <TableHead>Date</TableHead>
              </TableRow>
            </TableHeader>
            <TableBody>
              {scans.map((scan) => (
                <TableRow
                  key={scan.id}
                  className="cursor-pointer"
                  onClick={() => navigate(`/scans/${scan.id}`)}
                >
                  <TableCell className="font-medium">
                    {scan.input_filename}
                  </TableCell>
                  <TableCell className="capitalize">{scan.scan_type}</TableCell>
                  <TableCell>
                    <Badge variant={statusVariant[scan.status] || "outline"}>
                      {scan.status}
                    </Badge>
                  </TableCell>
                  <TableCell>
                    {scan.risk_score !== null ? (
                      <span className="font-mono font-medium">
                        {scan.risk_score}
                        {scan.risk_grade && (
                          <span className="ml-1 text-muted-foreground">
                            ({scan.risk_grade})
                          </span>
                        )}
                      </span>
                    ) : (
                      <span className="text-muted-foreground">-</span>
                    )}
                  </TableCell>
                  <TableCell>{scan.critical_count + scan.high_count + scan.medium_count + scan.low_count + scan.info_count}</TableCell>
                  <TableCell className="text-muted-foreground">
                    {new Date(scan.created_at).toLocaleDateString()}
                  </TableCell>
                </TableRow>
              ))}
            </TableBody>
          </Table>
        )}
      </CardContent>
    </Card>
  );
}
