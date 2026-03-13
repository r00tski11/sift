import { useEffect, useState } from "react";
import { FolderOpen, Scan, AlertTriangle, ShieldAlert } from "lucide-react";
import { StatCard } from "@/components/dashboard/StatCard";
import { TrendChart } from "@/components/dashboard/TrendChart";
import { SeverityChart } from "@/components/dashboard/SeverityChart";
import { RecentScans } from "@/components/dashboard/RecentScans";
import { Spinner } from "@/components/ui/spinner";
import * as dashboardApi from "@/api/dashboard";
import type { DashboardOverview, TrendPoint, Severity } from "@/api/types";

export function DashboardPage() {
  const [overview, setOverview] = useState<DashboardOverview | null>(null);
  const [trends, setTrends] = useState<TrendPoint[]>([]);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    async function loadData() {
      try {
        const [overviewData, trendsData] = await Promise.all([
          dashboardApi.getOverview(),
          dashboardApi.getTrends(),
        ]);
        setOverview(overviewData);
        setTrends(trendsData);
      } catch (err) {
        console.error("Failed to load dashboard data:", err);
      } finally {
        setLoading(false);
      }
    }
    loadData();
  }, []);

  if (loading) {
    return (
      <div className="flex h-96 items-center justify-center">
        <Spinner size="lg" />
      </div>
    );
  }

  if (!overview) {
    return (
      <div className="flex h-96 flex-col items-center justify-center text-muted-foreground">
        <AlertTriangle className="mb-4 h-12 w-12" />
        <p>Failed to load dashboard data.</p>
      </div>
    );
  }

  return (
    <div className="space-y-6">
      {/* Stat cards */}
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
        <StatCard
          icon={FolderOpen}
          label="Total Projects"
          value={overview.total_projects}
        />
        <StatCard
          icon={Scan}
          label="Total Scans"
          value={overview.total_scans}
        />
        <StatCard
          icon={AlertTriangle}
          label="Total Findings"
          value={overview.total_findings}
        />
        <StatCard
          icon={ShieldAlert}
          label="Critical Findings"
          value={overview.critical_findings}
          className={
            overview.critical_findings > 0 ? "border-red-500/30" : ""
          }
        />
      </div>

      {/* Charts */}
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
        <TrendChart data={trends} />
        <SeverityChart
          data={overview.recent_scans.reduce<Record<Severity, number>>(
            (acc, s) => ({
              CRITICAL: acc.CRITICAL + s.critical_count,
              HIGH: acc.HIGH + s.high_count,
              MEDIUM: acc.MEDIUM + s.medium_count,
              LOW: acc.LOW + s.low_count,
              INFO: acc.INFO + s.info_count,
            }),
            { CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 }
          )}
        />
      </div>

      {/* Recent scans */}
      <RecentScans scans={overview.recent_scans} />
    </div>
  );
}
