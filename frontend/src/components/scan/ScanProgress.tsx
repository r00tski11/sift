import { useEffect, useState } from "react";
import { Loader2, CheckCircle2, XCircle } from "lucide-react";
import { Card, CardContent } from "@/components/ui/card";
import type { ScanStatus } from "@/api/types";
import { cn } from "@/lib/utils";

interface ScanProgressProps {
  status: ScanStatus;
  currentDetector?: string;
}

const statusConfig: Record<
  ScanStatus,
  { icon: typeof Loader2; label: string; color: string }
> = {
  pending: { icon: Loader2, label: "Preparing scan...", color: "text-muted-foreground" },
  running: { icon: Loader2, label: "Scanning...", color: "text-primary" },
  completed: { icon: CheckCircle2, label: "Scan complete!", color: "text-green-500" },
  failed: { icon: XCircle, label: "Scan failed", color: "text-red-500" },
};

export function ScanProgress({ status, currentDetector }: ScanProgressProps) {
  const [progress, setProgress] = useState(0);
  const config = statusConfig[status];
  const Icon = config.icon;

  useEffect(() => {
    if (status === "running") {
      const interval = setInterval(() => {
        setProgress((prev) => {
          if (prev >= 90) return prev;
          return prev + Math.random() * 8;
        });
      }, 500);
      return () => clearInterval(interval);
    }
    if (status === "completed") {
      setProgress(100);
    }
  }, [status]);

  return (
    <Card>
      <CardContent className="p-6">
        <div className="flex flex-col items-center gap-4">
          <Icon
            className={cn(
              "h-12 w-12",
              config.color,
              status === "running" || status === "pending"
                ? "animate-spin"
                : ""
            )}
          />
          <p className={cn("text-lg font-medium", config.color)}>
            {config.label}
          </p>

          {(status === "running" || status === "pending") && (
            <div className="w-full max-w-md">
              <div className="h-2 w-full overflow-hidden rounded-full bg-muted">
                <div
                  className="h-full rounded-full bg-primary transition-all duration-300"
                  style={{ width: `${Math.min(progress, 100)}%` }}
                />
              </div>
              {currentDetector && (
                <p className="mt-2 text-center text-sm text-muted-foreground">
                  Running: {currentDetector}
                </p>
              )}
            </div>
          )}
        </div>
      </CardContent>
    </Card>
  );
}
