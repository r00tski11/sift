import { cn } from "@/lib/utils";

interface RiskGaugeProps {
  score: number;
  grade?: string | null;
}

function getGradeColor(score: number): string {
  if (score <= 20) return "text-green-500";
  if (score <= 40) return "text-teal-500";
  if (score <= 60) return "text-yellow-500";
  if (score <= 80) return "text-orange-500";
  return "text-red-500";
}

function getBarColor(score: number): string {
  if (score <= 20) return "bg-green-500";
  if (score <= 40) return "bg-teal-500";
  if (score <= 60) return "bg-yellow-500";
  if (score <= 80) return "bg-orange-500";
  return "bg-red-500";
}

function getGrade(score: number): string {
  if (score <= 20) return "A";
  if (score <= 40) return "B";
  if (score <= 60) return "C";
  if (score <= 80) return "D";
  return "F";
}

export function RiskGauge({ score, grade }: RiskGaugeProps) {
  const displayGrade = grade || getGrade(score);
  const clampedScore = Math.min(100, Math.max(0, score));

  return (
    <div className="flex items-center gap-6">
      {/* Grade circle */}
      <div
        className={cn(
          "flex h-20 w-20 items-center justify-center rounded-full border-4",
          getGradeColor(clampedScore),
          clampedScore <= 20
            ? "border-green-500/30"
            : clampedScore <= 40
            ? "border-teal-500/30"
            : clampedScore <= 60
            ? "border-yellow-500/30"
            : clampedScore <= 80
            ? "border-orange-500/30"
            : "border-red-500/30"
        )}
      >
        <span className={cn("text-3xl font-bold", getGradeColor(clampedScore))}>
          {displayGrade}
        </span>
      </div>

      {/* Score bar */}
      <div className="flex-1">
        <div className="flex items-baseline gap-2">
          <span className={cn("text-2xl font-bold", getGradeColor(clampedScore))}>
            {clampedScore}
          </span>
          <span className="text-sm text-muted-foreground">/ 100 risk score</span>
        </div>
        <div className="mt-2 h-3 w-full overflow-hidden rounded-full bg-muted">
          <div
            className={cn("h-full rounded-full transition-all duration-500", getBarColor(clampedScore))}
            style={{ width: `${clampedScore}%` }}
          />
        </div>
        <p className="mt-1 text-xs text-muted-foreground">
          {clampedScore <= 20
            ? "Excellent - minimal security concerns"
            : clampedScore <= 40
            ? "Good - minor issues detected"
            : clampedScore <= 60
            ? "Fair - several issues need attention"
            : clampedScore <= 80
            ? "Poor - significant vulnerabilities found"
            : "Critical - immediate action required"}
        </p>
      </div>
    </div>
  );
}
