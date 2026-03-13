import { Badge } from "@/components/ui/badge";
import type { Severity } from "@/api/types";

const severityVariant: Record<Severity, "critical" | "high" | "medium" | "low" | "info"> = {
  CRITICAL: "critical",
  HIGH: "high",
  MEDIUM: "medium",
  LOW: "low",
  INFO: "info",
};

interface SeverityBadgeProps {
  severity: Severity;
}

export function SeverityBadge({ severity }: SeverityBadgeProps) {
  return <Badge variant={severityVariant[severity]}>{severity}</Badge>;
}
