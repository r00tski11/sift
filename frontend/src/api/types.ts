export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

export type ScanStatus = "pending" | "running" | "completed" | "failed";

export type FindingStatus = "open" | "confirmed" | "false_positive" | "mitigated";

export interface User {
  id: number;
  email: string;
  username: string;
  created_at: string;
}

export interface TokenResponse {
  access_token: string;
  refresh_token: string;
  token_type: string;
}

export interface Project {
  id: number;
  name: string;
  bundle_id: string | null;
  description: string | null;
  created_by: number;
  created_at: string;
  scan_count: number;
}

export interface ProjectCreate {
  name: string;
  bundle_id?: string;
  description?: string;
}

export interface Scan {
  id: number;
  project_id: number;
  scan_type: string;
  status: ScanStatus;
  input_filename: string;
  input_type: string;
  app_name: string | null;
  risk_score: number | null;
  risk_grade: string | null;
  critical_count: number;
  high_count: number;
  medium_count: number;
  low_count: number;
  info_count: number;
  error_message: string | null;
  celery_task_id: string | null;
  created_at: string;
  started_at: string | null;
  completed_at: string | null;
}

export interface Finding {
  id: number;
  uuid: string;
  scan_id: number;
  detector: string;
  severity: Severity;
  title: string;
  description: string;
  location: string;
  evidence: string;
  owasp: string;
  cwe_id: number;
  remediation: string;
  scan_type: string;
  status: FindingStatus;
  is_false_positive: boolean;
  notes: string | null;
  created_at: string;
}

export interface FindingUpdate {
  status?: FindingStatus;
  is_false_positive?: boolean;
  notes?: string;
}

export interface BulkFindingUpdate {
  finding_ids: number[];
  status?: FindingStatus;
  is_false_positive?: boolean;
  notes?: string;
}

export interface DashboardOverview {
  total_projects: number;
  total_scans: number;
  total_findings: number;
  critical_findings: number;
  avg_risk_score: number;
  recent_scans: Scan[];
}

export interface TrendPoint {
  date: string;
  scan_count: number;
  avg_score: number;
}

export interface VulnerabilityCount {
  title: string;
  count: number;
  severity: string;
}

export interface OWASPDistribution {
  category: string;
  count: number;
}
