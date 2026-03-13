import client from "./client";
import type {
  DashboardOverview,
  TrendPoint,
  VulnerabilityCount,
  OWASPDistribution,
} from "./types";

export async function getOverview(): Promise<DashboardOverview> {
  const response = await client.get<DashboardOverview>("/dashboard/overview");
  return response.data;
}

export async function getTrends(): Promise<TrendPoint[]> {
  const response = await client.get<TrendPoint[]>("/dashboard/trends");
  return response.data;
}

export async function getTopVulnerabilities(): Promise<VulnerabilityCount[]> {
  const response = await client.get<VulnerabilityCount[]>(
    "/dashboard/top-vulnerabilities"
  );
  return response.data;
}

export async function getOWASPDistribution(): Promise<OWASPDistribution[]> {
  const response = await client.get<OWASPDistribution[]>(
    "/dashboard/owasp-distribution"
  );
  return response.data;
}
