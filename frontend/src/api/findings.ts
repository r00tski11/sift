import client from "./client";
import type { Finding, FindingUpdate, BulkFindingUpdate } from "./types";

export async function getFinding(id: string): Promise<Finding> {
  const response = await client.get<Finding>(`/findings/${id}`);
  return response.data;
}

export async function updateFinding(
  id: string,
  data: FindingUpdate
): Promise<Finding> {
  const response = await client.patch<Finding>(`/findings/${id}`, data);
  return response.data;
}

export async function bulkUpdateFindings(
  data: BulkFindingUpdate
): Promise<{ updated: number }> {
  const response = await client.patch<{ updated: number }>(
    "/findings/bulk",
    data
  );
  return response.data;
}
