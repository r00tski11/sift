import client from "./client";
import type { Scan, Finding } from "./types";

export async function createScan(formData: FormData): Promise<Scan> {
  const response = await client.post<Scan>("/scans", formData, {
    headers: { "Content-Type": "multipart/form-data" },
  });
  return response.data;
}

export async function getScan(id: string | number): Promise<Scan> {
  const response = await client.get<Scan>(`/scans/${id}`);
  return response.data;
}

export async function getScanFindings(id: string | number): Promise<Finding[]> {
  const response = await client.get<{ findings: Finding[]; total: number }>(`/scans/${id}/findings`);
  return response.data.findings;
}

export async function downloadReport(
  scanId: string | number,
  format: "json" | "html" | "pdf" | "sarif"
): Promise<void> {
  const response = await client.get(`/scans/${scanId}/report/${format}`, {
    responseType: "blob",
  });
  const ext = format === "sarif" ? "sarif.json" : format;
  const filename = `scan_${scanId}_report.${ext}`;
  const url = window.URL.createObjectURL(new Blob([response.data]));
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  document.body.appendChild(link);
  link.click();
  link.remove();
  window.URL.revokeObjectURL(url);
}

export async function compareScans(
  scanIdA: string | number,
  scanIdB: string | number
): Promise<{ new: Finding[]; resolved: Finding[]; unchanged: Finding[]; summary: { new_count: number; resolved_count: number; unchanged_count: number } }> {
  const response = await client.get(`/scans/compare/`, {
    params: { a: scanIdA, b: scanIdB },
  });
  return response.data;
}
