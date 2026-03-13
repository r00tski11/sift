import client from "./client";
import type { Project, ProjectCreate, Scan } from "./types";

export async function getProjects(): Promise<Project[]> {
  const response = await client.get<Project[]>("/projects");
  return response.data;
}

export async function createProject(data: ProjectCreate): Promise<Project> {
  const response = await client.post<Project>("/projects", data);
  return response.data;
}

export async function getProject(id: string): Promise<Project> {
  const response = await client.get<Project>(`/projects/${id}`);
  return response.data;
}

export async function updateProject(
  id: string,
  data: Partial<ProjectCreate>
): Promise<Project> {
  const response = await client.put<Project>(`/projects/${id}`, data);
  return response.data;
}

export async function deleteProject(id: string): Promise<void> {
  await client.delete(`/projects/${id}`);
}

export async function getProjectScans(id: string): Promise<Scan[]> {
  const response = await client.get<Scan[]>(`/projects/${id}/scans`);
  return response.data;
}
