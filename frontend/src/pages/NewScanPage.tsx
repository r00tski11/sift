import { useEffect, useState } from "react";
import { useNavigate } from "react-router-dom";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Select } from "@/components/ui/select";
import { FileUpload } from "@/components/scan/FileUpload";
import { ScanProgress } from "@/components/scan/ScanProgress";
import { Spinner } from "@/components/ui/spinner";
import * as projectsApi from "@/api/projects";
import * as scansApi from "@/api/scans";
import type { Project, ScanStatus } from "@/api/types";

export function NewScanPage() {
  const navigate = useNavigate();
  const [projects, setProjects] = useState<Project[]>([]);
  const [loadingProjects, setLoadingProjects] = useState(true);
  const [selectedProjectId, setSelectedProjectId] = useState<number | null>(null);
  const [scanType, setScanType] = useState("static");
  const [file, setFile] = useState<File | null>(null);
  const [scanId, setScanId] = useState<number | null>(null);
  const [scanStatus, setScanStatus] = useState<ScanStatus | null>(null);
  const [submitting, setSubmitting] = useState(false);
  const [error, setError] = useState("");

  useEffect(() => {
    async function load() {
      try {
        const data = await projectsApi.getProjects();
        setProjects(data);
        if (data.length > 0 && !selectedProjectId) {
          setSelectedProjectId(data[0].id);
        }
      } catch (err) {
        console.error("Failed to load projects:", err);
      } finally {
        setLoadingProjects(false);
      }
    }
    load();
  }, []);

  // Poll scan status
  useEffect(() => {
    if (!scanId || scanStatus === "completed" || scanStatus === "failed") return;

    const interval = setInterval(async () => {
      try {
        const scan = await scansApi.getScan(scanId);
        setScanStatus(scan.status);
        if (scan.status === "completed" || scan.status === "failed") {
          clearInterval(interval);
          if (scan.status === "completed") {
            setTimeout(() => navigate(`/scans/${scanId}`), 1500);
          }
        }
      } catch (err) {
        console.error("Failed to poll scan:", err);
      }
    }, 2000);

    return () => clearInterval(interval);
  }, [scanId, scanStatus, navigate]);

  const handleStartScan = async () => {
    if (!selectedProjectId || !file) return;
    setError("");
    setSubmitting(true);

    try {
      const formData = new FormData();
      formData.append("file", file);
      formData.append("project_id", String(selectedProjectId));
      formData.append("scan_type", scanType);

      const scan = await scansApi.createScan(formData);
      setScanId(scan.id);
      setScanStatus(scan.status);
    } catch {
      setError("Failed to start scan. Please try again.");
    } finally {
      setSubmitting(false);
    }
  };

  if (loadingProjects) {
    return (
      <div className="flex h-96 items-center justify-center">
        <Spinner size="lg" />
      </div>
    );
  }

  // Show progress if scan started
  if (scanId && scanStatus) {
    return (
      <div className="mx-auto max-w-2xl space-y-6">
        <h2 className="text-xl font-bold text-foreground">Scan in Progress</h2>
        <ScanProgress status={scanStatus} />
      </div>
    );
  }

  return (
    <div className="mx-auto max-w-2xl space-y-6">
      {/* Step 1: Select Project */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Step 1: Select Project</CardTitle>
        </CardHeader>
        <CardContent>
          {projects.length === 0 ? (
            <p className="text-sm text-muted-foreground">
              No projects found. Please create a project first.
            </p>
          ) : (
            <Select
              value={selectedProjectId ?? ""}
              onChange={(e) => setSelectedProjectId(Number(e.target.value))}
            >
              {projects.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.name} ({p.bundle_id})
                </option>
              ))}
            </Select>
          )}
        </CardContent>
      </Card>

      {/* Step 2: Select Scan Type */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Step 2: Scan Type</CardTitle>
        </CardHeader>
        <CardContent>
          <Select
            value={scanType}
            onChange={(e) => setScanType(e.target.value)}
          >
            <option value="static">Static Analysis</option>
            <option value="dynamic" disabled>
              Dynamic Analysis (coming soon)
            </option>
          </Select>
        </CardContent>
      </Card>

      {/* Step 3: Upload File */}
      <Card>
        <CardHeader>
          <CardTitle className="text-base">Step 3: Upload File</CardTitle>
        </CardHeader>
        <CardContent>
          <FileUpload
            onFileSelect={setFile}
            selectedFile={file}
            onClear={() => setFile(null)}
          />
        </CardContent>
      </Card>

      {/* Step 4: Start Scan */}
      {error && (
        <div className="rounded-md bg-destructive/10 p-3 text-sm text-red-400">
          {error}
        </div>
      )}

      <Button
        className="w-full"
        size="lg"
        disabled={!selectedProjectId || !file || submitting}
        onClick={handleStartScan}
      >
        {submitting ? "Starting Scan..." : "Start Security Scan"}
      </Button>
    </div>
  );
}
