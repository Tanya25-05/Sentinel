"use client";

import { useState, useEffect } from "react";
import axios from "axios";
import ScanForm from "./ScanForm";
import ScanResults from "./ScanResults";
import { Scan, Vulnerability } from "../lib/types";

const API_BASE = "http://localhost:8000/api";

export default function Dashboard() {
  const [scans, setScans] = useState<Scan[]>([]);
  const [selectedScan, setSelectedScan] = useState<Scan | null>(null);
  const [vulnerabilities, setVulnerabilities] = useState<Vulnerability[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    loadScans();
  }, []);

  const loadScans = async () => {
    try {
      const response = await axios.get(`${API_BASE}/scans/`);
      setScans(response.data);
    } catch (error) {
      console.error("Failed to load scans:", error);
    }
  };

  const handleScanSubmit = async (repoUrl: string, branch: string) => {
    setLoading(true);
    try {
      const response = await axios.post(`${API_BASE}/scans/`, {
        repo_url: repoUrl,
        branch,
      });
      const newScan = response.data;
      setScans((prev) => [newScan, ...prev]);
      setSelectedScan(newScan);
      // Poll for updates
      pollScanStatus(newScan.id);
    } catch (error) {
      console.error("Failed to start scan:", error);
    } finally {
      setLoading(false);
    }
  };

  const pollScanStatus = async (scanId: string) => {
    const poll = async () => {
      try {
        const response = await axios.get(`${API_BASE}/scans/${scanId}`);
        const scan = response.data;
        setScans((prev) => prev.map((s) => (s.id === scanId ? scan : s)));
        if (scan.status === "completed" || scan.status === "failed") {
          setSelectedScan(scan);
          loadVulnerabilities(scanId);
        } else {
          setTimeout(poll, 2000); // Poll every 2 seconds
        }
      } catch (error) {
        console.error("Failed to poll scan status:", error);
      }
    };
    poll();
  };

  const loadVulnerabilities = async (scanId: string) => {
    try {
      // For now, we'll load from a mock endpoint or assume vulnerabilities are part of scan
      // In real implementation, you'd have a separate vulnerabilities endpoint
      setVulnerabilities([]); // Placeholder
    } catch (error) {
      console.error("Failed to load vulnerabilities:", error);
    }
  };

  return (
    <div className="grid grid-cols-1 lg:grid-cols-3 gap-8">
      <div className="lg:col-span-1">
        <ScanForm onSubmit={handleScanSubmit} loading={loading} />
        <div className="mt-8">
          <h3 className="text-lg font-semibold mb-4">Recent Scans</h3>
          <div className="space-y-2">
            {scans.map((scan) => (
              <div
                key={scan.id}
                className={`p-4 border rounded-lg cursor-pointer ${
                  selectedScan?.id === scan.id
                    ? "border-blue-500 bg-blue-50"
                    : "border-gray-200"
                }`}
                onClick={() => setSelectedScan(scan)}
              >
                <div className="font-medium">{scan.repo_url}</div>
                <div className="text-sm text-gray-600">{scan.status}</div>
                <div className="text-sm text-gray-500">
                  {scan.created_at
                    ? new Date(scan.created_at).toLocaleString()
                    : ""}
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="lg:col-span-2">
        {selectedScan && (
          <ScanResults scan={selectedScan} vulnerabilities={vulnerabilities} />
        )}
      </div>
    </div>
  );
}
