"use client";

import { Scan, Vulnerability } from "../lib/types";

interface ScanResultsProps {
  scan: Scan;
  vulnerabilities: Vulnerability[];
}

export default function ScanResults({
  scan,
  vulnerabilities,
}: ScanResultsProps) {
  const getStatusColor = (status: string) => {
    switch (status) {
      case "completed":
        return "text-green-600";
      case "running":
        return "text-blue-600";
      case "failed":
        return "text-red-600";
      default:
        return "text-gray-600";
    }
  };

  return (
    <div className="bg-white p-6 rounded-lg shadow-md">
      <h2 className="text-xl font-semibold mb-4">Scan Results</h2>

      <div className="mb-6">
        <div className="grid grid-cols-2 gap-4">
          <div>
            <span className="text-sm font-medium text-gray-500">Status:</span>
            <span className={`ml-2 font-medium ${getStatusColor(scan.status)}`}>
              {scan.status.toUpperCase()}
            </span>
          </div>
          <div>
            <span className="text-sm font-medium text-gray-500">Findings:</span>
            <span className="ml-2 font-medium">{scan.findings_count || 0}</span>
          </div>
          <div>
            <span className="text-sm font-medium text-gray-500">Started:</span>
            <span className="ml-2 text-sm">
              {scan.started_at
                ? new Date(scan.started_at).toLocaleString()
                : "Not started"}
            </span>
          </div>
          <div>
            <span className="text-sm font-medium text-gray-500">
              Completed:
            </span>
            <span className="ml-2 text-sm">
              {scan.completed_at
                ? new Date(scan.completed_at).toLocaleString()
                : "In progress"}
            </span>
          </div>
        </div>
      </div>

      {scan.status === "running" && (
        <div className="mb-6">
          <div className="flex items-center">
            <div className="animate-spin rounded-full h-4 w-4 border-b-2 border-blue-600 mr-2"></div>
            <span className="text-blue-600">Scan in progress...</span>
          </div>
        </div>
      )}

      {scan.status === "completed" && vulnerabilities.length > 0 && (
        <div>
          <h3 className="text-lg font-medium mb-4">Vulnerabilities</h3>
          <div className="space-y-4">
            {vulnerabilities.map((vuln) => (
              <div
                key={vuln.id}
                className="border border-gray-200 rounded-lg p-4"
              >
                <div className="flex justify-between items-start mb-2">
                  <h4 className="font-medium text-gray-900">{vuln.title}</h4>
                  <span
                    className={`px-2 py-1 text-xs font-medium rounded ${
                      vuln.severity === "critical"
                        ? "bg-red-100 text-red-800"
                        : vuln.severity === "high"
                          ? "bg-orange-100 text-orange-800"
                          : vuln.severity === "medium"
                            ? "bg-yellow-100 text-yellow-800"
                            : "bg-gray-100 text-gray-800"
                    }`}
                  >
                    {vuln.severity.toUpperCase()}
                  </span>
                </div>
                <p className="text-sm text-gray-600 mb-2">{vuln.description}</p>
                <div className="text-xs text-gray-500">
                  <span>File: {vuln.file_path}</span>
                  {vuln.line_number && <span> | Line: {vuln.line_number}</span>}
                  {vuln.cwe_id && <span> | CWE: {vuln.cwe_id}</span>}
                </div>
                {vuln.remediation && (
                  <div className="mt-2 p-2 bg-gray-50 rounded text-sm">
                    <strong>Remediation:</strong> {vuln.remediation}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>
      )}

      {scan.status === "completed" && vulnerabilities.length === 0 && (
        <div className="text-center py-8">
          <div className="text-green-600 text-4xl mb-4">✓</div>
          <p className="text-gray-600">No vulnerabilities found!</p>
        </div>
      )}

      {scan.status === "failed" && (
        <div className="text-center py-8">
          <div className="text-red-600 text-4xl mb-4">✗</div>
          <p className="text-red-600">Scan failed. Please try again.</p>
        </div>
      )}
    </div>
  );
}
