export interface Scan {
  id: string;
  repo_url: string;
  branch: string;
  status: "pending" | "running" | "completed" | "failed";
  started_at?: string;
  completed_at?: string;
  findings_count: number;
  created_at: string;
}

export interface Vulnerability {
  id: string;
  title: string;
  scan_id: string;
  file_path: string;
  line_number?: number;
  category: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  code_snippet?: string;
  cwe_id?: string;
  owasp_top_10?: string;
  remediation?: string;
  ai_analysis?: string;
  created_at: string;
}

export interface Repository {
  id: string;
  url: string;
  branch: string;
  created_at: string;
  last_scanned?: string;
}

export interface AttackChain {
  id: string;
  scan_id: string;
  title: string;
  steps: string[];
  severity: "critical" | "high" | "medium" | "low" | "info";
  likelihood: string;
  impact: string;
  created_at: string;
}

export interface Report {
  id: string;
  scan_id: string;
  format: string;
  content: string;
  created_at: string;
}
