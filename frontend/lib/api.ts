const API_BASE =
  typeof window !== "undefined" && window.location.hostname !== "localhost"
    ? `http://${window.location.hostname}:5000`
    : "http://127.0.0.1:5000";

export interface AnalysisResult {
  prediction?: string;
  confidence?: number;
  error?: string;
  url?: string;
  log?: string;
}

export interface ThreatAnalysisItem {
  column: string;
  value: string;
  type: "URL" | "LOG_ENTRY";
  prediction: string;
  confidence: number;
}

export interface CsvRowResult {
  row_number: number;
  data: Record<string, string>;
  threat_analysis: ThreatAnalysisItem[];
  prediction?: string;
}

export interface LogLineResult {
  line_number: number;
  log_entry: string;
  prediction?: string;
  confidence?: number;
  error?: string;
  threat_analysis?: ThreatAnalysisItem[];
}

export interface FileAnalysisResult {
  filename?: string;
  total_rows?: number;
  total_lines?: number;
  results: (CsvRowResult | LogLineResult)[];
  error?: string;
}

export const analyzePayload = async (
  type: "url" | "log",
  input: string,
): Promise<AnalysisResult> => {
  const endpoint = type === "url" ? "/api/analyze-url" : "/api/analyze-log";
  const body = type === "url" ? { url: input } : { log: input };

  const res = await fetch(`${API_BASE}${endpoint}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  return res.json();
};

export const uploadCSVFile = async (
  file: File,
): Promise<FileAnalysisResult> => {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/api/upload-csv`, {
    method: "POST",
    body: formData,
  });
  return res.json();
};

export const uploadLogFile = async (
  file: File,
): Promise<FileAnalysisResult> => {
  const formData = new FormData();
  formData.append("file", file);

  const res = await fetch(`${API_BASE}/api/upload-log`, {
    method: "POST",
    body: formData,
  });
  return res.json();
};
