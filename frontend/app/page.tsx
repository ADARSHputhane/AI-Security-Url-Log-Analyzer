"use client";

import { useState } from "react";
import {
  analyzePayload,
  AnalysisResult,
  uploadCSVFile,
  uploadLogFile,
  FileAnalysisResult,
  ThreatAnalysisItem,
} from "../lib/api";

// 1. Reusable Loading Component
const LoadingSpinner = () => (
  <div className="flex items-center gap-2">
    <div className="flex gap-1">
      {[0, 150, 300].map((delay) => (
        <div
          key={delay}
          className="w-2 h-2 rounded-full bg-current animate-bounce"
          style={{ animationDelay: `${delay}ms` }}
        ></div>
      ))}
    </div>
  </div>
);

interface ResultDisplayProps {
  res: (AnalysisResult & { id?: string }) | null;
  type: "url" | "log";
}

// 2. Single Payload Result Component
const ResultDisplay = ({ res, type }: ResultDisplayProps) => {
  if (!res) return null;
  if (res.error)
    return (
      <div className="mt-6 p-4 bg-red-950/40 border border-red-500/60 text-red-300 rounded-lg text-sm font-mono flex items-start gap-3 animate-in fade-in slide-in-from-top-2 duration-300">
        <span className="text-lg mt-0.5">⚠️</span>
        <div>{res.error}</div>
      </div>
    );

  const isThreat =
    type === "url"
      ? res.prediction?.toLowerCase().includes("malicious")
      : res.prediction !== "Normal Web Traffic";

  return (
    <div
      className={`mt-6 p-6 rounded-lg border-l-4 animate-in fade-in slide-in-from-bottom-2 duration-500 bg-gradient-to-br ${
        isThreat
          ? "from-red-950/30 to-red-950/10 border-red-500 shadow-[0_0_20px_rgba(239,68,68,0.15)]"
          : "from-emerald-950/30 to-emerald-950/10 border-emerald-500 shadow-[0_0_20px_rgba(16,185,129,0.15)]"
      }`}
    >
      <div className="flex items-start justify-between mb-4 pb-4 border-b border-slate-700/50">
        <div className="flex items-center gap-3">
          <span
            className={`text-2xl ${isThreat ? "text-red-500" : "text-emerald-500"}`}
          >
            {isThreat ? "🚨" : "✓"}
          </span>
          <div>
            <span
              className={`text-xs font-bold uppercase tracking-widest block ${isThreat ? "text-red-400" : "text-emerald-400"}`}
            >
              {isThreat ? "Critical Threat Detected" : "Payload Verified Clean"}
            </span>
            <span className="text-slate-500 text-[10px] font-mono uppercase tracking-tighter">
              ID: {res.id || "GEN-ALPHA-NODE"}
            </span>
          </div>
        </div>
      </div>
      <h3 className="text-lg font-semibold text-slate-100 mb-4">
        {res.prediction}
      </h3>
      <div className="space-y-3">
        <div className="flex justify-between text-xs font-mono text-slate-300 mb-2">
          <span className="text-slate-400 uppercase tracking-tighter">
            Model Confidence
          </span>
          <span
            className={`font-bold ${isThreat ? "text-red-400" : "text-emerald-400"}`}
          >
            {res.confidence}%
          </span>
        </div>
        <div className="h-2 w-full bg-slate-800 rounded-full overflow-hidden border border-slate-700">
          <div
            className={`h-full transition-all duration-1000 ease-out ${
              isThreat ? "bg-red-500" : "bg-emerald-500"
            }`}
            style={{ width: `${res.confidence}%` }}
          ></div>
        </div>
      </div>
    </div>
  );
};

// 3. Bulk File Result Component
const FileResultsDisplay = ({ results }: { results: FileAnalysisResult }) => {
  if (results.error) {
    return (
      <div className="mt-6 p-4 bg-red-950/40 border border-red-500/60 text-red-300 rounded-lg text-sm font-mono flex items-start gap-3">
        <span className="text-lg mt-0.5">⚠️</span>
        <div>{results.error}</div>
      </div>
    );
  }

  return (
    <div className="mt-6 space-y-4">
      <div className="p-4 bg-slate-900/30 border border-slate-700/50 rounded-lg flex justify-between items-center">
        <p className="text-xs font-mono text-slate-400">
          FILE_REF: <span className="text-cyan-400">{results.filename}</span>
        </p>
        <p className="text-xs font-mono text-slate-400">
          TOTAL_NODES:{" "}
          <span className="text-emerald-400">
            {results.total_rows || results.total_lines}
          </span>
        </p>
      </div>

      <div className="max-h-96 overflow-y-auto space-y-2 pr-2 scrollbar-thin scrollbar-thumb-slate-700">
        {results.results.slice(0, 20).map((item, idx: number) => {
          const isThreat =
            item.prediction?.toLowerCase().includes("malicious") ||
            (item.prediction && item.prediction !== "Normal Web Traffic") ||
            (item.threat_analysis &&
              item.threat_analysis.some((t: ThreatAnalysisItem) =>
                t.prediction?.toLowerCase().includes("malicious"),
              ));

          return (
            <div
              key={idx}
              className={`p-3 rounded border-l-2 bg-slate-950/40 text-[11px] ${isThreat ? "border-red-500 text-red-300" : "border-emerald-500 text-emerald-300"}`}
            >
              <div className="flex justify-between items-center mb-1 opacity-70">
                <span className="font-mono">
                  {"row_number" in item
                    ? `ROW_${item.row_number}`
                    : `LINE_${item.line_number}`}
                </span>
                <span>{item.prediction}</span>
              </div>
              {item.threat_analysis?.[0] && (
                <p className="text-slate-500 truncate italic">
                  {item.threat_analysis[0].column}:{" "}
                  {item.threat_analysis[0].prediction}
                </p>
              )}
            </div>
          );
        })}
      </div>
    </div>
  );
};

export default function Home() {
  const [tab, setTab] = useState<"payloads" | "files">("payloads");

  // State Management
  const [urlInput, setUrlInput] = useState("");
  const [urlRes, setUrlRes] = useState<
    (AnalysisResult & { id?: string }) | null
  >(null);
  const [isUrlLoading, setIsUrlLoading] = useState(false);

  const [logInput, setLogInput] = useState("");
  const [logRes, setLogRes] = useState<
    (AnalysisResult & { id?: string }) | null
  >(null);
  const [isLogLoading, setIsLogLoading] = useState(false);

  const [csvResults, setCsvResults] = useState<FileAnalysisResult | null>(null);
  const [isCsvLoading, setIsCsvLoading] = useState(false);

  const [logFileResults, setLogFileResults] =
    useState<FileAnalysisResult | null>(null);
  const [isLogFileLoading, setIsLogFileLoading] = useState(false);

  const handleScan = async (type: "url" | "log") => {
    const id = Math.random().toString(36).substr(2, 9).toUpperCase();
    if (type === "url") {
      if (!urlInput.trim()) return;
      setIsUrlLoading(true);
      try {
        const result = await analyzePayload("url", urlInput);
        setUrlRes({ ...result, id });
      } catch {
        setUrlRes({ error: "Backend unreachable. Is the Flask server running on port 5000?", id });
      } finally {
        setIsUrlLoading(false);
      }
    } else {
      if (!logInput.trim()) return;
      setIsLogLoading(true);
      try {
        const result = await analyzePayload("log", logInput);
        setLogRes({ ...result, id });
      } catch {
        setLogRes({ error: "Backend unreachable. Is the Flask server running on port 5000?", id });
      } finally {
        setIsLogLoading(false);
      }
    }
  };

  const handleCsvUpload = async (file: File) => {
    setIsCsvLoading(true);
    try {
      const results = await uploadCSVFile(file);
      setCsvResults(results);
    } catch {
      setCsvResults({ error: "Backend unreachable. Is the Flask server running on port 5000?", results: [] });
    } finally {
      setIsCsvLoading(false);
    }
  };

  const handleLogFileUpload = async (file: File) => {
    setIsLogFileLoading(true);
    try {
      const results = await uploadLogFile(file);
      setLogFileResults(results);
    } catch {
      setLogFileResults({ error: "Backend unreachable. Is the Flask server running on port 5000?", results: [] });
    } finally {
      setIsLogFileLoading(false);
    }
  };

  return (
    <div className="min-h-screen bg-[#020617] text-slate-200 selection:bg-cyan-500/30">
      {/* Background Decor */}
      <div className="fixed inset-0 bg-[linear-gradient(to_right,#1e293b_1px,transparent_1px),linear-gradient(to_bottom,#1e293b_1px,transparent_1px)] bg-[size:40px_40px] [mask-image:radial-gradient(ellipse_60%_50%_at_50%_0%,#000_70%,transparent_100%)] pointer-events-none opacity-20"></div>

      <main className="relative max-w-6xl mx-auto px-6 py-20">
        <header className="text-center mb-16 space-y-4">
          <div className="inline-flex items-center gap-2 px-4 py-2 rounded-full border border-cyan-500/30 bg-cyan-500/5 text-cyan-400 text-[10px] font-bold tracking-[0.2em] uppercase mb-4">
            Security Operations Dashboard
          </div>
          <h1 className="text-5xl font-black tracking-tighter text-white">
            AI Threat Intelligence
          </h1>
          <p className="text-slate-400 font-mono text-xs">
            Neural Node // Local Inference // BART + DistilBERT
          </p>
        </header>

        {/* Tab Navigation */}
        <div className="flex gap-4 mb-10 justify-center">
          {[
            { id: "payloads", label: "Individual Payloads", color: "cyan" },
            { id: "files", label: "Bulk File Analysis", color: "purple" },
          ].map((t) => (
            <button
              key={t.id}
              onClick={() => setTab(t.id as any)}
              className={`px-8 py-3 rounded-xl font-bold transition-all border ${
                tab === t.id
                  ? `bg-${t.color}-500/10 border-${t.color}-500/60 text-${t.color}-400 shadow-[0_0_20px_rgba(0,0,0,0.4)]`
                  : "bg-slate-900/30 border-slate-800 text-slate-500 hover:text-slate-300"
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        {tab === "payloads" ? (
          <div className="grid lg:grid-cols-2 gap-8">
            {/* URL Sandbox */}
            <section className="bg-slate-900/40 backdrop-blur-xl border border-slate-800 p-8 rounded-2xl hover:border-cyan-500/40 transition-all duration-500">
              <h2 className="text-xl font-bold mb-6 flex items-center gap-3">
                <span className="p-2 bg-cyan-500/10 rounded-lg text-cyan-500 text-xs font-mono">
                  URL
                </span>{" "}
                Sandbox
              </h2>
              <div className="space-y-4">
                <input
                  type="text"
                  value={urlInput}
                  onChange={(e) => setUrlInput(e.target.value)}
                  placeholder="https://suspicious-domain.com/verify"
                  className="w-full bg-black/40 border border-slate-800 rounded-xl p-4 text-sm font-mono focus:border-cyan-500 outline-none transition-all"
                />
                <button
                  onClick={() => handleScan("url")}
                  disabled={isUrlLoading || !urlInput.trim()}
                  className="w-full py-4 bg-cyan-600 text-slate-950 font-bold rounded-xl hover:bg-cyan-500 disabled:opacity-50 transition-all flex justify-center items-center gap-2"
                >
                  {isUrlLoading ? <LoadingSpinner /> : "SCAN DOMAIN"}
                </button>
              </div>
              <ResultDisplay res={urlRes} type="url" />
            </section>

            {/* Log Heuristics */}
            <section className="bg-slate-900/40 backdrop-blur-xl border border-slate-800 p-8 rounded-2xl hover:border-purple-500/40 transition-all duration-500">
              <h2 className="text-xl font-bold mb-6 flex items-center gap-3">
                <span className="p-2 bg-purple-500/10 rounded-lg text-purple-500 text-xs font-mono">
                  LOG
                </span>{" "}
                Heuristics
              </h2>
              <div className="space-y-4">
                <textarea
                  rows={4}
                  value={logInput}
                  onChange={(e) => setLogInput(e.target.value)}
                  placeholder="GET /admin.php?id=1' OR '1'='1 --"
                  className="w-full bg-black/40 border border-slate-800 rounded-xl p-4 text-sm font-mono focus:border-purple-500 outline-none transition-all resize-none"
                />
                <button
                  onClick={() => handleScan("log")}
                  disabled={isLogLoading || !logInput.trim()}
                  className="w-full py-4 bg-purple-600 text-white font-bold rounded-xl hover:bg-purple-500 disabled:opacity-50 transition-all flex justify-center items-center gap-2"
                >
                  {isLogLoading ? <LoadingSpinner /> : "ANALYZE PAYLOAD"}
                </button>
              </div>
              <ResultDisplay res={logRes} type="log" />
            </section>
          </div>
        ) : (
          <div className="grid lg:grid-cols-2 gap-8">
            {/* CSV Upload */}
            <section className="bg-slate-900/40 backdrop-blur-xl border border-slate-800 p-8 rounded-2xl hover:border-cyan-500/40 transition-all">
              <h2 className="text-xl font-bold mb-6 flex items-center gap-3">
                CSV Batch Processing
              </h2>
              <input
                type="file"
                accept=".csv"
                onChange={(e) =>
                  e.target.files?.[0] && handleCsvUpload(e.target.files[0])
                }
                className="w-full bg-black/40 border border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-500 file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:bg-cyan-500/20 file:text-cyan-400 hover:file:bg-cyan-500/30"
              />
              {isCsvLoading ? (
                <div className="flex items-center justify-center py-10 gap-3 text-cyan-500">
                  <LoadingSpinner /> CRUNCHING DATA...
                </div>
              ) : (
                csvResults && <FileResultsDisplay results={csvResults} />
              )}
            </section>

            {/* Log File Upload */}
            <section className="bg-slate-900/40 backdrop-blur-xl border border-slate-800 p-8 rounded-2xl hover:border-purple-500/40 transition-all">
              <h2 className="text-xl font-bold mb-6 flex items-center gap-3">
                Log File Extraction
              </h2>
              <input
                type="file"
                accept=".log,.txt"
                onChange={(e) =>
                  e.target.files?.[0] && handleLogFileUpload(e.target.files[0])
                }
                className="w-full bg-black/40 border border-slate-800 rounded-xl p-4 text-xs font-mono text-slate-500 file:mr-4 file:py-1 file:px-3 file:rounded file:border-0 file:bg-purple-500/20 file:text-purple-400 hover:file:bg-purple-500/30"
              />
              {isLogFileLoading ? (
                <div className="flex items-center justify-center py-10 gap-3 text-purple-500">
                  <LoadingSpinner /> PARSING LOGS...
                </div>
              ) : (
                logFileResults && (
                  <FileResultsDisplay results={logFileResults} />
                )
              )}
            </section>
          </div>
        )}

        <footer className="mt-20 pt-10 border-t border-slate-800 text-center text-[10px] font-mono text-slate-600 tracking-[0.3em]">
          &copy; 2026 SECURITY ANALYSIS NODE // SYSTEM_STATUS: NOMINAL
        </footer>
      </main>
    </div>
  );
}
