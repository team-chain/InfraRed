/**
 * Phase 5-A: 보고서 관리 페이지
 * - 생성된 보고서 목록
 * - 주간/월간 보고서 생성 트리거
 * - S3 다운로드 링크
 */
import { useEffect, useState } from "react";
import { fetchReports, generateReport, deleteReport, type ReportItem } from "../lib/api";
import { FileText, Download, RefreshCw, Plus, Trash2 } from "lucide-react";

export function ReportsPage() {
  const [reports, setReports] = useState<ReportItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [generating, setGenerating] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);
  const [reportType, setReportType] = useState<"weekly" | "monthly">("weekly");
  const [deleting, setDeleting] = useState<string | null>(null);

  async function load() {
    setLoading(true);
    try {
      const r = await fetchReports();
      setReports(r);
    } catch (e: any) {
      setError(e.message || "보고서 목록 로드 실패");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); }, []);

  async function handleDelete(id: string) {
    if (!confirm("보고서를 삭제하시겠습니까?")) return;
    setDeleting(id);
    try {
      await deleteReport(id);
      setReports((prev) => prev.filter((r) => r.id !== id));
    } catch (e: any) {
      setError(e.message || "보고서 삭제 실패");
    } finally {
      setDeleting(null);
    }
  }

  async function handleGenerate() {
    setGenerating(true);
    setError(null);
    try {
      await generateReport(reportType);
      setNotice(`${reportType === "weekly" ? "주간" : "월간"} 보고서 생성이 시작되었습니다. 잠시 후 목록에 나타납니다.`);
      setTimeout(load, 3000);
    } catch (e: any) {
      setError(e.message || "보고서 생성 실패");
    } finally {
      setGenerating(false);
    }
  }

  function formatSize(bytes?: number): string {
    if (!bytes) return "-";
    if (bytes < 1024) return `${bytes}B`;
    if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)}KB`;
    return `${(bytes / (1024 * 1024)).toFixed(1)}MB`;
  }

  return (
    <div className="page-wrap">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h2 className="page-title">보고서</h2>
            <p className="page-subtitle">주간·월간 인시던트 보고서 생성 및 이메일 발송 (SendGrid)</p>
          </div>
          <button className="btn btn-sm" onClick={load} disabled={loading}>
            <RefreshCw size={13} className={loading ? "spin" : ""} /> 새로고침
          </button>
        </div>
      </div>

      {error && <div className="alert" style={{ marginBottom: 12 }}>{error}</div>}
      {notice && <div className="notice" style={{ marginBottom: 12 }}>{notice}</div>}

      {/* 보고서 생성 */}
      <div className="card" style={{ display: "flex", gap: 12, alignItems: "center", padding: "16px 20px", marginBottom: 20, flexWrap: "wrap" }}>
        <span style={{ fontSize: 14, fontWeight: 600, color: "var(--text)" }}>새 보고서 생성:</span>
        <select
          value={reportType}
          onChange={(e) => setReportType(e.target.value as any)}
className="form-input" style={{ width: "auto" }}
        >
          <option value="weekly">주간 보고서</option>
          <option value="monthly">월간 보고서</option>
        </select>
        <button
          className="btn btn-primary"
          onClick={handleGenerate}
          disabled={generating}
        >
          <Plus size={14} />
          {generating ? "생성 중…" : `${reportType === "weekly" ? "주간" : "월간"} 보고서 생성`}
        </button>
        <span style={{ fontSize: 12, color: "var(--text-3)" }}>
          생성된 보고서는 S3에 저장되고 이메일로 발송됩니다
        </span>
      </div>

      {/* 보고서 목록 */}
      {reports.length === 0 && !loading ? (
        <div className="card" style={{ textAlign: "center", padding: "60px 24px", color: "var(--text-3)", fontSize: 14 }}>
          <FileText size={32} style={{ marginBottom: 12, opacity: 0.3 }} />
          <p>생성된 보고서가 없습니다.</p>
          <p style={{ fontSize: 12, marginTop: 4 }}>위의 버튼을 클릭해 첫 번째 보고서를 생성하세요.</p>
        </div>
      ) : (
        <div style={{ display: "grid", gap: 12 }}>
          {reports.map((r) => (
            <div key={r.id} className="card" style={{ display: "flex", alignItems: "center", gap: 16, padding: "16px 20px" }}>
              <div
style={{
                  width: 44, height: 44, borderRadius: 10,
                  background: r.report_type === "weekly" ? "var(--c-blue-50)" : "var(--c-purple-50, #ede9fe)",
                  display: "flex", alignItems: "center", justifyContent: "center",
                  flexShrink: 0,
                }}
              >
                <FileText size={20} color={r.report_type === "weekly" ? "var(--c-blue-600)" : "#7c3aed"} />
              </div>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 600, fontSize: 14, color: "var(--text)" }}>
                  {r.report_type === "weekly" ? "주간" : "월간"} 보고서
                  <span
  className={r.report_type === "weekly" ? "pill pill-sm sev-info" : "pill pill-sm"}
                    style={{ marginLeft: 8, background: r.report_type !== "weekly" ? "#ede9fe" : undefined, color: r.report_type !== "weekly" ? "#7c3aed" : undefined }}
                  >
                    {r.report_type}
                  </span>
                </div>
                <div style={{ fontSize: 12, color: "var(--text-3)", marginTop: 3 }}>
                  생성: {new Date(r.generated_at).toLocaleString("ko-KR")}
                  {r.period_start && r.period_end && (
                    <span style={{ marginLeft: 12 }}>
                      기간: {new Date(r.period_start).toLocaleDateString("ko-KR")} ~{" "}
                      {new Date(r.period_end).toLocaleDateString("ko-KR")}
                    </span>
                  )}
                  {r.file_size_bytes && (
                    <span style={{ marginLeft: 12 }}>크기: {formatSize(r.file_size_bytes)}</span>
                  )}
                </div>
                {r.email_sent_to && (
                  <div style={{ fontSize: 11, color: "var(--c-green-600)", marginTop: 2 }}>
                    {r.email_sent_to} 로 발송됨
                  </div>
                )}
              </div>
              <div style={{ display: "flex", gap: 8, flexShrink: 0 }}>
                <a
                  href={r.download_url || `/reports/${r.id}/download`}
                  target="_blank"
                  rel="noreferrer"
                  className="btn btn-sm"
                  style={{ textDecoration: "none" }}
                >
                  <Download size={13} /> 다운로드
                </a>
                <button
                  className="btn btn-sm"
                  style={{ color: "var(--c-red-500)", borderColor: "var(--c-red-200, #fecaca)" }}
                  onClick={() => handleDelete(r.id)}
                  disabled={deleting === r.id}
                  title="보고서 삭제"
                >
                  <Trash2 size={13} />
                  {deleting === r.id ? "삭제 중…" : "삭제"}
                </button>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}
