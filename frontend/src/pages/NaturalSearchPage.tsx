/**
 * Phase 5-B: 자연어 검색 + 시계열 차트 + FP 통계 시각화
 * - 한국어/영어 자연어로 인시던트 검색 (NL2SQL Safe)
 * - 시계열 인시던트 추이 차트 (SVG)
 * - FP 비율 통계 시각화
 */
import { useEffect, useState } from "react";
import {
  naturalSearch,
  fetchTimeseries,
  fetchFpStats,
  type IncidentListItem,
  type TimeseriesItem,
  type FpStatItem,
} from "../lib/api";
import { Search, BarChart2, AlertTriangle, RefreshCw } from "lucide-react";

type ActiveTab = "search" | "timeseries" | "fp_stats";

// 간단한 SVG 막대 차트
function BarChart({ data, height = 160 }: { data: TimeseriesItem[]; height?: number }) {
  if (!data.length) return <div style={{ textAlign: "center", color: "var(--text-3)", fontSize: 13, padding: "40px 0" }}>데이터 없음</div>;

  const maxVal = Math.max(...data.map((d) => d.count), 1);
  const barWidth = Math.max(10, Math.min(48, Math.floor(700 / data.length) - 4));
  const chartW = data.length * (barWidth + 4);

  return (
    <div style={{ overflowX: "auto" }}>
      <svg viewBox={`0 0 ${chartW + 40} ${height + 40}`} style={{ minWidth: chartW + 40, height: height + 40 }}>
        {/* Y grid lines */}
        {[0, 0.25, 0.5, 0.75, 1].map((pct) => {
          const y = 10 + (1 - pct) * height;
          return (
            <g key={pct}>
              <line x1={30} y1={y} x2={chartW + 34} y2={y} stroke="#f3f4f6" strokeWidth={1} />
              <text x={28} y={y + 4} textAnchor="end" fontSize={9} fill="var(--text-3)">
                {Math.round(pct * maxVal)}
              </text>
            </g>
          );
        })}

        {data.map((d, i) => {
          const barH = Math.max(2, (d.count / maxVal) * height);
          const x = 32 + i * (barWidth + 4);
          const y = 10 + (height - barH);
          const color = (d.critical ?? 0) > 0 ? "#ef4444" : (d.high ?? 0) > 0 ? "#f59e0b" : "#3b82f6";
          return (
            <g key={d.bucket}>
              <rect x={x} y={y} width={barWidth} height={barH} fill={color} rx={2} opacity={0.85} />
              <title>{`${d.bucket}: ${d.count}건 (critical:${d.critical ?? 0} high:${d.high ?? 0})`}</title>
              {data.length <= 20 && (
                <text
                  x={x + barWidth / 2} y={height + 24}
                  textAnchor="middle" fontSize={9} fill="var(--text-3)"
                  transform={`rotate(-30, ${x + barWidth / 2}, ${height + 24})`}
                >
                  {d.bucket.slice(5, 16)}
                </text>
              )}
            </g>
          );
        })}
      </svg>
      <div style={{ display: "flex", gap: 14, fontSize: 11, color: "var(--text-3)", marginTop: 4, justifyContent: "center" }}>
        <span><span style={{ display: "inline-block", width: 10, height: 10, background: "#ef4444", borderRadius: 2, marginRight: 4 }} />Critical 포함</span>
        <span><span style={{ display: "inline-block", width: 10, height: 10, background: "#f59e0b", borderRadius: 2, marginRight: 4 }} />High 포함</span>
        <span><span style={{ display: "inline-block", width: 10, height: 10, background: "#3b82f6", borderRadius: 2, marginRight: 4 }} />기타</span>
      </div>
    </div>
  );
}

// FP 비율 수평 막대
function FpBar({ rate }: { rate: number }) {
  const color = rate >= 30 ? "#ef4444" : rate >= 15 ? "#f59e0b" : "#10b981";
  return (
    <div style={{ display: "flex", alignItems: "center", gap: 8 }}>
      <div style={{ flex: 1, height: 8, background: "var(--c-gray-100)", borderRadius: 4, overflow: "hidden" }}>
        <div style={{ width: `${Math.min(100, rate)}%`, height: "100%", background: color, borderRadius: 4 }} />
      </div>
      <span style={{ fontSize: 12, fontWeight: 700, color, minWidth: 42 }}>{rate.toFixed(1)}%</span>
    </div>
  );
}

export function NaturalSearchPage() {
  const [activeTab, setActiveTab] = useState<ActiveTab>("search");
  // Search
  const [query, setQuery] = useState("");
  const [searchResults, setSearchResults] = useState<IncidentListItem[] | null>(null);
  const [searching, setSearching] = useState(false);
  const [searchError, setSearchError] = useState<string | null>(null);
  // Timeseries
  const [interval, setIntervalType] = useState<"1h" | "1d" | "1w">("1d");
  const [tsData, setTsData] = useState<TimeseriesItem[]>([]);
  const [tsLoading, setTsLoading] = useState(false);
  // FP stats
  const [fpStats, setFpStats] = useState<FpStatItem[]>([]);
  const [fpLoading, setFpLoading] = useState(false);
  const [fpError, setFpError] = useState<string | null>(null);

  const EXAMPLE_QUERIES = [
    "어제 발생한 critical 인시던트",
    "지난 7일간 SSH 공격",
    "이번 달 open 상태 인시던트",
    "high severity brute force",
    "지난주 해결된 인시던트",
  ];

  async function handleSearch(e?: React.FormEvent) {
    e?.preventDefault();
    if (!query.trim()) return;
    setSearching(true);
    setSearchError(null);
    try {
      const results = await naturalSearch(query);
      setSearchResults(results);
    } catch (err: any) {
      setSearchError(err.message || "검색 실패");
    } finally {
      setSearching(false);
    }
  }

  async function loadTimeseries() {
    setTsLoading(true);
    try {
      const data = await fetchTimeseries(interval);
      setTsData(data);
    } catch {
      setTsData([]);
    } finally {
      setTsLoading(false);
    }
  }

  async function loadFpStats() {
    setFpLoading(true);
    setFpError(null);
    try {
      const data = await fetchFpStats();
      setFpStats(data);
    } catch (e: any) {
      setFpError(e.message || "FP 통계 로드 실패");
    } finally {
      setFpLoading(false);
    }
  }

  useEffect(() => {
    if (activeTab === "timeseries") loadTimeseries();
    if (activeTab === "fp_stats") loadFpStats();
  }, [activeTab, interval]);

  const STATUS_LABEL: Record<string, string> = {
    open: "탐지됨", acknowledged: "확인됨", in_progress: "처리 중",
    contained: "격리됨", resolved: "해결됨", closed: "종결",
  };

  return (
    <div className="page-wrap">
      <div className="page-header">
        <h2 className="page-title">분석 & 검색</h2>
        <p className="page-subtitle">자연어 인시던트 검색 · 시계열 추이 · FP 통계 시각화</p>
      </div>

      {/* 탭 */}
      <div style={{ display: "flex", gap: 0, borderBottom: "2px solid var(--border)", marginBottom: 24 }}>
        {([
          { key: "search", label: "자연어 검색" },
          { key: "timeseries", label: "시계열 추이" },
          { key: "fp_stats", label: "FP 통계" },
        ] as const).map(({ key, label }) => (
          <button
            key={key}
            onClick={() => setActiveTab(key)}
            style={{
              padding: "10px 20px", border: "none", background: "none",
              cursor: "pointer", fontSize: 13,
              fontWeight: activeTab === key ? 700 : 500,
              color: activeTab === key ? "var(--accent)" : "var(--text-3)",
              borderBottom: activeTab === key ? "2px solid var(--accent)" : "2px solid transparent",
              marginBottom: -2,
            }}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── 자연어 검색 ── */}
      {activeTab === "search" && (
        <div>
          <form onSubmit={handleSearch} style={{ marginBottom: 16 }}>
            <div style={{ display: "flex", gap: 8 }}>
              <input
                type="text"
                value={query}
                onChange={(e) => setQuery(e.target.value)}
                placeholder="자연어로 인시던트를 검색하세요 (예: 어제 critical 인시던트)"
className="form-input" style={{ flex: 1 }}
              />
              <button type="submit" className="btn btn-primary" disabled={searching}>
                <Search size={14} /> {searching ? "검색 중…" : "검색"}
              </button>
            </div>
          </form>

          {/* 예시 쿼리 */}
          {!searchResults && (
            <div style={{ marginBottom: 20 }}>
              <p style={{ fontSize: 12, color: "var(--text-3)", marginBottom: 8 }}>예시 검색어:</p>
              <div style={{ display: "flex", gap: 8, flexWrap: "wrap" }}>
                {EXAMPLE_QUERIES.map((q) => (
                  <button
                    key={q}
                    onClick={() => { setQuery(q); }}
className="pill" style={{ cursor: "pointer", border: "1px solid var(--border)", background: "var(--surface-2)", color: "var(--text-2)", fontSize: 12, padding: "4px 12px" }}
                  >
                    {q}
                  </button>
                ))}
              </div>
            </div>
          )}

          {searchError && <div className="alert" style={{ marginBottom: 12 }}>{searchError}</div>}

          {searchResults !== null && (
            <div>
              <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", marginBottom: 12 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: "var(--text)" }}>
                  검색 결과: {searchResults.length}건
                  <span style={{ marginLeft: 8, fontSize: 12, color: "var(--text-3)", fontWeight: 400 }}>
                    "{query}"
                  </span>
                </span>
                <button className="btn btn-sm" onClick={() => { setSearchResults(null); setQuery(""); }}>
                  초기화
                </button>
              </div>

              {searchResults.length === 0 ? (
                <div style={{ textAlign: "center", padding: "48px 24px", color: "var(--text-3)", fontSize: 14 }}>
                  검색 결과가 없습니다
                </div>
              ) : (
                <div className="tbl-wrap">
                  <table className="tbl">
                    <thead>
                      <tr><th>심각도</th><th>인시던트 ID</th><th>MITRE 전술</th><th>상태</th><th>발생 시각</th><th>Source IP</th></tr>
                    </thead>
                    <tbody>
                      {searchResults.map((item) => (
                        <tr key={item.incident_id}>
                          <td><span className={`pill pill-sm sev-${item.severity}`}>{item.severity}</span></td>
                          <td><code style={{ fontSize: 12 }}>{item.incident_id}</code></td>
                          <td style={{ fontSize: 13 }}>{item.mitre_tactic ?? "-"}</td>
                          <td>
                            <span style={{ fontSize: 12, color: "var(--text-3)" }}>
                              {STATUS_LABEL[item.status] ?? item.status}
                            </span>
                          </td>
                          <td style={{ fontSize: 12, color: "var(--text-3)" }}>
                            {new Date(item.created_at).toLocaleString("ko-KR")}
                          </td>
                          <td><code style={{ fontSize: 11 }}>{item.source_ip ?? "-"}</code></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── 시계열 차트 ── */}
      {activeTab === "timeseries" && (
        <div>
          <div style={{ display: "flex", gap: 8, alignItems: "center", marginBottom: 20 }}>
            <span style={{ fontSize: 13, color: "var(--text-3)" }}>집계 단위:</span>
            {(["1h", "1d", "1w"] as const).map((iv) => (
              <button
                key={iv}
                onClick={() => setIntervalType(iv)}
className={interval === iv ? "btn btn-primary btn-sm" : "btn btn-sm"}
              >
                {iv === "1h" ? "1시간" : iv === "1d" ? "1일" : "1주"}
              </button>
            ))}
            <button className="btn btn-sm" onClick={loadTimeseries} disabled={tsLoading} style={{ marginLeft: "auto" }}>
              <RefreshCw size={12} className={tsLoading ? "spin" : ""} />
            </button>
          </div>

          {tsLoading ? (
            <div style={{ textAlign: "center", padding: "48px", color: "var(--text-3)", fontSize: 14 }}>로딩 중…</div>
          ) : (
            <div className="card" style={{ padding: 24 }}>
              <div style={{ fontSize: 13, fontWeight: 600, color: "var(--text)", marginBottom: 16 }}>
                <BarChart2 size={14} style={{ verticalAlign: "middle", marginRight: 6 }} />
                인시던트 발생 추이
                <span style={{ fontSize: 12, color: "var(--text-3)", fontWeight: 400, marginLeft: 8 }}>
                  총 {tsData.reduce((sum, d) => sum + d.count, 0)}건
                </span>
              </div>
              <BarChart data={tsData} height={180} />
            </div>
          )}

          {/* 통계 요약 */}
          {tsData.length > 0 && (
            <div style={{ display: "flex", gap: 12, marginTop: 16, flexWrap: "wrap" }}>
              {[
                { label: "총 인시던트", value: tsData.reduce((s, d) => s + d.count, 0) },
                { label: "Critical", value: tsData.reduce((s, d) => s + (d.critical ?? 0), 0), color: "#ef4444" },
                { label: "High", value: tsData.reduce((s, d) => s + (d.high ?? 0), 0), color: "#f59e0b" },
                { label: "기간 최고 (단일)", value: Math.max(...tsData.map((d) => d.count)) },
              ].map(({ label, value, color }) => (
                <div key={label} style={{
                  padding: "12px 18px", background: "white",
                  border: "1px solid #e5e7eb", borderRadius: 8, flex: 1, minWidth: 120,
                }}>
                  <div style={{ fontSize: 11, color: "var(--text-3)", marginBottom: 4, textTransform: "uppercase", fontWeight: 600 }}>{label}</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: color ?? "var(--text)" }}>{value}</div>
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {/* ── FP 통계 ── */}
      {activeTab === "fp_stats" && (
        <div>
          <div style={{ display: "flex", justifyContent: "flex-end", marginBottom: 16 }}>
            <button className="btn btn-sm" onClick={loadFpStats} disabled={fpLoading}>
              <RefreshCw size={12} className={fpLoading ? "spin" : ""} /> 새로고침
            </button>
          </div>

          {fpError && <div className="alert" style={{ marginBottom: 12 }}>{fpError}</div>}

          {fpLoading ? (
            <div style={{ textAlign: "center", padding: "48px", color: "var(--text-3)", fontSize: 14 }}>로딩 중…</div>
          ) : fpStats.length === 0 ? (
            <div style={{ textAlign: "center", padding: "60px", color: "var(--text-3)", fontSize: 14 }}>
              <AlertTriangle size={28} style={{ marginBottom: 10, opacity: 0.3 }} />
              <p>FP 통계가 없습니다.</p>
              <p style={{ fontSize: 12 }}>인시던트에서 판정(disposition) 데이터가 30건 이상 쌓여야 표시됩니다.</p>
            </div>
          ) : (
            <div>
              {/* 검토 필요 배너 */}
              {fpStats.some((f) => f.review_recommended) && (
                <div style={{
                  display: "flex", alignItems: "center", gap: 10,
                  padding: "12px 16px", background: "#fef3c7",
                  border: "1px solid #fcd34d", borderRadius: 8, marginBottom: 16,
                  fontSize: 13, color: "#92400e",
                }}>
                  <AlertTriangle size={16} />
                  FP 비율 30% 이상인 룰이 {fpStats.filter((f) => f.review_recommended).length}개 있습니다. 검토를 권장합니다.
                </div>
              )}

              <div className="tbl-wrap">
                <table className="tbl">
                  <thead>
                    <tr>
                      <th>Rule ID</th>
                      <th>FP 비율</th>
                      <th>판정 건수</th>
                      <th>FP 건수</th>
                      <th>상태</th>
                    </tr>
                  </thead>
                  <tbody>
                    {[...fpStats]
                      .sort((a, b) => b.fp_rate_pct - a.fp_rate_pct)
                      .map((fp) => (
                        <tr key={fp.rule_id}>
                          <td><code style={{ fontSize: 12 }}>{fp.rule_id}</code></td>
                          <td style={{ minWidth: 180 }}>
                            <FpBar rate={fp.fp_rate_pct} />
                          </td>
                          <td style={{ fontSize: 13 }}>{fp.total.toLocaleString()}</td>
                          <td style={{ fontSize: 13, color: fp.fp > 0 ? "var(--c-red-500)" : "var(--c-green-500)" }}>
                            {fp.fp.toLocaleString()}
                          </td>
                          <td>
                            {fp.review_recommended ? (
                              <span style={{
                                display: "inline-flex", alignItems: "center", gap: 4,
                                padding: "2px 8px", borderRadius: 10,
                                background: "#fef3c7", color: "#92400e", fontSize: 11, fontWeight: 600,
                              }}>
                                <AlertTriangle size={11} /> 검토 필요
                              </span>
                            ) : (
                              <span style={{ fontSize: 11, color: "#10b981", fontWeight: 600 }}>정상</span>
                            )}
                          </td>
                        </tr>
                      ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  );
}
