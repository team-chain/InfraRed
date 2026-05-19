import { useState, useEffect } from "react";
import { Activity, AlertTriangle, Shield, RefreshCw, Target } from "lucide-react";
import { fetchCampaigns, containCampaign, type Campaign } from "../lib/api";

function relTime(iso: string) {
  const m = Math.floor((Date.now() - new Date(iso).getTime()) / 60000);
  if (m < 1) return "방금";
  if (m < 60) return `${m}분 전`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}시간 전`;
  return `${Math.floor(h / 24)}일 전`;
}

function StatusBadge({ status }: { status: string }) {
  if (status === "active") {
    return <span className="pill pill-sm sev-critical">{status}</span>;
  }
  if (status === "contained") {
    return <span className="pill pill-sm sev-info">{status}</span>;
  }
  return (
    <span
      className="pill pill-sm"
      style={{ background: "var(--c-gray-100)", color: "var(--text-3)", border: "1px solid var(--border)" }}
    >
      {status}
    </span>
  );
}

export function CampaignsPage() {
  const [campaigns, setCampaigns] = useState<Campaign[]>([]);
  const [selectedCampaign, setSelectedCampaign] = useState<Campaign | undefined>();
  const [loading, setLoading] = useState(false);
  const [statusFilter, setStatusFilter] = useState<"" | "active" | "contained" | "closed">("");
  const [error, setError] = useState<string | undefined>();
  const [notice, setNotice] = useState<string | undefined>();
  const [containing, setContaining] = useState(false);

  async function load() {
    setLoading(true);
    setError(undefined);
    try {
      const items = await fetchCampaigns(statusFilter || undefined);
      setCampaigns(items);
      if (selectedCampaign) {
        const updated = items.find((c) => c.id === selectedCampaign.id);
        setSelectedCampaign(updated);
      }
    } catch (e) {
      setError(e instanceof Error ? e.message : "오류 발생");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => {
    load();
  }, [statusFilter]);

  useEffect(() => {
    if (!notice) return;
    const t = setTimeout(() => setNotice(undefined), 4000);
    return () => clearTimeout(t);
  }, [notice]);

  async function handleContain(id: string) {
    setContaining(true);
    setError(undefined);
    try {
      await containCampaign(id);
      setNotice("캠페인이 격리(Contain) 처리됐습니다.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "격리 실패");
    } finally {
      setContaining(false);
    }
  }

  const totalN = campaigns.length;
  const activeN = campaigns.filter((c) => c.status === "active").length;
  const containedN = campaigns.filter((c) => c.status === "contained").length;
  const closedN = campaigns.filter((c) => c.status === "closed").length;

  return (
    <div className="page-wrap">
      <div className="page-header">
        <div style={{ display: "flex", alignItems: "flex-start", justifyContent: "space-between" }}>
          <div>
            <h2 className="page-title">공격 캠페인</h2>
            <p className="page-subtitle">연관 인시던트를 묶은 공격 캠페인 추적 및 대응</p>
          </div>
          <button className="btn btn-sm" onClick={load} disabled={loading}>
            <RefreshCw size={13} className={loading ? "spin" : ""} /> 새로고침
          </button>
        </div>
      </div>

      {error && (
        <div className="alert">
          {error}{" "}
          <button
            onClick={() => setError(undefined)}
            style={{ float: "right", background: "none", border: "none", cursor: "pointer", fontWeight: 700 }}
          >
            ×
          </button>
        </div>
      )}
      {notice && (
        <div className="notice">
          {notice}{" "}
          <button
            onClick={() => setNotice(undefined)}
            style={{ float: "right", background: "none", border: "none", cursor: "pointer", fontWeight: 700 }}
          >
            ×
          </button>
        </div>
      )}

      {/* 통계바 */}
      <div className="stats-bar">
        {[
          { icon: <Activity size={16} />, cls: "blue", val: totalN, label: "전체 캠페인" },
          { icon: <AlertTriangle size={16} />, cls: "red", val: activeN, label: "Active" },
          { icon: <Shield size={16} />, cls: "blue", val: containedN, label: "Contained" },
          { icon: <Target size={16} />, cls: "gray", val: closedN, label: "Closed" },
        ].map(({ icon, cls, val, label }) => (
          <div key={label} className="stat-card">
            <div className={`stat-icon ${cls}`}>{icon}</div>
            <div>
              <div className="stat-value">{val}</div>
              <div className="stat-label">{label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* 필터 */}
      <div style={{ display: "flex", gap: 8, marginBottom: 16, flexWrap: "wrap" }}>
        {(["", "active", "contained", "closed"] as const).map((s) => (
          <button
            key={s || "all"}
            className={`btn btn-sm${statusFilter === s ? " btn-primary" : ""}`}
            onClick={() => setStatusFilter(s)}
          >
            {s === "" ? "전체" : s}
          </button>
        ))}
      </div>

      <div className="layout">
        {/* 왼쪽: 캠페인 목록 */}
        <div className="left-pane">
          <div className="pane-header">
            <span className="pane-header-title">캠페인 목록</span>
            <span className="pane-header-count">{campaigns.length}</span>
          </div>
          <div className="incident-list">
            {campaigns.map((c) => (
              <button
                key={c.id}
                className={`incident-card${selectedCampaign?.id === c.id ? " selected" : ""}`}
                onClick={() => setSelectedCampaign(c)}
              >
                <div
                  className="inc-sev-dot"
                  style={{
                    background:
                      c.status === "active"
                        ? "var(--c-red-500)"
                        : c.status === "contained"
                        ? "var(--c-blue-500)"
                        : "var(--c-gray-400)",
                  }}
                />
                <div className="inc-card-body">
                  <div className="inc-card-top">
                    <StatusBadge status={c.status} />
                    <span className="inc-card-time">{relTime(c.last_seen_at)}</span>
                  </div>
                  <div className="inc-card-id">{c.campaign_type}</div>
                  {c.source_asn && (
                    <div className="inc-card-rule" style={{ fontFamily: "var(--mono)", fontSize: 11 }}>
                      ASN: {c.source_asn}
                    </div>
                  )}
                  <div className="inc-card-meta">
                    <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                      최초: {new Date(c.first_seen_at).toLocaleDateString("ko-KR")}
                    </span>
                    <span style={{ fontSize: 11, color: "var(--text-3)" }}>·</span>
                    <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                      최후: {new Date(c.last_seen_at).toLocaleDateString("ko-KR")}
                    </span>
                    {c.total_signals != null && (
                      <>
                        <span style={{ fontSize: 11, color: "var(--text-3)" }}>·</span>
                        <span style={{ fontSize: 11, color: "var(--text-3)" }}>
                          시그널 {c.total_signals}건
                        </span>
                      </>
                    )}
                  </div>
                </div>
              </button>
            ))}
            {!campaigns.length && (
              <div style={{ padding: "48px 24px", textAlign: "center", color: "var(--text-3)", fontSize: 13.5 }}>
                {loading ? "로딩 중…" : "캠페인이 없습니다"}
              </div>
            )}
          </div>
        </div>

        {/* 오른쪽: 상세 패널 */}
        <div className="right-pane">
          {!selectedCampaign ? (
            <div className="empty-state">
              <div className="empty-icon">
                <Target size={26} />
              </div>
              <h3>캠페인을 선택하세요</h3>
              <p>왼쪽 목록에서 캠페인을 클릭하면 상세 정보와 대응 옵션을 확인할 수 있습니다.</p>
            </div>
          ) : (
            <div className="cards-stack">
              {/* 헤더 카드 */}
              <div className="card">
                <div className="card-head">
                  <div className="card-head-icon red">
                    <Target size={14} />
                  </div>
                  <span className="card-head-title">{selectedCampaign.campaign_type}</span>
                  <span className="card-head-sub">
                    <StatusBadge status={selectedCampaign.status} />
                  </span>
                </div>
                <div className="card-body">
                  <div className="meta-grid">
                    {[
                      { label: "캠페인 ID", value: selectedCampaign.id, mono: true },
                      { label: "캠페인 레이블", value: selectedCampaign.campaign_label ?? "-" },
                      { label: "Source ASN", value: selectedCampaign.source_asn ?? "-", mono: true },
                      {
                        label: "최초 발견",
                        value: new Date(selectedCampaign.first_seen_at).toLocaleString("ko-KR"),
                      },
                      {
                        label: "최후 발견",
                        value: new Date(selectedCampaign.last_seen_at).toLocaleString("ko-KR"),
                      },
                      {
                        label: "총 시그널",
                        value:
                          selectedCampaign.total_signals != null
                            ? String(selectedCampaign.total_signals)
                            : "-",
                      },
                    ].map((item) => (
                      <div key={item.label} className="meta-cell">
                        <div className="meta-cell-label">{item.label}</div>
                        <div
                          className="meta-cell-value"
                          style={{ fontFamily: item.mono ? "var(--mono)" : undefined }}
                        >
                          {item.value}
                        </div>
                      </div>
                    ))}
                  </div>

                  {/* Contain 버튼 */}
                  <div style={{ marginTop: 16 }}>
                    <button
                      className="btn btn-primary"
                      disabled={selectedCampaign.status !== "active" || containing}
                      onClick={() => handleContain(selectedCampaign.id)}
                      title={
                        selectedCampaign.status !== "active"
                          ? "active 상태인 캠페인만 격리할 수 있습니다"
                          : "캠페인 격리"
                      }
                    >
                      <Shield size={14} />
                      {containing ? "격리 중…" : "캠페인 격리 (Contain)"}
                    </button>
                  </div>
                </div>
              </div>

              {/* Source IPs */}
              {(selectedCampaign.source_ips?.length ?? 0) > 0 && (
                <div className="card">
                  <div className="card-head">
                    <div className="card-head-icon orange">
                      <AlertTriangle size={14} />
                    </div>
                    <span className="card-head-title">Source IP 목록</span>
                    <span className="card-head-sub">{selectedCampaign.source_ips!.length}개</span>
                  </div>
                  <div className="card-body">
                    <div className="tbl-wrap">
                      <table className="tbl">
                        <thead>
                          <tr>
                            <th>#</th>
                            <th>IP 주소</th>
                          </tr>
                        </thead>
                        <tbody>
                          {selectedCampaign.source_ips!.map((ip, i) => (
                            <tr key={ip}>
                              <td style={{ color: "var(--text-3)", fontSize: 12 }}>{i + 1}</td>
                              <td>
                                <code>{ip}</code>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  </div>
                </div>
              )}

              {/* 영향 자산 */}
              {(selectedCampaign.affected_asset_ids?.length ?? 0) > 0 && (
                <div className="card">
                  <div className="card-head">
                    <div className="card-head-icon blue">
                      <Shield size={14} />
                    </div>
                    <span className="card-head-title">영향받은 자산</span>
                    <span className="card-head-sub">
                      {selectedCampaign.affected_asset_ids!.length}개
                    </span>
                  </div>
                  <div className="card-body">
                    <div style={{ display: "flex", flexWrap: "wrap", gap: 6 }}>
                      {selectedCampaign.affected_asset_ids!.map((aid) => (
                        <span
                          key={aid}
                          className="pill pill-sm sev-info"
                          style={{ fontFamily: "var(--mono)" }}
                        >
                          {aid}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {/* 연관 인시던트 */}
              {(selectedCampaign.incident_ids?.length ?? 0) > 0 && (
                <div className="card">
                  <div className="card-head">
                    <div className="card-head-icon red">
                      <Activity size={14} />
                    </div>
                    <span className="card-head-title">연관 인시던트</span>
                    <span className="card-head-sub">{selectedCampaign.incident_ids!.length}건</span>
                  </div>
                  <div className="card-body">
                    <div style={{ display: "flex", flexDirection: "column", gap: 4 }}>
                      {selectedCampaign.incident_ids!.map((iid) => (
                        <div
                          key={iid}
                          style={{
                            fontFamily: "var(--mono)",
                            fontSize: 12,
                            padding: "4px 8px",
                            background: "var(--surface-2)",
                            borderRadius: 4,
                            color: "var(--text-2)",
                          }}
                        >
                          {iid}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
