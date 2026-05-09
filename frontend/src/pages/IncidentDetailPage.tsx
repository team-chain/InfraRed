/**
 * IncidentDetailPage — 인시던트 상세 패널
 *
 * Dashboard 우측 패널에 렌더링됩니다.
 *
 * 구성
 * ────
 * 1. LLM 3줄 요약 (Summary Strip)  — AI 분석 결과에서 핵심 3문장 추출
 * 2. 헤더 + 액션 버튼
 * 3. 문제 카드  (plain_summary / attack_intent / kill_chain_analysis)
 * 4. 권장 조치 카드
 * 5. Evidence Timeline + CTI 패널
 */
import {
  AlertTriangle, Bell, BrainCircuit, GitCommitVertical,
  Shield, ShieldAlert,
} from "lucide-react";
import type { IncidentContract } from "../lib/api";

// ── helpers ──────────────────────────────────────────────

function flag(code: string) {
  return String.fromCodePoint(...[...code].map(c => 0x1F1A5 + c.charCodeAt(0)));
}

function abuseColor(n: number) {
  if (n >= 70) return "var(--c-red-500)";
  if (n >= 40) return "var(--c-orange-500)";
  return "var(--c-green-500)";
}

/**
 * LLM plain_summary에서 핵심 3줄을 추출합니다.
 * 문장 구분 기준: ". " / ".\n" / "! " / "? "
 * 3문장 미만이면 전체 반환.
 */
function extractTop3(text: string): string[] {
  const sentences = text
    .split(/(?<=[.!?])\s+/)
    .map(s => s.trim())
    .filter(s => s.length > 10);
  return sentences.slice(0, 3);
}

// ── Types ─────────────────────────────────────────────────

type Props = {
  selected?: IncidentContract;
  busy?: string;
  analyzingIds?: Set<string>;
  onRunAnalysis: (refresh?: boolean) => void;
  onSendAlert: () => void;
  onChangeStatus: (status: string) => void;
};

// ── LLM Summary Strip ─────────────────────────────────────

function LlmSummaryStrip({ summary }: { summary: string }) {
  const lines = extractTop3(summary);
  if (!lines.length) return null;

  return (
    <div className="llm-summary-strip">
      <div className="llm-summary-strip-title">
        <BrainCircuit size={13} />
        AI 핵심 요약 (3줄)
      </div>
      <ol className="llm-summary-list">
        {lines.map((line, i) => (
          <li key={i} className="llm-summary-item">
            <span className="llm-summary-num">{i + 1}</span>
            <span>{line}</span>
          </li>
        ))}
      </ol>
    </div>
  );
}

// ── Evidence Timeline ─────────────────────────────────────

function EvidenceTimeline({ events }: {
  events: Array<{ timestamp: string; description: string; signal_id?: string; rule_id?: string }>;
}) {
  if (!events.length) {
    return (
      <div style={{ color: "var(--text-3)", fontSize: 13.5, padding: "8px 0" }}>
        증거 없음
      </div>
    );
  }

  return (
    <ol className="timeline timeline-v2">
      {events.map((item, idx) => {
        const ts = new Date(item.timestamp);
        const timeStr = ts.toLocaleString("ko-KR", {
          month: "numeric", day: "numeric",
          hour: "2-digit", minute: "2-digit", second: "2-digit",
        });
        const isFirst = idx === 0;
        const isLast  = idx === events.length - 1;

        return (
          <li key={`${item.timestamp}-${idx}`} className={`timeline-item-v2${isFirst ? " tl-first" : ""}${isLast ? " tl-last" : ""}`}>
            {/* 세로 선 */}
            <div className="tl-track">
              <div className="tl-dot-v2">
                <GitCommitVertical size={11} />
              </div>
              {!isLast && <div className="tl-line" />}
            </div>
            {/* 내용 */}
            <div className="tl-body-v2">
              <div className="tl-time-v2">{timeStr}</div>
              <div className="tl-desc-v2">{item.description}</div>
              {(item.rule_id || item.signal_id) && (
                <span className="tl-rule-v2">{item.rule_id ?? item.signal_id}</span>
              )}
            </div>
          </li>
        );
      })}
    </ol>
  );
}

// ── Main component ────────────────────────────────────────

export function IncidentDetailPage({
  selected,
  busy,
  analyzingIds,
  onRunAnalysis,
  onSendAlert,
  onChangeStatus,
}: Props) {
  const inc = selected?.incident;
  const llm = selected?.llm_result;
  const cti = inc?.cti_enrichment;

  if (!inc) {
    return (
      <div className="empty-state">
        <div className="empty-icon"><ShieldAlert size={26} /></div>
        <h3>인시던트를 선택하세요</h3>
        <p>왼쪽 목록에서 인시던트를 클릭하면 AI 분석, 권장 조치, 위협 정보를 확인할 수 있습니다.</p>
      </div>
    );
  }

  const isAnalyzing = analyzingIds?.has(inc.incident_id) ?? busy === "analysis";

  return (
    <>
      {/* ── ① LLM 3줄 요약 스트립 ── */}
      {llm?.plain_summary ? (
        <LlmSummaryStrip summary={llm.plain_summary} />
      ) : (
        <div className="llm-summary-strip llm-summary-strip-empty">
          <BrainCircuit size={13} />
          <span>AI 분석 전입니다 — 상단 <strong>AI 재분석</strong> 버튼으로 요약을 생성하세요.</span>
        </div>
      )}

      {/* ── ② 헤더 ── */}
      <div className="detail-header">
        <div>
          <div className="detail-id">{inc.incident_id}</div>
          <div className="detail-title-row">
            <span className={`pill sev-${inc.severity}`}>
              <AlertTriangle size={11} /> {inc.severity.toUpperCase()}
            </span>
            <span className={`pill status-pill-${inc.status.replace(" ", "_")}`}>
              {{ open:"미해결", acknowledged:"확인됨", resolved:"해결됨", false_positive:"오탐" }[inc.status] ?? inc.status}
            </span>
            {isAnalyzing && (
              <span style={{ display:"flex", alignItems:"center", gap:4, fontSize:12, color:"var(--c-orange-500)" }}>
                <BrainCircuit size={12} className="spin" /> 분석 중…
              </span>
            )}
          </div>
          <div className="detail-meta-row">
            <Shield size={12} />
            <span>{inc.mitre_tactic}</span>
            <code>{inc.mitre_technique}</code>
            <span className="detail-meta-sep">·</span>
            <span>{inc.kill_chain_stage}</span>
            <span className="detail-meta-sep">·</span>
            <span>Priority: <strong>{inc.priority}</strong></span>
            <span className="detail-meta-sep">·</span>
            <span>Confidence: <strong>{inc.confidence}</strong></span>
          </div>
        </div>
        <div className="detail-actions">
          <button className="btn btn-primary" disabled={busy === "analysis"} onClick={() => onRunAnalysis(true)}>
            <BrainCircuit size={14} />
            {busy === "analysis" ? "분석 중…" : "AI 재분석"}
          </button>
          <button className="btn" disabled={busy === "dispatch"} onClick={onSendAlert}>
            <Bell size={14} />
            {busy === "dispatch" ? "발송 중…" : "알림 발송"}
          </button>
          <select
            className="status-select"
            value={inc.status}
            disabled={busy === "status"}
            onChange={e => onChangeStatus(e.target.value)}
          >
            <option value="open">미해결 (Open)</option>
            <option value="acknowledged">확인됨 (Acknowledged)</option>
            <option value="resolved">해결됨 (Resolved)</option>
            <option value="false_positive">오탐 (False Positive)</option>
          </select>
        </div>
      </div>

      <div className="cards-stack">

        {/* ── ③ 문제 카드 ── */}
        <div className="card">
          <div className="card-head">
            <div className="card-head-icon red">🔴</div>
            <span className="card-head-title">문제 — 무슨 일이 발생했나요?</span>
            <span className="card-head-sub">{new Date(inc.created_at).toLocaleString("ko-KR")}</span>
          </div>
          <div className="card-body">
            <p className="summary-text">
              {llm?.plain_summary ?? "AI 분석 결과가 아직 없습니다. 상단의 'AI 재분석' 버튼으로 분석을 시작하세요."}
            </p>

            {llm?.attack_intent && (
              <div className="analysis-section">
                <div className="analysis-label">공격 의도</div>
                <p className="analysis-text">{llm.attack_intent}</p>
              </div>
            )}
            {llm?.kill_chain_analysis && (
              <div className="analysis-section">
                <div className="analysis-label">Kill Chain 분석</div>
                <p className="analysis-text">{llm.kill_chain_analysis}</p>
              </div>
            )}
            {llm && (
              <div className="llm-meta">
                <span className="llm-model-badge">{llm.model}</span>
                {llm.cached && <span className="cached-badge">캐시됨</span>}
                <span style={{ marginLeft: "auto" }}>{new Date(llm.generated_at).toLocaleString("ko-KR")}</span>
              </div>
            )}

            <div className="meta-grid">
              {[
                { label: "Source IP", value: inc.source_ip, mono: true },
                inc.username ? { label: "계정", value: inc.username } : null,
                (cti?.country || cti?.city)
                  ? { label: "IP 위치", value: `${cti?.country ? flag(cti.country) + " " : ""}${[cti?.country, cti?.city].filter(Boolean).join(" / ")}` }
                  : null,
                cti?.asn_org ? { label: "AS 기관", value: cti.asn_org } : null,
                cti?.abuse_score != null
                  ? { label: "Abuse Score", value: `${cti.abuse_score} / 100`, color: abuseColor(cti.abuse_score) }
                  : null,
                { label: "MITRE", value: `${inc.mitre_tactic} · ${inc.mitre_technique}` },
              ].filter(Boolean).map((item: any) => (
                <div key={item.label} className="meta-cell">
                  <div className="meta-cell-label">{item.label}</div>
                  <div className="meta-cell-value" style={{
                    fontFamily: item.mono ? "var(--mono)" : undefined,
                    color: item.color ?? "var(--text)",
                  }}>{item.value ?? "-"}</div>
                </div>
              ))}
            </div>

            {cti?.user_agent && (
              <div style={{ marginTop: 14 }}>
                <div style={{ fontSize: 11, fontWeight: 700, textTransform: "uppercase", letterSpacing: ".05em", color: "var(--text-3)", marginBottom: 6 }}>
                  기기 정보 (User-Agent)
                </div>
                <div className="ua-box">{cti.user_agent}</div>
              </div>
            )}
          </div>
        </div>

        {/* ── ④ 권장 조치 카드 ── */}
        <div className="card">
          <div className="card-head">
            <div className="card-head-icon green">✅</div>
            <span className="card-head-title">권장 조치 — 어떻게 대응해야 하나요?</span>
            <span className="card-head-sub">AI 분석 기반 권고</span>
          </div>
          <div className="card-body">
            {llm?.recommended_actions?.length ? (
              <div className="action-list">
                {llm.recommended_actions.map((a, i) => (
                  <div key={a} className="action-item">
                    <span className="action-num">{i + 1}</span>
                    <span className="action-text">{a}</span>
                  </div>
                ))}
              </div>
            ) : (
              <div style={{ display: "flex", alignItems: "center", gap: 10, color: "var(--text-3)", fontSize: 13.5, padding: "8px 0" }}>
                <BrainCircuit size={16} /> AI 분석 후 권장 조치가 표시됩니다.
              </div>
            )}
            {llm?.confidence_note && (
              <div className="confidence-note">💡 {llm.confidence_note}</div>
            )}
          </div>
        </div>

        {/* ── ⑤ Evidence Timeline + CTI ── */}
        <div className="card">
          <div className="card-head">
            <div className="card-head-icon blue">🛡️</div>
            <span className="card-head-title">대응 현황 — Evidence Timeline</span>
            <span className="card-head-sub">{selected?.evidence_timeline.length ?? 0}개 이벤트</span>
          </div>
          <div className="card-body">
            <div className="response-grid">

              {/* Timeline */}
              <EvidenceTimeline events={selected?.evidence_timeline ?? []} />

              {/* CTI 패널 */}
              <div className="cti-panel">
                <div className="cti-panel-title">위협 인텔리전스 (CTI)</div>
                {cti ? (
                  <>
                    {cti.abuse_score != null && (
                      <div className="cti-row">
                        <span className="cti-key">Abuse Score</span>
                        <div className="abuse-wrap">
                          <span className="cti-val" style={{ color: abuseColor(cti.abuse_score) }}>
                            {cti.abuse_score}/100
                          </span>
                          <div className="abuse-bar">
                            <div className="abuse-fill" style={{
                              width: `${cti.abuse_score}%`,
                              background: abuseColor(cti.abuse_score),
                            }} />
                          </div>
                        </div>
                      </div>
                    )}
                    {cti.country && (
                      <div className="cti-row">
                        <span className="cti-key">국가</span>
                        <span className="cti-val">
                          {flag(cti.country)} {cti.country}{cti.city ? ` / ${cti.city}` : ""}
                        </span>
                      </div>
                    )}
                    {cti.asn_org && (
                      <div className="cti-row">
                        <span className="cti-key">AS 기관</span>
                        <span className="cti-val">{cti.asn_org}</span>
                      </div>
                    )}
                    {cti.tags?.length > 0 && (
                      <div className="cti-row" style={{ alignItems: "flex-start" }}>
                        <span className="cti-key">태그</span>
                        <div className="cti-tags">
                          {cti.tags.map(t => <span key={t} className="cti-tag">{t}</span>)}
                        </div>
                      </div>
                    )}
                    {cti.sources?.length > 0 && (
                      <div className="cti-row" style={{ alignItems: "flex-start" }}>
                        <span className="cti-key">출처</span>
                        <div className="cti-tags">
                          {cti.sources.map(s => <span key={s} className="cti-tag">{s}</span>)}
                        </div>
                      </div>
                    )}
                  </>
                ) : (
                  <p style={{ color: "var(--text-3)", fontSize: 13 }}>CTI 데이터 없음</p>
                )}
              </div>
            </div>
          </div>
        </div>

      </div>
    </>
  );
}
