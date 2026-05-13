/**
 * Phase 1-A: 인시던트 상태 워크플로우 컴포넌트
 * - 6단계 상태 전이 UI
 * - 담당자 지정
 * - 코멘트
 * - 인시던트 연결
 * - 상태 이력
 */
import { useState, useEffect } from "react";
import {
  transitionIncidentStatus,
  fetchComments,
  addComment,
  fetchStatusHistory,
  type IncidentComment,
  type StatusHistoryItem,
} from "../lib/api";

type Status =
  | "open"
  | "acknowledged"
  | "in_progress"
  | "contained"
  | "resolved"
  | "closed";

type Props = {
  incidentId: string;
  currentStatus: Status;
  userRole: string;
  onStatusChange?: (newStatus: string) => void;
};

const STATUS_LABELS: Record<Status, string> = {
  open: "탐지됨",
  acknowledged: "확인됨",
  in_progress: "처리 중",
  contained: "격리됨",
  resolved: "해결됨",
  closed: "종결",
};

const STATUS_COLORS: Record<Status, string> = {
  open: "#e74c3c",
  acknowledged: "#e67e22",
  in_progress: "#3498db",
  contained: "#9b59b6",
  resolved: "#2ecc71",
  closed: "#7f8c8d",
};

const ALLOWED_TRANSITIONS: Record<Status, Status[]> = {
  open: ["acknowledged", "in_progress"],
  acknowledged: ["in_progress", "closed"],
  in_progress: ["contained", "resolved"],
  contained: ["resolved"],
  resolved: ["closed", "in_progress"],
  closed: [],
};

const DISPOSITION_OPTIONS = [
  { value: "true_positive", label: "실제 공격 (True Positive)" },
  { value: "false_positive", label: "오탐 (False Positive)" },
  { value: "benign", label: "정상 행위 (Benign)" },
  { value: "duplicate", label: "중복 인시던트 (Duplicate)" },
];

export function IncidentWorkflow({ incidentId, currentStatus, userRole, onStatusChange }: Props) {
  const [status, setStatus] = useState<Status>(currentStatus);
  const [showTransitionModal, setShowTransitionModal] = useState(false);
  const [targetStatus, setTargetStatus] = useState<Status | null>(null);
  const [disposition, setDisposition] = useState("");
  const [closeReason, setCloseReason] = useState("");
  const [reason, setReason] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const [comments, setComments] = useState<IncidentComment[]>([]);
  const [commentBody, setCommentBody] = useState("");
  const [history, setHistory] = useState<StatusHistoryItem[]>([]);
  const [activeTab, setActiveTab] = useState<"comments" | "history">("comments");

  useEffect(() => {
    fetchComments(incidentId).then(setComments).catch(() => {});
    fetchStatusHistory(incidentId).then(setHistory).catch(() => {});
  }, [incidentId]);

  const handleTransition = (newStatus: Status) => {
    setTargetStatus(newStatus);
    setShowTransitionModal(true);
    setError(null);
  };

  const confirmTransition = async () => {
    if (!targetStatus) return;
    setLoading(true);
    setError(null);
    try {
      await transitionIncidentStatus(incidentId, targetStatus, {
        reason,
        disposition: targetStatus === "closed" ? disposition : undefined,
        close_reason: targetStatus === "closed" ? closeReason : undefined,
      });
      const prevStatus = status;
      setStatus(targetStatus);
      setHistory((h) => [
        {
          id: Date.now().toString(),
          from_status: prevStatus,
          to_status: targetStatus,
          changed_at: new Date().toISOString(),
          reason,
        },
        ...h,
      ]);
      setShowTransitionModal(false);
      setReason("");
      setDisposition("");
      setCloseReason("");
      onStatusChange?.(targetStatus);
    } catch (e: any) {
      setError(e.message || "상태 전환 실패");
    } finally {
      setLoading(false);
    }
  };

  const handleAddComment = async () => {
    if (!commentBody.trim()) return;
    try {
      const comment = await addComment(incidentId, commentBody);
      setComments((c) => [...c, comment]);
      setCommentBody("");
    } catch {}
  };

  const allowedNext = ALLOWED_TRANSITIONS[status];

  return (
    <div style={{ fontFamily: "sans-serif" }}>
      {/* 현재 상태 뱃지 */}
      <div style={{ marginBottom: 16 }}>
        <span
          style={{
            display: "inline-block",
            padding: "4px 14px",
            borderRadius: 20,
            background: STATUS_COLORS[status],
            color: "white",
            fontWeight: "bold",
            fontSize: 13,
          }}
        >
          {STATUS_LABELS[status]}
        </span>
      </div>

      {/* 상태 전이 버튼 */}
      {allowedNext.length > 0 && (
        <div style={{ marginBottom: 16, display: "flex", gap: 8, flexWrap: "wrap" }}>
          {allowedNext.map((s) => (
            <button
              key={s}
              onClick={() => handleTransition(s)}
              style={{
                padding: "6px 14px",
                borderRadius: 6,
                border: `1.5px solid ${STATUS_COLORS[s]}`,
                background: "white",
                color: STATUS_COLORS[s],
                cursor: "pointer",
                fontWeight: 500,
                fontSize: 13,
              }}
            >
              → {STATUS_LABELS[s]}
            </button>
          ))}
        </div>
      )}

      {/* 전이 모달 */}
      {showTransitionModal && targetStatus && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            background: "rgba(0,0,0,0.4)",
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            zIndex: 1000,
          }}
        >
          <div
            style={{
              background: "white",
              borderRadius: 12,
              padding: 28,
              minWidth: 380,
              maxWidth: 500,
              boxShadow: "0 8px 32px rgba(0,0,0,0.2)",
            }}
          >
            <h3 style={{ margin: "0 0 16px" }}>
              상태 전환: {STATUS_LABELS[status]} → {STATUS_LABELS[targetStatus]}
            </h3>

            <div style={{ marginBottom: 12 }}>
              <label style={{ display: "block", marginBottom: 4, fontSize: 13, color: "#555" }}>
                전환 사유 (선택)
              </label>
              <textarea
                value={reason}
                onChange={(e) => setReason(e.target.value)}
                style={{
                  width: "100%",
                  minHeight: 72,
                  padding: "8px 10px",
                  borderRadius: 6,
                  border: "1px solid #ddd",
                  fontSize: 14,
                  boxSizing: "border-box",
                }}
                placeholder="전환 사유를 입력하세요"
              />
            </div>

            {targetStatus === "closed" && (
              <>
                <div style={{ marginBottom: 12 }}>
                  <label style={{ display: "block", marginBottom: 4, fontSize: 13, color: "#555" }}>
                    판정 결과 <span style={{ color: "red" }}>*필수</span>
                  </label>
                  <select
                    value={disposition}
                    onChange={(e) => setDisposition(e.target.value)}
                    style={{
                      width: "100%",
                      padding: "8px 10px",
                      borderRadius: 6,
                      border: "1px solid #ddd",
                      fontSize: 14,
                    }}
                  >
                    <option value="">선택하세요</option>
                    {DISPOSITION_OPTIONS.map((o) => (
                      <option key={o.value} value={o.value}>
                        {o.label}
                      </option>
                    ))}
                  </select>
                </div>

                {(disposition === "false_positive" || disposition === "duplicate") && (
                  <div style={{ marginBottom: 12 }}>
                    <label style={{ display: "block", marginBottom: 4, fontSize: 13, color: "#555" }}>
                      근거 코멘트 <span style={{ color: "red" }}>*필수</span>
                    </label>
                    <textarea
                      value={closeReason}
                      onChange={(e) => setCloseReason(e.target.value)}
                      style={{
                        width: "100%",
                        minHeight: 60,
                        padding: "8px 10px",
                        borderRadius: 6,
                        border: "1px solid #ddd",
                        fontSize: 14,
                        boxSizing: "border-box",
                      }}
                      placeholder="오탐/중복 판정 근거를 입력하세요"
                    />
                  </div>
                )}
              </>
            )}

            {error && (
              <div
                style={{
                  marginBottom: 12,
                  padding: "8px 12px",
                  background: "#fef2f2",
                  border: "1px solid #fca5a5",
                  borderRadius: 6,
                  color: "#dc2626",
                  fontSize: 13,
                }}
              >
                {error}
              </div>
            )}

            <div style={{ display: "flex", gap: 8, justifyContent: "flex-end" }}>
              <button
                onClick={() => setShowTransitionModal(false)}
                style={{
                  padding: "8px 18px",
                  borderRadius: 6,
                  border: "1px solid #ddd",
                  background: "white",
                  cursor: "pointer",
                }}
              >
                취소
              </button>
              <button
                onClick={confirmTransition}
                disabled={loading}
                style={{
                  padding: "8px 18px",
                  borderRadius: 6,
                  border: "none",
                  background: STATUS_COLORS[targetStatus],
                  color: "white",
                  cursor: "pointer",
                  fontWeight: "bold",
                }}
              >
                {loading ? "처리 중..." : "확인"}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* 탭: 코멘트 / 이력 */}
      <div style={{ marginTop: 20 }}>
        <div style={{ display: "flex", gap: 0, marginBottom: 0, borderBottom: "2px solid #eee" }}>
          {(["comments", "history"] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              style={{
                padding: "8px 18px",
                border: "none",
                background: "none",
                cursor: "pointer",
                fontSize: 14,
                fontWeight: activeTab === tab ? "bold" : "normal",
                color: activeTab === tab ? "#e74c3c" : "#555",
                borderBottom: activeTab === tab ? "2px solid #e74c3c" : "2px solid transparent",
                marginBottom: -2,
              }}
            >
              {tab === "comments" ? `💬 코멘트 (${comments.length})` : `📋 상태 이력 (${history.length})`}
            </button>
          ))}
        </div>

        {activeTab === "comments" && (
          <div style={{ padding: "12px 0" }}>
            {comments.map((c) => (
              <div
                key={c.id}
                style={{
                  padding: "10px 14px",
                  background: "#f8f9fa",
                  borderRadius: 8,
                  marginBottom: 8,
                }}
              >
                <div style={{ fontSize: 12, color: "#888", marginBottom: 4 }}>
                  {c.author_email || c.author_id} · {new Date(c.created_at).toLocaleString("ko-KR")}
                </div>
                <div style={{ fontSize: 14 }}>{c.body}</div>
              </div>
            ))}
            <div style={{ display: "flex", gap: 8, marginTop: 8 }}>
              <textarea
                value={commentBody}
                onChange={(e) => setCommentBody(e.target.value)}
                placeholder="코멘트를 입력하세요..."
                style={{
                  flex: 1,
                  padding: "8px 10px",
                  borderRadius: 6,
                  border: "1px solid #ddd",
                  fontSize: 13,
                  minHeight: 60,
                  resize: "vertical",
                }}
              />
              <button
                onClick={handleAddComment}
                style={{
                  padding: "0 16px",
                  borderRadius: 6,
                  border: "none",
                  background: "#3498db",
                  color: "white",
                  cursor: "pointer",
                  fontWeight: "bold",
                  alignSelf: "flex-end",
                  height: 36,
                }}
              >
                등록
              </button>
            </div>
          </div>
        )}

        {activeTab === "history" && (
          <div style={{ padding: "12px 0" }}>
            {history.map((h) => (
              <div
                key={h.id}
                style={{
                  padding: "8px 14px",
                  borderLeft: `3px solid ${STATUS_COLORS[(h.to_status as Status) || "open"]}`,
                  marginBottom: 8,
                  background: "#f8f9fa",
                  borderRadius: "0 6px 6px 0",
                }}
              >
                <div style={{ fontSize: 13, fontWeight: "bold" }}>
                  {h.from_status ? `${STATUS_LABELS[h.from_status as Status]} → ` : ""}
                  {STATUS_LABELS[h.to_status as Status]}
                </div>
                <div style={{ fontSize: 12, color: "#888" }}>
                  {h.changed_by_email || h.changed_by || "시스템"} · {new Date(h.changed_at).toLocaleString("ko-KR")}
                </div>
                {h.reason && (
                  <div style={{ fontSize: 12, color: "#555", marginTop: 2 }}>{h.reason}</div>
                )}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}
