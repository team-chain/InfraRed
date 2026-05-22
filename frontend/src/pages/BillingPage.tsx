import { useEffect, useState } from "react";
import { CreditCard, CheckCircle2, AlertTriangle, RefreshCw, TrendingUp, Check } from "lucide-react";
import type { AuthUser } from "../lib/api";

type Props = { user: AuthUser };

type BillingStatus = {
  tenant_id?: string;
  plan?: string;
  status?: string;          // active / trial / past_due / canceled
  current_period_end?: string;
  stripe_customer_id?: string;
  trial_ends_at?: string;
};

type UsageEntry = {
  agent_count: number;
  reported_at: string;
  stripe_reported: boolean;
};

const API_BASE = (import.meta as any).env?.DEV
  ? ""
  : ((import.meta as any).env?.VITE_API_BASE_URL ?? "");

const PLANS = [
  {
    id: "starter",
    name: "Starter",
    price: "$49 / month",
    description: "소규모 팀, 최대 10대",
    features: ["10 agents", "AUTH/WEB 탐지", "Discord 알림", "7일 보존"],
  },
  {
    id: "growth",
    name: "Growth",
    price: "$199 / month",
    description: "성장 단계, 최대 100대",
    features: ["100 agents", "전체 룰 28개", "Slack + 이메일", "30일 보존", "AI 분석"],
  },
  {
    id: "enterprise",
    name: "Enterprise",
    price: "Contact",
    description: "무제한, SLA, 전용 지원",
    features: ["Unlimited agents", "Custom 룰", "전용 Slack 채널", "1년 보존", "SLA 99.9%"],
  },
];

export function BillingPage({ user }: Props) {
  const [status, setStatus] = useState<BillingStatus | null>(null);
  const [usage, setUsage] = useState<UsageEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [acting, setActing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const isOwner = user.role === "owner";

  async function load() {
    setLoading(true);
    setError(null);
    try {
      const [s, u] = await Promise.all([
        fetch(`${API_BASE}/api/v1/billing/status`, { credentials: "include" }).then((r) => r.json()),
        fetch(`${API_BASE}/api/v1/billing/usage`,  { credentials: "include" }).then((r) => r.json()),
      ]);
      setStatus(s ?? {});
      setUsage(u.usage_history ?? []);
    } catch (e) {
      setError(e instanceof Error ? e.message : "Load failed");
    } finally {
      setLoading(false);
    }
  }

  useEffect(() => { load(); /* eslint-disable-next-line */ }, []);

  async function subscribe(plan: string) {
    if (!isOwner) {
      setError("플랜 변경은 owner만 가능합니다");
      return;
    }
    if (!user.email) {
      setError("이메일이 없습니다");
      return;
    }
    setActing(true);
    setError(null);
    setNotice(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/billing/subscribe`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        credentials: "include",
        body: JSON.stringify({ plan, email: user.email, company_name: user.tenant_id }),
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.detail ?? `HTTP ${res.status}`);
      // Stripe Checkout URL이 있으면 redirect
      if (data.checkout_url) {
        window.location.href = data.checkout_url;
        return;
      }
      setNotice(`${plan} 플랜으로 변경되었습니다`);
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "구독 실패");
    } finally {
      setActing(false);
    }
  }

  async function cancel() {
    if (!isOwner) {
      setError("구독 취소는 owner만 가능합니다");
      return;
    }
    if (!confirm("정말 구독을 취소하시겠습니까? 현재 청구 기간 종료 후 비활성화됩니다.")) return;
    setActing(true);
    setError(null);
    try {
      const res = await fetch(`${API_BASE}/api/v1/billing/cancel`, {
        method: "POST",
        credentials: "include",
      });
      if (!res.ok) throw new Error(`HTTP ${res.status}`);
      setNotice("구독 취소 요청 완료. 현재 기간 종료 후 비활성화됩니다.");
      await load();
    } catch (e) {
      setError(e instanceof Error ? e.message : "취소 실패");
    } finally {
      setActing(false);
    }
  }

  const currentPlan = (status?.plan || "free").toLowerCase();
  const isActive = (status?.status || "").toLowerCase() === "active";
  const latestAgentCount = usage[0]?.agent_count ?? 0;
  const planLimits: Record<string, number> = { starter: 10, growth: 100, enterprise: 9999 };
  const limit = planLimits[currentPlan] ?? 0;
  const usagePct = limit > 0 ? Math.min(100, Math.round((latestAgentCount / limit) * 100)) : 0;

  return (
    <div className="page-wrap">
      <div className="page-header" style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start" }}>
        <div>
          <h2 className="page-title">
            <CreditCard size={20} style={{ marginRight: 8, verticalAlign: "text-bottom" }} />
            Billing
          </h2>
          <p className="page-subtitle">
            테넌트: <code style={{ fontSize: 12 }}>{user.tenant_id}</code> · 구독 / 사용량 / 인보이스
          </p>
        </div>
        <button className="btn btn-sm" onClick={load} disabled={loading}>
          <RefreshCw size={13} className={loading ? "spin" : ""} /> 새로고침
        </button>
      </div>

      {error && <div className="alert" style={{ marginBottom: 12 }}>{error}</div>}
      {notice && <div className="notice" style={{ marginBottom: 12 }}>{notice}</div>}

      {/* 현재 플랜 + 사용량 */}
      <div className="card" style={{ padding: 20, marginBottom: 20 }}>
        <div style={{ display: "flex", justifyContent: "space-between", alignItems: "flex-start", flexWrap: "wrap", gap: 16 }}>
          <div>
            <div style={{ fontSize: 12, color: "var(--text-3)", marginBottom: 4 }}>현재 플랜</div>
            <div style={{ fontSize: 24, fontWeight: 700, textTransform: "capitalize" }}>
              {currentPlan} {isActive && <CheckCircle2 size={20} style={{ color: "var(--c-green-500, #16a34a)", verticalAlign: "middle" }} />}
            </div>
            <div style={{ fontSize: 13, color: "var(--text-3)", marginTop: 4 }}>
              상태: <strong>{status?.status ?? "—"}</strong>
              {status?.current_period_end && (
                <> · 다음 결제: {new Date(status.current_period_end).toLocaleDateString("ko-KR")}</>
              )}
            </div>
          </div>
          <div style={{ minWidth: 200 }}>
            <div style={{ fontSize: 12, color: "var(--text-3)", marginBottom: 4 }}>
              <TrendingUp size={12} style={{ verticalAlign: "text-bottom", marginRight: 4 }} />
              현재 사용량
            </div>
            <div style={{ fontSize: 20, fontWeight: 700 }}>
              {latestAgentCount}
              {limit > 0 && <span style={{ fontSize: 14, color: "var(--text-3)", fontWeight: 400 }}> / {limit} agents</span>}
            </div>
            {limit > 0 && (
              <div style={{ marginTop: 8, height: 6, background: "var(--c-gray-100, #f3f4f6)", borderRadius: 3, overflow: "hidden" }}>
                <div style={{
                  height: "100%",
                  width: `${usagePct}%`,
                  background: usagePct > 80 ? "var(--c-orange-500, #f97316)" : "var(--brand-primary, #E07000)",
                  transition: "width 0.3s",
                }} />
              </div>
            )}
          </div>
        </div>

        {isActive && (
          <button
            className="btn btn-sm"
            onClick={cancel}
            disabled={acting || !isOwner}
            style={{ marginTop: 16, color: "var(--c-red-600, #dc2626)" }}
          >
            구독 취소
          </button>
        )}
      </div>

      {/* 플랜 선택 */}
      <div className="settings-section-title" style={{ marginBottom: 12 }}>플랜 선택</div>
      <div style={{ display: "grid", gridTemplateColumns: "repeat(auto-fit, minmax(260px, 1fr))", gap: 16, marginBottom: 24 }}>
        {PLANS.map((p) => {
          const selected = p.id === currentPlan;
          return (
            <div
              key={p.id}
              className="card"
              style={{
                padding: 20,
                border: selected ? "2px solid var(--brand-primary, #E07000)" : "1px solid var(--c-gray-150, #e5e7eb)",
                position: "relative",
              }}
            >
              {selected && (
                <span style={{
                  position: "absolute", top: 12, right: 12,
                  fontSize: 11, fontWeight: 700,
                  background: "var(--brand-primary, #E07000)",
                  color: "white", padding: "3px 8px", borderRadius: 10,
                }}>
                  현재
                </span>
              )}
              <div style={{ fontSize: 18, fontWeight: 700, marginBottom: 4 }}>{p.name}</div>
              <div style={{ fontSize: 22, fontWeight: 700, color: "var(--brand-primary, #E07000)", marginBottom: 8 }}>
                {p.price}
              </div>
              <div style={{ fontSize: 12, color: "var(--text-3)", marginBottom: 12 }}>
                {p.description}
              </div>
              <ul style={{ listStyle: "none", padding: 0, margin: "0 0 16px", fontSize: 13 }}>
                {p.features.map((f) => (
                  <li key={f} style={{ display: "flex", alignItems: "center", gap: 6, padding: "4px 0" }}>
                    <CheckCircle2 size={14} style={{ color: "var(--c-green-500, #16a34a)", flexShrink: 0 }} />
                    {f}
                  </li>
                ))}
              </ul>
              <button
                className="btn btn-primary"
                style={{ width: "100%" }}
                onClick={() => subscribe(p.id)}
                disabled={selected || acting || !isOwner}
              >
                {selected ? "현재 플랜" : p.id === "enterprise" ? "문의하기" : "이 플랜 선택"}
              </button>
            </div>
          );
        })}
      </div>

      {/* 사용량 히스토리 */}
      <div className="settings-section-title" style={{ marginBottom: 12 }}>최근 사용량 (30일)</div>
      {usage.length === 0 ? (
        <div className="card" style={{ padding: 32, textAlign: "center", color: "var(--text-3)", fontSize: 13 }}>
          <AlertTriangle size={24} style={{ marginBottom: 8, opacity: 0.5 }} />
          <div>아직 사용량 데이터가 없습니다.</div>
        </div>
      ) : (
        <div className="tbl-wrap">
          <table className="tbl">
            <thead>
              <tr>
                <th>날짜</th>
                <th>활성 Agent 수</th>
                <th>Stripe 보고</th>
              </tr>
            </thead>
            <tbody>
              {usage.map((row, i) => (
                <tr key={i}>
                  <td style={{ fontSize: 12 }}>{new Date(row.reported_at).toLocaleDateString("ko-KR")}</td>
                  <td><strong>{row.agent_count}</strong></td>
                  <td>{row.stripe_reported ? <Check size={14} color="var(--c-green-600)" /> : "—"}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {!isOwner && (
        <div style={{ marginTop: 16, padding: 12, fontSize: 12, color: "var(--text-3)", textAlign: "center" }}>
          구독 변경 / 취소는 owner 권한이 필요합니다.
        </div>
      )}
    </div>
  );
}
