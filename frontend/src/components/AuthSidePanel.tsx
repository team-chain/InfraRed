/**
 * AuthSidePanel — 인증 페이지(Login/Register) 좌측에 표시되는 보안 비주얼 패널.
 *
 * 다크 그라데이션 + 격자 패턴 + 실시간 통계 카드 + 신뢰 메시지로 구성.
 * 보안 제품의 전문성·신뢰감을 강화하기 위한 시각 자료.
 *
 * 모바일(≤900px)에서는 숨겨지고 폼이 전체 화면을 차지합니다.
 */

import { Activity, Bell, Shield, ShieldCheck, Zap } from "lucide-react";
import { Logo } from "./Logo";

type Variant = "login" | "register";

const COPY = {
  login: {
    eyebrow: "InfraRed SOC",
    title: "다시 만나서 반갑습니다",
    sub: "실시간으로 침해를 탐지하고 자동으로 차단하는 SOC 운영 플랫폼.",
  },
  register: {
    eyebrow: "Get started",
    title: "5분이면 시작할 수 있습니다",
    sub: "신용카드 없이 무료로 시작. 에이전트 한 줄 설치로 24시간 자동 방어를 켜세요.",
  },
} as const;

export function AuthSidePanel({ variant }: { variant: Variant }) {
  const copy = COPY[variant];
  return (
    <aside className="auth-side">
      <div className="auth-side-grid" aria-hidden="true" />
      <div className="auth-side-glow" aria-hidden="true" />

      <div className="auth-side-top">
        <Logo height={28} />
      </div>

      <div className="auth-side-content">
        <span className="auth-side-eyebrow">{copy.eyebrow}</span>
        <h2 className="auth-side-title">{copy.title}</h2>
        <p className="auth-side-sub">{copy.sub}</p>

        {/* 신뢰 카드들 */}
        <div className="auth-side-cards">
          <SideStat
            icon={<Activity size={16} />}
            label="실시간 탐지"
            value="28개"
            desc="MITRE ATT&CK 룰"
          />
          <SideStat
            icon={<Zap size={16} />}
            label="자동 대응"
            value="iptables · 격리 · 토큰 폐기"
          />
          <SideStat
            icon={<Bell size={16} />}
            label="알림"
            value="Slack · Discord · Email"
          />
        </div>

        <ul className="auth-side-bullets">
          <li>
            <ShieldCheck size={14} />
            <span>변조 불가 감사 로그 · SOC 2 대비</span>
          </li>
          <li>
            <Shield size={14} />
            <span>멀티 테넌트 격리 · RBAC · SSO</span>
          </li>
        </ul>
      </div>

      <div className="auth-side-footer">
        © {new Date().getFullYear()} InfraRed · <a href="/status">서비스 상태</a>
      </div>
    </aside>
  );
}

function SideStat({
  icon,
  label,
  value,
  desc,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  desc?: string;
}) {
  return (
    <div className="auth-side-card">
      <div className="auth-side-card-icon">{icon}</div>
      <div className="auth-side-card-text">
        <div className="auth-side-card-label">{label}</div>
        <div className="auth-side-card-value">
          {value}
          {desc && <span className="auth-side-card-desc"> · {desc}</span>}
        </div>
      </div>
    </div>
  );
}
