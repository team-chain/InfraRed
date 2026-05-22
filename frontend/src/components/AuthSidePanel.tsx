/**
 * AuthSidePanel — 인증 페이지(Login/Register) 좌측 패널.
 *
 * Linear 스타일: 라이트 그레이 배경, 절제된 카피, 작은 통계 카드.
 * 다크 그라데이션·그래픽 효과 없음. 폼에 시선이 가도록 조용한 디자인.
 *
 * 모바일(≤900px)에서는 숨겨지고 폼이 전체 화면을 차지합니다.
 */

import { Activity, Bell, ShieldCheck, Zap } from "lucide-react";
import { Logo } from "./Logo";

type Variant = "login" | "register";

const COPY = {
  login: {
    eyebrow: "InfraRed",
    title: "다시 만나서 반갑습니다.",
    sub: "실시간 침해 탐지와 자동 차단으로 인프라를 보호하는 SOC 플랫폼.",
  },
  register: {
    eyebrow: "Get started",
    title: "5분이면 시작할 수 있습니다.",
    sub: "공개 베타 진행 중. 한 줄 설치로 24시간 자동 방어를 시작하세요.",
  },
} as const;

export function AuthSidePanel({ variant }: { variant: Variant }) {
  const copy = COPY[variant];
  return (
    <aside className="auth-side">
      <div className="auth-side-top">
        <Logo height={26} />
      </div>

      <div className="auth-side-content">
        <span className="auth-side-eyebrow">{copy.eyebrow}</span>
        <h2 className="auth-side-title">{copy.title}</h2>
        <p className="auth-side-sub">{copy.sub}</p>

        <div className="auth-side-cards">
          <SideStat
            icon={<Activity size={14} />}
            label="실시간 탐지"
            value="28개 MITRE ATT&CK 룰"
          />
          <SideStat
            icon={<Zap size={14} />}
            label="자동 대응"
            value="iptables · 격리 · 토큰 폐기"
          />
          <SideStat
            icon={<Bell size={14} />}
            label="알림 채널"
            value="Slack · Discord · Email"
          />
          <SideStat
            icon={<ShieldCheck size={14} />}
            label="감사 로그"
            value="변조 불가 · SOC 2 대비"
          />
        </div>
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
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
}) {
  return (
    <div className="auth-side-card">
      <div className="auth-side-card-icon">{icon}</div>
      <div className="auth-side-card-text">
        <div className="auth-side-card-label">{label}</div>
        <div className="auth-side-card-value">{value}</div>
      </div>
    </div>
  );
}
