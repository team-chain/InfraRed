/**
 * InfraRed Landing Page
 *
 * 비인증 사용자가 / 접속 시 표시되는 마케팅용 페이지.
 * 보안 제품의 전문성과 신뢰감을 우선시한 split-hero + 트러스트 스트립 구조.
 */

import {
  Activity,
  ArrowRight,
  Bell,
  CheckCircle2,
  ExternalLink,
  Lock,
  Network,
  Server,
  ShieldAlert,
  ShieldCheck,
  Sparkles,
  Terminal,
  Users,
  Zap,
} from "lucide-react";
import { Logo } from "../components/Logo";

type Props = {
  onGoToLogin: () => void;
  onGoToRegister: () => void;
};

export function LandingPage({ onGoToLogin, onGoToRegister }: Props) {
  return (
    <div className="landing-root">
      <header className="landing-nav">
        <div className="landing-nav-inner">
          <Logo height={30} />
          <nav className="landing-nav-links">
            <a href="#features">기능</a>
            <a href="#how">동작 방식</a>
            <a href="#pricing">요금</a>
            <a href="/status">서비스 상태</a>
            <button className="landing-nav-login" onClick={onGoToLogin}>
              로그인
            </button>
            <button className="landing-nav-cta" onClick={onGoToRegister}>
              무료로 시작
            </button>
          </nav>
        </div>
      </header>

      <section className="landing-hero">
        <div className="landing-hero-glow" aria-hidden="true" />
        <div className="landing-hero-inner">
          <div className="landing-hero-copy">
            <div className="landing-hero-badge">
              <Sparkles size={13} />
              <span>AI 기반 SOC 자동화 플랫폼</span>
            </div>
            <h1 className="landing-hero-title">
              침해를 <span className="landing-gradient-text">탐지</span>하는 데
              <br />그치지 않습니다.
              <br />
              <span className="landing-gradient-text">차단</span>까지 합니다.
            </h1>
            <p className="landing-hero-sub">
              InfraRed는 로그를 실시간으로 분석해 침해 패턴을 발견하고,
              위협을 자동으로 격리하는 SOC 운영 플랫폼입니다.
              SOC 팀 없이도 24시간 방어가 가능합니다.
            </p>
            <div className="landing-hero-cta">
              <button className="landing-btn-primary" onClick={onGoToRegister}>
                무료로 시작하기 <ArrowRight size={16} />
              </button>
              <a href="#how" className="landing-btn-secondary">
                동작 원리 보기
              </a>
            </div>
            <div className="landing-trust">
              <div className="landing-trust-item">
                <CheckCircle2 size={14} />
                <span>신용카드 없이 5분 가입</span>
              </div>
              <div className="landing-trust-item">
                <CheckCircle2 size={14} />
                <span>한 줄 명령어 설치</span>
              </div>
              <div className="landing-trust-item">
                <CheckCircle2 size={14} />
                <span>MITRE ATT&amp;CK 매핑</span>
              </div>
            </div>
          </div>

          <div className="landing-hero-visual" aria-hidden="true">
            <HeroDashboardMockup />
          </div>
        </div>
      </section>

      <section className="landing-trust-strip">
        <div className="landing-trust-strip-inner">
          <span className="landing-trust-strip-label">기반 기술</span>
          <div className="landing-trust-strip-items">
            <TrustBadge>MITRE ATT&amp;CK</TrustBadge>
            <TrustBadge>AWS Bedrock</TrustBadge>
            <TrustBadge>PostgreSQL · Timescale</TrustBadge>
            <TrustBadge>OpenTelemetry</TrustBadge>
            <TrustBadge>OAuth 2.1 · OIDC</TrustBadge>
          </div>
        </div>
      </section>

      <section className="landing-section">
        <div className="landing-section-inner">
          <h2 className="landing-section-title">SOC 운영이 어려운 이유</h2>
          <p className="landing-section-sub">
            대부분의 기업은 보안 인력이 부족합니다. 침해를 당해도 인지까지 며칠이 걸리는 게 현실입니다.
          </p>
          <div className="landing-problems">
            <div className="landing-problem-card">
              <div className="landing-problem-num">01</div>
              <h3>로그가 너무 많습니다</h3>
              <p>하루 수십만 건의 이벤트. 사람이 모두 확인할 수 없고, 의미 있는 패턴을 놓칩니다.</p>
            </div>
            <div className="landing-problem-card">
              <div className="landing-problem-num">02</div>
              <h3>대응이 느립니다</h3>
              <p>침해를 인지해도 IP 차단·계정 잠금까지 평균 6시간. 그 사이 피해는 확산됩니다.</p>
            </div>
            <div className="landing-problem-card">
              <div className="landing-problem-num">03</div>
              <h3>SOC는 고비용입니다</h3>
              <p>외부 위탁은 월 수백만 원, 사내 인력은 최소 3명. 작은 팀에는 현실적이지 않습니다.</p>
            </div>
          </div>
        </div>
      </section>

      <section id="features" className="landing-section landing-section-alt">
        <div className="landing-section-inner">
          <h2 className="landing-section-title">핵심 기능</h2>
          <p className="landing-section-sub">탐지부터 자동 차단·알림까지 단일 플랫폼에서.</p>
          <div className="landing-features">
            <FeatureCard icon={<Activity size={20} />} title="실시간 침해 탐지" desc="SSH 무차별 공격, 웹쉘, SQL 인젝션 등 28개 MITRE ATT&CK 룰을 즉시 매칭합니다." />
            <FeatureCard icon={<ShieldAlert size={20} />} title="AI 인시던트 분석" desc="LLM이 각 인시던트의 위협 수준·근본 원인·권장 대응을 분석합니다." />
            <FeatureCard icon={<Zap size={20} />} title="자동 대응" desc="고신뢰도 위협은 iptables 차단·컨테이너 격리·토큰 폐기까지 자동 실행됩니다." />
            <FeatureCard icon={<Bell size={20} />} title="멀티 채널 알림" desc="Slack · Discord · Email로 실시간 전송. 채널별 심각도 라우팅 가능." />
            <FeatureCard icon={<Lock size={20} />} title="감사 로그 · 컴플라이언스" desc="모든 admin 액션을 변조 불가 로그로 기록. SOC 2 · ISMS 대응 준비." />
            <FeatureCard icon={<Users size={20} />} title="멀티 테넌트 · RBAC" desc="조직별 완전 격리, Owner/Admin/Member 3단계 권한, SSO·MFA." />
          </div>
        </div>
      </section>

      <section id="how" className="landing-section">
        <div className="landing-section-inner">
          <h2 className="landing-section-title">5분 만에 시작</h2>
          <p className="landing-section-sub">설치 컨설팅 없이 명령어 한 줄이면 끝납니다.</p>
          <div className="landing-steps">
            <StepCard num={1} icon={<ShieldCheck size={18} />} title="가입" desc="이메일로 1분 가입. 신용카드 불필요. Free 플랜으로 즉시 시작." />
            <StepCard num={2} icon={<Terminal size={18} />} title="에이전트 설치" desc={<>서버에서 한 줄 명령:<code className="landing-step-code">curl -sSL infrared.kr/install | sh</code></>} />
            <StepCard num={3} icon={<Activity size={18} />} title="모니터링 시작" desc="대시보드에서 실시간 인시던트 확인. 위협은 자동 차단, Slack으로 즉시 알림." />
          </div>
        </div>
      </section>

      <section id="pricing" className="landing-section landing-section-alt">
        <div className="landing-section-inner">
          <h2 className="landing-section-title">합리적인 요금</h2>
          <p className="landing-section-sub">작은 팀부터 엔터프라이즈까지. 사용량 기반 투명 과금.</p>
          <div className="landing-pricing">
            <PricingCard name="Free" price="₩0" period="forever" features={["에이전트 3대", "기본 룰 28개", "Discord 알림", "7일 로그 보관"]} cta="무료로 시작" onCta={onGoToRegister} />
            <PricingCard name="Pro" price="₩99,000" period="/월" features={["에이전트 25대", "전체 룰 + 커스텀 룰", "Slack · Email 알림", "AI 인시던트 분석 포함", "90일 로그 보관", "감사 로그 export"]} cta="14일 무료 시작" onCta={onGoToRegister} highlighted />
            <PricingCard name="Enterprise" price="문의" period="" features={["무제한 에이전트", "SSO · MFA · SAML", "전담 SLA", "On-prem 배포 옵션", "1년+ 로그 보관", "전용 보안 컨설팅"]} cta="영업팀 문의" onCta={() => (window.location.href = "mailto:sales@infrared.kr")} />
          </div>
        </div>
      </section>

      <section className="landing-final-cta">
        <div className="landing-final-cta-grid" aria-hidden="true" />
        <div className="landing-final-cta-inner">
          <h2>지금 인프라를 보호하세요</h2>
          <p>5분이면 끝납니다. 신용카드 없이 시작.</p>
          <button className="landing-btn-primary landing-btn-large" onClick={onGoToRegister}>
            무료로 시작하기 <ArrowRight size={16} />
          </button>
        </div>
      </section>

      <footer className="landing-footer">
        <div className="landing-footer-inner">
          <div className="landing-footer-brand">
            <Logo height={22} />
            <p>(C) {new Date().getFullYear()} InfraRed. All rights reserved.</p>
          </div>
          <div className="landing-footer-links">
            <a href="https://github.com/team-chain/InfraRed" target="_blank" rel="noreferrer">
              <ExternalLink size={13} /> GitHub
            </a>
            <a href="/status">서비스 상태</a>
            <a href="/docs">문서</a>
            <a href="/privacy">개인정보처리방침</a>
            <a href="/terms">이용약관</a>
          </div>
        </div>
      </footer>
    </div>
  );
}

function FeatureCard({ icon, title, desc }: { icon: React.ReactNode; title: string; desc: string; }) {
  return (
    <div className="landing-feature-card">
      <div className="landing-feature-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{desc}</p>
    </div>
  );
}

function StepCard({ num, icon, title, desc }: { num: number; icon: React.ReactNode; title: string; desc: React.ReactNode; }) {
  return (
    <div className="landing-step-card">
      <div className="landing-step-head">
        <span className="landing-step-num">{num}</span>
        <span className="landing-step-icon">{icon}</span>
      </div>
      <h3>{title}</h3>
      <div className="landing-step-desc">{desc}</div>
    </div>
  );
}

function PricingCard({ name, price, period, features, cta, onCta, highlighted }: { name: string; price: string; period: string; features: string[]; cta: string; onCta: () => void; highlighted?: boolean; }) {
  return (
    <div className={`landing-pricing-card${highlighted ? " landing-pricing-highlighted" : ""}`}>
      {highlighted && <div className="landing-pricing-badge">가장 인기</div>}
      <h3>{name}</h3>
      <div className="landing-pricing-price">
        <span className="landing-pricing-amount">{price}</span>
        {period && <span className="landing-pricing-period">{period}</span>}
      </div>
      <ul>
        {features.map((f) => (
          <li key={f}>
            <CheckCircle2 size={14} /> {f}
          </li>
        ))}
      </ul>
      <button className={highlighted ? "landing-btn-primary" : "landing-btn-secondary"} onClick={onCta}>
        {cta}
      </button>
    </div>
  );
}

function TrustBadge({ children }: { children: React.ReactNode }) {
  return <div className="landing-trust-badge">{children}</div>;
}

function HeroDashboardMockup() {
  return (
    <div className="landing-mockup">
      <div className="landing-mockup-window">
        <div className="landing-mockup-titlebar">
          <span className="landing-mockup-dot landing-mockup-dot-red" />
          <span className="landing-mockup-dot landing-mockup-dot-amber" />
          <span className="landing-mockup-dot landing-mockup-dot-green" />
          <span className="landing-mockup-title">infrared.kr/incidents</span>
        </div>
        <div className="landing-mockup-body">
          <div className="landing-mockup-incident landing-mockup-incident-critical">
            <div className="landing-mockup-incident-head">
              <span className="landing-mockup-sev landing-mockup-sev-critical">
                <ShieldAlert size={11} /> CRITICAL
              </span>
              <span className="landing-mockup-time">2초 전</span>
            </div>
            <div className="landing-mockup-incident-title">SSH Brute Force · T1110.001</div>
            <div className="landing-mockup-incident-meta">
              <span><Network size={10} /> 198.51.100.42</span>
              <span><Server size={10} /> web-prod-02</span>
            </div>
            <div className="landing-mockup-action">
              <Zap size={11} /> iptables DROP 자동 실행됨
            </div>
          </div>

          <div className="landing-mockup-incident">
            <div className="landing-mockup-incident-head">
              <span className="landing-mockup-sev landing-mockup-sev-high">
                <ShieldAlert size={11} /> HIGH
              </span>
              <span className="landing-mockup-time">12초 전</span>
            </div>
            <div className="landing-mockup-incident-title">Webshell Process · T1505.003</div>
            <div className="landing-mockup-incident-meta">
              <span><Network size={10} /> 203.0.113.15</span>
              <span><Server size={10} /> api-stg-01</span>
            </div>
            <div className="landing-mockup-action">
              <Zap size={11} /> 컨테이너 격리됨
            </div>
          </div>

          <div className="landing-mockup-incident">
            <div className="landing-mockup-incident-head">
              <span className="landing-mockup-sev landing-mockup-sev-medium">
                <ShieldAlert size={11} /> MEDIUM
              </span>
              <span className="landing-mockup-time">28초 전</span>
            </div>
            <div className="landing-mockup-incident-title">Admin Path Scan · T1595</div>
            <div className="landing-mockup-incident-meta">
              <span><Network size={10} /> 192.0.2.88</span>
              <span><Server size={10} /> web-prod-01</span>
            </div>
          </div>
        </div>
        <div className="landing-mockup-footer">
          <span className="landing-mockup-pulse" />
          실시간 스트리밍 · 28 룰 활성
        </div>
      </div>
    </div>
  );
}
