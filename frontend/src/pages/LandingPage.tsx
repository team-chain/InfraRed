/**
 * InfraRed Landing Page
 *
 * 미인증 사용자가 / 접속 시 표시되는 마케팅용 페이지.
 * - Hero (가치 제안 + 주요 CTA)
 * - Problem (왜 InfraRed인가)
 * - Features (6개 핵심 기능)
 * - How it works (3단계)
 * - Pricing teaser (3 tier)
 * - Final CTA
 * - Footer
 *
 * 디자인 원칙:
 * - 브랜드 컬러 (오렌지 그라데이션) 사용
 * - 모바일 반응형 (640px 이하에서 single column)
 * - 빠른 로딩 (이미지 최소화, 아이콘은 lucide-react 인라인 SVG)
 */

import {
  Activity,
  Bell,
  Brain,
  CheckCircle2,
  ExternalLink,
  Lock,
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
      {/* ── Top nav ─────────────────────────────────────────── */}
      <header className="landing-nav">
        <div className="landing-nav-inner">
          <Logo height={32} />
          <nav className="landing-nav-links">
            <a href="#features">기능</a>
            <a href="#how">동작 방식</a>
            <a href="#pricing">요금</a>
            <button className="landing-nav-login" onClick={onGoToLogin}>
              로그인
            </button>
            <button className="landing-nav-cta" onClick={onGoToRegister}>
              무료로 시작
            </button>
          </nav>
        </div>
      </header>

      {/* ── Hero ────────────────────────────────────────────── */}
      <section className="landing-hero">
        <div className="landing-hero-inner">
          <div className="landing-hero-badge">
            <Sparkles size={14} />
            <span>AI 기반 SOC 자동화 플랫폼</span>
          </div>
          <h1 className="landing-hero-title">
            <span>당신의 인프라,</span>
            <br />
            <span className="landing-gradient-text">24시간 자동 방어</span>
          </h1>
          <p className="landing-hero-sub">
            실시간 침해 탐지 · AI 인시던트 분석 · 자동 차단까지.
            <br />
            5분 설치로 SOC 팀 없이도 24/7 방어를 시작하세요.
          </p>
          <div className="landing-hero-cta">
            <button className="landing-btn-primary" onClick={onGoToRegister}>
              무료로 시작하기 →
            </button>
            <a href="#features" className="landing-btn-secondary">
              기능 살펴보기
            </a>
          </div>
          <div className="landing-trust">
            <div className="landing-trust-item">
              <CheckCircle2 size={16} />
              <span>28개 MITRE ATT&CK 룰</span>
            </div>
            <div className="landing-trust-item">
              <CheckCircle2 size={16} />
              <span>한 줄 에이전트 설치</span>
            </div>
            <div className="landing-trust-item">
              <CheckCircle2 size={16} />
              <span>Slack · Discord · Email 알림</span>
            </div>
          </div>
        </div>
        {/* 데코 배경 */}
        <div className="landing-hero-glow" />
      </section>

      {/* ── Problem ─────────────────────────────────────────── */}
      <section className="landing-section">
        <div className="landing-section-inner">
          <h2 className="landing-section-title">왜 InfraRed인가</h2>
          <p className="landing-section-sub">
            대부분의 스타트업은 보안 인력이 없습니다. 침해를 당해도 며칠 뒤에야 알게 되는 게 현실입니다.
          </p>
          <div className="landing-problems">
            <div className="landing-problem-card">
              <div className="landing-problem-num">01</div>
              <h3>로그가 너무 많다</h3>
              <p>하루에 수십만 줄. 사람이 다 볼 수 없고, 봐도 의미 있는 패턴을 놓칩니다.</p>
            </div>
            <div className="landing-problem-card">
              <div className="landing-problem-num">02</div>
              <h3>대응이 늦다</h3>
              <p>침해를 알아도 IP 차단·계정 잠금까지 평균 6시간. 그 사이에 피해는 커집니다.</p>
            </div>
            <div className="landing-problem-card">
              <div className="landing-problem-num">03</div>
              <h3>SOC는 비싸다</h3>
              <p>외부 SOC 위탁은 월 수백만원. 사내 인력은 3명 이상 필요. 작은 팀에겐 사치입니다.</p>
            </div>
          </div>
        </div>
      </section>

      {/* ── Features ────────────────────────────────────────── */}
      <section id="features" className="landing-section landing-section-alt">
        <div className="landing-section-inner">
          <h2 className="landing-section-title">핵심 기능</h2>
          <p className="landing-section-sub">
            탐지부터 자동 차단·알림까지 한 플랫폼에서.
          </p>
          <div className="landing-features">
            <FeatureCard
              icon={<Activity size={22} />}
              title="실시간 침해 탐지"
              desc="SSH 무차별 공격, 웹쉘, SQL 인젝션 등 28개 MITRE ATT&CK 룰을 즉시 매칭합니다."
            />
            <FeatureCard
              icon={<Brain size={22} />}
              title="AI 인시던트 분석"
              desc="Bedrock Claude가 각 인시던트를 분석해 위협 수준·근본 원인·권장 대응을 알려줍니다."
            />
            <FeatureCard
              icon={<Zap size={22} />}
              title="자동 대응"
              desc="높은 신뢰도의 공격은 iptables 차단·컨테이너 격리·토큰 폐기까지 자동 실행합니다."
            />
            <FeatureCard
              icon={<Bell size={22} />}
              title="멀티 채널 알림"
              desc="Slack · Discord · Email로 인시던트를 실시간 전송. 채널별 심각도 라우팅 가능."
            />
            <FeatureCard
              icon={<Lock size={22} />}
              title="감사 로그 & 컴플라이언스"
              desc="모든 owner 액션은 변조 불가 감사 로그에 기록. SOC 2 · ISMS 대응 준비 완료."
            />
            <FeatureCard
              icon={<Users size={22} />}
              title="멀티 테넌트 · RBAC"
              desc="조직별 완전 격리 · Owner/Admin/Member 3단계 권한 · SSO·MFA 지원."
            />
          </div>
        </div>
      </section>

      {/* ── How it works ────────────────────────────────────── */}
      <section id="how" className="landing-section">
        <div className="landing-section-inner">
          <h2 className="landing-section-title">5분 만에 시작</h2>
          <p className="landing-section-sub">
            세팅 컨설팅 없이, 명령어 한 줄이면 끝납니다.
          </p>
          <div className="landing-steps">
            <StepCard
              num={1}
              icon={<ShieldCheck size={20} />}
              title="가입"
              desc="이메일로 1분 회원가입. 신용카드 불필요. Free 플랜으로 즉시 시작."
            />
            <StepCard
              num={2}
              icon={<Terminal size={20} />}
              title="에이전트 설치"
              desc={
                <>
                  서버에서 한 줄 명령:
                  <code className="landing-step-code">curl -sSL infrared.kr/install | sh</code>
                </>
              }
            />
            <StepCard
              num={3}
              icon={<Activity size={20} />}
              title="모니터링 시작"
              desc="대시보드에서 실시간 인시던트 확인. 위협은 자동 차단, Slack으로 즉시 알림."
            />
          </div>
        </div>
      </section>

      {/* ── Pricing teaser ──────────────────────────────────── */}
      <section id="pricing" className="landing-section landing-section-alt">
        <div className="landing-section-inner">
          <h2 className="landing-section-title">합리적인 요금</h2>
          <p className="landing-section-sub">
            작은 팀부터 엔터프라이즈까지. 사용량 기반 투명 과금.
          </p>
          <div className="landing-pricing">
            <PricingCard
              name="Free"
              price="₩0"
              period="forever"
              features={["에이전트 3대", "기본 룰 28개", "Discord 알림", "7일 로그 보관"]}
              cta="무료로 시작"
              onCta={onGoToRegister}
            />
            <PricingCard
              name="Pro"
              price="₩99,000"
              period="/월"
              features={[
                "에이전트 25대",
                "전체 룰 + 커스텀 룰",
                "Slack · Email 알림",
                "AI 인시던트 분석 포함",
                "90일 로그 보관",
                "감사 로그 export",
              ]}
              cta="14일 무료 시작"
              onCta={onGoToRegister}
              highlighted
            />
            <PricingCard
              name="Enterprise"
              price="문의"
              period=""
              features={[
                "무제한 에이전트",
                "SSO · MFA · SAML",
                "전담 SLA",
                "On-prem 배포 옵션",
                "1년+ 로그 보관",
                "전용 보안 컨설팅",
              ]}
              cta="영업팀 문의"
              onCta={() => (window.location.href = "mailto:sales@infrared.kr")}
            />
          </div>
        </div>
      </section>

      {/* ── Final CTA ───────────────────────────────────────── */}
      <section className="landing-final-cta">
        <div className="landing-final-cta-inner">
          <h2>지금 인프라를 보호하세요</h2>
          <p>5분이면 끝. 신용카드 없이 시작.</p>
          <button className="landing-btn-primary landing-btn-large" onClick={onGoToRegister}>
            무료로 시작하기 →
          </button>
        </div>
      </section>

      {/* ── Footer ──────────────────────────────────────────── */}
      <footer className="landing-footer">
        <div className="landing-footer-inner">
          <div className="landing-footer-brand">
            <Logo height={24} />
            <p>© {new Date().getFullYear()} InfraRed. All rights reserved.</p>
          </div>
          <div className="landing-footer-links">
            <a href="https://github.com/team-chain/InfraRed" target="_blank" rel="noreferrer">
              <ExternalLink size={14} /> GitHub
            </a>
            <a href="/docs">문서</a>
            <a href="/privacy">개인정보처리방침</a>
            <a href="/terms">이용약관</a>
          </div>
        </div>
      </footer>
    </div>
  );
}

/* ── Sub-components ────────────────────────────────────────── */

function FeatureCard({
  icon,
  title,
  desc,
}: {
  icon: React.ReactNode;
  title: string;
  desc: string;
}) {
  return (
    <div className="landing-feature-card">
      <div className="landing-feature-icon">{icon}</div>
      <h3>{title}</h3>
      <p>{desc}</p>
    </div>
  );
}

function StepCard({
  num,
  icon,
  title,
  desc,
}: {
  num: number;
  icon: React.ReactNode;
  title: string;
  desc: React.ReactNode;
}) {
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

function PricingCard({
  name,
  price,
  period,
  features,
  cta,
  onCta,
  highlighted,
}: {
  name: string;
  price: string;
  period: string;
  features: string[];
  cta: string;
  onCta: () => void;
  highlighted?: boolean;
}) {
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
            <CheckCircle2 size={15} /> {f}
          </li>
        ))}
      </ul>
      <button
        className={highlighted ? "landing-btn-primary" : "landing-btn-secondary"}
        onClick={onCta}
      >
        {cta}
      </button>
    </div>
  );
}
