/**
 * InfraRed Landing Page — Linear-inspired minimal design.
 *
 * 원칙:
 * - 흰색 베이스 + near-black 텍스트, 오렌지(#E07000) 액센트는 CTA·키워드 1단어에만.
 * - tight letter-spacing, 절제된 그라데이션, 그래픽 대신 코드/UI 스니펫.
 * - 카피는 마케팅 추상화 대신 구체적 사실 (실제 룰 ID, 자동 대응 명령, 통합 대상).
 *
 * 섹션:
 *   1. Nav
 *   2. Hero (좌 카피 + 우 코드/터미널 블록)
 *   3. Tech strip
 *   4. What is InfraRed (3-col 설명)
 *   5. How it works (4단계, 실제 코드·UI)
 *   6. Features (6개)
 *   7. Product preview (다크 dashboard mockup, 1개만)
 *   8. Pricing
 *   9. FAQ
 *   10. Final CTA
 *   11. Footer (4-col)
 */

import { useState } from "react";
import {
  Activity,
  ArrowRight,
  ArrowUpRight,
  Bell,
  ChevronDown,
  Code2,
  Database,
  ExternalLink,
  FileSearch,
  Lock,
  Network,
  ShieldCheck,
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
    <div className="ln-root">
      <LandingNav onGoToLogin={onGoToLogin} onGoToRegister={onGoToRegister} />
      <Hero onGoToRegister={onGoToRegister} />
      <TechStrip />
      <WhatIsSection />
      <HowItWorksSection />
      <FeaturesSection />
      <ProductPreviewSection />
      <PricingSection onGoToRegister={onGoToRegister} />
      <FaqSection />
      <FinalCta onGoToRegister={onGoToRegister} />
      <Footer />
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function LandingNav({ onGoToLogin, onGoToRegister }: Props) {
  return (
    <header className="ln-nav">
      <div className="ln-container ln-nav-inner">
        <div className="ln-nav-left">
          <Logo height={26} />
          <span className="ln-nav-divider" aria-hidden="true" />
          <span className="ln-nav-tag">SOC Platform</span>
        </div>
        <nav className="ln-nav-links">
          <a href="#features">제품</a>
          <a href="#how">동작</a>
          <a href="#pricing">요금</a>
          <a href="/docs">문서</a>
          <a href="/status">상태</a>
        </nav>
        <div className="ln-nav-right">
          <button className="ln-nav-login" onClick={onGoToLogin}>로그인</button>
          <button className="ln-btn ln-btn-primary ln-btn-sm" onClick={onGoToRegister}>
            베타 시작하기 <ArrowRight size={13} />
          </button>
        </div>
      </div>
    </header>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function Hero({ onGoToRegister }: { onGoToRegister: () => void }) {
  return (
    <section className="ln-hero">
      <div className="ln-container ln-hero-grid">
        <div className="ln-hero-copy">
          <a href="/changelog" className="ln-eyebrow">
            <span className="ln-eyebrow-dot" />
            Public Beta · 한정 액세스
            <ArrowUpRight size={12} />
          </a>
          <h1 className="ln-h1">
            서버 로그가 침해 신호를 보내면,
            <br />
            <span className="ln-accent">자동으로 차단</span>합니다.
          </h1>
          <p className="ln-lead">
            InfraRed는 Linux 서버·웹·컨테이너의 실시간 로그를 분석해
            SSH 무차별 공격·웹쉘·SQL 인젝션 등 28개 MITRE ATT&amp;CK 패턴을 탐지하고,
            고신뢰도 위협은 iptables 차단·컨테이너 격리·세션 폐기까지 자동으로 실행하는
            오픈소스 SOC 플랫폼입니다.
          </p>
          <div className="ln-hero-cta">
            <button className="ln-btn ln-btn-primary" onClick={onGoToRegister}>
              베타 시작하기 <ArrowRight size={14} />
            </button>
            <a href="#how" className="ln-btn ln-btn-ghost">
              동작 원리 보기
            </a>
          </div>
          <div className="ln-hero-meta">
            <span>공개 베타 진행 중</span>
            <span className="ln-meta-sep">·</span>
            <span>한 줄 설치</span>
            <span className="ln-meta-sep">·</span>
            <span>Self-host 가능</span>
          </div>
        </div>

        <div className="ln-hero-visual" aria-hidden="true">
          <HeroTerminal />
        </div>
      </div>
    </section>
  );
}

function HeroTerminal() {
  return (
    <div className="ln-term">
      <div className="ln-term-head">
        <span className="ln-term-dot ln-term-dot-r" />
        <span className="ln-term-dot ln-term-dot-y" />
        <span className="ln-term-dot ln-term-dot-g" />
        <span className="ln-term-path">infrared@web-prod-02:~</span>
      </div>
      <div className="ln-term-body">
        <div className="ln-term-line"><span className="ln-term-prompt">$</span> infrared status</div>
        <div className="ln-term-line ln-term-muted">agent v0.8.2 · connected · 28 rules active · 0 backlog</div>

        <div className="ln-term-line ln-term-line-spaced">
          <span className="ln-term-ts">15:42:08</span>
          <span className="ln-term-tag ln-term-tag-warn">DETECT</span>
          <span>AUTH-001 SSH Brute Force</span>
        </div>
        <div className="ln-term-line ln-term-indent ln-term-muted">
          source_ip=198.51.100.42 · attempts=11 · username=root
        </div>

        <div className="ln-term-line">
          <span className="ln-term-ts">15:42:09</span>
          <span className="ln-term-tag ln-term-tag-info">ANALYZE</span>
          <span>severity=HIGH · confidence=0.94</span>
        </div>

        <div className="ln-term-line">
          <span className="ln-term-ts">15:42:09</span>
          <span className="ln-term-tag ln-term-tag-ok">RESPOND</span>
          <span>iptables -A INPUT -s 198.51.100.42 -j DROP</span>
        </div>
        <div className="ln-term-line ln-term-indent ln-term-muted">
          discord.send(channel=#security) · audit.log
        </div>

        <div className="ln-term-line ln-term-line-spaced">
          <span className="ln-term-ts">15:42:31</span>
          <span className="ln-term-tag ln-term-tag-warn">DETECT</span>
          <span>WEB-005 SQL Injection</span>
        </div>
        <div className="ln-term-line ln-term-indent ln-term-muted">
          path=/api/users · payload=" OR 1=1 --" · host=api-stg-01
        </div>
        <div className="ln-term-line">
          <span className="ln-term-ts">15:42:31</span>
          <span className="ln-term-tag ln-term-tag-ok">RESPOND</span>
          <span>container.isolate(api-stg-01)</span>
        </div>

        <div className="ln-term-line ln-term-line-spaced ln-term-cursor">
          <span className="ln-term-prompt">$</span> <span className="ln-term-caret">▮</span>
        </div>
      </div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function TechStrip() {
  const items = [
    "MITRE ATT&CK",
    "AWS Bedrock",
    "PostgreSQL · Timescale",
    "Redis Streams",
    "OpenTelemetry",
    "OAuth 2.1 · OIDC",
  ];
  return (
    <section className="ln-tech-strip">
      <div className="ln-container ln-tech-inner">
        <span className="ln-tech-label">기반 기술</span>
        <div className="ln-tech-items">
          {items.map((t) => (
            <span key={t} className="ln-tech-badge">{t}</span>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function WhatIsSection() {
  return (
    <section className="ln-section">
      <div className="ln-container">
        <div className="ln-section-head">
          <span className="ln-section-tag">What is InfraRed</span>
          <h2 className="ln-h2">작은 팀도 직접 운영할 수 있는 <span className="ln-accent">현대적 SOC 플랫폼.</span></h2>
          <p className="ln-section-lead">
            엔터프라이즈 보안 도구는 강력하지만 도입과 운영에 적지 않은 비용·인력이 필요합니다.
            InfraRed는 5분 안에 설치되고, 작은 팀이 직접 운영할 수 있게 설계됐습니다.
            오픈소스이고, 모든 코드는 GitHub에 공개되어 있습니다.
          </p>
        </div>

        <div className="ln-three">
          <ThreeItem
            num="01"
            title="실시간 로그 분석"
            desc="에이전트가 auth.log·nginx·docker·systemd 출력을 5초 이내 백엔드로 스트리밍합니다. PostgreSQL Timescale로 저장하고, Redis Streams로 워커에 분배합니다."
          />
          <ThreeItem
            num="02"
            title="규칙 기반 + AI 분석"
            desc="28개 MITRE ATT&CK 매핑 룰이 1차 매칭. 일치 시 AWS Bedrock의 Claude가 컨텍스트(자산·과거 인시던트·CTI)와 함께 위협도·근본 원인·권장 대응을 산출합니다."
          />
          <ThreeItem
            num="03"
            title="고신뢰 위협 자동 격리"
            desc="confidence ≥ 0.85 인시던트는 자동 대응. iptables INPUT DROP, Docker network disconnect, JWT denylist 등 3종의 액션을 즉시 실행하고 모든 액션은 변조 불가 감사 로그에 기록됩니다."
          />
        </div>
      </div>
    </section>
  );
}

function ThreeItem({ num, title, desc }: { num: string; title: string; desc: string }) {
  return (
    <div className="ln-three-item">
      <div className="ln-three-num">{num}</div>
      <h3 className="ln-three-title">{title}</h3>
      <p className="ln-three-desc">{desc}</p>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function HowItWorksSection() {
  return (
    <section id="how" className="ln-section ln-section-alt">
      <div className="ln-container">
        <div className="ln-section-head">
          <span className="ln-section-tag">How it works</span>
          <h2 className="ln-h2">설치 4분, 첫 인시던트 감지 30초.</h2>
          <p className="ln-section-lead">
            컨설팅·전담 인력 필요 없습니다. 명령어 한 줄로 에이전트가 설치되면 즉시 동작합니다.
          </p>
        </div>

        <div className="ln-steps">
          <StepRow
            num={1}
            title="에이전트 설치"
            desc="서버에서 한 줄. 의존성 없는 단일 바이너리. systemd 자동 등록."
            visual={
              <pre className="ln-code">
                <span className="ln-code-prompt">$</span> curl -sSL infrared.kr/install | sh
                {"\n"}
                <span className="ln-code-muted">→ infrared-agent v0.8.2 installed</span>
                {"\n"}
                <span className="ln-code-muted">→ systemd service enabled, connected</span>
              </pre>
            }
          />
          <StepRow
            num={2}
            title="로그 수집"
            desc="auth.log, nginx access.log, docker events, FIM(/etc/passwd 등), 프로세스 실행을 자동 수집. 추가 설정 불필요."
            visual={
              <pre className="ln-code">
                <span className="ln-code-muted"># 자동 감지되는 소스</span>
                {"\n"}/var/log/auth.log
                {"\n"}/var/log/nginx/access.log
                {"\n"}docker.events
                {"\n"}fim:/etc/{`{passwd,shadow,sudoers}`}
                {"\n"}exec:/tmp /dev/shm
              </pre>
            }
          />
          <StepRow
            num={3}
            title="탐지 · AI 분석"
            desc="28개 룰 매칭 + LLM이 위협도/근본 원인/권장 대응을 산출. 대시보드 또는 Slack/Discord/Email로 전송."
            visual={
              <div className="ln-incident-mini">
                <div className="ln-incident-mini-head">
                  <span className="ln-pill ln-pill-high">HIGH</span>
                  <span className="ln-incident-mini-rule">AUTH-001 · T1110.001</span>
                </div>
                <div className="ln-incident-mini-title">SSH Brute Force from 198.51.100.42</div>
                <div className="ln-incident-mini-text">
                  11번의 실패 로그인 · 동일 IP · 5분 윈도우. 분산형 자격 증명 공격 패턴 일치.
                </div>
              </div>
            }
          />
          <StepRow
            num={4}
            title="자동 대응"
            desc="confidence ≥ 0.85면 즉시 차단. iptables, Docker network, JWT denylist 세 가지 액션 지원. 모든 액션은 감사 로그에 기록됩니다."
            visual={
              <pre className="ln-code">
                <span className="ln-code-ok">RESPOND</span> 15:42:09
                {"\n"}  iptables -A INPUT -s 198.51.100.42 -j DROP
                {"\n"}  audit.log: action=block_ip · actor=auto · sig=...
              </pre>
            }
          />
        </div>
      </div>
    </section>
  );
}

function StepRow({
  num,
  title,
  desc,
  visual,
}: {
  num: number;
  title: string;
  desc: string;
  visual: React.ReactNode;
}) {
  return (
    <div className="ln-step-row">
      <div className="ln-step-text">
        <div className="ln-step-num">Step {num}</div>
        <h3 className="ln-step-title">{title}</h3>
        <p className="ln-step-desc">{desc}</p>
      </div>
      <div className="ln-step-visual">{visual}</div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function FeaturesSection() {
  const features = [
    { icon: <Activity size={18} />, title: "28개 탐지 룰", desc: "AUTH (SSH brute, 권한 상승) · WEB (웹쉘, SQLi, scanner) · FIM (sudoers 변조) · EXEC (/tmp 실행) — 모두 MITRE ATT&CK 매핑." },
    { icon: <FileSearch size={18} />, title: "AI 인시던트 분석", desc: "AWS Bedrock Claude가 자산 컨텍스트·과거 인시던트·CTI(OTX)와 결합해 위협도와 근본 원인을 산출." },
    { icon: <Zap size={18} />, title: "3종 자동 대응", desc: "iptables 차단 · 컨테이너 네트워크 격리 · JWT 토큰 폐기. 사람 개입 없이 1초 이내 실행." },
    { icon: <Bell size={18} />, title: "멀티 채널 알림", desc: "Slack · Discord · Email. 채널별로 심각도 라우팅(예: critical만 Slack). 알림에는 LLM 요약 포함." },
    { icon: <Lock size={18} />, title: "변조 불가 감사 로그", desc: "모든 owner/admin 액션은 hash chain으로 검증되는 감사 로그에 기록. SOC 2 · ISMS 대비." },
    { icon: <Users size={18} />, title: "멀티 테넌트 · RBAC", desc: "조직별 데이터 격리 · Owner/Admin/Analyst/Viewer 4단계 권한 · SAML SSO · TOTP MFA 지원." },
  ];
  return (
    <section id="features" className="ln-section">
      <div className="ln-container">
        <div className="ln-section-head">
          <span className="ln-section-tag">Features</span>
          <h2 className="ln-h2">SOC 운영에 필요한 모든 것.</h2>
          <p className="ln-section-lead">탐지 · 분석 · 대응 · 알림 · 감사까지 한 플랫폼에서.</p>
        </div>

        <div className="ln-features">
          {features.map((f) => (
            <div key={f.title} className="ln-feature-card">
              <div className="ln-feature-icon">{f.icon}</div>
              <h3 className="ln-feature-title">{f.title}</h3>
              <p className="ln-feature-desc">{f.desc}</p>
            </div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function ProductPreviewSection() {
  return (
    <section className="ln-section ln-section-alt">
      <div className="ln-container">
        <div className="ln-section-head">
          <span className="ln-section-tag">Product</span>
          <h2 className="ln-h2">실제 대시보드.</h2>
          <p className="ln-section-lead">실시간 인시던트 스트림 · MTTR · 자산별 위험도 · 자동 대응 액션 이력.</p>
        </div>

        <div className="ln-preview">
          <div className="ln-preview-window">
            <div className="ln-preview-titlebar">
              <span className="ln-preview-dots">
                <span className="ln-preview-dot ln-preview-dot-r" />
                <span className="ln-preview-dot ln-preview-dot-y" />
                <span className="ln-preview-dot ln-preview-dot-g" />
              </span>
              <span className="ln-preview-tab">app.infrared.kr / incidents</span>
            </div>
            <div className="ln-preview-body">
              <div className="ln-preview-side">
                <span className="ln-preview-side-item ln-preview-side-active">
                  <Activity size={13} /> Incidents
                </span>
                <span className="ln-preview-side-item">
                  <Database size={13} /> Assets
                </span>
                <span className="ln-preview-side-item">
                  <ShieldCheck size={13} /> Rules
                </span>
                <span className="ln-preview-side-item">
                  <FileSearch size={13} /> Audit
                </span>
                <span className="ln-preview-side-item">
                  <Bell size={13} /> Settings
                </span>
              </div>
              <div className="ln-preview-main">
                <div className="ln-preview-kpi-row">
                  <Kpi label="OPEN" value="3" />
                  <Kpi label="LAST 24H" value="11" />
                  <Kpi label="AUTO-BLOCKED" value="8" />
                  <Kpi label="MTTR" value="38s" accent />
                </div>
                <PreviewIncidentRow sev="CRITICAL" rule="AUTH-004 · Failed→Success" host="db-prod-01" time="2초 전" action="account.locked" />
                <PreviewIncidentRow sev="HIGH" rule="WEB-005 · SQL Injection" host="api-stg-01" time="14초 전" action="container.isolated" />
                <PreviewIncidentRow sev="HIGH" rule="EXEC-001 · /tmp execution" host="web-prod-02" time="1분 전" action="iptables.drop" />
                <PreviewIncidentRow sev="MED" rule="WEB-002 · Admin scan" host="web-prod-01" time="3분 전" action="alert.discord" />
              </div>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Kpi({ label, value, accent }: { label: string; value: string; accent?: boolean }) {
  return (
    <div className={`ln-preview-kpi${accent ? " ln-preview-kpi-accent" : ""}`}>
      <div className="ln-preview-kpi-label">{label}</div>
      <div className="ln-preview-kpi-value">{value}</div>
    </div>
  );
}

function PreviewIncidentRow({
  sev,
  rule,
  host,
  time,
  action,
}: {
  sev: "CRITICAL" | "HIGH" | "MED";
  rule: string;
  host: string;
  time: string;
  action: string;
}) {
  const sevClass =
    sev === "CRITICAL" ? "ln-pill ln-pill-critical" :
    sev === "HIGH" ? "ln-pill ln-pill-high" :
    "ln-pill ln-pill-med";
  return (
    <div className="ln-preview-row">
      <span className={sevClass}>{sev}</span>
      <div className="ln-preview-row-rule">{rule}</div>
      <div className="ln-preview-row-host"><Network size={11} /> {host}</div>
      <div className="ln-preview-row-action"><Zap size={11} /> {action}</div>
      <div className="ln-preview-row-time">{time}</div>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function PricingSection({ onGoToRegister }: { onGoToRegister: () => void }) {
  const included = [
    "에이전트 대수 제한 없음 (베타 기간 한정)",
    "28개 MITRE ATT&CK 탐지 룰 전체",
    "AI 인시던트 분석 (AWS Bedrock)",
    "자동 대응 — iptables · 컨테이너 격리 · 토큰 폐기",
    "Slack · Discord · Email 알림",
    "변조 불가 감사 로그",
    "멀티 테넌트 · RBAC · SSO · MFA",
    "Self-host 옵션 (Docker Compose)",
  ];

  return (
    <section id="pricing" className="ln-section">
      <div className="ln-container">
        <div className="ln-section-head">
          <span className="ln-section-tag">Pricing</span>
          <h2 className="ln-h2">공개 베타 진행 중.</h2>
          <p className="ln-section-lead">
            InfraRed는 현재 공개 베타 단계입니다.
            정식 출시 시 가격을 발표하며, 베타 사용자에게는 Founding 요금 혜택을 제공할 예정입니다.
          </p>
        </div>

        <div className="ln-beta-card">
          <div className="ln-beta-card-head">
            <div>
              <span className="ln-beta-eyebrow">Public Beta</span>
              <h3 className="ln-beta-title">전체 기능 · 베타 액세스</h3>
              <p className="ln-beta-desc">
                정식 출시 전까지 InfraRed의 모든 기능을 사용할 수 있습니다.
                과금은 정식 출시 시점부터 시작됩니다.
              </p>
            </div>
            <button className="ln-btn ln-btn-primary ln-btn-lg" onClick={onGoToRegister}>
              베타 시작하기 <ArrowRight size={15} />
            </button>
          </div>
          <ul className="ln-beta-features">
            {included.map((f) => (
              <li key={f}>{f}</li>
            ))}
          </ul>
          <div className="ln-beta-footer">
            정식 출시 일정과 가격 정책은 가입한 사용자에게 먼저 안내됩니다.
            대규모 인프라 · 규제 산업 도입 문의는{" "}
            <a href="mailto:sales@infrared.kr">sales@infrared.kr</a>
            로 연락 부탁드립니다.
          </div>
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

const FAQS = [
  {
    q: "기존 보안 솔루션과 어떻게 다른가요?",
    a: "전통적인 보안 솔루션은 도입에 많은 시간과 인력이 필요하고, 룰을 직접 작성·튜닝해야 합니다. InfraRed는 사전 정의된 28개 룰과 AI 인시던트 분석이 즉시 동작합니다. 5분 설치, 추가 컨설팅 없이 운영을 시작할 수 있습니다. 현재 공개 베타 단계이며, 모든 기능을 사용할 수 있습니다.",
  },
  {
    q: "Self-host 할 수 있나요?",
    a: "네. 모든 코드는 MIT 라이선스로 GitHub에 공개되어 있고, Docker Compose 한 줄로 띄울 수 있습니다. Enterprise 플랜은 on-prem 배포 지원을 포함합니다.",
  },
  {
    q: "자동 대응이 정상 트래픽을 차단하면 어떻게 하나요?",
    a: "자동 대응은 confidence ≥ 0.85 인시던트에만 적용되고, 모든 차단 IP는 24시간 후 자동 해제됩니다. 사내 IP/known good 목록은 settings에서 영구 화이트리스트 가능합니다. 의심스러우면 dry-run 모드로 전환해 알림만 받을 수도 있습니다.",
  },
  {
    q: "로그를 InfraRed 서버로 보내는데, 보안은 어떻게 보장하나요?",
    a: "에이전트와 백엔드는 mTLS로 통신합니다. 모든 로그는 전송 중·저장 시 암호화됩니다. PII는 필드 단위 마스킹 후 저장됩니다. 데이터는 호스팅 리전(현재 ap-northeast-2) 밖으로 나가지 않습니다.",
  },
  {
    q: "어떤 환경을 지원하나요?",
    a: "Linux (Ubuntu 20.04+, Debian 11+, RHEL 9, Amazon Linux 2023) · Docker · Kubernetes (DaemonSet). Windows 에이전트는 베타입니다. macOS는 Q3에 추가됩니다.",
  },
  {
    q: "AI 분석에 우리 회사 로그가 외부 모델 학습에 사용되나요?",
    a: "아니요. AWS Bedrock의 Claude를 사용하며, Bedrock는 정의상 입력 데이터를 모델 학습에 사용하지 않습니다. 추론 결과는 InfraRed DB에 저장되고, 원본 로그는 외부로 전송되지 않습니다.",
  },
];

function FaqSection() {
  return (
    <section className="ln-section ln-section-alt">
      <div className="ln-container ln-faq-wrap">
        <div className="ln-section-head ln-section-head-narrow">
          <span className="ln-section-tag">FAQ</span>
          <h2 className="ln-h2">자주 묻는 질문.</h2>
        </div>
        <div className="ln-faq-list">
          {FAQS.map((f, i) => (
            <FaqItem key={i} q={f.q} a={f.a} defaultOpen={i === 0} />
          ))}
        </div>
      </div>
    </section>
  );
}

function FaqItem({ q, a, defaultOpen }: { q: string; a: string; defaultOpen?: boolean }) {
  const [open, setOpen] = useState(Boolean(defaultOpen));
  return (
    <div className={`ln-faq-item${open ? " ln-faq-open" : ""}`}>
      <button className="ln-faq-q" onClick={() => setOpen((v) => !v)}>
        <span>{q}</span>
        <ChevronDown size={16} className="ln-faq-chev" />
      </button>
      {open && <div className="ln-faq-a">{a}</div>}
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function FinalCta({ onGoToRegister }: { onGoToRegister: () => void }) {
  return (
    <section className="ln-final">
      <div className="ln-container ln-final-inner">
        <h2 className="ln-final-title">
          지금 인프라를 보호하세요.
        </h2>
        <p className="ln-final-sub">
          공개 베타 진행 중. 5분 설치로 즉시 운영을 시작하세요.
        </p>
        <div className="ln-final-cta">
          <button className="ln-btn ln-btn-primary ln-btn-lg" onClick={onGoToRegister}>
            베타 시작하기 <ArrowRight size={15} />
          </button>
          <a href="/docs" className="ln-btn ln-btn-ghost ln-btn-lg">
            <Code2 size={15} /> 문서 보기
          </a>
        </div>
      </div>
    </section>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function Footer() {
  return (
    <footer className="ln-footer">
      <div className="ln-container ln-footer-grid">
        <div className="ln-footer-brand">
          <Logo height={22} />
          <p className="ln-footer-tag">SOC platform for modern teams.</p>
          <p className="ln-footer-copy">(C) {new Date().getFullYear()} InfraRed. MIT Licensed.</p>
        </div>
        <FooterCol title="제품">
          <a href="#features">기능</a>
          <a href="#how">동작 방식</a>
          <a href="#pricing">요금</a>
          <a href="/changelog">Changelog</a>
        </FooterCol>
        <FooterCol title="리소스">
          <a href="/docs">문서</a>
          <a href="/docs/api">API 레퍼런스</a>
          <a href="/docs/agent">에이전트 설치 가이드</a>
          <a href="https://github.com/team-chain/InfraRed" target="_blank" rel="noreferrer">GitHub <ExternalLink size={11} /></a>
        </FooterCol>
        <FooterCol title="운영">
          <a href="/status">서비스 상태</a>
          <a href="/security">보안</a>
          <a href="/privacy">개인정보처리방침</a>
          <a href="/terms">이용약관</a>
        </FooterCol>
      </div>
    </footer>
  );
}

function FooterCol({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div className="ln-footer-col">
      <div className="ln-footer-col-title">{title}</div>
      <div className="ln-footer-col-links">{children}</div>
    </div>
  );
}
