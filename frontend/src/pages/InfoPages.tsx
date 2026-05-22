/**
 * Static info pages — Stub + 실제 내용.
 *
 * 페이지:
 *   /docs       — 문서 안내 (실제 문서는 베타 단계 이메일 공유)
 *   /changelog  — 릴리스 노트
 *   /privacy    — 개인정보처리방침 (PIPA 베타 단계 기본)
 *   /terms      — 이용약관 (베타 단계 기본)
 *   /security   — 보안 실천사항
 *
 * 디자인: Landing과 같은 톤(Linear). 단일 컬럼 prose 레이아웃.
 */

import { ArrowLeft, Mail } from "lucide-react";
import { Logo } from "../components/Logo";

type Variant = "docs" | "changelog" | "privacy" | "terms" | "security";

const META: Record<Variant, { eyebrow: string; title: string }> = {
  docs:      { eyebrow: "Docs", title: "문서" },
  changelog: { eyebrow: "Changelog", title: "릴리스 노트" },
  privacy:   { eyebrow: "Privacy", title: "개인정보처리방침" },
  terms:     { eyebrow: "Terms", title: "이용약관" },
  security:  { eyebrow: "Security", title: "보안 실천사항" },
};

export function InfoPage({ variant }: { variant: Variant }) {
  const meta = META[variant];
  return (
    <div className="info-root">
      <header className="info-nav">
        <div className="info-container info-nav-inner">
          <Logo height={26} className="info-brand" />
          <a href="/" className="info-back">
            <ArrowLeft size={14} /> 홈으로
          </a>
        </div>
      </header>

      <article className="info-article">
        <div className="info-container info-prose">
          <span className="info-eyebrow">{meta.eyebrow}</span>
          <h1 className="info-title">{meta.title}</h1>
          {variant === "docs" && <DocsContent />}
          {variant === "changelog" && <ChangelogContent />}
          {variant === "privacy" && <PrivacyContent />}
          {variant === "terms" && <TermsContent />}
          {variant === "security" && <SecurityContent />}
        </div>
      </article>

      <footer className="info-footer">
        <div className="info-container">
          <span>© {new Date().getFullYear()} InfraRed</span>
          <span className="info-footer-sep">·</span>
          <a href="/privacy">개인정보</a>
          <a href="/terms">약관</a>
          <a href="/security">보안</a>
          <a href="/status">상태</a>
        </div>
      </footer>
    </div>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function DocsContent() {
  return (
    <>
      <p className="info-lead">
        InfraRed의 정식 문서 사이트는 베타 종료 시점에 공개됩니다.
        그 전까지는 가입한 사용자에게 이메일로 자료를 안내합니다.
      </p>
      <h2>지금 가능한 것</h2>
      <ul>
        <li>에이전트 설치 가이드 — 가입 후 온보딩 화면에서 단계별 안내</li>
        <li>API 레퍼런스 — <code>https://api.infrared.kr/docs</code> (OpenAPI)</li>
        <li>탐지 룰 목록 — Dashboard → 룰 목록 탭</li>
        <li>운영 상태 — <a href="/status">상태 페이지</a></li>
      </ul>
      <h2>도움이 필요하면</h2>
      <p>
        설치·운영 관련 질문은{" "}
        <a href="mailto:support@infrared.kr">support@infrared.kr</a>로,
        대규모 도입·SLA 문의는{" "}
        <a href="mailto:sales@infrared.kr">sales@infrared.kr</a>로 보내주세요.
      </p>
      <div className="info-cta-box">
        <Mail size={16} />
        <span>베타 사용자는 새 가이드가 공개되면 이메일로 알림을 받습니다.</span>
      </div>
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function ChangelogContent() {
  return (
    <>
      <p className="info-lead">
        주요 변경사항을 시간 순으로 정리합니다. 베타 기간 동안 빠르게 변경될 수 있습니다.
      </p>

      <div className="info-release">
        <div className="info-release-head">
          <span className="info-release-version">v0.9.0</span>
          <span className="info-release-date">2026-05-22</span>
        </div>
        <ul>
          <li>공식 랜딩 페이지 공개 (Public Beta)</li>
          <li>운영 메트릭 대시보드 (owner 전용)</li>
          <li>공개 서비스 상태 페이지 (<a href="/status">/status</a>)</li>
          <li>이메일 인증 · 비밀번호 재설정</li>
          <li>초대 메일 자동 발송</li>
        </ul>
      </div>

      <div className="info-release">
        <div className="info-release-head">
          <span className="info-release-version">v0.8.x</span>
          <span className="info-release-date">2026-05</span>
        </div>
        <ul>
          <li>28개 MITRE ATT&amp;CK 탐지 룰</li>
          <li>자동 대응 — iptables 차단, 컨테이너 격리, 토큰 폐기</li>
          <li>AI 인시던트 분석 (AWS Bedrock)</li>
          <li>감사 로그 · 멀티 테넌트 · RBAC · SSO · MFA</li>
          <li>Slack · Discord · Email 알림 + 채널별 라우팅</li>
        </ul>
      </div>

      <p className="info-muted">
        세부 릴리스 노트는 베타 사용자에게 이메일로도 전달됩니다.
      </p>
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function PrivacyContent() {
  return (
    <>
      <p className="info-muted info-effective">
        시행일: 2026년 5월 22일 · 베타 단계 임시 정책
      </p>
      <p className="info-lead">
        InfraRed (이하 “회사”)는 사용자의 개인정보를 중요하게 다루며,
        「개인정보보호법」을 비롯한 관련 법령을 준수합니다.
        본 처리방침은 회사가 제공하는 SOC 플랫폼 서비스(이하 “서비스”)
        이용 과정에서 수집·이용되는 개인정보의 항목, 목적, 보관 기간, 제3자 제공,
        이용자 권리 행사 방법을 안내합니다.
      </p>

      <h2>1. 수집하는 개인정보 항목</h2>
      <ul>
        <li><strong>회원 가입</strong>: 이메일, 비밀번호(해시 저장), 조직 ID, 역할</li>
        <li><strong>서비스 이용</strong>: 로그인 IP, 브라우저 정보, 접속 일시</li>
        <li><strong>에이전트 수집 로그</strong>: 서버에서 발생한 시스템 로그(auth.log, nginx access.log, FIM·EXEC 이벤트). 사용자가 명시적으로 설치한 에이전트가 발생시킵니다.</li>
        <li><strong>결제</strong>: 정식 출시 시 Stripe를 통해 처리되며, 회사는 결제 카드 정보를 보관하지 않습니다.</li>
      </ul>

      <h2>2. 이용 목적</h2>
      <ul>
        <li>회원 식별·인증·서비스 제공</li>
        <li>침해 탐지·인시던트 분석·자동 대응 실행</li>
        <li>고객 지원 응대 및 공지</li>
        <li>서비스 품질 개선 및 부정 이용 방지</li>
        <li>법령상 의무 이행</li>
      </ul>

      <h2>3. 보관 기간</h2>
      <ul>
        <li>계정 정보: 회원 탈퇴 시까지 (탈퇴 후 30일 내 파기)</li>
        <li>로그·이벤트 데이터: 가입 플랜에 따라 7일 ~ 1년</li>
        <li>감사 로그: 법령상 의무에 따라 최대 3년</li>
      </ul>

      <h2>4. 제3자 제공 및 처리 위탁</h2>
      <p>
        회사는 원칙적으로 개인정보를 제3자에게 제공하지 않습니다.
        서비스 운영에 필요한 다음 위탁 처리자에게만 최소한의 정보가 전달됩니다.
      </p>
      <ul>
        <li>Amazon Web Services (AWS) — 클라우드 호스팅 (Seoul 리전)</li>
        <li>AWS Bedrock — AI 인시던트 분석 (입력 데이터는 모델 학습에 사용되지 않음)</li>
        <li>Stripe Inc. — 결제 처리 (정식 출시 시)</li>
        <li>Cloudflare — CDN 및 봇 보호</li>
      </ul>

      <h2>5. 이용자 권리</h2>
      <p>
        이용자는 자신의 개인정보에 대해 열람, 정정, 삭제, 처리정지를 요청할 수 있습니다.
        대시보드 → 설정 → 계정에서 직접 처리하거나,{" "}
        <a href="mailto:privacy@infrared.kr">privacy@infrared.kr</a>로 요청할 수 있습니다.
      </p>

      <h2>6. 보안 조치</h2>
      <p>
        TLS 1.3 전송 암호화, 저장 시 AES-256 암호화, 비밀번호 bcrypt 해시,
        엄격한 접근 제어, 변조 불가 감사 로그를 운영합니다. 자세한 내용은{" "}
        <a href="/security">보안 페이지</a>를 참고하세요.
      </p>

      <h2>7. 개인정보 보호 책임자</h2>
      <p>
        담당: privacy@infrared.kr · 문의 접수일로부터 영업일 기준 10일 이내에 답변드립니다.
      </p>

      <p className="info-muted">
        본 정책은 베타 단계 임시본이며, 정식 출시 시 법률 검토를 거친 최종본으로 갱신됩니다.
        변경 시 가입 이메일로 사전 안내합니다.
      </p>
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function TermsContent() {
  return (
    <>
      <p className="info-muted info-effective">
        시행일: 2026년 5월 22일 · 베타 단계 임시 약관
      </p>
      <p className="info-lead">
        본 약관은 InfraRed가 제공하는 SOC 플랫폼 서비스(이하 “서비스”)의 이용 조건을 정합니다.
        서비스 가입 시 본 약관에 동의한 것으로 간주됩니다.
      </p>

      <h2>1. 서비스 내용</h2>
      <p>
        InfraRed는 실시간 침해 탐지·AI 인시던트 분석·자동 대응을 제공하는 SOC 운영 플랫폼입니다.
        현재 공개 베타 단계이며, 기능과 가격 정책이 변경될 수 있습니다.
      </p>

      <h2>2. 베타 단계 특별 조건</h2>
      <ul>
        <li>베타 기간 동안 무상으로 제공되며, 정식 출시 시 별도 안내 후 과금이 시작됩니다.</li>
        <li>SLA·가용성 보장은 정식 출시 시점부터 적용됩니다.</li>
        <li>회사는 사전 안내를 거쳐 기능을 추가·변경·중단할 수 있습니다.</li>
      </ul>

      <h2>3. 이용자 의무</h2>
      <ul>
        <li>본인 인증 정보를 안전하게 관리해야 합니다.</li>
        <li>타인의 권리를 침해하거나 법령을 위반하는 용도로 서비스를 사용할 수 없습니다.</li>
        <li>서비스의 안정성을 해치는 행위(과도한 자동화, 취약점 악용 등)는 금지됩니다.</li>
        <li>에이전트는 본인이 권한을 가진 시스템에만 설치해야 합니다.</li>
      </ul>

      <h2>4. 회사의 의무</h2>
      <ul>
        <li>서비스 안정성을 위해 합리적인 노력을 다합니다.</li>
        <li>이용자의 개인정보를 「개인정보처리방침」에 따라 보호합니다.</li>
      </ul>

      <h2>5. 책임의 제한</h2>
      <p>
        베타 단계 동안 회사는 서비스 중단·오류·데이터 손실에 대해 법령상 허용되는 범위 내에서
        책임이 제한됩니다. 정식 출시 후의 SLA·책임 범위는 별도 계약으로 정합니다.
      </p>

      <h2>6. 해지</h2>
      <p>
        이용자는 언제든 대시보드 → 설정에서 탈퇴할 수 있습니다.
        회사는 약관 위반·서비스 안정성 위협이 있는 경우 사전 통지 후 이용을 제한할 수 있습니다.
      </p>

      <h2>7. 준거법 및 분쟁 해결</h2>
      <p>
        본 약관은 대한민국 법령에 따라 해석되며,
        서비스 이용으로 발생한 분쟁은 회사 소재지 관할 법원을 1심으로 합니다.
      </p>

      <p className="info-muted">
        문의: <a href="mailto:legal@infrared.kr">legal@infrared.kr</a>
      </p>
    </>
  );
}

/* ─────────────────────────────────────────────────────────────────── */

function SecurityContent() {
  return (
    <>
      <p className="info-lead">
        InfraRed는 보안 제품인 만큼, 우리 자신의 보안에도 같은 수준의 엄격함을 적용합니다.
        아래는 서비스를 운영하는 방식입니다.
      </p>

      <h2>전송 및 저장 암호화</h2>
      <ul>
        <li>모든 트래픽은 TLS 1.3으로 암호화됩니다.</li>
        <li>에이전트 ↔ 백엔드 통신은 mTLS(상호 인증서) 기반입니다.</li>
        <li>데이터는 AES-256으로 저장됩니다 (PostgreSQL TDE, Redis at-rest).</li>
        <li>로그는 호스팅 리전(AWS ap-northeast-2)을 벗어나지 않습니다.</li>
      </ul>

      <h2>인증 및 권한</h2>
      <ul>
        <li>비밀번호는 bcrypt 해시로만 저장됩니다 (평문 비저장).</li>
        <li>JWT 기반 세션, 로그아웃 시 즉시 폐기되는 deny-list.</li>
        <li>Owner / Admin / Analyst / Viewer 4단계 RBAC.</li>
        <li>TOTP MFA · SAML SSO 지원.</li>
      </ul>

      <h2>감사 가능성</h2>
      <ul>
        <li>모든 admin 액션은 hash-chain 감사 로그에 기록됩니다.</li>
        <li>변조 시도가 발생하면 chain이 깨져 즉시 감지됩니다.</li>
        <li>감사 로그는 owner만 조회·export 가능합니다.</li>
      </ul>

      <h2>인프라 보안</h2>
      <ul>
        <li>AWS IAM 최소 권한 원칙. 장기 access key 미사용 (IAM Role 기반).</li>
        <li>Secrets는 환경 변수로만 주입. 코드 저장소에 평문 미포함.</li>
        <li>Redis · PostgreSQL은 VPC 내부 통신만 허용.</li>
        <li>의존성 취약점은 GitHub Dependabot으로 매일 스캔, High 등급은 24시간 내 패치.</li>
      </ul>

      <h2>응답성 및 투명성</h2>
      <ul>
        <li>서비스 상태는 <a href="/status">/status</a>에서 공개됩니다.</li>
        <li>주요 변경사항은 <a href="/changelog">/changelog</a>에 기록됩니다.</li>
        <li>보안 취약점 제보는{" "}
          <a href="mailto:security@infrared.kr">security@infrared.kr</a>로
          PGP 또는 평문으로 받습니다. Coordinated disclosure 원칙을 따릅니다.
        </li>
      </ul>

      <h2>준수 중인 기준</h2>
      <ul>
        <li>「개인정보보호법」(한국 PIPA) — 베타 단계 기본 준수, 정식 출시 시 ISMS-P 인증 예정</li>
        <li>SOC 2 Type 2 — 정식 출시 후 12개월 내 감사 예정</li>
        <li>OWASP Top 10 — 정기 검증</li>
      </ul>

      <p className="info-muted">
        본 페이지의 내용은 운영 정책 변경에 따라 갱신될 수 있습니다.
      </p>
    </>
  );
}
