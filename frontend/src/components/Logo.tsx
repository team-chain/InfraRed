/**
 * InfraRed brand logo component.
 *
 * 두 가지 모드:
 *   <Logo />              풀 로고 (iR 아이콘 + InfraRed 텍스트 lockup)
 *   <Logo monogram />     모노그램만 (favicon 형태, 정사각형)
 *
 * 클릭 동작:
 *   기본값으로 "/"로 이동 (홈으로). href={null} 전달 시 비클릭 정적 표시.
 *
 * height prop 으로 픽셀 단위 사이즈 지정 (default 28). 가로는 비율 유지.
 *
 * 이미지 자산:
 *   /favicon.svg   iR 모노그램 (브랜드 SVG, 모든 모드의 아이콘 부분)
 *   /favicon.ico   레거시 브라우저용 (HTML <link>에서만 사용)
 */

type Props = {
  /** true면 모노그램(iR 아이콘)만, false면 풀 lockup (아이콘 + 텍스트) */
  monogram?: boolean;
  /** 픽셀 단위 height. 가로는 비율 유지 */
  height?: number;
  /** alt text */
  alt?: string;
  /** className 추가 */
  className?: string;
  /** 클릭 시 이동 경로. null이면 정적 (링크 wrap 없음). 기본 "/" */
  href?: string | null;
};

export function Logo({
  monogram = false,
  height = 28,
  alt = "InfraRed",
  className,
  href = "/",
}: Props) {
  const content = monogram ? renderMonogram(alt, height) : renderLockup(alt, height);

  if (href === null || href === undefined) {
    return <span className={className}>{content}</span>;
  }

  return (
    <a
      href={href}
      className={className}
      aria-label={alt}
      style={{
        display: "inline-flex",
        alignItems: "center",
        textDecoration: "none",
        color: "inherit",
      }}
    >
      {content}
    </a>
  );
}

function renderMonogram(alt: string, height: number) {
  return (
    <img
      src="/favicon.svg?v=2"
      alt={alt}
      height={height}
      width={height}
      style={{
        height,
        width: height,
        display: "inline-block",
        verticalAlign: "middle",
      }}
    />
  );
}

function renderLockup(alt: string, height: number) {
  const fontSize = Math.round(height * 0.62);
  return (
    <span
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: Math.round(height * 0.28),
        lineHeight: 1,
        color: "inherit",
      }}
      aria-label={alt}
    >
      <img
        src="/favicon.svg?v=2"
        alt=""
        aria-hidden="true"
        height={height}
        width={height}
        style={{
          height,
          width: height,
          display: "block",
          flexShrink: 0,
        }}
      />
      <span
        style={{
          fontSize,
          fontWeight: 600,
          letterSpacing: "-0.02em",
          color: "inherit",
        }}
      >
        InfraRed
      </span>
    </span>
  );
}

/**
 * 브랜드 컬러 (CSS 변수와 동기화 — globals.css의 --brand-* 와 일치).
 * JS 로직에서 직접 참조할 일이 있을 때 사용.
 */
export const BRAND_COLORS = {
  primary: "#E07000",       // 메인 오렌지
  primaryLight: "#FF8A3D",  // 그라데이션 우측
  primaryDark: "#B85A00",   // hover/active
  textOnBrand: "#FFFFFF",
} as const;
