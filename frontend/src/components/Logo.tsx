/**
 * InfraRed brand logo component.
 *
 * 두 가지 모드:
 *   <Logo />              풀 로고 (iR 아이콘 + InfraRed 텍스트 lockup)
 *   <Logo monogram />     모노그램만 (favicon 형태, 정사각형)
 *
 * height prop 으로 픽셀 단위 사이즈 지정 (default 28). 가로는 비율 유지.
 *
 * 이미지 자산:
 *   /favicon.svg   iR 모노그램 (브랜드 SVG, 모든 모드의 아이콘 부분)
 *   /favicon.ico   레거시 브라우저용 (HTML <link>에서만 사용)
 *
 * 풀 로고는 별도 PNG 자산 없이 컴포넌트에서 SVG + 텍스트를 합성합니다.
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
};

export function Logo({
  monogram = false,
  height = 28,
  alt = "InfraRed",
  className,
}: Props) {
  // 모노그램 — favicon.svg 단독 표시
  if (monogram) {
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
        className={className}
      />
    );
  }

  // 풀 lockup — 아이콘 + "InfraRed" 텍스트
  // 텍스트 크기는 height에 비례 (Linear 톤: tight letter-spacing, weight 600)
  const fontSize = Math.round(height * 0.62);
  return (
    <span
      className={className}
      style={{
        display: "inline-flex",
        alignItems: "center",
        gap: Math.round(height * 0.28),
        lineHeight: 1,
        color: "var(--text, #0A0A0A)",
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
