/**
 * InfraRed brand logo component.
 *
 * 사용 예:
 *   <Logo />                          기본 (full lockup, 28px height)
 *   <Logo height={40} />              크기 지정
 *   <Logo monogram />                 모노그램만 (favicon 형태)
 *   <Logo monogram height={20} />     인라인 마크
 *   <Logo variant="dark" />           다크 배경용 (필요 시 향후)
 *
 * 이미지 자산:
 *   /logo.png        풀 로고 (iR + InfraRed 텍스트 + 태그라인)
 *   /logo-text.svg   (선택) 텍스트만 SVG 버전
 *   /favicon.png     iR 모노그램만 (정사각형)
 *   /favicon.svg     (선택) SVG 버전
 */

type Props = {
  /** true면 모노그램(iR)만, false면 풀 로고 */
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
  height = 32,
  alt = "InfraRed",
  className,
}: Props) {
  const src = monogram ? "/favicon.png" : "/logo.png";
  return (
    <img
      src={src}
      alt={alt}
      height={height}
      style={{ height, width: "auto", display: "inline-block", verticalAlign: "middle" }}
      className={className}
    />
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
