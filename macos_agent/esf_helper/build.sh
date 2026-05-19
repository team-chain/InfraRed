#!/usr/bin/env bash
# ESF 헬퍼 바이너리 빌드 스크립트
# 실행 환경: macOS 10.15+, Xcode Command Line Tools
# Entitlement: com.apple.developer.endpoint-security.client 필요

set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
OUTPUT_DIR="$SCRIPT_DIR/../bin"
BINARY_NAME="esf_helper"

mkdir -p "$OUTPUT_DIR"

echo "ESF 헬퍼 빌드 중..."

swiftc \
  -o "$OUTPUT_DIR/$BINARY_NAME" \
  -framework EndpointSecurity \
  -framework Foundation \
  "$SCRIPT_DIR/main.swift"

# Entitlement 서명 (개발 테스트용 — 배포는 Apple Developer Account 필요)
ENTITLEMENT_PLIST="$SCRIPT_DIR/esf_helper.entitlements"
cat > "$ENTITLEMENT_PLIST" << 'PLIST'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
  "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>com.apple.developer.endpoint-security.client</key>
    <true/>
    <key>com.apple.security.cs.allow-unsigned-executable-memory</key>
    <true/>
</dict>
</plist>
PLIST

# 로컬 서명 (System Integrity Protection 비활성화 필요)
codesign \
  --sign - \
  --entitlements "$ENTITLEMENT_PLIST" \
  --force \
  "$OUTPUT_DIR/$BINARY_NAME" \
  2>/dev/null || {
    echo "⚠️  코드서명 실패 (SIP 비활성화 또는 Apple Developer Certificate 필요)"
    echo "   배포 환경에서는 Apple Developer ID Application 인증서로 서명하세요."
  }

echo "✅ 빌드 완료: $OUTPUT_DIR/$BINARY_NAME"
echo ""
echo "실행 방법:"
echo "  sudo $OUTPUT_DIR/$BINARY_NAME --json"
echo ""
echo "Python 에이전트 통합:"
echo "  collector = ESFCollector(server_url='...', ...)"
echo "  collector.start()"
