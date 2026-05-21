# InfraRed — Security Practices

보안 제품이라 자기 자신에도 같은 원칙을 적용한다. 운영자는 이 문서의 항목을
checklist로 분기별로 점검할 것.

---

## 1. AWS IAM 위생

### Long-lived access key 금지

EC2에서는 **IAM instance role**을 사용한다. `.env`에 `AWS_ACCESS_KEY_ID` /
`AWS_SECRET_ACCESS_KEY`를 두지 않는다. (boto3는 환경변수가 있으면 그걸 우선해
instance role을 무시함.)

EC2 IAM role (`infrared-dev-ec2-role`)은 `infra/terraform/iam.tf`에서 정의되며
다음 권한만 가진다:
- ECR (이미지 pull/push)
- SSM Parameter Store (시크릿 읽기, `/infrared/*` 범위)
- S3 (logs, reports 버킷만)
- Bedrock InvokeModel
- CloudWatch Logs
- IAM (Honey Key 생성/회수, `infrared-honey-*` 범위)

CI/CD는 **GitHub OIDC**를 통해 ECR push role을 임시 assume — long-lived key 미사용.
`deploy.yml`의 `AWS_DEPLOY_ROLE_ARN` 참고.

### IAM user 권한 축소

`sebin-user` 같은 개인 user에 `AdministratorAccess`가 붙어있으면 보안 위험. 운영
원칙:
- 개발자 access는 SSO + IAM Identity Center로 전환
- 임시 root user는 MFA 필수, AccessKey 발급 금지
- 모든 IAM user에 정기적 (90일) audit

### Honey Key 격리

`AWSHoneyKeyManager`가 생성하는 IAM Honey User는 `infrared-honey-*` 접두사로
제한되며, 별도 가짜 권한 정책만 갖는다. CloudTrail에서 호출 감지되면 즉시
DECEPTION-003 alert 발생.

---

## 2. Secret rotation

### 회전 주기

| Secret | 주기 | 회전 방법 |
|---|---|---|
| `JWT_SECRET` | 90일 또는 침해 의심 시 즉시 | 새 키 생성 → blue/green 배포 → 모든 토큰 자동 만료 |
| DB password (RDS) | 90일 | AWS Secrets Manager 자동 회전 (권장) |
| Redis password | 180일 | `.env` 갱신 → docker compose restart |
| `AGENT_TOKEN` | 30일 또는 agent 침해 의심 시 | `python scripts/generate_jwt.py --role agent` |
| `AGENT_COMMAND_SECRET` | 90일 | nonce HMAC 키, 모든 agent + backend 동시 회전 |
| `DISCORD_WEBHOOK_URL` / `SLACK_WEBHOOK_URL` | 침해 시 즉시 | Webhook 재발급 → tenant_settings 업데이트 |
| `STRIPE_SECRET_KEY` | 90일 | Stripe Dashboard에서 rolling rotation |
| OIDC role trust policy | 변경 시 audit | terraform plan 검토 |

### JWT_SECRET 회전 절차

1. 새 secret 생성: `python -c "import secrets; print(secrets.token_urlsafe(64))"`
2. EC2의 `.env`에 `JWT_SECRET_NEW=...` 추가 (옛 키와 함께)
3. backend 코드를 두 키 모두 verify하도록 패치 (옛 키 유효 동안 graceful)
4. `docker compose restart ingestion` → 새 토큰부터 새 키로 발급
5. 옛 토큰 만료 (max TTL 24h) 후 `JWT_SECRET_NEW` → `JWT_SECRET`로 promote, 옛 키 제거

(현재는 graceful rotation 코드 미구현 — 회전 시 사용자 전원 강제 재로그인. v1.1에서 dual-key 지원 예정.)

---

## 3. 자체 OWASP 점검

### 매 PR review checklist

- [ ] 새 SQL은 parameterized? (`text("...:param")`, `text(f"...{var}")` 금지)
- [ ] 새 endpoint에 tenant 검증? (`assert_same_tenant(claims, tenant_id)`)
- [ ] resource_id (incident/asset/user)는 caller tenant 소속 확인?
  (`assert_resource_belongs_to(...)` 또는 SQL 조회 시 `AND tenant_id = :tid`)
- [ ] sensitive endpoint에 rate limit? (`Depends(limit_*)`)
- [ ] secret이 log/audit/exception에 노출되지 않음?
- [ ] 사용자 입력이 path/HTTP redirect/SSRF에 사용되지 않음?

### 정기 자체 점검

- 분기별 `pip-audit` + `npm audit` 실행
- 분기별 `bandit` (Python 보안 lint) 실행
- 6개월마다 외부 pentest (또는 자체 scenario: 시나리오 파일 참조)
- Dependabot alert는 high/critical 발견 시 7일 내 머지

---

## 4. mTLS (agent ↔ backend)

production에서 `MTLS_ENABLED=true` + nginx `ssl_verify_client on`. step-ca가 발급한
agent 인증서만 ingestion에 도달 가능. `infra/terraform/step-ca*` 참고.

CN 형식: `agent-{tenant_id}-{asset_id}`. 백엔드 미들웨어 `app/middleware/mtls.py`가
CN을 추출해 claims에 추가.

---

## 5. Token revocation

- JWT에 `jti` claim 포함 (모든 토큰 unique ID).
- logout 시 해당 jti를 Redis deny-list에 추가 (TTL = token 남은 수명).
- owner는 `/auth/revoke-all`로 자신 또는 타 사용자의 모든 토큰 일괄 만료 가능.
- 코드: `app/iam/token_revocation.py`.

침해 의심 시 운영자가 직접 호출:
```bash
curl -X POST https://api.infrared.kr/auth/revoke-all \
  -H "Authorization: Bearer <owner_token>" \
  -H "Content-Type: application/json" \
  -d '{"target_user_id": "<침해_사용자_id>"}'
```

---

## 6. 보고서 (전사 공유용)

월간 보안 상태 리포트는 `/api/v1/compliance/security-summary`에서 PDF로 자동 생성.
KPI: 평균 탐지/대응 시간, MTTR, false positive rate, top 공격 IP, 차단된 IP 수.
