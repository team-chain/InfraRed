# InfraRed 프리티어 → 유료 전환 비용 타임라인
> 설계서: `InfraRed_프리티어_설계서_v1.0.docx` §5.3  
> 기준: AWS ap-northeast-2 (서울 리전), 2026년 기준 요금

---

## 단계별 비용 타임라인

### Phase 0 — 프리티어 전환 직후 (월 $0)

| 서비스 | 사양 | 요금 |
|--------|------|------|
| EC2 t2.micro | 750시간/월 | **$0** (Free Tier 12개월) |
| PostgreSQL | EC2 로컬 (Docker) | **$0** |
| Redis | EC2 로컬 (Docker) | **$0** |
| step-ca PKI | EC2 로컬 | **$0** |
| S3 스토리지 | 5GB | **$0** (Free Tier) |
| Lambda | 100만 요청 이하 | **$0** (영구 무료) |
| SQS | 100만 메시지 이하 | **$0** (영구 무료) |
| CloudWatch | 기본 메트릭 | **$0** |
| **월 합계** | | **$0** |

> ⚠️ Free Tier는 계정 생성 후 12개월만 적용됩니다.

---

### Phase 1 — Free Tier 만료 후 (월 ~$15~25)

| 서비스 | 사양 | 요금 |
|--------|------|------|
| EC2 t2.micro (On-Demand) | 730시간 | ~$10.00 |
| EC2 EBS gp2 20GB | | ~$2.00 |
| S3 스토리지 10GB | | ~$0.23 |
| CloudWatch 커스텀 메트릭 10개 | | ~$3.00 |
| Lambda 호출 (탐지 AI) | 100만 요청 이하 | $0 |
| SQS | 100만 이하 | $0 |
| 데이터 전송 | 1GB 이하 | $0.09 |
| **월 합계** | | **~$15~18** |

**권장 액션**: Reserved Instance 1년 약정 전환 시 t3.small $8.03/월

---

### Phase 2 — 스탠다드 플랜 (월 ~$80)
> 에이전트 50대 이상, 동시 사용자 10명 이상 시 권장

| 서비스 | 사양 | 요금 |
|--------|------|------|
| EC2 t3.medium (On-Demand) | | ~$35.00 |
| RDS PostgreSQL db.t3.micro | 싱글 AZ | ~$15.00 |
| ElastiCache Redis cache.t3.micro | | ~$12.00 |
| ACM 인증서 | | $0 (무료) |
| S3 50GB | | ~$1.15 |
| Lambda 500만 요청 | | ~$1.00 |
| CloudWatch 로그 10GB | | ~$5.00 |
| SQS 1000만 메시지 | | ~$4.00 |
| **월 합계** | | **~$73~85** |

---

### Phase 3 — 엔터프라이즈 플랜 (월 ~$250+)
> 에이전트 200대 이상, SLA 99.9% 이상 요구 시

| 서비스 | 사양 | 요금 |
|--------|------|------|
| EC2 t3.large (On-Demand) | | ~$67.00 |
| ALB (Application Load Balancer) | | ~$22.00 |
| RDS PostgreSQL r6g.large | Multi-AZ | ~$90.00 |
| ElastiCache r6g.large | | ~$90.00 |
| ACM 인증서 | | $0 |
| S3 200GB | | ~$4.60 |
| Lambda 2000만 요청 | | ~$4.00 |
| CloudWatch 50GB | | ~$25.00 |
| SQS 5000만 메시지 | | ~$20.00 |
| Bedrock Claude Sonnet | 추론 비용 (변동) | ~$10~50 |
| **월 합계** | | **~$230~370** |

---

## 전환 명령어 요약

### 프리티어 → 스탠다드 전환
```bash
# 1. 계획 확인
./terraform_restore.sh plan standard

# 2. 검토 후 적용
./terraform_restore.sh apply migration_plan_standard_<timestamp>.tfplan

# 3. 롤백 필요 시
./terraform_restore.sh rollback
```

### Terraform 변수 변경만으로 완전 전환 가능
```hcl
# terraform.tfvars 수정
tier              = "standard"  # freetier → standard
ec2_instance_type = "t3.medium"
use_rds           = true
use_elasticache   = true
```

---

## 비용 최적화 체크리스트

| 항목 | 절감액 | 적용 시점 |
|------|--------|----------|
| EC2 1년 Reserved Instance | 30~40% 절감 | Phase 1 만료 전 |
| RDS Reserved Instance | 40% 절감 | Phase 2 시작 시 |
| S3 Intelligent-Tiering | ~15% 절감 | Phase 2 시작 시 |
| Lambda Provisioned Concurrency 제거 | 변동 | 피크 시간 외 |
| CloudWatch 로그 보존 기간 단축 | ~30% 절감 | 즉시 적용 |
| Spot Instance 활용 (비프로덕션) | 70% 절감 | 개발 환경 |

---

## 소프트웨어 불변 원칙

> **설계 원칙**: 인프라가 바뀌어도 소프트웨어 코드는 변경되지 않습니다.
> 
> 프리티어 ↔ 엔터프라이즈 전환 시 변경되는 것:
> - `terraform.tfvars` 변수 값만 변경
> - 애플리케이션 코드 (`backend/`, `agent/`, `frontend/`) 변경 없음
> - 데이터 마이그레이션 없음 (RDS 전환 시 `pg_dump`/`pg_restore` 제외)

---

*최종 업데이트: 2026-05-18*
