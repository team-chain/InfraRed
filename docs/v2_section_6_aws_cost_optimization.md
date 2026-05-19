# 섹션 6 — AWS 비용 최적화 방안
> InfraRed 고도화 설계서 v2.0 §6 (미완성 → 완성)

---

## 6.1 현황 분석 및 비용 구조

InfraRed 서비스의 AWS 비용 구조는 크게 4가지 레이어로 분류된다.

### 6.1.1 비용 레이어별 분석

**Compute (EC2 / Lambda)**
- EC2 단일 인스턴스 (t3.small) On-Demand: 월 $16.64
- Lambda AI 처리 워커: 월 $1~$15 (요청량 비례)
- **최적화**: EC2 Reserved Instance 1년 약정 시 38% 절감 → 월 $10.30

**Database (RDS PostgreSQL)**
- db.t3.micro Single-AZ: 월 $15.33
- 스토리지 20GB gp2: 월 $2.30
- **최적화**: db.t3.micro Reserved 1년 약정 → 월 $8.94 (42% 절감)

**Cache (ElastiCache Redis)**
- cache.t3.micro: 월 $12.24
- **최적화**: Reserved Node 1년 약정 → 월 $6.94 (43% 절감)

**Storage / Network (S3, SQS, CloudWatch)**
- S3 로그 스토리지: 월 $0.5~5 (30일 보관 기준)
- SQS: 월 $0~4 (무료 한도 100만 req 이내 $0)
- CloudWatch: 월 $3~10 (커스텀 메트릭 10개 기준)

---

## 6.2 단계별 최적화 전략

### 6.2.1 즉시 적용 가능 (추가 개발 없음)

**S3 Intelligent-Tiering 전환**
```bash
# Terraform 변경 (terraform.tfvars)
s3_lifecycle_transition_days = 30   # 30일 후 IA로 전환
s3_lifecycle_deep_archive_days = 90 # 90일 후 Glacier 전환
```
효과: S3 비용 40~60% 절감 (30일+ 데이터가 많은 경우)

**CloudWatch 로그 보존 기간 최적화**
```hcl
# infra/terraform/cloudwatch.tf
resource "aws_cloudwatch_log_group" "infrared" {
  retention_in_days = 30  # 현재 90일 → 30일 단축
}
```
효과: 월 $2~8 절감

**Lambda 메모리 최적화**
```python
# 현재: 256MB → AWS Lambda Power Tuning 결과 적용
# 탐지 AI: 512MB (최적 가성비 지점)
# 리포트 생성: 1024MB
lambda_memory_mb = 512  # 256 → 512 (속도 2배, 비용 동일)
```

### 6.2.2 중기 최적화 (1~3개월)

**EC2 Savings Plans 적용**
- 1년 Compute Savings Plan 약정: 32% 절감
- 인스턴스 패밀리 유연성 유지 (t3 → c6i 전환 가능)

**RDS + ElastiCache Reserved Instance**
```bash
# AWS CLI로 예약 인스턴스 구매
aws rds purchase-reserved-db-instances-offering \
  --reserved-db-instances-offering-id <offering-id> \
  --db-instance-count 1

aws elasticache purchase-reserved-cache-nodes-offering \
  --reserved-cache-nodes-offering-id <offering-id> \
  --cache-node-count 1
```

**SQS → EventBridge 전환 검토**
- 현재: SQS 3큐 구조 (signals, ai_worker, incident_worker)
- 대안: EventBridge Rules + SQS DLQ 조합
- 효과: 100만 이벤트/월 이하 무료 (현재 SQS 비용 $0~4 절감)

### 6.2.3 장기 최적화 (3~12개월)

**Bedrock 비용 최적화**
```python
# backend/app/workers/llm/providers.py 에 배치 처리 추가
# On-demand → Provisioned Throughput (월 $50+ 사용 시 50% 절감)
BEDROCK_USE_PROVISIONED = os.getenv("BEDROCK_USE_PROVISIONED", "false") == "true"
BEDROCK_MODEL_UNIT = int(os.getenv("BEDROCK_MODEL_UNIT", "1"))
```

**Aurora Serverless v2 전환** (엔터프라이즈)
- 현재 RDS on: 항상 $15/월
- Aurora Serverless v2: 0 ACU 시 $0, 트래픽 비례 과금
- 소규모 테넌트: 월 $5~8로 절감 가능

---

## 6.3 비용 모니터링 자동화

### 6.3.1 CloudWatch 비용 알람

```hcl
# infra/terraform/cloudwatch.tf에 추가
resource "aws_cloudwatch_metric_alarm" "cost_alert" {
  alarm_name          = "infrared-monthly-cost-alert"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 1
  metric_name         = "EstimatedCharges"
  namespace           = "AWS/Billing"
  period              = 86400  # 1일
  statistic           = "Maximum"
  threshold           = 100    # $100 초과 시 알람

  dimensions = { Currency = "USD" }

  alarm_actions = [aws_sns_topic.alerts.arn]
}
```

### 6.3.2 Prometheus 비용 메트릭 (내부)
```python
# backend/app/workers/kpi/kpi_worker.py에 통합됨
# /metrics 엔드포인트에서 조회 가능:
# infrared_aws_estimated_cost_usd{service="ec2"}
# infrared_aws_estimated_cost_usd{service="rds"}
# infrared_aws_estimated_cost_usd{service="lambda"}
```

---

## 6.4 티어별 월 비용 요약

| 티어 | EC2 | DB | Cache | AI | 기타 | 월 합계 |
|------|-----|----|-------|-----|------|---------|
| 프리티어 | $0 | $0 | $0 | $0~1 | $0 | **$0~1** |
| 스몰 | $10 | $0 | $0 | $1~5 | $5 | **$16~20** |
| 스탠다드 | $16 | $15 | $12 | $5~15 | $10 | **$58~68** |
| 엔터프라이즈 | $60 | $90 | $90 | $10~50 | $25 | **$275~315** |

*Reserved Instance 미적용 기준. 1년 약정 시 30~43% 절감 가능.*

