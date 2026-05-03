# C Workflow

This document is the working guide for the AI, alerting, dashboard, IAM, and monitoring track.

## Owned Components

- `backend/app/workers/llm/`
- `backend/app/dispatcher/`
- `backend/app/iam/`
- `frontend/`
- `infra/prometheus/`
- `infra/grafana/`
- `backend/app/models/llm.py`

## Implemented Starter Flow

```text
POST /auth/login
  -> user JWT
  -> GET /incidents
  -> GET /incidents/{incident_id}
  -> POST /incidents/{incident_id}/analyze
  -> POST /incidents/{incident_id}/dispatch
```

The dashboard uses the same API contract that the LLM worker uses.

## Demo User

Seeded by `infra/postgres/seed.sql`:

```text
tenant: company-a
email: admin@infrared.local
password: infrared123
role: admin
```

## C API Surface

- `POST /auth/login`
- `GET /auth/me`
- `GET /incidents`
- `GET /incidents/{incident_id}`
- `POST /incidents/{incident_id}/analyze`
- `POST /incidents/{incident_id}/dispatch`
- `PATCH /incidents/{incident_id}/status`
- `GET /detection-rules`
- `GET /audit-logs`
- `GET /metrics`

## LLM Behavior

The LLM service tries Bedrock only when AWS credentials are configured.

If credentials are empty or Bedrock fails, it uses the Static Playbook fallback in:

```text
backend/app/workers/llm/playbook.py
```

Results are cached per incident through Redis:

```text
llm:cache:incident:{incident_id}
```

For real Bedrock setup, see:

```text
docs/AWS_BEDROCK_SETUP.md
```

## Dashboard Behavior

The frontend supports:

- Login with tenant/email/password
- Incident list
- Incident detail
- LLM summary
- Evidence timeline
- Recommended actions
- CTI panel
- Manual LLM analysis
- Manual alert dispatch through Discord and/or email
- Incident status update

## Local Verification

```powershell
python scripts/check_syntax.py
docker compose config --quiet
docker compose up --build
```

Open:

```text
http://localhost:3000
```

## Notes for Later B Work

B should produce incidents that keep this shape stable:

- `incident_id`
- `tenant_id`
- `asset_id`
- `severity`
- `confidence`
- `priority`
- `kill_chain_stage`
- `mitre_tactic`
- `mitre_technique`
- `source_ip`
- `username`
- `status`
- `signal_ids`
- `cti_enrichment`
- `evidence_timeline`

If B needs to add fields, prefer additive changes so the C dashboard does not break.
