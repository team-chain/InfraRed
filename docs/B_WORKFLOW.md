# B Workflow

This document is the working guide for the detection / enrichment / correlation
track. B owns the path from "Redis raw event" to "PostgreSQL incident +
incidents:new trigger" — i.e. everything between A's ingestion API and C's
LLM/dashboard.

## Owned Components

- `backend/app/workers/detection/`
- `backend/app/workers/enrichment/`
- `backend/app/workers/correlation/`
- `backend/app/db/`
- `backend/app/models/signal.py`
- `backend/app/models/incident.py`
- `backend/app/models/envelope.py` (NormalizedEvent half)

## Pipeline B Implements

```text
tenant:{tid}:stream:events:raw
  -> Detection Worker
       (dedup, parse auth.log, save normalized_events,
        evaluate AUTH-001..005, emit Signal)
  -> tenant:{tid}:stream:signals:matched
  -> Enrichment Worker
       (GeoIP + Mock CTI, merged into CtiEnrichment, cached in Redis)
  -> tenant:{tid}:stream:signals:enriched
  -> Correlation Worker
       (kill-chain stage tracking, build_incident,
        save_or_merge_incident, emit trigger)
  -> tenant:{tid}:stream:incidents:new   (consumed by role C)
```

## Detection Worker

`backend/app/workers/detection/worker.py`

1. Validates the `RawEventEnvelope`.
2. Dedupes by `event_id` via `event:dedup:*` Redis key (TTL = `dedup_ttl_seconds`).
3. Parses with `parser.parse_auth_log`. Drops the line if it cannot be classified.
4. Persists a `NormalizedEvent` (idempotent `INSERT ... ON CONFLICT DO NOTHING`).
5. Runs `rules.evaluate_rules` and emits one `Signal` payload per match onto
   `signals:matched`.

Failures are written to `events:failed` with stage = `detection` so they don't
block the consumer group. Prometheus counters:

- `infrared_detection_events_total{outcome=...}`
- `infrared_detection_signals_total{rule_id=...}`

### Rules (AUTH-001..005)

| Rule | Trigger | Window | MITRE | Kill chain |
| --- | --- | --- | --- | --- |
| AUTH-001 SSH Brute Force | >= 3 failures from one IP | 5 min | T1110.001 | Credential Access |
| AUTH-002 Root Login Attempt | username == root | n/a | T1078 | Initial Access |
| AUTH-003 Invalid User Enumeration | >= 2 invalid-user probes from one IP | 5 min | T1592 | Reconnaissance |
| AUTH-004 Failed Then Success | success after failures (same user/IP) | 10 min | T1110.001 -> T1078 | Initial Access |
| AUTH-005 Suspicious Login | success from a not-previously-seen IP for that user | 90 d | T1078 | Initial Access |

## Enrichment Worker

`backend/app/workers/enrichment/worker.py`

- Calls `geoip.lookup_geoip` (deterministic mock — country, city, ASN).
- Calls `provider.mock_cti_lookup` (deterministic mock — abuse_score, tags).
- Merges them into one `CtiEnrichment` so the correlation stage only has to
  reason about a single shape.
- Caches the merged result on `cti:ip:{ip}` for `cti_cache_ttl_seconds`.
- Re-emits `signal`, `cti`, `geo` onto `signals:enriched`.

## Correlation Worker

`backend/app/workers/correlation/worker.py`

- Tracks the highest kill-chain stage seen per `(tenant, asset, source_ip)` in
  `killchain:{asset}:{ip}` (TTL 1h). When the incoming signal advances the
  stage, the previous stage is added as a "kill chain transition" evidence
  item.
- Calls `build_incident` (severity / confidence / priority + evidence).
- Calls `save_or_merge_incident`. If a recent open/acknowledged incident exists
  for the same `(tenant, asset, source_ip)` (within 5 minutes), the new signal
  is merged in instead of creating a duplicate.
- Emits a trigger envelope onto `incidents:new` only when a new incident is
  created.

## DB

`backend/app/db/schema.sql`

B owns the writes to:

- `normalized_events`
- `signals`
- `incidents`
- `incident_evidence`

C owns writes to `llm_results`, `users`, `audit_logs`. A owns the `tenants`,
`assets`, `agents` rows that B references.

## Tests

```powershell
cd backend
pytest -q
```

The B suite (in `backend/tests/`) covers:

- `test_detection_parser.py` — auth.log line classification.
- `test_detection_rules.py` — AUTH-001..005 with a `fakeredis` backend.
- `test_correlation_builder.py` — severity / confidence / priority and
  kill-chain transition evidence.
- `test_enrichment_geoip.py` — deterministic GeoIP mock.

## Tuning Knobs

If you need to change behavior without touching the pipeline glue:

- Brute-force / invalid-user thresholds: `backend/app/workers/detection/rules.py`
  (`>= 3` and `>= 2` count checks).
- Severity / confidence / priority weights: `backend/app/workers/correlation/builder.py`.
- Incident merge window: `INCIDENT_MERGE_WINDOW` in `backend/app/db/repositories.py`.
- Kill-chain stage TTL: `_KILLCHAIN_TTL_SECONDS` in
  `backend/app/workers/correlation/worker.py`.
- GeoIP / CTI providers: replace `geoip.py` / `provider.py` with real
  integrations; the rest of the pipeline keeps the same shape.

## Contract Stability For C

`docs/C_WORKFLOW.md` lists the incident fields C depends on. B keeps that shape
stable; new fields are added as additive-only changes so the dashboard never
breaks on a deploy.
