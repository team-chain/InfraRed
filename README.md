<div align="center">

# InfraRed

**Multi-tenant SaaS for Linux/Container Security Operations**

Real-time SSH/Web attack detection · automatic IP block in ~10 seconds · MITRE ATT&CK attack-chain correlation · AI incident summarization · Discord/Slack/Email alerts.

[Live demo](https://app.infrared.kr) · [API docs](https://api.infrared.kr/docs) · [Architecture](docs/ARCHITECTURE.md) · [Install guide](docs/INSTALL.md)

</div>

---

## What it does

InfraRed is a hosted SOC platform that watches your Linux servers and containers for SSH brute-force, web shells, SQL injection, FIM tampering, and privilege escalation chains. When a high-confidence threat is detected, it pushes an iptables block to the agent within ~10 seconds, files an incident with kill-chain stage and ATT&CK technique, and notifies your team via Discord/Slack/email.

Built for teams that want SOC-grade detection + automatic response without standing up Wazuh/Splunk/Sentinel themselves.

## Key capabilities

| Capability | Status | Notes |
|---|---|---|
| AUTH detection (brute force, root login, invalid user, failed→success, suspicious login) | ✅ | AUTH-001 through AUTH-007 |
| WEB detection (SQL injection, path traversal, admin scan, 404 burst, webshell, CVE probe) | ✅ | WEB-001 through WEB-007 + WEB-HNY-001 |
| FIM (authorized_keys, sshd_config, crontab, /etc/passwd, /etc/sudoers tamper) | ✅ | hash-based, agent-side |
| Tmp / webshell / bulk-mod execution monitor | ✅ | EXEC-001/002/003 |
| Deception (honeytokens, fake admin accounts, canary paths) | ✅ | DECEPTION-001/002 |
| Attack-chain correlation (SSH compromise, webshell, priv-esc, ransomware, lateral movement) | ✅ | 7 scenarios |
| Auto-response: iptables block, server isolation, container quarantine, account lock, JIT-SSH revoke | ✅ | confidence ≥ 0.85 + CRITICAL = automatic |
| Approval workflow for mid-confidence blocks | ✅ | TTL + extension supported |
| AI incident summarization (Bedrock Claude, static fallback) | ✅ | per-incident, cached |
| RBAC (owner / security_manager / analyst / viewer) + invite + email verification + password reset | ✅ | multi-tenant |
| Discord / Slack / Email alerts with embed/Block Kit | ✅ | per-tenant webhook config |
| Sentry + Prometheus integration | ✅ | optional, opt-in via env |
| Dashboard (incidents timeline, members, rule management, reports) | ✅ | React + Vite |
| Agent: Linux (Python + systemd), Windows, macOS | 🟡 | Linux production-ready; Windows/macOS preview |

## Quick start (self-hosted)

Requires Docker, Docker Compose, and ~2 GB RAM.

```bash
git clone https://github.com/team-chain/InfraRed.git
cd InfraRed
cp .env.example .env

# Generate the agent JWT secret
python scripts/generate_jwt.py --role agent > /tmp/agent_token.txt
sed -i "s|^AGENT_TOKEN=.*|AGENT_TOKEN=$(cat /tmp/agent_token.txt)|" .env

# Bring up the stack
docker compose up -d
```

Then open:

- Dashboard: http://localhost:3000
- API: http://localhost:8000 (Swagger: `/docs`)

Default demo login: `admin@infrared.local` / `infrared123` (tenant `company-a`). For production, set `INITIAL_ADMIN_EMAIL` + `INITIAL_ADMIN_PASSWORD` in `.env` before `docker compose up` — your real admin is created automatically on first migrate.

Full install guide: [docs/INSTALL.md](docs/INSTALL.md).

## Architecture (high level)

```
                                  ┌─────────────────────────┐
                                  │      Dashboard (React)  │
                                  └──────────┬──────────────┘
                                             │ HTTPS + JWT
                                             ▼
 Linux/Container hosts                ┌──────────────┐         ┌──────────────┐
   ┌────────────┐  POST /ingest       │   FastAPI    │◄────────│  PostgreSQL  │
   │   Agent    │ ──────────────────► │  Ingestion   │         │ users,       │
   │ tailer +   │  GET  /commands     │     API      │────────►│ incidents,   │
   │ commander  │ ◄────────────────── └──────┬───────┘         │ signals,     │
   └─────┬──────┘   block_ip / isolate       │                 │ rules, etc.  │
         │ iptables/docker                   │ Redis Streams   └──────────────┘
         ▼                                   ▼
   ─ host kernel ─                ┌─────────────────────┐
                                  │  detection-worker   │  rule match
                                  │  enrichment-worker  │  CTI / GeoIP
                                  │  correlation-worker │  attack chain
                                  │  llm-worker         │  Bedrock Claude
                                  │  campaign-worker    │  alert grouping
                                  │  cleanup-worker     │  retention
                                  └──────────┬──────────┘
                                             │
                          Discord / Slack / Email / Webhook
```

Full diagram with data flow: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## What's inside

```
backend/        FastAPI + workers (detection, enrichment, correlation, LLM, dispatcher)
frontend/       React + Vite dashboard
agent/          Python agent (auth.log + nginx tailer, FIM, EXEC monitor, commander)
infra/          Terraform, Docker, nginx, Prometheus, sample logs
scripts/        Install one-liner, JWT helper, log generator, smoke tests
docs/           Architecture, install, role workflows, design specs
```

## Detection rules

28 production rules across AUTH / WEB / FIM / EXEC / DECEPTION / NET / Correlation. Each rule has confidence scoring; ≥ 0.85 + CRITICAL severity auto-triggers iptables block via the agent. Full rule catalog: [docs/RULES.md](docs/RULES.md).

## Security posture

InfraRed is itself a security product, so we apply our own controls:

- multi-tenant data isolation (per-tenant `tenant_id` scoping on every query)
- bcrypt password hashing via Postgres `pgcrypto.crypt()`
- JWT with revocation deny-list (Redis-backed, per-jti + per-user)
- Discord/Slack webhook URLs never logged
- mTLS for agent ↔ ingestion in production (`MTLS_ENABLED=true`)
- Dead Man's Switch for server isolation TTL
- nonce + HMAC signing for backend → agent commands
- input validation via Pydantic, parameterized SQL only

## License

Source-available for evaluation. Production use under contract — contact the team.

## Contributing

Internal development docs in [CONTRIBUTING.md](CONTRIBUTING.md).
