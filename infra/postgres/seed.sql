INSERT INTO tenants (tenant_id, name, plan)
VALUES ('company-a', 'Company A (Demo)', 'mvp')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO assets (asset_id, tenant_id, hostname, os)
VALUES ('asset-001', 'company-a', 'web-01', 'ubuntu-22.04')
ON CONFLICT (asset_id) DO NOTHING;

INSERT INTO agents (agent_id, tenant_id, asset_id, status)
VALUES ('agent-001', 'company-a', 'asset-001', 'registered')
ON CONFLICT (agent_id) DO NOTHING;

INSERT INTO users (tenant_id, email, password_hash, role)
VALUES (
  'company-a',
  'admin@infrared.local',
  crypt('infrared123', gen_salt('bf')),
  'admin'
)
ON CONFLICT (tenant_id, email) DO NOTHING;

INSERT INTO detection_rules (rule_id, name, source, mitre_tactic, mitre_technique, enabled)
VALUES
  ('AUTH-001', 'SSH Brute Force',          'auth.log', 'Credential Access', 'T1110.001', TRUE),
  ('AUTH-002', 'Root Login Attempt',       'auth.log', 'Initial Access',    'T1078',     TRUE),
  ('AUTH-003', 'Invalid User Enumeration', 'auth.log', 'Reconnaissance',    'T1592',     TRUE),
  ('AUTH-004', 'Failed Then Success',      'auth.log', 'Initial Access',    'T1110.001 -> T1078', TRUE),
  ('AUTH-005', 'Suspicious Login',         'auth.log', 'Initial Access',    'T1078',     TRUE),
  ('WEB-001',  'Web Shell Access',         'nginx',    'Initial Access',    'T1505.003', FALSE),
  ('WEB-002',  'Admin Path Scan',          'nginx',    'Reconnaissance',    'T1595',     FALSE),
  ('WEB-003',  'Automation Tool Access',   'nginx',    'Initial Access',    'T1190',     FALSE),
  ('WEB-004',  '404 Burst',                'nginx',    'Reconnaissance',    'T1595',     FALSE)
ON CONFLICT (rule_id) DO NOTHING;

INSERT INTO incidents (
  incident_id, tenant_id, asset_id, severity, confidence, priority,
  kill_chain_stage, mitre_tactic, mitre_technique, cti_enrichment,
  source_ip, username, signal_ids, status, created_at, updated_at
)
VALUES (
  'INC-DEMO-SSH-001',
  'company-a',
  'asset-001',
  'high',
  'medium',
  'high',
  'Initial Access',
  'Initial Access',
  'T1110.001 -> T1078',
  '{"abuse_score": 82, "country": "NL", "tags": ["scanner", "high-risk-ip"], "sources": ["mock-cti"]}'::jsonb,
  '185.12.34.56',
  'root',
  '["SIG-DEMO-001", "SIG-DEMO-002"]'::jsonb,
  'open',
  NOW() - INTERVAL '10 minutes',
  NOW() - INTERVAL '10 minutes'
)
ON CONFLICT (incident_id) DO NOTHING;

INSERT INTO incident_evidence (incident_id, tenant_id, timestamp, description, signal_id, rule_id)
SELECT 'INC-DEMO-SSH-001', 'company-a', NOW() - INTERVAL '13 minutes',
       'AUTH-003 Invalid User Enumeration: repeated invalid-user probes from 185.12.34.56',
       'SIG-DEMO-001', 'AUTH-003'
WHERE NOT EXISTS (
  SELECT 1 FROM incident_evidence
  WHERE incident_id = 'INC-DEMO-SSH-001' AND signal_id = 'SIG-DEMO-001'
);

INSERT INTO incident_evidence (incident_id, tenant_id, timestamp, description, signal_id, rule_id)
SELECT 'INC-DEMO-SSH-001', 'company-a', NOW() - INTERVAL '10 minutes',
       'AUTH-004 Failed Then Success: successful root login after failures from same source IP',
       'SIG-DEMO-002', 'AUTH-004'
WHERE NOT EXISTS (
  SELECT 1 FROM incident_evidence
  WHERE incident_id = 'INC-DEMO-SSH-001' AND signal_id = 'SIG-DEMO-002'
);

INSERT INTO llm_results (
  incident_id, tenant_id, plain_summary, attack_intent, kill_chain_analysis,
  recommended_actions, confidence_note, model, cached, generated_at
)
SELECT
  'INC-DEMO-SSH-001',
  'company-a',
  'HIGH SSH incident from 185.12.34.56 against root. Evidence shows failed attempts followed by a successful login. Treat this as possible credential compromise until the login is verified.',
  'The pattern suggests credential brute force followed by account access.',
  'Current stage: Initial Access. Mapped ATT&CK: Initial Access / T1110.001 -> T1078.',
  '["Verify whether the root login was authorized.", "Block 185.12.34.56 at the edge while investigating.", "Rotate root credentials and enforce key-only SSH."]'::jsonb,
  'Medium confidence because the MVP correlation uses deterministic starter rules.',
  'static-playbook',
  false,
  NOW() - INTERVAL '9 minutes'
WHERE NOT EXISTS (
  SELECT 1 FROM llm_results WHERE incident_id = 'INC-DEMO-SSH-001'
);
