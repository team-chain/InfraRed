INSERT INTO tenants (tenant_id, name, plan)
VALUES ('company-a', 'Company A (Demo)', 'mvp')
ON CONFLICT (tenant_id) DO NOTHING;

INSERT INTO assets (asset_id, tenant_id, hostname, os)
VALUES ('asset-001', 'company-a', 'web-01', 'ubuntu-22.04')
ON CONFLICT (asset_id) DO NOTHING;

INSERT INTO agents (agent_id, tenant_id, asset_id, status)
VALUES ('agent-001', 'company-a', 'asset-001', 'registered')
ON CONFLICT (agent_id) DO NOTHING;

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
