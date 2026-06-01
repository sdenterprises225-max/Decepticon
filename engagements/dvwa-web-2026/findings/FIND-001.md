---
id: FIND-001
severity: critical
title: OS Command Injection via vulnerabilities/exec/
agent: exploit
objective_id: OBJ-001
discovered_at: "2026-06-01T04:35:00Z"
evidence_pointer: findings/evidence/FIND-001_cmdi_output.txt
---

## Description
The DVWA Command Injection module at /vulnerabilities/exec/index.php accepts unsanitized user input in the ip parameter.

## Evidence
- Endpoint: http://dvwa-test/vulnerabilities/exec/index.php
- Payload: ip=127.0.0.1|id
- Response: uid=33(www-data) gid=33(www-data)
- MITRE ATT&CK: T1190

## Next
postexploit agent should: leverage www-data shell for lateral movement and privilege escalation.
