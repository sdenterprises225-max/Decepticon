---
id: FIND-002
severity: critical
title: SQL Injection - Credential Dump
agent: exploit
objective_id: OBJ-002
discovered_at: "2026-06-01T04:37:00Z"
evidence_pointer: findings/evidence/FIND-002_sqli_creds.txt
---

## Description
UNION-based SQL injection on /vulnerabilities/sqli/ allowed full dump of users table.

## Evidence
- Database: MariaDB 10.1.26
- Tables: guestbook, users
- Credentials: admin:password, gordonb:abc123, 1337:charley, pablo:letmein, smithy:password
- MITRE ATT&CK: T1190, T1003

## Next
postexploit agent should: attempt authentication with captured credentials and pivot.
