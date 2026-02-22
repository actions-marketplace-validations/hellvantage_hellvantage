# HellVantage Offensive Rule Arsenal

| Rule ID | Title | Target | Severity | Vector / Exploit Path |
| :--- | :--- | :---: | :---: | :--- |
| HV-001 | Hardcoded AWS Credentials | TF | CRITICAL | Initial Foothold via exposed keys. |
| HV-002 | IAM Privilege Escalation | TF | HIGH | Shadow Admin via wildcard policies. |
| HV-003 | EC2 IMDSv1 Enabled | TF | HIGH | Lateral Movement via SSRF metadata theft. |
| HV-004 | S3 Bucket Public Exposure | TF/CFN | CRITICAL | Data Exfiltration vector. |

Note on Freemium Model: Advanced lateral movement rules are available in the Enterprise Tier.
