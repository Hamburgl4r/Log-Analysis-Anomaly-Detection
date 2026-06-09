# Log Analysis Anomaly Detector

> Real-time threat detection and security audit platform for high-volume log analysis

## Overview

A Python-based security analysis platform that ingests, parses, and analyzes server logs
to detect active threats and anomalous behavior. Built for SOC analysts and security
engineers who need actionable intelligence from raw log data — without expensive SIEM tooling.

Processes Apache access logs and syslog data to identify 10+ distinct attack patterns
including web exploitation, credential attacks, lateral movement, and data exfiltration
indicators. Scales to hundreds of thousands of log entries.

---

## Detection Capabilities

### Web-Based Attacks (Apache/Nginx Logs)
| Detection            | What It Catches                              | Severity |
|----------------------|----------------------------------------------|----------|
| SQL Injection        | SQLi payloads in URI parameters              | Critical |
| XSS Attempts         | Script injection in request fields           | High     |
| Path Traversal       | `../` and URL-encoded directory traversal    | High     |
| Web Scanning         | Automated scanner signatures (Nikto, dirbuster) | Medium |
| Exploit Patterns     | Known CVE and exploit framework signatures   | Critical |

### Credential Attacks (Auth / Syslog)
| Detection                  | What It Catches                                 | Severity |
|----------------------------|-------------------------------------------------|----------|
| Brute Force                | High-frequency failed auth from a single IP     | Critical |
| Password Spraying          | Low-frequency auth spread across many accounts  | High     |
| Credential Stuffing        | Rapid sequential login attempts, varied IPs     | High     |
| Post-Failure Login Success | Successful auth immediately after failure burst | Critical |

### Lateral Movement (Auth Logs)
| Detection             | What It Catches                            | Severity |
|-----------------------|--------------------------------------------|----------|
| Unusual System Access | Auth to sensitive or rarely accessed paths | High     |
| Admin Tool Usage      | sudo, su, admin CLI commands in logs       | High     |
| Pivot Behavior        | Sequential internal resource access chains | High     |

### Data Exfiltration Indicators
| Detection            | What It Catches                              | Severity |
|----------------------|----------------------------------------------|----------|
| Large Transfers      | Response sizes significantly above baseline  | High     |
| Off-Hours Activity   | Access outside established operational hours | Medium   |
| Unusual Destinations | Requests to unexpected or rare endpoints     | Medium   |

---

## Architecture
