# Detection Engineering Portfolio

## What is Detection Engineering?

Detection engineering is the discipline of designing, building, and continuously improving the rules that tell a security monitoring platform when to raise an alert. A detection engineer asks: *given everything an attacker might do, what evidence does each action leave in logs — and how do I write a rule precise enough to catch the attacker without drowning analysts in false positives?*

This is distinct from operating a SIEM. Anyone can click through a dashboard. A detection engineer writes the logic that determines what the dashboard shows.

## What is MITRE ATT&CK?

MITRE ATT&CK (Adversarial Tactics, Techniques & Common Knowledge) is a publicly maintained library of every technique adversaries have been observed using against real organisations. Each technique has an ID (e.g. T1059), a description, real-world examples from named threat groups, and documented detection approaches.

Using ATT&CK as a framework means detections are:
- **Threat-informed** — grounded in observed attacker behaviour, not hypothetical
- **Portable** — any analyst globally understands what T1059.001 means without reading your internal docs
- **Measurable** — you can track what percentage of the ATT&CK matrix your detection coverage addresses

## What This Portfolio Demonstrates

This repository contains production-quality detection rules across two platforms — Splunk (SPL) and Microsoft Sentinel (KQL) — covering four high-priority MITRE ATT&CK techniques, plus documented alert tuning work.

| Technique | ID | Platform Coverage |
|---|---|---|
| Command and Scripting Interpreter: PowerShell | T1059.001 | Splunk + Sentinel |
| Valid Accounts | T1078 | Splunk + Sentinel |
| Boot or Logon Autostart Execution | T1547.001 | Splunk |
| Phishing: Spearphishing Attachment | T1566.001 | Sentinel |

Each detection includes:
- The detection query
- Why the technique is dangerous
- What a true positive looks like
- What a false positive looks like
- Tuning recommendations

## Repository Structure

```
/splunk-detections/         Splunk SPL detection rules
/sentinel-kql-rules/        Microsoft Sentinel KQL detection rules
/alert-tuning-log/          Documented false positive reduction work
/README.md                  This file
```

## Threat Actor Relevance

These techniques are commonly associated with:
- **Lazarus Group (DPRK)** — heavy PowerShell use, credential theft via valid accounts
- **APT28 (Fancy Bear)** — spearphishing as primary initial access, autostart persistence
- **Scattered Spider** — valid account abuse, social engineering at scale

## Author

Security analyst with hands-on experience in SIEM operations, detection rule authorship, and MITRE ATT&CK-aligned threat modelling. Background includes physical and logical access control, endpoint detection, and incident triage.

---
*All detection logic is written for educational and portfolio purposes. Queries are validated against documented log schemas for each platform.*
