# T1566.001 — Phishing: Spearphishing Attachment

**MITRE ATT&CK:** [T1566.001](https://attack.mitre.org/techniques/T1566/001/)  
**Tactic:** Initial Access  
**Platform:** Windows, macOS, Linux  
**Detection Platform:** Microsoft Sentinel (KQL)  
**Severity:** High  
**Data Sources Required:** Microsoft Defender for Office 365, Microsoft Defender for Endpoint, Azure AD Sign-in Logs, Email gateway logs

---

## Why This Technique Is Dangerous

Phishing is the most common initial access technique across all threat actor categories — nation-state, criminal, and hacktivist. Spearphishing (targeted phishing) uses personalised content about the recipient's organisation, role, or recent activities to increase the likelihood of the victim opening the attachment.

Common attachment types:
- **Macro-enabled Office documents** (.docm, .xlsm) — user clicks "Enable Content" and runs the macro
- **PDF files** containing malicious links or exploiting PDF reader vulnerabilities
- **Archive files** (.zip, .7z) containing executables disguised as documents
- **ISO files** — Windows mounts these as virtual drives, bypassing Mark of the Web (MOTW) security warnings
- **LNK files** — Windows shortcut files that execute arbitrary commands

APT28 (Fancy Bear) is particularly associated with spearphishing targeting government and defence organisations. The 2016 DNC breach began with a spearphishing email.

---

## Detection Rule 1: Malicious Attachment Detected by Defender for Office 365

```kql
EmailAttachmentInfo
| where Timestamp > ago(24h)
| where ThreatTypes has_any ("Malware", "Phish", "Spam")
| join kind=leftouter (
    EmailEvents
    | where Timestamp > ago(24h)
    | project NetworkMessageId, RecipientEmailAddress, Subject, SenderFromAddress, SenderIPv4
) on NetworkMessageId
| project 
    Timestamp,
    RecipientEmailAddress,
    SenderFromAddress,
    SenderIPv4,
    Subject,
    FileName,
    FileType,
    ThreatTypes,
    DetectionMethods
| order by Timestamp desc
```

**What this detects:** Emails with attachments flagged as malware or phishing by Microsoft Defender for Office 365 Safe Attachments — prioritised for analyst triage because the email gateway has already flagged it as suspicious.

---

## Detection Rule 2: Suspicious File Type Received via Email then Executed

The most dangerous pattern: user receives email with attachment, downloads it, and executes it within a short window.

```kql
let suspicious_extensions = dynamic([".iso", ".img", ".lnk", ".vbs", ".js", ".hta", ".bat", ".cmd", ".ps1"]);
let email_attachments = EmailAttachmentInfo
    | where Timestamp > ago(24h)
    | where FileName has_any (suspicious_extensions)
    | project NetworkMessageId, FileName, SHA256, RecipientEmailAddress, Timestamp;
let process_events = DeviceProcessEvents
    | where Timestamp > ago(24h)
    | where InitiatingProcessFileName in~ ("outlook.exe", "OUTLOOK.EXE", "winmail.exe")
        or FolderPath has_any ("Downloads", "Temp", "AppData")
    | project DeviceName, AccountName, FileName, FolderPath, ProcessCommandLine, Timestamp, SHA256;
email_attachments
| join kind=inner (process_events) on SHA256
| project 
    email_attachments.Timestamp,
    RecipientEmailAddress,
    FileName,
    SHA256,
    DeviceName,
    AccountName,
    FolderPath,
    ProcessCommandLine
| order by email_attachments.Timestamp desc
```

**What this detects:** A file received as an email attachment that is subsequently executed — correlating email telemetry with endpoint process creation to catch the full kill chain.

---

## Detection Rule 3: Office Application Spawning Unusual Child Processes

When a user opens a malicious macro-enabled document, the macro code executes as a child process of Word or Excel. Legitimate documents do not spawn command interpreters.

```kql
DeviceProcessEvents
| where Timestamp > ago(24h)
| where InitiatingProcessFileName in~ (
    "winword.exe", "excel.exe", "powerpnt.exe", 
    "outlook.exe", "onenote.exe", "mspub.exe"
)
| where FileName in~ (
    "powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe",
    "mshta.exe", "rundll32.exe", "regsvr32.exe", "certutil.exe",
    "msiexec.exe", "wmic.exe", "curl.exe", "wget.exe"
)
| project 
    Timestamp,
    DeviceName,
    AccountName,
    InitiatingProcessFileName,
    FileName,
    ProcessCommandLine,
    FolderPath
| order by Timestamp desc
```

**What this detects:** Office applications spawning command-line tools — the signature behaviour of macro-based malware executing its next stage payload.

---

## Detection Rule 4: Suspicious Email Sender Patterns (Lookalike Domain)

Spearphishing often uses lookalike domains — `micros0ft.com` instead of `microsoft.com`, or `payroll-hr-dept.com` instead of an internal domain.

```kql
let internal_domains = dynamic(["yourdomain.com", "yourdomain.ie"]);  // Replace with actual domains
EmailEvents
| where Timestamp > ago(7d)
| where DeliveryAction == "Delivered"
| where not(SenderFromDomain has_any (internal_domains))
| extend domain_parts = split(SenderFromDomain, ".")
| extend tld = tostring(domain_parts[array_length(domain_parts)-1])
| extend sld = tostring(domain_parts[array_length(domain_parts)-2])
| where RecipientEmailAddress has_any (internal_domains)
// Flag emails from recently-registered domains (< 30 days) if enrichment data available
// or emails that have high similarity to internal domain names
| where SenderFromDomain matches regex @"(?i)(payroll|hr|finance|accounts|invoice|payment|it-support|helpdesk)"
| project 
    Timestamp,
    SenderFromAddress,
    SenderFromDomain,
    RecipientEmailAddress,
    Subject,
    DeliveryAction,
    ThreatTypes
| order by Timestamp desc
```

**What this detects:** Inbound emails from external senders using keywords commonly associated with spearphishing lures (payroll, HR, finance, IT helpdesk) — a pattern used to impersonate internal departments.

---

## True Positive Example

```
Time: 2024-03-15 08:14:22 UTC
Recipient: c.ohara@company.com
Sender: payroll-notifications@payro11.company-hr.net (note: typosquat)
Subject: ACTION REQUIRED: Update your direct deposit information
Attachment: DirectDepositForm_March2024.xlsm (macro-enabled Excel)

Subsequent endpoint event (08:17:33):
Host: SALES-PC-12
Process: powershell.exe
Parent: EXCEL.EXE
Command: powershell -enc JABjAGwAaQBlAG4AdAAgAD0A... (encoded download cradle)
```

Interpretation: Full phishing kill chain captured — lookalike sender domain, urgency lure, macro-enabled attachment, PowerShell download cradle executed 3 minutes after email arrival. Isolate host. Reset user credentials. Investigate other recipients of same email.

---

## False Positive Examples

| Scenario | Why It Fires | How to Distinguish |
|---|---|---|
| Third-party payroll provider (ADP, Workday) sending payroll notifications | Sender contains "payroll" | Add confirmed legitimate vendor domains to allowlist; verify DKIM/SPF pass |
| IT department sending macro-enabled Excel reports via email | Office spawns child process | Known sender, signed macro certificate, predictable schedule — suppress by sender hash |
| Security awareness training phishing simulation | Simulated phishing email | Training vendor domains should be added to a suppression list during campaign periods |

---

## Tuning Recommendations

1. **Integrate with your email gateway's vendor allowlist** — Mimecast, Proofpoint, and Defender for O365 all maintain reputation databases. Trust their verdicts for large-volume senders.
2. **Suppress training simulations** — security awareness platforms like KnowBe4 should have their sending infrastructure added to a permanent suppression list to avoid alert fatigue during phishing simulation campaigns.
3. **Add DKIM/SPF/DMARC validation status** to all email rules — legitimate senders from established domains will pass all three checks.
4. **Correlate attachment hash with VirusTotal** — if available via enrichment, a hash with 0 detections needs more manual review than one with 40/70 AV hits.

---

## References

- [MITRE ATT&CK T1566.001](https://attack.mitre.org/techniques/T1566/001/)
- [Microsoft: Email Security in Defender for O365](https://learn.microsoft.com/en-us/microsoft-365/security/office-365-security/)
- [APT28 Spearphishing TTPs — Mandiant](https://www.mandiant.com/resources/insights/apt-groups)
- [CISA: Phishing Guidance](https://www.cisa.gov/phishing)
