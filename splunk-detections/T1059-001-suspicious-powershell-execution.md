# T1059.001 — Command and Scripting Interpreter: PowerShell

**MITRE ATT&CK:** [T1059.001](https://attack.mitre.org/techniques/T1059/001/)  
**Tactic:** Execution  
**Platform:** Windows  
**Detection Platform:** Splunk (SPL)  
**Severity:** High  
**Data Sources Required:** Windows Security Event Log (Event ID 4104, 4688), PowerShell Operational Log

---

## Why This Technique Is Dangerous

PowerShell is a legitimate Windows administration tool — which is exactly why attackers love it. Because it is built into Windows, execution rarely triggers antivirus. Attackers use it to:

- Download additional malware from the internet (`IEX (New-Object Net.WebClient).DownloadString(...)`)
- Execute code entirely in memory without writing files to disk (fileless malware)
- Bypass execution policies using encoded commands (`-EncodedCommand`)
- Disable security tools
- Establish reverse shells for command-and-control

The technique appears in campaigns from Lazarus Group, APT28, and the majority of ransomware operators. Microsoft's own detection research estimates PowerShell is involved in over 50% of enterprise intrusions.

---

## Detection Rule: Encoded PowerShell Command

PowerShell allows commands to be Base64-encoded, ostensibly to handle special characters. Attackers exploit this to obfuscate malicious commands from basic string-matching.

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
    EventCode=4104
    ScriptBlockText IN ("*-EncodedCommand*", "*-enc *", "*-e *")
| eval decoded_command=urldecode(ScriptBlockText)
| table _time, host, user, ScriptBlockText, decoded_command
| sort -_time
```

**What this detects:** PowerShell processes launched with encoded command flags, which are rarely used in legitimate administration and frequently used to conceal malicious payloads.

---

## Detection Rule: PowerShell Downloading from the Internet

```spl
index=wineventlog source="WinEventLog:Microsoft-Windows-PowerShell/Operational"
    EventCode=4104
    ScriptBlockText IN (
        "*Net.WebClient*",
        "*DownloadString*",
        "*DownloadFile*",
        "*Invoke-WebRequest*",
        "*IWR *",
        "*WebClient*",
        "*wget *",
        "*curl *"
    )
| stats count by _time, host, user, ScriptBlockText
| where count >= 1
| sort -_time
```

**What this detects:** PowerShell scripts that initiate outbound HTTP/HTTPS connections to retrieve content — the classic malware dropper pattern.

---

## Detection Rule: PowerShell Spawned by Unusual Parent Process

Legitimate PowerShell is typically launched by users (explorer.exe) or scheduled tasks (taskeng.exe). When it is spawned by Office applications, browsers, or script interpreters, that indicates a macro or exploit has executed.

```spl
index=wineventlog source="WinEventLog:Security" EventCode=4688
    New_Process_Name="*powershell.exe"
    Creator_Process_Name IN (
        "*winword.exe",
        "*excel.exe",
        "*outlook.exe",
        "*mshta.exe",
        "*wscript.exe",
        "*cscript.exe",
        "*regsvr32.exe",
        "*rundll32.exe"
    )
| table _time, host, user, Creator_Process_Name, New_Process_Name, Process_Command_Line
| sort -_time
```

**What this detects:** Process-parent relationships that indicate a macro-enabled document, browser exploit, or living-off-the-land binary launching PowerShell — a pattern associated with spearphishing initial access (T1566) leading to execution.

---

## True Positive Example

```
Time: 2024-03-15 02:47:33
Host: FINANCE-WS-04
User: jsmith
Parent: WINWORD.EXE
Command: powershell.exe -EncodedCommand JAB...AAAA (200+ char Base64 string)
```

Interpretation: Word document opened outside business hours executed a macro that launched an encoded PowerShell command. High confidence malicious. Analyst should isolate host immediately, preserve memory, and begin incident response.

---

## False Positive Examples

| Scenario | Why It Fires | How to Distinguish |
|---|---|---|
| IT team runs encoded PS for software deployment | `-EncodedCommand` flag present | Known source IPs, during business hours, user is in IT admin group |
| SCCM/Intune management agent | Spawns powershell.exe for patching | Parent will be `ccmexec.exe` or similar known system process — add to exclusion |
| Developer running `Invoke-WebRequest` in testing | Downloads from internal repo | Destination URL is internal RFC1918 address or known CDN |

---

## Tuning Recommendations

1. **Build an allowlist of known-good encoded commands** used by your IT team. Hash the Base64 strings and exclude matching hashes.
2. **Exclude known management tools** (SCCM, Ansible, Intune) by parent process name and signed binary hash.
3. **Add destination URL context** to the download rule — internal RFC1918 destinations are lower risk than external unknown domains.
4. **Correlate with business hours** — the same activity at 2am is significantly higher severity than at 10am.
5. **Threshold tuning:** If a host regularly runs PS downloads as part of patching, suppress those specific hosts during maintenance windows rather than disabling the rule globally.

---

## References

- [MITRE ATT&CK T1059.001](https://attack.mitre.org/techniques/T1059/001/)
- [Microsoft: PowerShell Logging](https://docs.microsoft.com/en-us/powershell/scripting/windows-powershell/wmf/whats-new/script-tracing-and-logging)
- [NSA/CISA Advisory on PowerShell Security](https://media.defense.gov/2022/Jun/22/2003021689/-1/-1/1/CSI_KEEPING_POWERSHELL_SECURITY_MEASURES_TO_USE_AND_EMBRACE_20220622.PDF)
