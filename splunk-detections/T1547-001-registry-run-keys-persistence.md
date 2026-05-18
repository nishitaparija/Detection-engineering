# T1547.001 — Boot or Logon Autostart Execution: Registry Run Keys / Startup Folder

**MITRE ATT&CK:** [T1547.001](https://attack.mitre.org/techniques/T1547/001/)  
**Tactic:** Persistence, Privilege Escalation  
**Platform:** Windows  
**Detection Platform:** Splunk (SPL)  
**Severity:** High  
**Data Sources Required:** Windows Security Event Log, Sysmon (Event IDs 12, 13, 14 — Registry events), Windows Registry Audit

---

## Why This Technique Is Dangerous

Persistence is what separates a one-time intrusion from an ongoing compromise. Malware that cannot survive a reboot is relatively easy to remediate — switch the machine off and on. Malware that persists is a fundamentally different problem.

Windows Registry Run Keys are the most commonly abused persistence mechanism because:
- They are built into Windows and legitimate software uses them constantly (making detection noisy)
- They require no elevated privileges for HKCU (current user) keys
- They execute automatically at logon — no user interaction required after initial infection
- Many antivirus products scan for known-bad executables, not registry entries pointing to renamed copies

Registry keys of interest:
```
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\Run
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows\CurrentVersion\RunOnce
HKEY_LOCAL_MACHINE\Software\Microsoft\Windows NT\CurrentVersion\Winlogon
```

This technique is heavily used by: Lazarus Group, Emotet, TrickBot, QakBot, and virtually all ransomware operators.

---

## Detection Rule 1: New Entry in Run Key (Sysmon)

Sysmon must be deployed and configured to log registry events (Event ID 13 = Registry value set).

```spl
index=sysmon EventCode=13
    TargetObject IN (
        "*\\CurrentVersion\\Run\\*",
        "*\\CurrentVersion\\RunOnce\\*",
        "*\\CurrentVersion\\RunOnceEx\\*",
        "*\\Winlogon\\*"
    )
| where NOT (
    Details IN (
        "*MicrosoftEdgeUpdate*",
        "*OneDrive*",
        "*SecurityHealth*",
        "*Teams*",
        "*Zoom*"
    )
)
| eval suspicious_path=if(match(Details,"(?i)(temp|appdata|programdata|public|downloads)"),1,0)
| table _time, host, user, TargetObject, Details, suspicious_path
| sort -_time
```

**What this detects:** Any new value written to a Windows Run key, filtered to exclude common legitimate applications. Values pointing to temp directories or AppData are flagged as higher suspicion.

---

## Detection Rule 2: Executable Written to Startup Folder

The Windows Startup folder is an alternative persistence mechanism — files placed here execute at logon.

```spl
index=sysmon EventCode=11
    TargetFilename IN (
        "*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*",
        "*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*"
    )
    (TargetFilename="*.exe" OR TargetFilename="*.bat" OR TargetFilename="*.vbs" OR TargetFilename="*.ps1" OR TargetFilename="*.lnk")
| table _time, host, user, TargetFilename, Image, ProcessId
| sort -_time
```

**What this detects:** Executable files (or script files that act as executables) being written to a startup folder — a direct persistence artefact.

---

## Detection Rule 3: Run Key Value Pointing to Suspicious Location

Even if we catch every write event, an attacker who disabled logging before writing would evade rules 1 and 2. This rule checks the *current state* of run keys on a schedule rather than relying on event-based detection.

```spl
index=sysmon EventCode=13
    TargetObject="*\\CurrentVersion\\Run*"
| rex field=Details "(?i)(?P<exec_path>[A-Z]:\\[^\s]+\.(exe|dll|bat|vbs|ps1))"
| eval is_suspicious=case(
    match(exec_path,"(?i)(\\temp\\|\\appdata\\|\\programdata\\|\\public\\|\\downloads\\)"),"High - Executable in user-writable path",
    match(exec_path,"(?i)(\\windows\\system32\\|\\program files\\)"),"Low - System path",
    isnull(exec_path),"Medium - No clear executable path extracted",
    1=1,"Medium - Review manually"
)
| where is_suspicious!="Low - System path"
| table _time, host, user, TargetObject, exec_path, is_suspicious
| sort -_time
```

**What this detects:** Run key entries where the executable lives in user-writable directories — a strong indicator of malware, since legitimate software installs to Program Files.

---

## True Positive Example

```
Time: 2024-03-15 14:22:11
Host: ACCT-PC-07
User: jdoe
Registry Key: HKCU\Software\Microsoft\Windows\CurrentVersion\Run\WindowsDefender
Value: C:\Users\jdoe\AppData\Roaming\svhost.exe
```

Interpretation: Registry key named "WindowsDefender" (impersonating a legitimate process) pointing to `svhost.exe` (misspelling of `svchost.exe`) in AppData. Classic malware persistence — impersonating trusted names in user-writable locations. Isolate host, collect `svhost.exe` for malware analysis.

---

## False Positive Examples

| Scenario | Why It Fires | How to Distinguish |
|---|---|---|
| OneDrive auto-update writes Run key | Modifies HKCU Run | Signed Microsoft binary — verify signature and path (`C:\Program Files\Microsoft OneDrive\`) |
| Corporate software deployment writes Run key via GPO | Writes to HKLM Run | Source process will be `msiexec.exe` or a known deployment tool; correlate with change management records |
| User installs legitimate software manually | New Run key entry | Verify binary signature, check install time correlates with user-reported activity |

---

## Tuning Recommendations

1. **Build and maintain a baseline** of all Run key entries on clean, imaged workstations. Alert only on *new* entries that differ from baseline.
2. **Verify binary signatures** — Microsoft-signed and vendor-signed binaries from expected paths are low risk. Unsigned binaries are high risk.
3. **Correlate with process creation events** — if the Run key was written by a known-good installer (`msiexec.exe`, a corporate deployment tool), lower the priority.
4. **Hash-based allowlisting** is more reliable than path-based allowlisting — attackers can copy malware to `C:\Program Files\`.

---

## References

- [MITRE ATT&CK T1547.001](https://attack.mitre.org/techniques/T1547/001/)
- [Microsoft: Autorun Keys](https://learn.microsoft.com/en-us/sysinternals/downloads/autoruns)
- [Sysmon Configuration Guide — SwiftOnSecurity](https://github.com/SwiftOnSecurity/sysmon-config)
- [Lazarus Group Persistence Techniques — Kaspersky](https://securelist.com/lazarus-on-the-hunt-for-big-game/97757/)
