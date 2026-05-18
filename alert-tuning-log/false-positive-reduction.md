# Alert Tuning Log — False Positive Reduction

**Environment:** Simulated enterprise SOC (Windows Active Directory domain, O365, Splunk Enterprise)  
**Period:** Ongoing  
**Purpose:** Document the iterative process of refining detection rules to reduce false positive volume without sacrificing true positive coverage.

---

## Why Alert Tuning Matters

A detection rule that fires 500 times a day for legitimate activity is worse than no rule at all. Analysts experiencing alert fatigue stop investigating alerts carefully. Alert fatigue is directly responsible for real intrusions being missed — including the Target breach (2013), where the initial detection fired correctly but was dismissed amid thousands of other alerts.

Tuning is not weakening a rule. It is making a rule *actionable*.

The goal is a signal-to-noise ratio where every alert an analyst receives has a high enough probability of being true that the analyst cannot afford to ignore it.

---

## Tuning Entry 001 — T1059.001 Encoded PowerShell

**Date:** 2024-03-01  
**Rule:** Encoded PowerShell Command Detection  
**Initial False Positive Rate:** ~40 alerts/day, estimated 85% false positive

**Root Cause of False Positives:**
- Corporate software deployment tool (Ansible) uses `-EncodedCommand` for cross-platform compatibility
- Microsoft 365 management scripts run by IT team on a schedule
- SCCM client management uses encoded PS for inventory collection

**Investigation Method:**
1. Pulled all firing alerts for 7-day baseline period
2. Identified recurring source hosts and users
3. Cross-referenced with IT team's list of authorised automation scripts
4. Verified binary signatures on all flagged parent processes

**Tuning Applied:**
```spl
| where NOT (
    user IN ("svc-ansible", "svc-sccm", "svc-m365mgmt")
    AND src_ip IN ("10.10.1.50", "10.10.1.51")  // Known automation servers
)
| where NOT (
    match(ScriptBlockText, "(?i)(ansible|sccm|ConfigurationManager)")
)
```

**Result After Tuning:**
- Alert volume: 40/day → 3/day
- False positive rate: 85% → ~15%
- True positive coverage: No reduction (verified by re-running test attack)

**Validation Method:**
Ran a test encoded PowerShell download cradle from a non-excluded host. Alert fired within 60 seconds. Rule confirmed effective for adversarial use cases while suppressing operational noise.

---

## Tuning Entry 002 — T1078 Brute Force Followed by Success

**Date:** 2024-03-08  
**Rule:** Brute Force + Successful Login  
**Initial False Positive Rate:** ~15 alerts/day, estimated 70% false positive

**Root Cause of False Positives:**
- Automated backup agents with stale credentials generating repeated failures before a scheduled credential rotation succeeded
- Users who mistype their password multiple times then succeed (normal human behaviour)
- One application server using a misconfigured service account that retried authentication in a loop

**Investigation Method:**
1. Grouped all alerts by source IP and user
2. Found 3 source IPs responsible for 80% of volume — all internal server IPs
3. Interviewed IT team — confirmed these were known issues being remediated
4. Reviewed remaining alerts — found 2 genuine suspicious cases from external IPs

**Tuning Applied:**
```spl
| where NOT src_ip IN ("10.10.5.12", "10.10.5.20", "10.10.5.33")  // Known internal agents
| where failures >= 8  // Raised from 5 — human mistyping rarely exceeds 7 attempts
| where NOT (user="svc-backup*" AND src_ip IN ("10.10.1.0/24"))
```

**Result After Tuning:**
- Alert volume: 15/day → 2/day
- False positive rate: 70% → ~20%
- True positive coverage: Maintained — human brute force typically exceeds 8 attempts; credential stuffing attacks make hundreds of attempts

**Residual Risk:**
A sophisticated attacker who knows the threshold could attempt exactly 7 logins, pause, and try again. Mitigated by account lockout policy (account locks at 5 failed attempts in this environment — the attacker would be locked out before reaching the threshold anyway).

---

## Tuning Entry 003 — T1547.001 Run Key Modification

**Date:** 2024-03-14  
**Rule:** New Entry in Registry Run Key  
**Initial False Positive Rate:** ~25 alerts/day, estimated 92% false positive

**Root Cause of False Positives:**
- OneDrive, Teams, Zoom, Slack all write Run keys during updates
- Chrome auto-update writes to HKCU Run
- Corporate endpoint agent (CrowdStrike Falcon) modifies Run keys during version updates

**Investigation Method:**
1. Captured all Run key values from a clean, fully-patched workstation immediately post-image
2. Created a lookup table (`run_key_baseline.csv`) containing all expected values
3. Modified rule to only alert on values NOT in the baseline

**Tuning Applied:**
```spl
| lookup run_key_baseline.csv TargetObject OUTPUT expected_value
| where isnull(expected_value) OR Details!=expected_value
| where NOT (
    match(Image, "(?i)(OneDriveSetup|Teams|Zoom|Slack|chrome|CrowdStrike)")
    AND match(Details, "(?i)(OneDrive|Teams|Zoom|Slack|chrome|CrowdStrike)")
)
```

**Result After Tuning:**
- Alert volume: 25/day → 1-2/day (most days 0)
- False positive rate: 92% → <10%
- True positive coverage: Maintained — test malware sample writing a novel Run key was detected within 30 seconds

**Maintenance Note:**
Baseline lookup table requires updating after each major software deployment. Added to IT change management checklist — any GPO software deployment must update `run_key_baseline.csv` before deployment week.

---

## Key Lessons Learned

1. **Alert volume is a symptom, not the problem.** High alert volume indicates the rule is detecting real activity — the question is whether that activity is malicious or legitimate. Investigate before suppressing.

2. **Allowlists decay.** An IP address that is safe today might be compromised tomorrow. Prefer allowlisting by verified binary hash and code signature over source IP.

3. **Threshold tuning has limits.** Raising a threshold from 5 to 8 reduces noise but also potentially reduces true positive coverage. Every threshold change requires validation against a test attack.

4. **Document everything.** When a rule has been suppressed for a source IP, the reason must be documented. Without documentation, a future analyst will see a suspicious IP in an alert and not know whether it was previously reviewed — and the suppression may have outlived its validity.

5. **Re-validate after tuning.** Every time a rule is modified, re-run the test attack that the rule is designed to catch. Tuning can inadvertently break detection coverage.

---

## Alert Tuning Metrics Summary

| Rule | Before Tuning (alerts/day) | After Tuning (alerts/day) | FP Rate Before | FP Rate After |
|---|---|---|---|---|
| T1059 Encoded PS | 40 | 3 | 85% | 15% |
| T1078 Brute Force | 15 | 2 | 70% | 20% |
| T1547 Run Keys | 25 | 1 | 92% | <10% |
| **Total** | **80** | **6** | **82%** | **16%** |

Net result: 92.5% reduction in alert volume with validated true positive coverage maintained across all three rules.
