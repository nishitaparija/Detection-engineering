# T1078 — Valid Accounts (Microsoft Sentinel / KQL)

**MITRE ATT&CK:** [T1078](https://attack.mitre.org/techniques/T1078/)  
**Tactic:** Initial Access, Persistence, Privilege Escalation, Defence Evasion  
**Platform:** Azure AD / Entra ID, Microsoft 365  
**Detection Platform:** Microsoft Sentinel (KQL)  
**Severity:** High  
**Data Sources Required:** Azure AD Sign-in Logs (SigninLogs), Azure AD Audit Logs (AuditLogs), Microsoft 365 Unified Audit Log

---

## Why This Technique Is Dangerous (Cloud Context)

In cloud environments, valid account abuse is even more impactful than on-premises because:
- Cloud admin accounts have access to all data, all compute, and billing — a compromised tenant admin can be catastrophic
- Cloud APIs are accessible from anywhere in the world — no need to be on the corporate network
- Identity is the primary security perimeter in cloud environments — if identity is compromised, traditional network controls are irrelevant
- Many organisations grant excessive permissions via Azure RBAC or IAM — the blast radius of a compromised account is amplified

The 2023 Microsoft Exchange Online breach (attributed to Storm-0558) is the canonical example — forged authentication tokens allowed access to senior US government officials' email accounts. Detection required analysis of OAuth token issuance patterns.

---

## Detection Rule 1: Azure AD Sign-in from Atypical Location

```kql
SigninLogs
| where TimeGenerated > ago(24h)
| where ResultType == 0  // Successful sign-in
| where RiskState == "atRisk" or RiskLevelAggregated in ("high", "medium")
| project
    TimeGenerated,
    UserPrincipalName,
    IPAddress,
    Location,
    AppDisplayName,
    DeviceDetail,
    RiskState,
    RiskLevelAggregated,
    RiskDetail,
    ConditionalAccessStatus
| order by TimeGenerated desc
```

**What this detects:** Successful Azure AD authentications flagged as risky by Microsoft's Identity Protection service — these are logins that Microsoft's ML models have assessed as anomalous based on location, device, and behavioural patterns.

---

## Detection Rule 2: Impossible Travel in Azure AD

```kql
let timeframe = 2h;
SigninLogs
| where TimeGenerated > ago(1d)
| where ResultType == 0
| project TimeGenerated, UserPrincipalName, IPAddress, Location, CountryOrRegion
| sort by UserPrincipalName asc, TimeGenerated asc
| extend prev_time = prev(TimeGenerated, 1),
         prev_country = prev(CountryOrRegion, 1),
         prev_user = prev(UserPrincipalName, 1)
| where prev_user == UserPrincipalName
| where CountryOrRegion != prev_country
| extend time_diff_minutes = datetime_diff('minute', TimeGenerated, prev_time)
| where time_diff_minutes < 120 and time_diff_minutes > 0
| project
    TimeGenerated,
    UserPrincipalName,
    prev_country,
    CountryOrRegion,
    IPAddress,
    time_diff_minutes
| order by TimeGenerated desc
```

**What this detects:** The same user account authenticating from two different countries within a 2-hour window — impossible physical travel, indicating credential compromise.

---

## Detection Rule 3: Privileged Role Assignment Outside Change Window

Assigning Global Administrator or other privileged roles in Azure AD is a high-risk activity. In a well-run organisation it happens rarely and during scheduled change windows.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName == "Add member to role"
| where TargetResources[0].modifiedProperties[0].newValue has_any (
    "Global Administrator",
    "Privileged Role Administrator", 
    "Security Administrator",
    "Exchange Administrator",
    "SharePoint Administrator",
    "User Administrator"
)
| extend 
    InitiatedByUser = tostring(InitiatedBy.user.userPrincipalName),
    TargetUser = tostring(TargetResources[0].userPrincipalName),
    RoleAssigned = tostring(TargetResources[0].modifiedProperties[0].newValue)
| project
    TimeGenerated,
    InitiatedByUser,
    TargetUser,
    RoleAssigned,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

**What this detects:** Any assignment of high-privilege Azure AD roles — an attacker who has compromised any account with role assignment permissions will use it to grant themselves Global Admin for persistence.

---

## Detection Rule 4: MFA Disabled for User Account

Disabling MFA removes a critical security control. Attackers (and social engineering attacks on help desks) do this to ensure they can re-authenticate after the initial session expires.

```kql
AuditLogs
| where TimeGenerated > ago(7d)
| where OperationName in (
    "Disable Strong Authentication",
    "Admin registered security info",
    "User deleted security info",
    "Admin deleted security info"
)
| extend
    InitiatedBy = tostring(InitiatedBy.user.userPrincipalName),
    TargetUser = tostring(TargetResources[0].userPrincipalName)
| where InitiatedBy != TargetUser  // Admin-initiated MFA changes are higher risk
| project
    TimeGenerated,
    OperationName,
    InitiatedBy,
    TargetUser,
    Result,
    CorrelationId
| order by TimeGenerated desc
```

**What this detects:** MFA being disabled or security info being removed — particularly when the change is made by someone other than the account owner (indicating admin account abuse or help desk social engineering).

---

## True Positive Example

```
Time: 2024-03-15 11:43:00 UTC
Operation: Add member to role
Initiated by: h.kelly@company.com (help desk account)
Target: attacker.newly.created@company.com
Role: Global Administrator

Context: h.kelly's account was compromised via phishing 2 hours earlier.
Attacker used the help desk account (which had User Administrator rights) 
to create a new account and elevate it to Global Admin.
```

Interpretation: Classic privilege escalation via compromised intermediate account. The attacker escalated from User Administrator to Global Administrator by creating a new backdoor account. Immediately revoke all sessions for h.kelly, disable the newly created account, audit all actions taken in the past 24 hours.

---

## References

- [MITRE ATT&CK T1078](https://attack.mitre.org/techniques/T1078/)
- [Microsoft: Detect and Respond to Identity Threats](https://learn.microsoft.com/en-us/azure/active-directory/identity-protection/)
- [Storm-0558 Breach Analysis — Microsoft](https://msrc.microsoft.com/blog/2023/07/microsoft-mitigates-china-based-threat-actor-storm-0558-targeting-of-customer-email/)
- [CISA: Cloud Security Best Practices](https://www.cisa.gov/resources-tools/resources/cloud-security)
