# 🔐 CA Security Weekly Digest
### Microsoft Entra ID | PowerShell | Microsoft Graph API

![PowerShell](https://img.shields.io/badge/PowerShell-7.5-blue?logo=powershell)
![Microsoft Graph](https://img.shields.io/badge/Microsoft%20Graph-API-green?logo=microsoft)
![Platform](https://img.shields.io/badge/Platform-Entra%20ID-0078D4?logo=microsoftazure)
![License](https://img.shields.io/badge/License-MIT-yellow)

> Combines five Conditional Access security checks into a single weekly
> digest — total policies, disabled policies, policies without MFA,
> users with no CA coverage, and report-only policies. Prints a clean
> formatted dashboard with an overall risk score combining all findings.

---

### Why CA Policy Health Matters Weekly

Conditional Access is your primary enforcement layer for identity
security. A misconfigured or disabled CA policy creates an immediate
gap that attackers can exploit:
Disabled policy → protection silently removed — nobody noticed
No MFA requirement → users can sign in with password only
Users without coverage → accounts outside CA enforcement entirely
Report-only policies → logging but not blocking — false sense of security

One disabled policy or one group of uncovered users is enough to
create a breach entry point that bypasses your entire CA strategy.

### What This Script Delivers
- Five CA health checks combined into one weekly run
- Clean formatted digest for security team review
- Dynamic color coding — green when clean, red when flagged
- Overall risk score combining all findings
- Recurring capability — schedule every Friday morning

---

## 📄 Executive Summary

**Problem:** CA policies change over time. Admins disable policies
during troubleshooting and forget to re-enable them. New users get
created outside policy scope. Report-only policies never get promoted
to enforcement. Nobody has weekly visibility into CA health without
manually reviewing each policy in the portal.

**Solution:** This script runs five checks in a single execution and
produces a one-page digest — ready to share with the security team
every Friday morning.

**Result:** Complete CA security health picture in under 10 minutes.

**Time to value:** Under 10 minutes from first run to digest ready.

---

## 🔍 Real Findings From Lab Tenant

| Metric | Result |
|---|---|
| Total CA policies | 8 |
| Disabled policies | 1 🟡 |
| No MFA requirement | 2 🔴 |
| Users with no coverage | 10 🔴 |
| Report-only policies | 1 🟡 |
| Overall risk | HIGH |

---

## 🔍 Overall Risk Calculation

| Findings Flagged | Risk Level |
|---|---|
| 3 or more | HIGH |
| 1 or 2 | MEDIUM |
| 0 | LOW |

A finding is flagged when:
disabledCount -gt 0 → at least one policy is disabled
noMFACount -gt 0 → at least one enabled policy has no MFA
noCoverageCount -gt 0 → at least one user has no CA coverage
reportOnlyCount -gt 0 → at least one policy is in report-only mode

---

## ✅ Step by Step Breakdown

**Step 1 — Connected to Microsoft Graph**
```powershell
Connect-MgGraph -Scopes "Policy.Read.All","User.Read.All","Group.Read.All" -NoWelcome
```
- Three scopes required for all five checks
- `Policy.Read.All` — read CA policies and their conditions
- `User.Read.All` — read all user accounts for coverage check
- `Group.Read.All` — check group membership for coverage check

---

**Step 2 — Initialized counters**
```powershell
$totalPolicies   = 0
$disabledCount   = 0
$noMFACount      = 0
$noCoverageCount = 0
$reportOnlyCount = 0
```
- Five counters — one per check
- No results list needed — counters only
- Incremented with `++` as findings are discovered

---

**Step 3 — Pulled all data before loops**
```powershell
$policies        = Get-MgIdentityConditionalAccessPolicy
$users           = Get-MgUser -All -Property "Id,DisplayName,UserPrincipalName,Department,AccountEnabled"
$enabledUsers    = $users | Where-Object AccountEnabled -eq $true
$enabledPolicies = $policies | Where-Object State -eq "enabled"
```
- All data pulled ONCE before any loop
- `$enabledPolicies` used for coverage check — disabled policies don't protect users
- `$enabledUsers` used for coverage check — disabled accounts can't sign in

---

**Step 4 — Checked policy state and MFA per policy**
```powershell
foreach ($policy in $policies) {
    if ($policy.State -eq "disabled")                          { $disabledCount++ }
    if ($policy.State -eq "enabledForReportingButNotEnforced") { $reportOnlyCount++ }
    if ($policy.State -eq "enabled" -and
        -not ($policy.GrantControls.BuiltInControls -contains "mfa")) { $noMFACount++ }
}
```
- Three checks run for every policy in one loop
- `State -eq "disabled"` — policy exists but protecting nobody
- `enabledForReportingButNotEnforced` — report-only mode — logs but never blocks
- Enabled + no MFA — policy is active but lets users sign in without MFA

---

**Step 5 — Checked user CA coverage**
```powershell
foreach ($user in $enabledUsers) {
    $covered = $false
    foreach ($policy in $enabledPolicies) {
        $includeUsers  = $policy.Conditions.Users.IncludeUsers
        $includeGroups = $policy.Conditions.Users.IncludeGroups
        $excludeUsers  = $policy.Conditions.Users.ExcludeUsers

        if ($includeUsers -contains "All") {
            if ($excludeUsers -notcontains $user.Id) {
                $covered = $true
                break
            }
        }
        elseif ($includeUsers -contains $user.Id) { $covered = $true; break }
        elseif ($includeGroups.Count -gt 0) {
            foreach ($groupId in $includeGroups) {
                try {
                    $groupMembers = Get-MgGroupMember -GroupId $groupId -ErrorAction SilentlyContinue
                    if ($groupMembers.Id -contains $user.Id) { $covered = $true; break }
                } catch { continue }
            }
        }
        if ($covered) { break }
    }
    if (-not $covered) { $noCoverageCount++ }
}
```
- Three ways a policy can cover a user — All users, specific user, group membership
- Reset `$covered = $false` per user — fresh check for each person
- `break` exits inner loop as soon as coverage is confirmed — no point checking more policies
- `try/catch` handles deleted groups still referenced in policies
- Users not covered by any enabled policy → increment counter

---

**Step 6 — Calculated overall risk**
```powershell
$highFindings = 0
if ($disabledCount -gt 0)   { $highFindings++ }
if ($noMFACount -gt 0)      { $highFindings++ }
if ($noCoverageCount -gt 0) { $highFindings++ }
if ($reportOnlyCount -gt 0) { $highFindings++ }

$overallRisk = if ($highFindings -ge 3)    { "HIGH" }
               elseif ($highFindings -ge 1) { "MEDIUM" }
               else                         { "LOW" }
```
- Each finding category counts as one point
- Three or more categories flagged — HIGH risk
- Calculated ONCE after all loops finish — not inside any loop

---

**Step 7 — Printed digest with dynamic colors**
```powershell
Write-Host "  Disabled policies : $disabledCount $(if ($disabledCount -gt 0) { '🟡' } else { '✅' })" -ForegroundColor $(if ($disabledCount -gt 0) { "Yellow" } else { "Green" })
```
- Each line changes color based on whether the finding exists
- Green with checkmark when clean
- Yellow or red with emoji when flagged
- Overall risk printed in matching color at the bottom

---

## 📋 Compliance Relevance

| Framework | Control |
|---|---|
| NIST 800-53 | AC-2 — Account Management |
| SOC 2 Type II | CC6.1 — Logical Access Controls |
| ISO 27001 | A.9.4.2 — Secure Log-on Procedures |
| CIS Controls | Control 6 — Access Control Management |
| Microsoft Secure Score | Enable Conditional Access policies |

---

## 🎯 Use Cases

**Weekly Security Review**
Run every Friday to give the security team a one-page
view of CA policy health before the weekend.

**Post-Change Verification**
Run after any CA policy change to confirm no unintended
gaps were introduced.

**M&A Tenant Discovery**
Run on day one of an acquisition to immediately understand
the CA posture of the acquired tenant.

**Audit Preparation**
Run before an audit to identify and remediate CA gaps
before auditors find them.
