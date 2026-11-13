# Identity & Access Audit Toolkit

PowerShell audits that answer three questions every security review asks about an identity environment:

1. **Which enabled accounts have gone stale?** — accounts nobody has signed into for 90+ days, or ever, that still hold licenses and valid credentials.
2. **Who doesn't actually have MFA?** — registration coverage graded by risk, so an admin without MFA surfaces before a standard user.
3. **Who holds privileged access they may no longer need?** — privileged group / role membership, flagging service and shared accounts, dormant members, and groups that have grown past review size.

Built from hands-on identity governance work: auditing Active Directory / Entra ID environments for stale and over-privileged accounts, and automating recurring MFA and password audit checks that were previously run by hand. This repository is an original, clean-room implementation written for public sharing — it contains no employer data, systems, or internal details, and the demo tenant (`contoso-demo.com`) is fictional.

## Quick start — no tenant required

Every script runs against bundled sample data, so you can see exactly what the audits produce before pointing them at anything real:

```powershell
git clone https://github.com/tearbu/identity-access-audit-toolkit.git
cd identity-access-audit-toolkit
.\src\Invoke-IdentityAccessAudit.ps1 -UseSampleData
```

This writes per-audit CSVs and a combined `audit-summary.md` into `output\`. On the sample data you should see, among other findings:

- A service account that has **never signed in** but sits in **Global Administrators** with **no MFA registered**
- A **shared helpdesk account** holding Global Administrator
- A **vendor account** and a **former intern** still holding privileged roles long after their last sign-in
- MFA coverage of about **61%**, with the gaps graded Critical / High / Medium

## The audits

| Script | What it checks | Output |
| --- | --- | --- |
| `src/Get-StaleAccountAudit.ps1` | Enabled accounts vs. last sign-in date; classifies Active / Stale / NeverSignedIn | Findings to pipeline; optional CSV of all accounts |
| `src/Get-MfaCoverageAudit.ps1` | MFA registration per account; Critical = admin without MFA, High = service/shared without MFA | Findings to pipeline; optional CSV |
| `src/Get-PrivilegedGroupAudit.ps1` | Privileged group / role membership; service & shared accounts, dormant or disabled members, oversized groups | Findings to pipeline; optional CSV of full membership |
| `src/Invoke-IdentityAccessAudit.ps1` | Runs all three and builds the combined Markdown summary | `output\audit-summary.md` + CSVs |

Each script has full comment-based help — run `Get-Help .\src\Get-StaleAccountAudit.ps1 -Detailed`.

## Running it live

Live mode uses the [Microsoft Graph PowerShell SDK](https://learn.microsoft.com/powershell/microsoftgraph/):

```powershell
Install-Module Microsoft.Graph -Scope CurrentUser
.\src\Invoke-IdentityAccessAudit.ps1
```

Requirements and honest notes:

- Sign-in activity (`SignInActivity`) requires an **Entra ID P1/P2 license** and the `AuditLog.Read.All` permission.
- MFA registration data requires `UserAuthenticationMethod.Read.All`; directory roles require `RoleManagement.Read.Directory`.
- The audits are **read-only**. They report and recommend; they never disable an account or remove a membership. Remediation stays a human decision — verify each finding with the account owner first.

## Why this exists

Recurring identity checks — stale accounts, MFA gaps, privilege drift — are exactly the kind of work that gets skipped when it is manual, and exactly the kind an auditor asks about first. Automating the collection and grading turns a day of screenshots into a report a reviewer can act on: every finding has a severity, an owner-ready explanation, and a recommended action.

## Roadmap

- [ ] Risk scoring that combines the three audits (a stale, privileged, MFA-less account should outrank everything else)
- [ ] Scheduled run support with diffing against the previous report
- [ ] Export to HTML for sharing with non-technical reviewers
- [ ] Guest / external account audit (B2B accounts are a common blind spot)

## Disclaimer

Demo data is fictional. Review any audit output in your own environment before acting on it; account names that look stale can belong to break-glass or integration accounts with legitimate reasons to exist — which is why the scripts flag and recommend, and never modify.

## License

MIT — see `LICENSE`.
