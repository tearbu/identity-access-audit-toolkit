<#
.SYNOPSIS
    Reviews who holds privileged roles and flags membership that should not be there.

.DESCRIPTION
    Privileged group membership drifts: people change teams, vendors finish
    engagements, interns go home - and the access stays. This audit lists the
    membership of privileged groups / directory roles and flags:

      - Service or shared accounts in a privileged group (High)
      - Members whose accounts have not signed in for -StaleDays or ever (Medium)
      - Groups larger than -MaxMembersPerGroup, a sign membership is not being
        actively managed (Medium)

    Two modes:
      - Live mode reads Entra ID directory roles and their members through
        Microsoft Graph (RoleManagement.Read.Directory).
      - Sample mode (-UseSampleData) runs against the fictional CSV in ..\data.

.EXAMPLE
    .\Get-PrivilegedGroupAudit.ps1 -UseSampleData

.EXAMPLE
    .\Get-PrivilegedGroupAudit.ps1 -MaxMembersPerGroup 4 -OutputPath .\out\priv.csv

.NOTES
    Author : Araf Abubakar
    Part of the Identity & Access Audit Toolkit. Demo data is fictional.
#>
[CmdletBinding()]
param(
    [int]$StaleDays = 90,
    [int]$MaxMembersPerGroup = 5,
    [switch]$UseSampleData,
    [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\data\sample-privileged-groups.csv'),
    [string]$OutputPath
)

$members = @()

if ($UseSampleData) {
    Write-Verbose "Sample mode: reading $SampleDataPath"
    foreach ($row in (Import-Csv -Path $SampleDataPath)) {
        $members += [pscustomobject]@{
            GroupName         = $row.GroupName
            MemberDisplayName = $row.MemberDisplayName
            MemberUPN         = $row.MemberUPN
            MemberType        = $row.MemberType
            AccountEnabled    = ($row.AccountEnabled -eq 'True')
            LastSignInDateTime = if ($row.LastSignInDateTime) { [datetime]$row.LastSignInDateTime } else { $null }
        }
    }
}
else {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Identity.Governance)) {
        throw "Live mode needs the Microsoft Graph PowerShell SDK (Install-Module Microsoft.Graph). Or run with -UseSampleData."
    }
    Connect-MgGraph -Scopes 'RoleManagement.Read.Directory', 'User.Read.All', 'AuditLog.Read.All' | Out-Null
    foreach ($role in (Get-MgDirectoryRole -All)) {
        $roleUsers = Get-MgDirectoryRoleMemberAsUser -DirectoryRoleId $role.Id -All -ErrorAction SilentlyContinue
        foreach ($u in $roleUsers) {
            $members += [pscustomobject]@{
                GroupName          = $role.DisplayName
                MemberDisplayName  = $u.DisplayName
                MemberUPN          = $u.UserPrincipalName
                MemberType         = 'User'
                AccountEnabled     = [bool]$u.AccountEnabled
                LastSignInDateTime = $null  # Sign-in activity is covered by Get-StaleAccountAudit
            }
        }
    }
}

$now = Get-Date
$findings = @()

foreach ($group in ($members | Group-Object GroupName)) {
    if ($group.Count -gt $MaxMembersPerGroup) {
        $findings += [pscustomobject]@{
            GroupName = $group.Name; Member = "(group of $($group.Count))"
            Finding = "Group has $($group.Count) members, above the review threshold of $MaxMembersPerGroup"
            Severity = 'Medium'
            RecommendedAction = 'Review every member for current business need'
        }
    }
    foreach ($m in $group.Group) {
        if ($m.MemberType -in 'ServiceAccount', 'SharedAccount') {
            $findings += [pscustomobject]@{
                GroupName = $m.GroupName; Member = $m.MemberDisplayName
                Finding = "$($m.MemberType) holds privileged membership"
                Severity = 'High'
                RecommendedAction = 'Remove standing privilege; use a managed identity or just-in-time elevation instead'
            }
        }
        if (-not $m.AccountEnabled) {
            $findings += [pscustomobject]@{
                GroupName = $m.GroupName; Member = $m.MemberDisplayName
                Finding = 'Disabled account still in privileged group'
                Severity = 'Medium'
                RecommendedAction = 'Remove from group; disabled accounts should hold no memberships'
            }
        }
        elseif ($null -eq $m.LastSignInDateTime -or ($now - $m.LastSignInDateTime).Days -ge $StaleDays) {
            $findings += [pscustomobject]@{
                GroupName = $m.GroupName; Member = $m.MemberDisplayName
                Finding = 'Privileged member has not signed in recently (or ever)'
                Severity = 'Medium'
                RecommendedAction = 'Confirm the person still needs this role; remove if not'
            }
        }
    }
}

if ($OutputPath) {
    $members | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Full membership listing written to $OutputPath"
}

Write-Host ""
Write-Host "Privileged group audit - $(($members | Group-Object GroupName).Count) groups, $($members.Count) memberships"
Write-Host "  High findings   : $(@($findings | Where-Object Severity -eq 'High').Count)"
Write-Host "  Medium findings : $(@($findings | Where-Object Severity -eq 'Medium').Count)"

$findings | Sort-Object Severity, GroupName
