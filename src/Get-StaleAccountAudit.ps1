<#
.SYNOPSIS
    Finds enabled accounts that have not signed in recently (or ever).

.DESCRIPTION
    Identity hygiene audit for Microsoft Entra ID (Azure AD) / Active Directory
    style environments. Stale, enabled accounts are a common audit finding and a
    real attack surface: they keep valid credentials and licenses while nobody
    watches them.

    Two modes:
      - Live mode reads users and sign-in activity from Microsoft Graph
        (requires the Microsoft.Graph PowerShell SDK, the AuditLog.Read.All
        permission, and an Entra ID P1/P2 license for sign-in activity data).
      - Sample mode (-UseSampleData) runs against the fictional CSV in
        ..\data so anyone can try the audit with no tenant and no sign-in.

    Every enabled account is classified:
      - NeverSignedIn : no recorded sign-in and the account is older than
        -NewAccountGraceDays (default 30). Brand-new accounts inside the grace
        window are not flagged.
      - Stale         : last sign-in is older than -StaleDays (default 90).
      - Active        : signed in within the threshold.

    Disabled accounts are excluded - they cannot sign in, so they are not the
    finding this audit is about.

.EXAMPLE
    .\Get-StaleAccountAudit.ps1 -UseSampleData

.EXAMPLE
    .\Get-StaleAccountAudit.ps1 -StaleDays 180 -OutputPath .\out\stale.csv

.NOTES
    Author : Araf Abubakar
    Part of the Identity & Access Audit Toolkit. Demo data is fictional.
#>
[CmdletBinding()]
param(
    [int]$StaleDays = 90,
    [int]$NewAccountGraceDays = 30,
    [switch]$UseSampleData,
    [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\data\sample-users.csv'),
    [string]$OutputPath
)

function ConvertTo-AuditUser {
    param(
        [string]$DisplayName,
        [string]$UserPrincipalName,
        [bool]$AccountEnabled,
        [string]$Department,
        $CreatedDateTime,
        $LastSignInDateTime
    )
    [pscustomobject]@{
        DisplayName       = $DisplayName
        UserPrincipalName = $UserPrincipalName
        AccountEnabled    = $AccountEnabled
        Department        = $Department
        CreatedDateTime   = $CreatedDateTime
        LastSignInDateTime = $LastSignInDateTime
    }
}

$users = @()

if ($UseSampleData) {
    Write-Verbose "Sample mode: reading $SampleDataPath"
    foreach ($row in (Import-Csv -Path $SampleDataPath)) {
        $created = if ($row.CreatedDateTime) { [datetime]$row.CreatedDateTime } else { $null }
        $lastIn  = if ($row.LastSignInDateTime) { [datetime]$row.LastSignInDateTime } else { $null }
        $users += ConvertTo-AuditUser -DisplayName $row.DisplayName `
            -UserPrincipalName $row.UserPrincipalName `
            -AccountEnabled ($row.AccountEnabled -eq 'True') `
            -Department $row.Department -CreatedDateTime $created -LastSignInDateTime $lastIn
    }
}
else {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Users)) {
        throw "Live mode needs the Microsoft Graph PowerShell SDK (Install-Module Microsoft.Graph). Or run with -UseSampleData."
    }
    Connect-MgGraph -Scopes 'User.Read.All', 'AuditLog.Read.All' | Out-Null
    $mgUsers = Get-MgUser -All -Property DisplayName, UserPrincipalName, AccountEnabled, Department, CreatedDateTime, SignInActivity
    foreach ($u in $mgUsers) {
        $users += ConvertTo-AuditUser -DisplayName $u.DisplayName `
            -UserPrincipalName $u.UserPrincipalName `
            -AccountEnabled ([bool]$u.AccountEnabled) `
            -Department $u.Department -CreatedDateTime $u.CreatedDateTime `
            -LastSignInDateTime $u.SignInActivity.LastSignInDateTime
    }
}

$now = Get-Date
$results = foreach ($user in $users) {
    if (-not $user.AccountEnabled) { continue }

    if ($null -eq $user.LastSignInDateTime) {
        $ageDays = if ($user.CreatedDateTime) { ($now - $user.CreatedDateTime).Days } else { $null }
        $status  = if ($null -ne $ageDays -and $ageDays -le $NewAccountGraceDays) { 'Active' } else { 'NeverSignedIn' }
        $daysInactive = $ageDays
    }
    else {
        $daysInactive = ($now - $user.LastSignInDateTime).Days
        $status = if ($daysInactive -ge $StaleDays) { 'Stale' } else { 'Active' }
    }

    [pscustomobject]@{
        DisplayName        = $user.DisplayName
        UserPrincipalName  = $user.UserPrincipalName
        Department         = $user.Department
        CreatedDateTime    = $user.CreatedDateTime
        LastSignInDateTime = $user.LastSignInDateTime
        DaysInactive       = $daysInactive
        Status             = $status
        RecommendedAction  = switch ($status) {
            'Stale'         { 'Confirm with owner, then disable and remove licenses' }
            'NeverSignedIn' { 'Verify the account is still needed; disable if not' }
            default         { 'None' }
        }
    }
}

$findings = $results | Where-Object { $_.Status -ne 'Active' } | Sort-Object DaysInactive -Descending

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Full results written to $OutputPath"
}

Write-Host ""
Write-Host "Stale account audit - $($results.Count) enabled accounts evaluated"
Write-Host ("  Stale (>= {0} days inactive) : {1}" -f $StaleDays, @($results | Where-Object Status -eq 'Stale').Count)
Write-Host ("  Never signed in              : {0}" -f @($results | Where-Object Status -eq 'NeverSignedIn').Count)

# Findings go to the pipeline so the orchestrator (or your own tooling) can use them.
$findings
