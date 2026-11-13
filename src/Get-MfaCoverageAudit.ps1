<#
.SYNOPSIS
    Reports MFA registration coverage and flags the accounts that matter most.

.DESCRIPTION
    "We have MFA" is only true account by account. This audit reads the
    authentication-methods registration state for every user and grades the
    gaps by risk:

      - Critical : an administrator without MFA registered.
      - High     : a service or shared account without MFA registered
                   (matched by UPN prefix/name patterns, e.g. svc., shared).
      - Medium   : a standard user without MFA registered.

    Two modes:
      - Live mode uses the Microsoft Graph authentication methods registration
        report (Get-MgReportAuthenticationMethodUserRegistrationDetail;
        requires UserAuthenticationMethod.Read.All).
      - Sample mode (-UseSampleData) runs against the fictional CSV in ..\data.

.EXAMPLE
    .\Get-MfaCoverageAudit.ps1 -UseSampleData

.EXAMPLE
    .\Get-MfaCoverageAudit.ps1 -OutputPath .\out\mfa.csv

.NOTES
    Author : Araf Abubakar
    Part of the Identity & Access Audit Toolkit. Demo data is fictional.
#>
[CmdletBinding()]
param(
    [switch]$UseSampleData,
    [string]$SampleDataPath = (Join-Path $PSScriptRoot '..\data\sample-mfa-registration.csv'),
    [string]$OutputPath
)

$records = @()

if ($UseSampleData) {
    Write-Verbose "Sample mode: reading $SampleDataPath"
    foreach ($row in (Import-Csv -Path $SampleDataPath)) {
        $records += [pscustomobject]@{
            UserPrincipalName = $row.UserPrincipalName
            DisplayName       = $row.DisplayName
            IsAdmin           = ($row.IsAdmin -eq 'True')
            MfaRegistered     = ($row.MfaRegistered -eq 'True')
            MethodsRegistered = $row.MethodsRegistered
        }
    }
}
else {
    if (-not (Get-Module -ListAvailable -Name Microsoft.Graph.Reports)) {
        throw "Live mode needs the Microsoft Graph PowerShell SDK (Install-Module Microsoft.Graph). Or run with -UseSampleData."
    }
    Connect-MgGraph -Scopes 'UserAuthenticationMethod.Read.All', 'AuditLog.Read.All' | Out-Null
    $details = Get-MgReportAuthenticationMethodUserRegistrationDetail -All
    foreach ($d in $details) {
        $records += [pscustomobject]@{
            UserPrincipalName = $d.UserPrincipalName
            DisplayName       = $d.UserDisplayName
            IsAdmin           = [bool]$d.IsAdmin
            MfaRegistered     = [bool]$d.IsMfaRegistered
            MethodsRegistered = ($d.MethodsRegistered -join ';')
        }
    }
}

$servicePattern = '^(svc\.|svc-|shared|helpdesk\.shared|service)'

$results = foreach ($r in $records) {
    $isServiceLike = $r.UserPrincipalName -match $servicePattern -or $r.DisplayName -match '^(Svc|Shared|Service)\b'
    $severity = if ($r.MfaRegistered) { 'OK' }
                elseif ($r.IsAdmin) { 'Critical' }
                elseif ($isServiceLike) { 'High' }
                else { 'Medium' }
    [pscustomobject]@{
        DisplayName       = $r.DisplayName
        UserPrincipalName = $r.UserPrincipalName
        IsAdmin           = $r.IsAdmin
        MfaRegistered     = $r.MfaRegistered
        MethodsRegistered = $r.MethodsRegistered
        Severity          = $severity
        RecommendedAction = switch ($severity) {
            'Critical' { 'Enroll in MFA immediately; review recent sign-ins for this account' }
            'High'     { 'Enroll in MFA or document a compensating control and an owner' }
            'Medium'   { 'Send enrollment reminder; set a deadline' }
            default    { 'None' }
        }
    }
}

if ($OutputPath) {
    $results | Export-Csv -Path $OutputPath -NoTypeInformation
    Write-Host "Full results written to $OutputPath"
}

$total   = $results.Count
$covered = ($results | Where-Object MfaRegistered).Count
$pct     = if ($total -gt 0) { [math]::Round(100 * $covered / $total, 1) } else { 0 }

Write-Host ""
Write-Host "MFA coverage audit - $total accounts evaluated"
Write-Host "  Coverage            : $covered / $total ($pct%)"
Write-Host "  Critical (admin, no MFA) : $(@($results | Where-Object Severity -eq 'Critical').Count)"
Write-Host "  High (service/shared)    : $(@($results | Where-Object Severity -eq 'High').Count)"
Write-Host "  Medium (standard user)   : $(@($results | Where-Object Severity -eq 'Medium').Count)"

$results | Where-Object { $_.Severity -ne 'OK' } | Sort-Object Severity
