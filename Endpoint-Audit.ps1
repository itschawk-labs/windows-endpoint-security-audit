# ==========================================================
# WINDOWS ENDPOINT SECURITY BASELINE AUDIT
# Portfolio Lab - Post 4
#
# Purpose:
# Collect Windows security configuration data and evaluate
# selected controls against a simple PASS/WARN baseline.
#
# This script AUDITS configuration. It does not modify the
# endpoint.
# ==========================================================


# ----------------------------------------------------------
# HEADER
# ----------------------------------------------------------

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host "     WINDOWS ENDPOINT SECURITY BASELINE AUDIT" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan


# ==========================================================
# [1] WINDOWS FIREWALL
# ==========================================================

Write-Host "`n[1] WINDOWS FIREWALL" -ForegroundColor Yellow

$FirewallProfiles = Get-NetFirewallProfile

$FirewallProfiles |
    Select-Object Name,
                  Enabled,
                  DefaultInboundAction,
                  DefaultOutboundAction |
    Format-Table -AutoSize |
    Out-Host


# ==========================================================
# [2] MICROSOFT DEFENDER
# ==========================================================

Write-Host "`n[2] MICROSOFT DEFENDER" -ForegroundColor Yellow

$Defender = Get-MpComputerStatus

[PSCustomObject]@{
    "Antivirus"          = $Defender.AntivirusEnabled
    "Real-Time Protect"  = $Defender.RealTimeProtectionEnabled
    "Behavior Monitor"   = $Defender.BehaviorMonitorEnabled
    "Network Inspection" = $Defender.NISEnabled
    "Signatures Updated" = $Defender.AntivirusSignatureLastUpdated
} |
    Format-List |
    Out-Host


# ==========================================================
# [3] LOCAL ADMINISTRATOR AUDIT
# ==========================================================

Write-Host "`n[3] LOCAL ADMINISTRATOR AUDIT" -ForegroundColor Yellow

# Uses the built-in Administrators group SID so this remains
# reliable even if the group has been renamed.

$AdminGroup = Get-LocalGroup -SID "S-1-5-32-544"
$Admins = Get-LocalGroupMember -Group $AdminGroup.Name

[PSCustomObject]@{
    "Administrator Accounts" = $Admins.Count
    "Membership Enumerated"   = $true
    "Account Names Displayed" = $false
} |
    Format-List |
    Out-Host


# ==========================================================
# [4] BUILT-IN GUEST ACCOUNT
# ==========================================================

Write-Host "`n[4] BUILT-IN GUEST ACCOUNT" -ForegroundColor Yellow

# Built-in Guest accounts have a SID ending in -501.
# This works even if the Guest account has been renamed.

$Guest = Get-LocalUser |
    Where-Object { $_.SID.Value -match "-501$" }

if ($null -ne $Guest) {

    [PSCustomObject]@{
        "Guest Account Present" = $true
        "Enabled"               = $Guest.Enabled
    } |
        Format-List |
        Out-Host

}
else {

    [PSCustomObject]@{
        "Guest Account Present" = $false
        "Enabled"               = $false
    } |
        Format-List |
        Out-Host
}


# ==========================================================
# [5] SMBv1 STATUS
# ==========================================================

Write-Host "`n[5] SMBv1 STATUS" -ForegroundColor Yellow

$SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol

$SMB1 |
    Select-Object FeatureName, State |
    Format-Table -AutoSize |
    Out-Host


# ==========================================================
# [6] POWERSHELL EXECUTION POLICY
# ==========================================================

Write-Host "`n[6] POWERSHELL EXECUTION POLICY" -ForegroundColor Yellow

Get-ExecutionPolicy -List |
    Format-Table -AutoSize |
    Out-Host


# ==========================================================
# [7] USER ACCOUNT CONTROL
# ==========================================================

Write-Host "`n[7] USER ACCOUNT CONTROL" -ForegroundColor Yellow

$UAC = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"

[PSCustomObject]@{
    "UAC Enabled"           = [bool]$UAC.EnableLUA
    "Admin Consent Setting" = $UAC.ConsentPromptBehaviorAdmin
} |
    Format-List |
    Out-Host


# ==========================================================
# [8] RECENT WINDOWS UPDATES
# ==========================================================

Write-Host "`n[8] FIVE MOST RECENT WINDOWS UPDATES" -ForegroundColor Yellow

Get-HotFix |
    Sort-Object InstalledOn -Descending |
    Select-Object -First 5 HotFixID, InstalledOn |
    Format-Table -AutoSize |
    Out-Host


# ==========================================================
# [9] BASELINE ASSESSMENT
# ==========================================================

Write-Host "`n[9] BASELINE ASSESSMENT" -ForegroundColor Yellow


# ----------------------------------------------------------
# FIREWALL
# ----------------------------------------------------------

$DisabledFirewallProfiles = @(
    $FirewallProfiles |
        Where-Object { $_.Enabled -eq $false }
)

if ($DisabledFirewallProfiles.Count -eq 0) {

    Write-Host "[PASS] Windows Firewall enabled on all profiles" `
        -ForegroundColor Green

}
else {

    Write-Host "[WARN] One or more Windows Firewall profiles disabled" `
        -ForegroundColor Red
}


# ----------------------------------------------------------
# DEFENDER ANTIVIRUS
# ----------------------------------------------------------

if ($Defender.AntivirusEnabled -eq $true) {

    Write-Host "[PASS] Microsoft Defender Antivirus enabled" `
        -ForegroundColor Green

}
else {

    Write-Host "[WARN] Microsoft Defender Antivirus disabled" `
        -ForegroundColor Red
}


# ----------------------------------------------------------
# DEFENDER REAL-TIME PROTECTION
# ----------------------------------------------------------

if ($Defender.RealTimeProtectionEnabled -eq $true) {

    Write-Host "[PASS] Defender real-time protection enabled" `
        -ForegroundColor Green

}
else {

    Write-Host "[WARN] Defender real-time protection disabled" `
        -ForegroundColor Red
}


# ----------------------------------------------------------
# DEFENDER BEHAVIOR MONITORING
# ----------------------------------------------------------

if ($Defender.BehaviorMonitorEnabled -eq $true) {

    Write-Host "[PASS] Defender behavior monitoring enabled" `
        -ForegroundColor Green

}
else {

    Write-Host "[WARN] Defender behavior monitoring disabled" `
        -ForegroundColor Red
}


# ----------------------------------------------------------
# DEFENDER NETWORK INSPECTION
# ----------------------------------------------------------

if ($Defender.NISEnabled -eq $true) {

    Write-Host "[PASS] Defender network inspection enabled" `
        -ForegroundColor Green

}
else {

    Write-Host "[WARN] Defender network inspection disabled" `
        -ForegroundColor Red
}


# ----------------------------------------------------------
# SMBv1
# ----------------------------------------------------------

if ($SMB1.State -eq "Disabled") {

    Write-Host "[PASS] SMBv1 disabled" `
        -ForegroundColor Green

}
else {

    Write-Host "[WARN] SMBv1 enabled or available" `
        -ForegroundColor Red
}


# ----------------------------------------------------------
# GUEST ACCOUNT
# ----------------------------------------------------------

if ($null -eq $Guest) {

    Write-Host "[PASS] Built-in Guest account unavailable" `
        -ForegroundColor Green

}
elseif ($Guest.Enabled -eq $false) {

    Write-Host "[PASS] Built-in Guest account disabled" `
        -ForegroundColor Green

}
else {

    Write-Host "[WARN] Built-in Guest account enabled" `
        -ForegroundColor Red
}


# ----------------------------------------------------------
# USER ACCOUNT CONTROL
# ----------------------------------------------------------

if ([bool]$UAC.EnableLUA) {

    Write-Host "[PASS] User Account Control enabled" `
        -ForegroundColor Green

}
else {

    Write-Host "[WARN] User Account Control disabled" `
        -ForegroundColor Red
}


# ==========================================================
# AUDIT COMPLETE
# ==========================================================

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host "             BASELINE AUDIT COMPLETE" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green

Write-Host ""
Write-Host "Scope: Selected Windows endpoint configuration controls." `
    -ForegroundColor DarkGray

Write-Host "Result: PASS indicates the defined condition was satisfied;" `
    -ForegroundColor DarkGray

Write-Host "it does not indicate comprehensive endpoint security." `
    -ForegroundColor DarkGray

Write-Host ""