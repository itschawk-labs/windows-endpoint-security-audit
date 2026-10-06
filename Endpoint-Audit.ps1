<#
.SYNOPSIS
Performs a read-only Windows endpoint security baseline audit.

.DESCRIPTION
Collects selected Windows security configuration data and evaluates
defined controls against a simple PASS / WARN / UNKNOWN baseline.

PASS    - the defined condition was satisfied
WARN    - the defined condition was not satisfied
UNKNOWN - the data could not be retrieved, so no result is claimed

.NOTES
This script audits configuration only. It does not modify the endpoint.
Run from an elevated (Administrator) PowerShell session for complete results.
#>

# ==========================================================
# SETUP
# ==========================================================

$Summary = @{ PASS = 0; WARN = 0; UNKNOWN = 0 }

function Write-Result {
    param(
        [ValidateSet("PASS", "WARN", "UNKNOWN")]
        [string]$Status,
        [string]$Message
    )

    $Color = switch ($Status) {
        "PASS"    { "Green" }
        "WARN"    { "Red" }
        "UNKNOWN" { "Yellow" }
    }

    Write-Host "[$Status] $Message" -ForegroundColor $Color
    $script:Summary[$Status]++
}

function Test-Condition {
    # Evaluates a true/false control value. A missing value is UNKNOWN,
    # never WARN, so failed queries are not reported as findings.
    param(
        $Value,
        [string]$PassMessage,
        [string]$WarnMessage,
        [string]$UnknownMessage
    )

    if ($Value -eq $true) {
        Write-Result -Status PASS -Message $PassMessage
    }
    elseif ($Value -eq $false) {
        Write-Result -Status WARN -Message $WarnMessage
    }
    else {
        Write-Result -Status UNKNOWN -Message $UnknownMessage
    }
}

$IsAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

# ----------------------------------------------------------
# HEADER
# ----------------------------------------------------------

Write-Host ""
Write-Host "==================================================" -ForegroundColor Cyan
Write-Host " WINDOWS ENDPOINT SECURITY BASELINE AUDIT" -ForegroundColor Cyan
Write-Host "==================================================" -ForegroundColor Cyan

if (-not $IsAdmin) {
    Write-Host ""
    Write-Host "NOTE: Not running as Administrator. Some checks (such as SMBv1)" -ForegroundColor Yellow
    Write-Host "may be reported as UNKNOWN. Re-run from an elevated session for" -ForegroundColor Yellow
    Write-Host "complete results." -ForegroundColor Yellow
}

# ==========================================================
# [1] WINDOWS FIREWALL
# ==========================================================

Write-Host ""
Write-Host "[1] WINDOWS FIREWALL" -ForegroundColor Yellow

$FirewallProfiles = $null

try {
    $FirewallProfiles = Get-NetFirewallProfile -ErrorAction Stop

    $FirewallProfiles |
        Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction |
        Format-Table -AutoSize |
        Out-Host
}
catch {
    Write-Host "Windows Firewall information could not be retrieved." -ForegroundColor Red
}

# ==========================================================
# [2] MICROSOFT DEFENDER
# ==========================================================

Write-Host ""
Write-Host "[2] MICROSOFT DEFENDER" -ForegroundColor Yellow

$Defender = $null

try {
    $Defender = Get-MpComputerStatus -ErrorAction Stop

    [PSCustomObject]@{
        "Antivirus"          = $Defender.AntivirusEnabled
        "Real-Time Protect"  = $Defender.RealTimeProtectionEnabled
        "Behavior Monitor"   = $Defender.BehaviorMonitorEnabled
        "Network Inspection" = $Defender.NISEnabled
        "Signatures Updated" = $Defender.AntivirusSignatureLastUpdated
    } |
        Format-List |
        Out-Host
}
catch {
    Write-Host "Microsoft Defender status could not be retrieved." -ForegroundColor Red
    Write-Host "(Defender may be replaced by third-party antivirus, or its cmdlets are unavailable.)" -ForegroundColor DarkGray
}

# ==========================================================
# [3] LOCAL ADMINISTRATOR AUDIT
# ==========================================================

Write-Host ""
Write-Host "[3] LOCAL ADMINISTRATOR AUDIT" -ForegroundColor Yellow

# Uses the built-in Administrators group SID so this remains
# reliable even if the group has been renamed or localized.

$AdminsEnumerated = $false
$AdminCount = $null

try {
    $AdminGroup = Get-LocalGroup -SID "S-1-5-32-544" -ErrorAction Stop
    $Admins = @(Get-LocalGroupMember -Group $AdminGroup -ErrorAction Stop)
    $AdminCount = $Admins.Count
    $AdminsEnumerated = $true
}
catch {
    # Get-LocalGroupMember can fail on domain or Azure AD-joined
    # devices when the group contains orphaned SIDs.
}

[PSCustomObject]@{
    "Administrator Accounts"  = if ($AdminsEnumerated) { $AdminCount } else { "Unavailable" }
    "Membership Enumerated"   = $AdminsEnumerated
    "Account Names Displayed" = $false
} |
    Format-List |
    Out-Host

# ==========================================================
# [4] BUILT-IN GUEST ACCOUNT
# ==========================================================

Write-Host ""
Write-Host "[4] BUILT-IN GUEST ACCOUNT" -ForegroundColor Yellow

# Built-in Guest accounts have a SID ending in -501.
# This works even if the Guest account has been renamed.

$GuestQueried = $false
$Guest = $null

try {
    $Guest = Get-LocalUser -ErrorAction Stop |
        Where-Object { $_.SID.Value -match "-501$" }
    $GuestQueried = $true
}
catch {
    Write-Host "Local user information could not be retrieved." -ForegroundColor Red
}

if ($GuestQueried) {
    [PSCustomObject]@{
        "Guest Account Present" = ($null -ne $Guest)
        "Enabled"               = if ($null -ne $Guest) { $Guest.Enabled } else { $false }
    } |
        Format-List |
        Out-Host
}

# ==========================================================
# [5] SMBv1 STATUS
# ==========================================================

Write-Host ""
Write-Host "[5] SMBv1 STATUS" -ForegroundColor Yellow

$SMB1 = $null

try {
    $SMB1 = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction Stop

    $SMB1 |
        Select-Object FeatureName, State |
        Format-Table -AutoSize |
        Out-Host
}
catch {
    Write-Host "SMBv1 status could not be retrieved (this check requires Administrator)." -ForegroundColor Red
}

# ==========================================================
# [6] POWERSHELL EXECUTION POLICY
# ==========================================================

Write-Host ""
Write-Host "[6] POWERSHELL EXECUTION POLICY" -ForegroundColor Yellow

try {
    Get-ExecutionPolicy -List -ErrorAction Stop |
        Format-Table -AutoSize |
        Out-Host
}
catch {
    Write-Host "Execution policy could not be retrieved." -ForegroundColor Red
}

# ==========================================================
# [7] USER ACCOUNT CONTROL
# ==========================================================

Write-Host ""
Write-Host "[7] USER ACCOUNT CONTROL" -ForegroundColor Yellow

$UACEnabled = $null

$ConsentDescriptions = @{
    0 = "Elevate without prompting"
    1 = "Prompt for credentials on the secure desktop"
    2 = "Prompt for consent on the secure desktop"
    3 = "Prompt for credentials"
    4 = "Prompt for consent"
    5 = "Prompt for consent for non-Windows binaries (default)"
}

try {
    $UAC = Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" -ErrorAction Stop

    if ($null -ne $UAC.EnableLUA) {
        $UACEnabled = [bool]$UAC.EnableLUA
    }

    $Consent = $UAC.ConsentPromptBehaviorAdmin
    $ConsentText = if ($null -ne $Consent -and $ConsentDescriptions.ContainsKey([int]$Consent)) {
        "$Consent - $($ConsentDescriptions[[int]$Consent])"
    }
    else {
        "Not reported"
    }

    [PSCustomObject]@{
        "UAC Enabled"           = if ($null -ne $UACEnabled) { $UACEnabled } else { "Not reported" }
        "Admin Consent Setting" = $ConsentText
    } |
        Format-List |
        Out-Host
}
catch {
    Write-Host "User Account Control settings could not be retrieved." -ForegroundColor Red
}

# ==========================================================
# [8] RECENT WINDOWS UPDATES
# ==========================================================

Write-Host ""
Write-Host "[8] FIVE MOST RECENT INSTALLED HOTFIXES" -ForegroundColor Yellow

try {
    Get-HotFix -ErrorAction Stop |
        Where-Object { $null -ne $_.InstalledOn } |
        Sort-Object InstalledOn -Descending |
        Select-Object -First 5 HotFixID, InstalledOn |
        Format-Table -AutoSize |
        Out-Host
}
catch {
    Write-Host "Installed hotfix information could not be retrieved." -ForegroundColor Red
}

# ==========================================================
# [9] BASELINE ASSESSMENT
# ==========================================================

Write-Host ""
Write-Host "[9] BASELINE ASSESSMENT" -ForegroundColor Yellow

# ----- Firewall -----

if ($null -eq $FirewallProfiles) {
    Write-Result -Status UNKNOWN -Message "Windows Firewall status could not be determined"
}
else {
    $DisabledFirewallProfiles = @($FirewallProfiles | Where-Object { $_.Enabled -ne "True" })

    if ($DisabledFirewallProfiles.Count -eq 0) {
        Write-Result -Status PASS -Message "Windows Firewall enabled on all profiles"
    }
    else {
        $Names = ($DisabledFirewallProfiles.Name) -join ", "
        Write-Result -Status WARN -Message "Windows Firewall disabled on: $Names"
    }
}

# ----- Microsoft Defender -----

Test-Condition -Value $Defender.AntivirusEnabled -PassMessage "Microsoft Defender Antivirus enabled" -WarnMessage "Microsoft Defender Antivirus disabled" -UnknownMessage "Microsoft Defender Antivirus status could not be determined"

Test-Condition -Value $Defender.RealTimeProtectionEnabled -PassMessage "Defender real-time protection enabled" -WarnMessage "Defender real-time protection disabled" -UnknownMessage "Defender real-time protection status could not be determined"

Test-Condition -Value $Defender.BehaviorMonitorEnabled -PassMessage "Defender behavior monitoring enabled" -WarnMessage "Defender behavior monitoring disabled" -UnknownMessage "Defender behavior monitoring status could not be determined"

Test-Condition -Value $Defender.NISEnabled -PassMessage "Defender network inspection enabled" -WarnMessage "Defender network inspection disabled" -UnknownMessage "Defender network inspection status could not be determined"

# ----- SMBv1 -----

if ($null -eq $SMB1) {
    Write-Result -Status UNKNOWN -Message "SMBv1 status could not be determined"
}
elseif ("$($SMB1.State)" -like "Disabled*") {
    # Covers both Disabled and DisabledWithPayloadRemoved.
    Write-Result -Status PASS -Message "SMBv1 disabled"
}
else {
    Write-Result -Status WARN -Message "SMBv1 enabled or available (state: $($SMB1.State))"
}

# ----- Guest account -----

if (-not $GuestQueried) {
    Write-Result -Status UNKNOWN -Message "Built-in Guest account status could not be determined"
}
elseif ($null -eq $Guest) {
    Write-Result -Status PASS -Message "Built-in Guest account not present"
}
elseif ($Guest.Enabled -eq $false) {
    Write-Result -Status PASS -Message "Built-in Guest account disabled"
}
else {
    Write-Result -Status WARN -Message "Built-in Guest account enabled"
}

# ----- User Account Control -----

Test-Condition -Value $UACEnabled -PassMessage "User Account Control enabled" -WarnMessage "User Account Control disabled" -UnknownMessage "User Account Control status could not be determined"

# ==========================================================
# SUMMARY
# ==========================================================

Write-Host ""
Write-Host "==================================================" -ForegroundColor Green
Write-Host " BASELINE AUDIT COMPLETE" -ForegroundColor Green
Write-Host "==================================================" -ForegroundColor Green
Write-Host ""
Write-Host ("PASS: {0}   WARN: {1}   UNKNOWN: {2}" -f $Summary.PASS, $Summary.WARN, $Summary.UNKNOWN)
Write-Host ""
Write-Host "Scope: Selected Windows endpoint configuration controls." -ForegroundColor DarkGray
Write-Host "PASS indicates the defined condition was satisfied; it does not" -ForegroundColor DarkGray
Write-Host "indicate comprehensive endpoint security. UNKNOWN means the data" -ForegroundColor DarkGray
Write-Host "could not be retrieved and should be checked manually." -ForegroundColor DarkGray
Write-Host ""
