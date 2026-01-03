<#
.SYNOPSIS
    Customizable Windows Event Log Analyzer
.DESCRIPTION
    Searches for specified Event IDs across Windows Event Logs with detailed output
    Can be used for shutdown analysis or any custom event ID investigation
.PARAMETER EventID
    Single Event ID or array of Event IDs to search for
.PARAMETER LogName
    Log name to search (System, Application, Security, etc.). Default is 'System'
.PARAMETER ProviderName
    Optional filter for specific provider/source
.PARAMETER DaysToSearch
    Number of days to search back. Default is 7
.PARAMETER Level
    Event level filter: Critical(1), Error(2), Warning(3), Information(4), Verbose(5)
.PARAMETER MaxResults
    Maximum number of results to return per Event ID. Default is 50
.PARAMETER ExportToCSV
    Export results to CSV file
.EXAMPLE
    .\EventLogAnalyzer.ps1 -EventID 6008
.EXAMPLE
    .\EventLogAnalyzer.ps1 -EventID 41,6008,1074 -DaysToSearch 30
.EXAMPLE
    .\EventLogAnalyzer.ps1 -EventID 4625 -LogName Security -DaysToSearch 1
.EXAMPLE
    .\EventLogAnalyzer.ps1 -EventID 1000 -LogName Application -ProviderName "Application Error"
.NOTES
    Author: IT Support
    Date: 2026-01-02
    Version: 2.0
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$false)]
    [int[]]$EventID,
    
    [Parameter(Mandatory=$false)]
    [string]$LogName = "System",
    
    [Parameter(Mandatory=$false)]
    [string]$ProviderName,
    
    [Parameter(Mandatory=$false)]
    [int]$DaysToSearch = 7,
    
    [Parameter(Mandatory=$false)]
    [ValidateSet(1,2,3,4,5)]
    [int[]]$Level,
    
    [Parameter(Mandatory=$false)]
    [int]$MaxResults = 50,
    
    [Parameter(Mandatory=$false)]
    [switch]$ExportToCSV,
    
    [Parameter(Mandatory=$false)]
    [switch]$ShowPresets
)

# Common Event ID presets for quick reference
$EventPresets = @{
    "Shutdown Analysis" = @{
        EventIDs = @(6008, 41, 1074, 1076, 137, 153, 10010, 1001, 12, 13)
        Description = "Comprehensive shutdown and restart event analysis"
    }
    "Security - Failed Logins" = @{
        EventIDs = @(4625)
        LogName = "Security"
        Description = "Failed login attempts"
    }
    "Security - Successful Logins" = @{
        EventIDs = @(4624)
        LogName = "Security"
        Description = "Successful login events"
    }
    "Security - Account Lockouts" = @{
        EventIDs = @(4740)
        LogName = "Security"
        Description = "Account lockout events"
    }
    "Application Crashes" = @{
        EventIDs = @(1000, 1001, 1002)
        LogName = "Application"
        Description = "Application error and crash events"
    }
    "Disk Errors" = @{
        EventIDs = @(7, 9, 11, 15, 51, 52, 55, 137, 153)
        Description = "Disk and storage related errors"
    }
    "Network Issues" = @{
        EventIDs = @(4201, 4202, 5719, 5723, 8019)
        Description = "Network connectivity and domain communication issues"
    }
    "Service Failures" = @{
        EventIDs = @(7000, 7001, 7022, 7023, 7024, 7026, 7031, 7034)
        Description = "Service control manager errors"
    }
    "Time Sync Issues" = @{
        EventIDs = @(129, 134, 135, 138, 142, 150)
        ProviderName = "Microsoft-Windows-Time-Service"
        Description = "Windows Time Service synchronization issues"
    }
    "Kernel Issues" = @{
        EventIDs = @(41, 46, 109)
        ProviderName = "Microsoft-Windows-Kernel-Power"
        Description = "Kernel and power management issues"
    }
}

# Event ID descriptions database
$EventDescriptions = @{
    # Shutdown/Restart Events
    6008 = "Unexpected shutdown - The previous system shutdown was unexpected"
    41 = "Kernel-Power - System rebooted without cleanly shutting down (crash/power loss)"
    1074 = "User32 - System shutdown/restart was initiated"
    1076 = "User32 - Reason supplied for shutdown/restart"
    13 = "Kernel-General - Operating system is shutting down"
    12 = "Kernel-General - Operating system started at system boot"
    46 = "Kernel-Power - System entering sleep/hibernation"
    109 = "Kernel-Power - Kernel power manager initiated shutdown"
    
    # Disk Events
    7 = "Disk - Bad block detected on device"
    9 = "Disk - Device has a bad block"
    11 = "Disk - Driver detected controller error"
    15 = "Disk - Device is not ready for access"
    51 = "Disk - Page fault error occurred"
    52 = "Disk - Multipath fault detected"
    55 = "Disk - Request failed due to fatal device hardware error"
    137 = "Disk - Device did not respond within timeout period"
    153 = "Disk - IO error detected during an operation"
    
    # Application/System Errors
    1000 = "Application Error - Application crashed"
    1001 = "Windows Error Reporting - Bugcheck/BSOD occurred"
    1002 = "Application Hang - Application stopped responding"
    10010 = "DistributedCOM - DCOM server did not register (often after crash)"
    
    # Security Events
    4624 = "Security - Account successfully logged on"
    4625 = "Security - Account failed to log on"
    4634 = "Security - Account logged off"
    4647 = "Security - User initiated logoff"
    4648 = "Security - Logon using explicit credentials"
    4672 = "Security - Special privileges assigned to new logon"
    4720 = "Security - User account created"
    4722 = "Security - User account enabled"
    4723 = "Security - User attempted to change password"
    4724 = "Security - Password reset attempt"
    4725 = "Security - User account disabled"
    4726 = "Security - User account deleted"
    4738 = "Security - User account changed"
    4740 = "Security - User account locked out"
    4767 = "Security - User account unlocked"
    4768 = "Security - Kerberos authentication ticket (TGT) requested"
    4771 = "Security - Kerberos pre-authentication failed"
    4776 = "Security - Domain controller attempted to validate credentials"
    
    # Service Events
    7000 = "Service Control Manager - Service failed to start"
    7001 = "Service Control Manager - Service depends on service that failed to start"
    7009 = "Service Control Manager - Service timeout on start"
    7022 = "Service Control Manager - Service hung on starting"
    7023 = "Service Control Manager - Service terminated with error"
    7024 = "Service Control Manager - Service terminated with service-specific error"
    7026 = "Service Control Manager - Boot-start or system-start driver failed to load"
    7031 = "Service Control Manager - Service crashed and was restarted"
    7034 = "Service Control Manager - Service terminated unexpectedly"
    
    # Network Events
    4201 = "TCP/IP - Network adapter disabled or disconnected"
    4202 = "TCP/IP - Network adapter enabled or connected"
    5719 = "NETLOGON - Unable to establish secure channel with domain controller"
    5723 = "NETLOGON - Remote procedure call to domain controller failed"
    8019 = "DNS Client - DNS client failed to reach DNS servers"
    
    # Time Service
    129 = "Time-Service - NTP client received response from invalid server"
    134 = "Time-Service - Time provider did not respond"
    135 = "Time-Service - Unable to synchronize with time source"
    138 = "Time-Service - Time provider returned error during time sample request"
    150 = "Time-Service - Unable to synchronize system time"
    142 = "Time-Service - Clock discipline failed to discipline local clock"
    
    # VSS (Volume Shadow Copy)
    8193 = "VSS - Volume Shadow Copy Service error"
    8194 = "VSS - Volume Shadow Copy creation error"
    
    # Windows Update
    19 = "WindowsUpdateClient - Installation failure"
    20 = "WindowsUpdateClient - Installation ready"
    
    # DNS
    4000 = "DNS - Unable to load DNS zones"
    4004 = "DNS - DNS server unable to open Active Directory"
    
    # Active Directory
    1168 = "ActiveDirectory_DomainService - DFSR replication error"
    1202 = "ActiveDirectory_DomainService - Replication error"
    2042 = "ActiveDirectory_DomainService - Too much time has passed since last replication"
}

# Display presets if requested
if ($ShowPresets) {
    Write-Host "`n==================================================================" -ForegroundColor Cyan
    Write-Host "  AVAILABLE EVENT LOG PRESETS" -ForegroundColor Cyan
    Write-Host "==================================================================" -ForegroundColor Cyan
    
    $EventPresets.GetEnumerator() | Sort-Object Name | ForEach-Object {
        Write-Host "`n[$($_.Key)]" -ForegroundColor Yellow
        Write-Host "  Description: $($_.Value.Description)" -ForegroundColor White
        Write-Host "  Event IDs:   $($_.Value.EventIDs -join ', ')" -ForegroundColor Gray
        if ($_.Value.LogName) {
            Write-Host "  Log Name:    $($_.Value.LogName)" -ForegroundColor Gray
        }
        if ($_.Value.ProviderName) {
            Write-Host "  Provider:    $($_.Value.ProviderName)" -ForegroundColor Gray
        }
    }
    
    Write-Host "`n==================================================================" -ForegroundColor Cyan
    Write-Host "To use a preset, copy the Event IDs and run:" -ForegroundColor White
    Write-Host "  .\EventLogAnalyzer.ps1 -EventID <IDs> [-LogName <Name>]" -ForegroundColor Gray
    Write-Host "==================================================================" -ForegroundColor Cyan
    return
}

# Check if script was run with command-line parameters (non-interactive mode)
$RunOnceMode = $PSBoundParameters.Count -gt 0 -and $PSBoundParameters.ContainsKey('EventID')

# Main loop for continuous operation (only in interactive mode)
$ContinueRunning = $true

while ($ContinueRunning) {
    # If running in one-shot mode with parameters, don't reset variables
    if (-not $RunOnceMode) {
        # Reset variables for each iteration
        $EventID = $null
        $LogName = "System"
        $ProviderName = $null
        $DaysToSearch = 7
        # Don't reset Level to null due to ValidateSet - just clear it by not setting it
    }
    
    # Interactive mode if no Event ID specified
    if (-not $EventID) {
        # Load user presets if available
        $UserPresetsFile = Join-Path $PSScriptRoot "UserPresets.json"
        $UserPresets = @{}
        if (Test-Path $UserPresetsFile) {
            try {
                $UserPresets = Get-Content $UserPresetsFile | ConvertFrom-Json -AsHashtable
            } catch {
                Write-Host "Warning: Could not load user presets" -ForegroundColor Yellow
            }
        }
        
        Write-Host "`n==================================================================" -ForegroundColor Cyan
        Write-Host "  INTERACTIVE EVENT LOG ANALYZER" -ForegroundColor Cyan
        Write-Host "==================================================================" -ForegroundColor Cyan
        Write-Host "`nChoose an option:" -ForegroundColor Yellow
        Write-Host "`n--- GENERAL OPTIONS ---" -ForegroundColor Green
        Write-Host "  1. Enter custom Event ID(s)" -ForegroundColor White
        Write-Host "  2. View Event ID reference guide (opens browser)" -ForegroundColor White
        Write-Host "  3. Create/Save a custom preset" -ForegroundColor White
        
        Write-Host "`n--- PREDEFINED PRESETS ---" -ForegroundColor Green
        Write-Host "  10. Shutdown Analysis - Unexpected shutdowns, crashes, restarts" -ForegroundColor White
        Write-Host "  11. Disk Errors - Bad blocks, timeouts, I/O errors" -ForegroundColor White
        Write-Host "  12. Application Crashes - App errors, hangs, failures" -ForegroundColor White
        Write-Host "  13. Service Failures - Service start/stop/crash events" -ForegroundColor White
        Write-Host "  14. Network Issues - Connectivity and domain problems" -ForegroundColor White
        Write-Host "  15. Security - Failed Logins" -ForegroundColor White
        Write-Host "  16. Security - Successful Logins" -ForegroundColor White
        Write-Host "  17. Security - Account Lockouts" -ForegroundColor White
        Write-Host "  18. Kernel Issues - Power management and kernel errors" -ForegroundColor White
        Write-Host "  19. Time Sync Issues - NTP and time synchronization" -ForegroundColor White
        
        # Show user presets if available
        if ($UserPresets.Count -gt 0) {
            Write-Host "`n--- YOUR CUSTOM PRESETS ---" -ForegroundColor Green
            $PresetNumber = 20
            $UserPresets.GetEnumerator() | ForEach-Object {
                Write-Host "  $PresetNumber. $($_.Key) - $($_.Value.Description)" -ForegroundColor White
                $PresetNumber++
            }
        }
        
        Write-Host "`n  Q. Quit" -ForegroundColor White
        
        $Choice = Read-Host "`nEnter choice"
        
        switch ($Choice.ToUpper()) {
            "1" {
                $InputIDs = Read-Host "Enter Event ID(s) separated by commas (e.g., 6008,41,1074)"
                $EventID = $InputIDs -split ',' | ForEach-Object { [int]$_.Trim() }
                
                $CustomLog = Read-Host "Enter Log Name (press Enter for 'System')"
                if ($CustomLog) { $LogName = $CustomLog }
                
                $CustomDays = Read-Host "Days to search back (press Enter for 7)"
                if ($CustomDays) { $DaysToSearch = [int]$CustomDays }
            }
            "2" {
                # Open Event ID reference
                Write-Host "`nOpening Event ID reference guides in your browser..." -ForegroundColor Cyan
                Write-Host "`nUseful Event ID References:" -ForegroundColor Yellow
                Write-Host "  1. Microsoft Event ID List: https://learn.microsoft.com/en-us/windows/win32/eventlog/event-logging" -ForegroundColor White
                Write-Host "  2. Comprehensive Event ID Database: https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/" -ForegroundColor White
                Write-Host "  3. EventID.net: https://www.eventid.net/" -ForegroundColor White
                
                $OpenBrowser = Read-Host "`nOpen Ultimate Windows Security reference? (Y/N)"
                if ($OpenBrowser.ToUpper() -eq 'Y') {
                    Start-Process "https://www.ultimatewindowssecurity.com/securitylog/encyclopedia/"
                }
                
                Read-Host "`nPress ENTER to return to menu"
                continue
            }
            "3" {
                # Create custom preset
                Write-Host "`n=== CREATE CUSTOM PRESET ===" -ForegroundColor Green
                $PresetName = Read-Host "Enter preset name (e.g., 'My Custom Events')"
                if ([string]::IsNullOrWhiteSpace($PresetName)) {
                    Write-Host "Invalid name. Returning to menu..." -ForegroundColor Red
                    continue
                }
                
                $PresetDesc = Read-Host "Enter description"
                $PresetIDs = Read-Host "Enter Event IDs separated by commas (e.g., 6008,41,1074)"
                $PresetIDsArray = $PresetIDs -split ',' | ForEach-Object { [int]$_.Trim() }
                
                $PresetLog = Read-Host "Enter Log Name (press Enter for 'System')"
                if ([string]::IsNullOrWhiteSpace($PresetLog)) { $PresetLog = "System" }
                
                # Save to user presets file
                $UserPresetsFile = Join-Path $PSScriptRoot "UserPresets.json"
                $UserPresets = @{}
                if (Test-Path $UserPresetsFile) {
                    $UserPresets = Get-Content $UserPresetsFile | ConvertFrom-Json -AsHashtable
                }
                
                $UserPresets[$PresetName] = @{
                    Description = $PresetDesc
                    EventIDs = $PresetIDsArray
                    LogName = $PresetLog
                }
                
                $UserPresets | ConvertTo-Json | Set-Content $UserPresetsFile
                Write-Host "`nPreset '$PresetName' saved successfully!" -ForegroundColor Green
                Write-Host "It will appear in the menu on next run." -ForegroundColor Cyan
                Start-Sleep -Seconds 2
                continue
            }
            "10" {
                $EventID = $EventPresets["Shutdown Analysis"].EventIDs
                Write-Host "Using Shutdown Analysis preset" -ForegroundColor Green
            }
            "11" {
                $EventID = $EventPresets["Disk Errors"].EventIDs
                Write-Host "Using Disk Errors preset" -ForegroundColor Green
            }
            "12" {
                $EventID = $EventPresets["Application Crashes"].EventIDs
                $LogName = $EventPresets["Application Crashes"].LogName
                Write-Host "Using Application Crashes preset" -ForegroundColor Green
            }
            "13" {
                $EventID = $EventPresets["Service Failures"].EventIDs
                Write-Host "Using Service Failures preset" -ForegroundColor Green
            }
            "14" {
                $EventID = $EventPresets["Network Issues"].EventIDs
                Write-Host "Using Network Issues preset" -ForegroundColor Green
            }
            "15" {
                $EventID = $EventPresets["Security - Failed Logins"].EventIDs
                $LogName = $EventPresets["Security - Failed Logins"].LogName
                Write-Host "Using Security - Failed Logins preset" -ForegroundColor Green
            }
            "16" {
                $EventID = $EventPresets["Security - Successful Logins"].EventIDs
                $LogName = $EventPresets["Security - Successful Logins"].LogName
                Write-Host "Using Security - Successful Logins preset" -ForegroundColor Green
            }
            "17" {
                $EventID = $EventPresets["Security - Account Lockouts"].EventIDs
                $LogName = $EventPresets["Security - Account Lockouts"].LogName
                Write-Host "Using Security - Account Lockouts preset" -ForegroundColor Green
            }
            "18" {
                $EventID = $EventPresets["Kernel Issues"].EventIDs
                Write-Host "Using Kernel Issues preset" -ForegroundColor Green
            }
            "19" {
                $EventID = $EventPresets["Time Sync Issues"].EventIDs
                Write-Host "Using Time Sync Issues preset" -ForegroundColor Green
            }
            "Q" {
                Write-Host "Exiting..." -ForegroundColor Yellow
                $ContinueRunning = $false
                continue
            }
            default {
                # Check if it's a user preset number (starting at 20)
                if ($Choice -match '^\d+$') {
                    $ChoiceNum = [int]$Choice
                    if ($ChoiceNum -ge 20 -and $UserPresets.Count -gt 0) {
                        $PresetIndex = $ChoiceNum - 20
                        $UserPresetsList = @($UserPresets.GetEnumerator())
                        if ($PresetIndex -lt $UserPresetsList.Count) {
                            $SelectedPreset = $UserPresetsList[$PresetIndex]
                            $EventID = $SelectedPreset.Value.EventIDs
                            if ($SelectedPreset.Value.LogName) {
                                $LogName = $SelectedPreset.Value.LogName
                            }
                            Write-Host "Using preset: $($SelectedPreset.Key)" -ForegroundColor Green
                        } else {
                            Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                            continue
                        }
                    } else {
                        Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                        continue
                    }
                } else {
                    Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                    continue
                }
            }
        }
    }
    
    # Skip analysis if no Event ID was selected (e.g., user viewed presets and returned)
    if (-not $EventID) {
        continue
    }

# Main Analysis
$StartTime = (Get-Date).AddDays(-$DaysToSearch)
$AllResults = @()

Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "  EVENT LOG ANALYSIS" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan
Write-Host "Log Name:       $LogName" -ForegroundColor White
Write-Host "Event ID(s):    $($EventID -join ', ')" -ForegroundColor White
if ($ProviderName) {
    Write-Host "Provider:       $ProviderName" -ForegroundColor White
}
Write-Host "Search Period:  $($StartTime.ToString('yyyy-MM-dd HH:mm:ss')) to $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor White
Write-Host "Max Results:    $MaxResults per Event ID" -ForegroundColor White
Write-Host "==================================================================" -ForegroundColor Cyan

# Function to get event description
function Get-EventDescription {
    param([int]$EventIDNum)
    if ($EventDescriptions.ContainsKey($EventIDNum)) {
        return $EventDescriptions[$EventIDNum]
    } else {
        return "No description available for Event ID $EventIDNum"
    }
}

# Function to format and display events
function Show-EventDetails {
    param($Events, $EventIDNum)
    
    if (-not $Events -or $Events.Count -eq 0) {
        Write-Host "`n--- Event ID $EventIDNum ---" -ForegroundColor Yellow
        Write-Host "Description: $(Get-EventDescription -EventIDNum $EventIDNum)" -ForegroundColor Cyan
        Write-Host "Status:      No events found" -ForegroundColor Gray
        return
    }
    
    Write-Host "`n--- Event ID $EventIDNum ---" -ForegroundColor Yellow
    Write-Host "Description: $(Get-EventDescription -EventIDNum $EventIDNum)" -ForegroundColor Cyan
    Write-Host "Found:       $($Events.Count) event(s)" -ForegroundColor Green
    Write-Host ""
    
    $Events | ForEach-Object {
        $EventObj = [PSCustomObject]@{
            TimeCreated = $_.TimeCreated
            EventID = $_.Id
            LogName = $_.LogName
            ProviderName = $_.ProviderName
            Level = $_.LevelDisplayName
            Source = $_.ProviderName
            Computer = $_.MachineName
            UserName = if($_.UserId){$_.UserId.Value}else{"N/A"}
            Message = $_.Message
        }
        
        $script:AllResults += $EventObj
        
        # Highlight the time at the top
        Write-Host "`n>>> EVENT OCCURRED: " -NoNewline -ForegroundColor Magenta
        Write-Host $_.TimeCreated -ForegroundColor Yellow
        Write-Host ("=" * 80) -ForegroundColor DarkGray
        
        Write-Host "Event ID:    " -NoNewline -ForegroundColor Cyan
        Write-Host $_.Id
        Write-Host "Level:       " -NoNewline -ForegroundColor Cyan
        $LevelColor = switch ($_.LevelDisplayName) {
            "Critical" { "Red" }
            "Error" { "Red" }
            "Warning" { "Yellow" }
            "Information" { "Green" }
            default { "White" }
        }
        Write-Host $_.LevelDisplayName -ForegroundColor $LevelColor
        Write-Host "Provider:    " -NoNewline -ForegroundColor Cyan
        Write-Host $_.ProviderName
        Write-Host "Computer:    " -NoNewline -ForegroundColor Cyan
        Write-Host $_.MachineName
        
        if ($_.UserId) {
            Write-Host "User:        " -NoNewline -ForegroundColor Cyan
            Write-Host $_.UserId.Value
        }
        
        Write-Host "Message:     " -NoNewline -ForegroundColor Cyan
        $MessagePreview = $_.Message.Substring(0, [Math]::Min(800, $_.Message.Length))
        if ($_.Message.Length -gt 800) {
            $MessagePreview += "`n             ... (truncated)"
        }
        Write-Host $MessagePreview
        
        # Show additional properties if available
        if ($_.Properties.Count -gt 0) {
            Write-Host "Properties:  " -ForegroundColor Cyan
            $_.Properties | ForEach-Object {
                Write-Host "             $($_.Value)" -ForegroundColor Gray
            }
        }
        
        Write-Host ("-" * 80) -ForegroundColor DarkGray
    }
}

# Search for each Event ID
foreach ($ID in $EventID) {
    try {
        # Build filter hashtable
        $FilterHash = @{
            LogName = $LogName
            ID = $ID
            StartTime = $StartTime
        }
        
        if ($ProviderName) {
            $FilterHash.Add('ProviderName', $ProviderName)
        }
        
        if ($Level) {
            $FilterHash.Add('Level', $Level)
        }
        
        # Get events
        $Events = Get-WinEvent -FilterHashtable $FilterHash -ErrorAction SilentlyContinue -MaxEvents $MaxResults
        
        Show-EventDetails -Events $Events -EventIDNum $ID
        
    } catch {
        Write-Host "`n--- Event ID $ID ---" -ForegroundColor Yellow
        Write-Host "Description: $(Get-EventDescription -EventIDNum $ID)" -ForegroundColor Cyan
        Write-Host "Status:      Error accessing log - $($_.Exception.Message)" -ForegroundColor Red
    }
}

# Summary statistics
Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "  SUMMARY STATISTICS" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

$EventID | ForEach-Object {
    $ID = $_
    $Count = ($AllResults | Where-Object { $_.EventID -eq $ID }).Count
    $Description = Get-EventDescription -EventIDNum $ID
    
    Write-Host "Event ID $($ID.ToString().PadRight(6))" -NoNewline
    Write-Host " ($($Description.Substring(0, [Math]::Min(50, $Description.Length)))...)" -NoNewline -ForegroundColor Gray
    Write-Host ": " -NoNewline
    
    $Color = if ($Count -gt 0) { "Red" } else { "Green" }
    Write-Host $Count -ForegroundColor $Color
}

Write-Host "`nTotal Events Found: $($AllResults.Count)" -ForegroundColor White

# Export to CSV if requested
if ($ExportToCSV -and $AllResults.Count -gt 0) {
    $ExportPath = "EventLog_Analysis_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
    $AllResults | Export-Csv -Path $ExportPath -NoTypeInformation
    Write-Host "`nResults exported to: $ExportPath" -ForegroundColor Green
}

Write-Host "`n==================================================================" -ForegroundColor Cyan
Write-Host "Analysis Complete - $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')" -ForegroundColor Cyan
Write-Host "==================================================================" -ForegroundColor Cyan

# Handle continuation based on mode
if ($RunOnceMode) {
    # Exit after single run with parameters
    $ContinueRunning = $false
    Write-Host "`nCommand-line mode - Exiting" -ForegroundColor Gray
} else {
    # Show continuation options in interactive mode
    Write-Host "`nOptions:" -ForegroundColor Yellow
    Write-Host "  • Press ENTER to return to main menu and search more events" -ForegroundColor Gray
    Write-Host "  • Press 'Q' to quit" -ForegroundColor Gray

    $NextAction = Read-Host "`nYour choice"

    if ($NextAction.ToUpper() -eq 'Q') {
        $ContinueRunning = $false
    }
    # Otherwise loop continues to main menu
}

} # End of while loop
