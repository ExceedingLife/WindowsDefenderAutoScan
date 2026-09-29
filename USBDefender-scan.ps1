# ============================================================
# USB Defender Automatic Scanner
# Script Created by Andrew Harkins
#
# Purpose:
#   - Installs locally to: C:\ProgramData\USBDefenderScan
#   - Installs a scheduled task that watches for USB insertion
#   - Scans removable USB drives with Microsoft Defender
#   - No persistent USB serial/state tracking
#   - Existing scheduled task is NEVER modified
#   - Uses a temporary mutex to prevent duplicate simultaneous scans
#
# Deployment:
#   Computer Configuration
#   -> Windows Settings
#   -> Scripts
#   -> Startup
#   -> PowerShell Scripts
#
# In-Tune Deployment:
#    -> Run using logged-in credentials      (No)
#    -> Run script in 64-bit PowerShell Host (Yes)
#    -> Enforce script signature check       (No)
# ============================================================

param(
    [switch]$Scan
)

$ErrorActionPreference = "Stop"

# ============================================================
# CONFIGURATION
# ============================================================

$InstallDirectory = "C:\ProgramData\USBDefenderScan"
$InstalledScript   = Join-Path $InstallDirectory "USBDefender-scan.ps1"
$LogFile           = Join-Path $InstallDirectory "scan-log.txt"

$TaskName          = "USB Defender Scan"

# Windows Driver Frameworks User-Mode event channel
$EventChannel      = "Microsoft-Windows-DriverFrameworks-UserMode/Operational"

# USB/device arrival event
$EventId            = 2003

# Seconds to wait after the USB event before enumerating drives
$ScanDelaySeconds   = 5

# Temporary mutex name.
# This is NOT persistent state.
$MutexName          = "Global\USBDefenderScanMutex"


# ============================================================
# LOGGING
# ============================================================

function Write-Log {
    param(
        [string]$Message
    )

    try {
        if (-not (Test-Path $InstallDirectory)) {
            New-Item -Path $InstallDirectory -ItemType Directory -Force |
                Out-Null
        }

        $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

        "$Timestamp - $Message" |
            Out-File -FilePath $LogFile -Append -Encoding UTF8
    }
    catch {
        # Do not allow logging failures to break the scanner
    }
}


# ============================================================
# CHECK ADMIN / SYSTEM
# ============================================================

function Test-IsAdministrator {

    $CurrentIdentity = [Security.Principal.WindowsIdentity]::GetCurrent()

    $Principal = New-Object Security.Principal.WindowsPrincipal(
        $CurrentIdentity
    )

    return $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}


# ============================================================
# INSTALL / CONFIGURE
# ============================================================

function Install-USBDefenderScanner {

    Write-Log "============================================================"
    Write-Log "USB Defender GPO deployment starting."
    Write-Log "Computer: $env:COMPUTERNAME"
    Write-Log "Running as: $env:USERNAME"
    Write-Log "============================================================"

    if (-not (Test-IsAdministrator)) {

        Write-Log "ERROR: Script is not running with administrative privileges."

        throw "Administrative privileges are required."
    }


    # --------------------------------------------------------
    # Create installation directory
    # --------------------------------------------------------

    if (-not (Test-Path $InstallDirectory)) {

        Write-Log "Creating installation directory: $InstallDirectory"

        New-Item `
            -Path $InstallDirectory `
            -ItemType Directory `
            -Force |
            Out-Null
    }


    # --------------------------------------------------------
    # Copy the current script to ProgramData
    # --------------------------------------------------------

    $CurrentScript = $PSCommandPath

    if ([string]::IsNullOrWhiteSpace($CurrentScript)) {
        $CurrentScript = $MyInvocation.MyCommand.Path
    }

    if ([string]::IsNullOrWhiteSpace($CurrentScript)) {

        throw "Unable to determine the current script path."
    }

    $CurrentFullPath = [System.IO.Path]::GetFullPath($CurrentScript)

    $InstalledFullPath = [System.IO.Path]::GetFullPath($InstalledScript)


    if ($CurrentFullPath -ne $InstalledFullPath) {

        Write-Log "Updating local scanner script."

        Copy-Item `
            -Path $CurrentScript `
            -Destination $InstalledScript `
            -Force

        Write-Log "Local scanner installed at: $InstalledScript"
    }
    else {

        Write-Log "Running from installed scanner location."
    }


    # --------------------------------------------------------
    # Enable required Windows event log
    # --------------------------------------------------------

    Write-Log "Checking event log: $EventChannel"

    try {

        & wevtutil.exe sl "$EventChannel" /e:true 2>&1 |
            Out-Null

        Write-Log "Event channel enabled successfully."
    }
    catch {

        Write-Log "WARNING: Unable to enable event channel."
        Write-Log "WARNING: $($_.Exception.Message)"
    }


    # --------------------------------------------------------
    # CHECK IF SCHEDULED TASK ALREADY EXISTS
    #
    # IMPORTANT:
    # If it exists, DO NOT MODIFY IT.
    # --------------------------------------------------------

    Write-Log "Checking for scheduled task: $TaskName"

    $ExistingTask = $null

    try {

        $ExistingTask = Get-ScheduledTask `
            -TaskName $TaskName `
            -ErrorAction Stop
    }
    catch {

        $ExistingTask = $null
    }


    if ($null -ne $ExistingTask) {

        Write-Log "Scheduled Task already exists."
        Write-Log "Leaving existing Scheduled Task unchanged."
        Write-Log "Task Path: $($ExistingTask.TaskPath)"
        Write-Log "Task State: $($ExistingTask.State)"

        Write-Log "GPO deployment completed."

        return
    }


    # --------------------------------------------------------
    # CREATE SCHEDULED TASK
    # --------------------------------------------------------

    Write-Log "Scheduled Task does not exist."
    Write-Log "Creating Scheduled Task: $TaskName"


    # PowerShell command executed by Task Scheduler
    $ActionString =
        "powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File `"$InstalledScript`" -Scan"


    # Event XPath query
    $QueryString =
        "*[System[(EventID=$EventId)]]"


    Write-Log "Task Action:"
    Write-Log $ActionString

    Write-Log "Task Event Channel:"
    Write-Log $EventChannel

    Write-Log "Task Event ID:"
    Write-Log $EventId


    # --------------------------------------------------------
    # Create event-triggered task
    # --------------------------------------------------------

    & schtasks.exe /Create `
        /TN "$TaskName" `
        /TR "$ActionString" `
        /SC ONEVENT `
        /EC "$EventChannel" `
        /MO "$QueryString" `
        /RU SYSTEM `
        /RL HIGHEST `
        /F


    if ($LASTEXITCODE -ne 0) {

        Write-Log "ERROR: schtasks.exe failed."
        Write-Log "ERROR: Exit code $LASTEXITCODE"

        throw "Failed to create Scheduled Task."
    }


    Write-Log "Scheduled Task created successfully."


    # --------------------------------------------------------
    # Verify task exists
    # --------------------------------------------------------

    try {

        $VerifyTask = Get-ScheduledTask `
            -TaskName $TaskName `
            -ErrorAction Stop

        Write-Log "Task verification successful."
        Write-Log "Task State: $($VerifyTask.State)"
        Write-Log "Task Path: $($VerifyTask.TaskPath)"
    }
    catch {

        Write-Log "ERROR: Scheduled Task was created but could not be verified."

        throw
    }


    Write-Log "USB Defender GPO deployment completed."
}


# ============================================================
# SCAN USB DRIVES
# ============================================================

function Invoke-USBDefenderScan {

    Write-Log "============================================================"
    Write-Log "USB Defender scan triggered."
    Write-Log "Computer: $env:COMPUTERNAME"
    Write-Log "============================================================"


    # --------------------------------------------------------
    # Prevent duplicate simultaneous scans
    #
    # This is temporary memory only.
    # Nothing is written to disk.
    # --------------------------------------------------------

    $Mutex = $null

    try {

        $Mutex = New-Object System.Threading.Mutex(
            $false,
            $MutexName
        )

        $MutexAcquired = $Mutex.WaitOne(0)

        if (-not $MutexAcquired) {

            Write-Log "Another USB Defender scan is already running."
            Write-Log "Exiting duplicate scan event."

            return
        }


        # ----------------------------------------------------
        # Wait for Windows to finish mounting the USB drive
        # ----------------------------------------------------

        Write-Log "Waiting $ScanDelaySeconds seconds for USB device initialization."

        Start-Sleep -Seconds $ScanDelaySeconds


        # ----------------------------------------------------
        # Verify Microsoft Defender is available
        # ----------------------------------------------------

        try {

            $DefenderStatus = Get-MpComputerStatus

            if ($null -eq $DefenderStatus) {

                Write-Log "ERROR: Microsoft Defender status could not be obtained."

                return
            }


            Write-Log "Microsoft Defender status detected."

            Write-Log "Antivirus Enabled: $($DefenderStatus.AntivirusEnabled)"
            Write-Log "Real-Time Protection Enabled: $($DefenderStatus.RealTimeProtectionEnabled)"
            Write-Log "AM Service Enabled: $($DefenderStatus.AMServiceEnabled)"

        }
        catch {

            Write-Log "ERROR: Microsoft Defender PowerShell module is unavailable."
            Write-Log "ERROR: $($_.Exception.Message)"

            return
        }


        # ----------------------------------------------------
        # Find removable drives
        # DriveType 2 = Removable Disk
        # ----------------------------------------------------

        Write-Log "Enumerating removable drives."

        $RemovableDrives = @(
            Get-CimInstance Win32_LogicalDisk `
                -Filter "DriveType=2"
        )


        if ($RemovableDrives.Count -eq 0) {

            Write-Log "No removable drives detected."
            Write-Log "Scan completed."

            return
        }


        # ----------------------------------------------------
        # Scan each removable drive
        # ----------------------------------------------------

        foreach ($Drive in $RemovableDrives) {

            $DriveLetter = $Drive.DeviceID

            if ([string]::IsNullOrWhiteSpace($DriveLetter)) {
                continue
            }


            $ScanPath = "$DriveLetter\"


            Write-Log "------------------------------------------------------------"
            Write-Log "USB DRIVE DETECTED: $ScanPath"
            Write-Log "Volume Name: $($Drive.VolumeName)"
            Write-Log "File System: $($Drive.FileSystem)"
            Write-Log "Volume Serial: $($Drive.VolumeSerialNumber)"
            Write-Log "Starting Microsoft Defender Custom Scan."
            Write-Log "Scan Path: $ScanPath"


            $ScanStart = Get-Date


            try {

                Start-MpScan `
                    -ScanType CustomScan `
                    -ScanPath $ScanPath


                $ScanEnd = Get-Date

                $Duration = New-TimeSpan `
                    -Start $ScanStart `
                    -End $ScanEnd


                Write-Log "Microsoft Defender scan command completed."
                Write-Log "Scan duration: $($Duration.ToString())"


                # ------------------------------------------------
                # Check Defender threat history
                # ------------------------------------------------

                try {

                    $RecentThreats = @(
                        Get-MpThreatDetection |
                            Where-Object {
                                $_.InitialDetectionTime -ge $ScanStart
                            }
                    )


                    if ($RecentThreats.Count -gt 0) {

                        Write-Log "!!! THREAT DETECTION(S) FOUND !!!"
                        Write-Log "Threat count: $($RecentThreats.Count)"


                        foreach ($Threat in $RecentThreats) {

                            Write-Log "Threat: $($Threat.ThreatName)"
                            Write-Log "Action: $($Threat.ActionSuccess)"
                            Write-Log "Detection Time: $($Threat.InitialDetectionTime)"
                            Write-Log "Resources: $($Threat.Resources)"
                        }
                    }
                    else {

                        Write-Log "No new Defender threat detections were reported."
                    }

                }
                catch {

                    Write-Log "WARNING: Unable to query Defender threat history."
                    Write-Log "WARNING: $($_.Exception.Message)"
                }


            }
            catch {

                Write-Log "ERROR: Defender scan failed for $ScanPath"
                Write-Log "ERROR: $($_.Exception.Message)"
            }


            Write-Log "Finished processing $ScanPath"
            Write-Log "------------------------------------------------------------"
        }


        Write-Log "USB Defender scan completed."
    }
    catch {

        Write-Log "FATAL SCAN ERROR:"
        Write-Log $_.Exception.Message

        throw
    }
    finally {

        if ($null -ne $Mutex) {

            try {
                $Mutex.ReleaseMutex()
            }
            catch {
            }

            try {
                $Mutex.Dispose()
            }
            catch {
            }
        }
    }
}


# ============================================================
# MAIN
# ============================================================

try {

    if ($Scan) {

        Invoke-USBDefenderScan
    }
    else {

        Install-USBDefenderScanner
    }

}
catch {

    Write-Log "============================================================"
    Write-Log "SCRIPT ERROR"
    Write-Log $_.Exception.Message
    Write-Log "============================================================"

    throw
}