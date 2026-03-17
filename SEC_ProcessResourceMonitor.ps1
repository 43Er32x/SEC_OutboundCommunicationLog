#Requires -Version 5.1
<#
.SYNOPSIS
    Monitore la consommation CPU/RAM/GPU/IO d'une liste de processus sur une duree configurable.

.DESCRIPTION
    Collecte periodiquement les metriques de performance (CPU, RAM, GPU, IO disque, IO reseau,
    handles, threads) pour chaque processus surveille, puis genere :
      - Un rapport par processus
      - Un rapport filtre (pattern)
      - Un rapport total (toutes metriques agregees)
    L'export se fait en CSV (compatible BI : Power BI, Tableau, etc.) et optionnellement en JSON.

.PARAMETER ProcessNames
    Liste des noms de processus a surveiller (sans extension .exe).

.PARAMETER DurationSeconds
    Duree totale de l'analyse en secondes.

.PARAMETER IntervalSeconds
    Frequence de releve en secondes.

.PARAMETER OutputDirectory
    Repertoire de sortie pour les fichiers d'export.

.PARAMETER ExportFormat
    Format d'export : CSV, JSON ou Both.

.PARAMETER FilterPattern
    Pattern (regex) pour filtrer les processus dans le rapport filtre.

.EXAMPLE
    .\SEC_ProcessResourceMonitor.ps1 -ProcessNames "SentinelAgent","agent","vf_agent" -DurationSeconds 300 -IntervalSeconds 5
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string[]]$ProcessNames = @("SentinelAgent", "agent", "vf_agent"),

    [Parameter(Mandatory = $false)]
    [int]$DurationSeconds = 60,

    [Parameter(Mandatory = $false)]
    [int]$IntervalSeconds = 5,

    [Parameter(Mandatory = $false)]
    [string]$OutputDirectory = ".\SEC_Monitor_Output",

    [Parameter(Mandatory = $false)]
    [ValidateSet("CSV", "JSON", "Both")]
    [string]$ExportFormat = "Both",

    [Parameter(Mandatory = $false)]
    [string]$FilterPattern = ""
)

# ============================================================================
# Configuration
# ============================================================================
$ErrorActionPreference = "SilentlyContinue"
$Timestamp = Get-Date -Format "yyyyMMdd_HHmmss"

if (-not (Test-Path -Path $OutputDirectory)) {
    New-Item -ItemType Directory -Path $OutputDirectory -Force | Out-Null
}

# ============================================================================
# Fonctions utilitaires
# ============================================================================

function Get-ProcessCpuPercent {
    <#
    .SYNOPSIS
        Calcule le pourcentage CPU d'un processus entre deux releves.
    #>
    param(
        [System.Diagnostics.Process]$Process,
        [hashtable]$PreviousCpuTimes,
        [double]$ElapsedSeconds,
        [int]$LogicalProcessors
    )

    $pid_key = "$($Process.Id)"
    $currentCpu = $Process.TotalProcessorTime.TotalMilliseconds

    if ($PreviousCpuTimes.ContainsKey($pid_key)) {
        $deltaCpu = $currentCpu - $PreviousCpuTimes[$pid_key]
        $cpuPercent = ($deltaCpu / ($ElapsedSeconds * 1000 * $LogicalProcessors)) * 100
        if ($cpuPercent -lt 0) { $cpuPercent = 0 }
        if ($cpuPercent -gt 100) { $cpuPercent = 100 }
    }
    else {
        $cpuPercent = 0
    }

    $PreviousCpuTimes[$pid_key] = $currentCpu
    return [math]::Round($cpuPercent, 2)
}

function Get-GpuUsageForProcess {
    <#
    .SYNOPSIS
        Recupere l'utilisation GPU d'un processus via les compteurs de performance.
        Retourne un objet avec GPU Engine (3D/Compute/etc.) et GPU Memory.
    #>
    param([int]$ProcessId)

    $gpuEngine = 0.0
    $gpuMemory = 0

    try {
        $counters = Get-Counter -Counter "\GPU Engine(pid_${ProcessId}_*)\Utilization Percentage" -ErrorAction SilentlyContinue
        if ($counters) {
            foreach ($sample in $counters.CounterSamples) {
                $gpuEngine += $sample.CookedValue
            }
        }
    }
    catch { }

    try {
        $memCounters = Get-Counter -Counter "\GPU Process Memory(pid_${ProcessId}_*)\Dedicated Usage" -ErrorAction SilentlyContinue
        if ($memCounters) {
            foreach ($sample in $memCounters.CounterSamples) {
                $gpuMemory += $sample.CookedValue
            }
        }
    }
    catch { }

    return @{
        GpuEnginePercent = [math]::Round($gpuEngine, 2)
        GpuMemoryBytes   = [long]$gpuMemory
    }
}

function Get-ProcessIOCounters {
    <#
    .SYNOPSIS
        Recupere les compteurs IO via les proprietes .NET du processus.
    #>
    param([System.Diagnostics.Process]$Process)

    try {
        # Ces proprietes ne sont pas exposees directement en .NET sur toutes les versions.
        # On utilise les compteurs de performance comme fallback.
        $counter = Get-Counter -Counter "\Process($($Process.Name))\IO Read Bytes/sec", "\Process($($Process.Name))\IO Write Bytes/sec" -ErrorAction SilentlyContinue
        if ($counter) {
            $readBytes = ($counter.CounterSamples | Where-Object { $_.Path -like "*read*" }).CookedValue
            $writeBytes = ($counter.CounterSamples | Where-Object { $_.Path -like "*write*" }).CookedValue
            return @{
                IOReadBytesPerSec  = [math]::Round($readBytes, 0)
                IOWriteBytesPerSec = [math]::Round($writeBytes, 0)
            }
        }
    }
    catch { }

    return @{
        IOReadBytesPerSec  = 0
        IOWriteBytesPerSec = 0
    }
}

# ============================================================================
# Collecte des donnees
# ============================================================================

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " SEC Process Resource Monitor" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "Processus surveilles : $($ProcessNames -join ', ')"
Write-Host "Duree d'analyse      : $DurationSeconds secondes"
Write-Host "Frequence de releve  : $IntervalSeconds secondes"
Write-Host "Format d'export      : $ExportFormat"
Write-Host "Repertoire de sortie : $OutputDirectory"
if ($FilterPattern) {
    Write-Host "Filtre processus     : $FilterPattern"
}
Write-Host "------------------------------------------------------------"
Write-Host "Demarrage de la collecte..." -ForegroundColor Green
Write-Host ""

$LogicalProcessors = (Get-CimInstance -ClassName Win32_Processor -ErrorAction SilentlyContinue |
    Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
if (-not $LogicalProcessors -or $LogicalProcessors -eq 0) {
    $LogicalProcessors = [Environment]::ProcessorCount
}
if (-not $LogicalProcessors -or $LogicalProcessors -eq 0) {
    $LogicalProcessors = 1
}

$TotalRamBytes = 0
try {
    $TotalRamBytes = (Get-CimInstance -ClassName Win32_ComputerSystem).TotalPhysicalMemory
}
catch {
    $TotalRamBytes = 8GB  # fallback
}

$RawSamples = [System.Collections.ArrayList]::new()
$PreviousCpuTimes = @{}
$StartTime = Get-Date
$SampleIndex = 0

while ((Get-Date) -lt $StartTime.AddSeconds($DurationSeconds)) {
    $SampleTimestamp = Get-Date
    $SampleIndex++

    foreach ($procName in $ProcessNames) {
        $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue

        if (-not $processes) {
            # Processus non trouve, on enregistre une ligne a zero
            $sample = [PSCustomObject]@{
                SampleIndex         = $SampleIndex
                Timestamp           = $SampleTimestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")
                TimestampUTC        = $SampleTimestamp.ToUniversalTime().ToString("o")
                ProcessName         = $procName
                PID                 = -1
                Status              = "NotRunning"
                CpuPercent          = 0
                RamMB               = 0
                RamPercent          = 0
                WorkingSetMB        = 0
                PrivateBytesMB      = 0
                VirtualMemoryMB     = 0
                ThreadCount         = 0
                HandleCount         = 0
                GpuEnginePercent    = 0
                GpuMemoryMB         = 0
                IOReadBytesPerSec   = 0
                IOWriteBytesPerSec  = 0
                PageFaults          = 0
            }
            [void]$RawSamples.Add($sample)
            continue
        }

        foreach ($proc in $processes) {
            # CPU
            $cpuPercent = Get-ProcessCpuPercent -Process $proc `
                -PreviousCpuTimes $PreviousCpuTimes `
                -ElapsedSeconds $IntervalSeconds `
                -LogicalProcessors $LogicalProcessors

            # RAM
            $ramBytes = $proc.WorkingSet64
            $ramMB = [math]::Round($ramBytes / 1MB, 2)
            $ramPercent = [math]::Round(($ramBytes / $TotalRamBytes) * 100, 2)
            $privateBytesMB = [math]::Round($proc.PrivateMemorySize64 / 1MB, 2)
            $virtualMB = [math]::Round($proc.VirtualMemorySize64 / 1MB, 2)

            # GPU
            $gpuInfo = Get-GpuUsageForProcess -ProcessId $proc.Id
            $gpuMemoryMB = [math]::Round($gpuInfo.GpuMemoryBytes / 1MB, 2)

            # IO
            $ioInfo = Get-ProcessIOCounters -Process $proc

            # Page faults (non-paged pool)
            $pageFaults = 0
            try {
                $pageFaults = (Get-Counter -Counter "\Process($($proc.Name))\Page Faults/sec" -ErrorAction SilentlyContinue).CounterSamples[0].CookedValue
                $pageFaults = [math]::Round($pageFaults, 0)
            }
            catch { }

            $sample = [PSCustomObject]@{
                SampleIndex         = $SampleIndex
                Timestamp           = $SampleTimestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")
                TimestampUTC        = $SampleTimestamp.ToUniversalTime().ToString("o")
                ProcessName         = $proc.Name
                PID                 = $proc.Id
                Status              = "Running"
                CpuPercent          = $cpuPercent
                RamMB               = $ramMB
                RamPercent          = $ramPercent
                WorkingSetMB        = $ramMB
                PrivateBytesMB      = $privateBytesMB
                VirtualMemoryMB     = $virtualMB
                ThreadCount         = $proc.Threads.Count
                HandleCount         = $proc.HandleCount
                GpuEnginePercent    = $gpuInfo.GpuEnginePercent
                GpuMemoryMB         = $gpuMemoryMB
                IOReadBytesPerSec   = $ioInfo.IOReadBytesPerSec
                IOWriteBytesPerSec  = $ioInfo.IOWriteBytesPerSec
                PageFaults          = $pageFaults
            }
            [void]$RawSamples.Add($sample)
        }
    }

    # Progression
    $elapsed = ((Get-Date) - $StartTime).TotalSeconds
    $progress = [math]::Min(100, [math]::Round(($elapsed / $DurationSeconds) * 100, 0))
    Write-Host "`r  [$progress%] Echantillon $SampleIndex - $($RawSamples.Count) mesures collectees" -NoNewline -ForegroundColor Yellow

    Start-Sleep -Seconds $IntervalSeconds
}

Write-Host ""
Write-Host ""
Write-Host "Collecte terminee : $($RawSamples.Count) mesures sur $SampleIndex echantillons." -ForegroundColor Green
Write-Host ""

# ============================================================================
# Rapport 1 : Stats par processus
# ============================================================================

Write-Host "Generation du rapport par processus..." -ForegroundColor Cyan

$StatsPerProcess = $RawSamples |
    Where-Object { $_.Status -eq "Running" } |
    Group-Object -Property ProcessName |
    ForEach-Object {
        $groupName = $_.Name
        $groupData = $_.Group
        $count = $groupData.Count

        [PSCustomObject]@{
            ReportType          = "PerProcess"
            ProcessName         = $groupName
            SampleCount         = $count
            AnalysisDurationSec = $DurationSeconds
            IntervalSec         = $IntervalSeconds
            # CPU
            CpuPercent_Avg      = [math]::Round(($groupData | Measure-Object -Property CpuPercent -Average).Average, 2)
            CpuPercent_Max      = [math]::Round(($groupData | Measure-Object -Property CpuPercent -Maximum).Maximum, 2)
            CpuPercent_Min      = [math]::Round(($groupData | Measure-Object -Property CpuPercent -Minimum).Minimum, 2)
            CpuPercent_P95      = [math]::Round(($groupData | Sort-Object CpuPercent | Select-Object -Skip ([math]::Floor($count * 0.95)) -First 1).CpuPercent, 2)
            # RAM
            RamMB_Avg           = [math]::Round(($groupData | Measure-Object -Property RamMB -Average).Average, 2)
            RamMB_Max           = [math]::Round(($groupData | Measure-Object -Property RamMB -Maximum).Maximum, 2)
            RamPercent_Avg      = [math]::Round(($groupData | Measure-Object -Property RamPercent -Average).Average, 2)
            PrivateBytesMB_Avg  = [math]::Round(($groupData | Measure-Object -Property PrivateBytesMB -Average).Average, 2)
            VirtualMemoryMB_Avg = [math]::Round(($groupData | Measure-Object -Property VirtualMemoryMB -Average).Average, 2)
            # GPU
            GpuEnginePercent_Avg = [math]::Round(($groupData | Measure-Object -Property GpuEnginePercent -Average).Average, 2)
            GpuMemoryMB_Avg     = [math]::Round(($groupData | Measure-Object -Property GpuMemoryMB -Average).Average, 2)
            # IO
            IOReadBytesPerSec_Avg  = [math]::Round(($groupData | Measure-Object -Property IOReadBytesPerSec -Average).Average, 0)
            IOWriteBytesPerSec_Avg = [math]::Round(($groupData | Measure-Object -Property IOWriteBytesPerSec -Average).Average, 0)
            # Threads / Handles
            ThreadCount_Avg     = [math]::Round(($groupData | Measure-Object -Property ThreadCount -Average).Average, 0)
            HandleCount_Avg     = [math]::Round(($groupData | Measure-Object -Property HandleCount -Average).Average, 0)
            # Page Faults
            PageFaults_Avg      = [math]::Round(($groupData | Measure-Object -Property PageFaults -Average).Average, 0)
        }
    }

# ============================================================================
# Rapport 2 : Stats par processus filtre
# ============================================================================

if ($FilterPattern) {
    Write-Host "Generation du rapport filtre (pattern: $FilterPattern)..." -ForegroundColor Cyan

    $StatsFiltered = $RawSamples |
        Where-Object { $_.Status -eq "Running" -and $_.ProcessName -match $FilterPattern } |
        Group-Object -Property ProcessName |
        ForEach-Object {
            $groupName = $_.Name
            $groupData = $_.Group
            $count = $groupData.Count

            [PSCustomObject]@{
                ReportType          = "Filtered"
                FilterPattern       = $FilterPattern
                ProcessName         = $groupName
                SampleCount         = $count
                AnalysisDurationSec = $DurationSeconds
                IntervalSec         = $IntervalSeconds
                CpuPercent_Avg      = [math]::Round(($groupData | Measure-Object -Property CpuPercent -Average).Average, 2)
                CpuPercent_Max      = [math]::Round(($groupData | Measure-Object -Property CpuPercent -Maximum).Maximum, 2)
                RamMB_Avg           = [math]::Round(($groupData | Measure-Object -Property RamMB -Average).Average, 2)
                RamMB_Max           = [math]::Round(($groupData | Measure-Object -Property RamMB -Maximum).Maximum, 2)
                RamPercent_Avg      = [math]::Round(($groupData | Measure-Object -Property RamPercent -Average).Average, 2)
                GpuEnginePercent_Avg = [math]::Round(($groupData | Measure-Object -Property GpuEnginePercent -Average).Average, 2)
                GpuMemoryMB_Avg     = [math]::Round(($groupData | Measure-Object -Property GpuMemoryMB -Average).Average, 2)
                IOReadBytesPerSec_Avg  = [math]::Round(($groupData | Measure-Object -Property IOReadBytesPerSec -Average).Average, 0)
                IOWriteBytesPerSec_Avg = [math]::Round(($groupData | Measure-Object -Property IOWriteBytesPerSec -Average).Average, 0)
                ThreadCount_Avg     = [math]::Round(($groupData | Measure-Object -Property ThreadCount -Average).Average, 0)
                HandleCount_Avg     = [math]::Round(($groupData | Measure-Object -Property HandleCount -Average).Average, 0)
            }
        }
}

# ============================================================================
# Rapport 3 : Stats totales (tous processus confondus)
# ============================================================================

Write-Host "Generation du rapport total..." -ForegroundColor Cyan

$RunningData = $RawSamples | Where-Object { $_.Status -eq "Running" }
$totalCount = $RunningData.Count

if ($totalCount -gt 0) {
    $StatsTotal = [PSCustomObject]@{
        ReportType              = "Total"
        ProcessesMonitored      = ($ProcessNames -join ";")
        TotalSamples            = $totalCount
        UniqueProcesses         = ($RunningData | Select-Object -ExpandProperty ProcessName -Unique).Count
        AnalysisDurationSec     = $DurationSeconds
        IntervalSec             = $IntervalSeconds
        # CPU agrege
        CpuPercent_Sum_Avg      = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property CpuPercent -Sum).Sum } | Measure-Object -Average).Average, 2)
        CpuPercent_Sum_Max      = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property CpuPercent -Sum).Sum } | Measure-Object -Maximum).Maximum, 2)
        # RAM agrege
        RamMB_Sum_Avg           = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property RamMB -Sum).Sum } | Measure-Object -Average).Average, 2)
        RamMB_Sum_Max           = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property RamMB -Sum).Sum } | Measure-Object -Maximum).Maximum, 2)
        RamPercent_Sum_Avg      = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property RamPercent -Sum).Sum } | Measure-Object -Average).Average, 2)
        # GPU agrege
        GpuEnginePercent_Sum_Avg = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property GpuEnginePercent -Sum).Sum } | Measure-Object -Average).Average, 2)
        GpuMemoryMB_Sum_Avg     = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property GpuMemoryMB -Sum).Sum } | Measure-Object -Average).Average, 2)
        # IO agrege
        IOReadBytesPerSec_Sum_Avg  = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property IOReadBytesPerSec -Sum).Sum } | Measure-Object -Average).Average, 0)
        IOWriteBytesPerSec_Sum_Avg = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property IOWriteBytesPerSec -Sum).Sum } | Measure-Object -Average).Average, 0)
        # Threads / Handles
        ThreadCount_Sum_Avg     = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property ThreadCount -Sum).Sum } | Measure-Object -Average).Average, 0)
        HandleCount_Sum_Avg     = [math]::Round(($RunningData | Group-Object SampleIndex | ForEach-Object { ($_.Group | Measure-Object -Property HandleCount -Sum).Sum } | Measure-Object -Average).Average, 0)
    }
}

# ============================================================================
# Export
# ============================================================================

Write-Host "Export des donnees..." -ForegroundColor Cyan

$filePrefix = "SEC_ProcessMonitor_$Timestamp"

# --- Donnees brutes (pour BI : 1 ligne = 1 mesure = 1 fait) ---
if ($ExportFormat -eq "CSV" -or $ExportFormat -eq "Both") {
    $rawCsvPath = Join-Path $OutputDirectory "${filePrefix}_RawSamples.csv"
    $RawSamples | Export-Csv -Path $rawCsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Host "  [CSV] Donnees brutes  : $rawCsvPath" -ForegroundColor White

    $statsCsvPath = Join-Path $OutputDirectory "${filePrefix}_StatsPerProcess.csv"
    $StatsPerProcess | Export-Csv -Path $statsCsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
    Write-Host "  [CSV] Stats/processus : $statsCsvPath" -ForegroundColor White

    if ($FilterPattern -and $StatsFiltered) {
        $filteredCsvPath = Join-Path $OutputDirectory "${filePrefix}_StatsFiltered.csv"
        $StatsFiltered | Export-Csv -Path $filteredCsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
        Write-Host "  [CSV] Stats filtrees  : $filteredCsvPath" -ForegroundColor White
    }

    if ($StatsTotal) {
        $totalCsvPath = Join-Path $OutputDirectory "${filePrefix}_StatsTotal.csv"
        $StatsTotal | Export-Csv -Path $totalCsvPath -NoTypeInformation -Encoding UTF8 -Delimiter ";"
        Write-Host "  [CSV] Stats totales   : $totalCsvPath" -ForegroundColor White
    }
}

if ($ExportFormat -eq "JSON" -or $ExportFormat -eq "Both") {
    $jsonData = @{
        Metadata = @{
            GeneratedAt       = (Get-Date).ToString("o")
            MachineName       = $env:COMPUTERNAME
            LogicalProcessors = $LogicalProcessors
            TotalRamGB        = [math]::Round($TotalRamBytes / 1GB, 2)
            DurationSeconds   = $DurationSeconds
            IntervalSeconds   = $IntervalSeconds
            ProcessesMonitored = $ProcessNames
            FilterPattern     = $FilterPattern
            TotalSamples      = $RawSamples.Count
        }
        RawSamples      = $RawSamples
        StatsPerProcess = $StatsPerProcess
        StatsFiltered   = if ($FilterPattern) { $StatsFiltered } else { $null }
        StatsTotal      = $StatsTotal
    }

    $jsonPath = Join-Path $OutputDirectory "${filePrefix}_FullReport.json"
    $jsonData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
    Write-Host "  [JSON] Rapport complet : $jsonPath" -ForegroundColor White
}

# ============================================================================
# Resume console
# ============================================================================

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " RESUME - Stats par processus" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan

if ($StatsPerProcess) {
    foreach ($stat in $StatsPerProcess) {
        Write-Host ""
        Write-Host "  $($stat.ProcessName)" -ForegroundColor Yellow
        Write-Host "    CPU  : Avg=$($stat.CpuPercent_Avg)%  Max=$($stat.CpuPercent_Max)%  P95=$($stat.CpuPercent_P95)%"
        Write-Host "    RAM  : Avg=$($stat.RamMB_Avg) MB ($($stat.RamPercent_Avg)%)  Max=$($stat.RamMB_Max) MB"
        Write-Host "    GPU  : Engine=$($stat.GpuEnginePercent_Avg)%  VRAM=$($stat.GpuMemoryMB_Avg) MB"
        Write-Host "    IO   : Read=$($stat.IOReadBytesPerSec_Avg) B/s  Write=$($stat.IOWriteBytesPerSec_Avg) B/s"
        Write-Host "    Misc : Threads=$($stat.ThreadCount_Avg)  Handles=$($stat.HandleCount_Avg)  PageFaults=$($stat.PageFaults_Avg)/s"
    }
}
else {
    Write-Host "  Aucun processus surveille n'etait actif pendant l'analyse." -ForegroundColor Red
}

if ($StatsTotal) {
    Write-Host ""
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host " RESUME - Total (tous processus)" -ForegroundColor Cyan
    Write-Host "============================================================" -ForegroundColor Cyan
    Write-Host "    CPU Total  : Avg=$($StatsTotal.CpuPercent_Sum_Avg)%  Max=$($StatsTotal.CpuPercent_Sum_Max)%"
    Write-Host "    RAM Total  : Avg=$($StatsTotal.RamMB_Sum_Avg) MB ($($StatsTotal.RamPercent_Sum_Avg)%)  Max=$($StatsTotal.RamMB_Sum_Max) MB"
    Write-Host "    GPU Total  : Engine=$($StatsTotal.GpuEnginePercent_Sum_Avg)%  VRAM=$($StatsTotal.GpuMemoryMB_Sum_Avg) MB"
    Write-Host "    IO Total   : Read=$($StatsTotal.IOReadBytesPerSec_Sum_Avg) B/s  Write=$($StatsTotal.IOWriteBytesPerSec_Sum_Avg) B/s"
    Write-Host "    Misc Total : Threads=$($StatsTotal.ThreadCount_Sum_Avg)  Handles=$($StatsTotal.HandleCount_Sum_Avg)"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Analyse terminee. Fichiers exportes dans : $OutputDirectory" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
