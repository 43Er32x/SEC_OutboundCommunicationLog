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
# PAS de $ErrorActionPreference = "SilentlyContinue" global.
# Chaque appel gere ses erreurs explicitement avec -ErrorAction Stop + try/catch.
$ErrorActionPreference = "Continue"
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
        Calcule le % CPU d'un processus entre deux releves via TotalProcessorTime.
        Retourne $null uniquement si l'acces au processus est vraiment refuse.
    #>
    param(
        [System.Diagnostics.Process]$Process,
        [hashtable]$PreviousCpuTimes,
        [datetime]$PreviousTimestamp,
        [datetime]$CurrentTimestamp,
        [int]$LogicalProcessors
    )

    # Refresh pour avoir les compteurs a jour
    try { $Process.Refresh() } catch { }

    # Lecture directe de TotalProcessorTime
    $currentCpu = $null
    try {
        $currentCpu = $Process.TotalProcessorTime.TotalMilliseconds
    }
    catch {
        # Acces refuse (.NET exception) — fallback Get-Counter
        try {
            $counterPath = "\Process($($Process.Name))\% Processor Time"
            $sample = (Get-Counter -Counter $counterPath -ErrorAction Stop).CounterSamples[0].CookedValue
            return [math]::Round($sample / $LogicalProcessors, 2)
        }
        catch {
            return $null
        }
    }

    # Cle composite PID + StartTime pour detecter recyclage PID
    $startTicks = 0
    try { $startTicks = $Process.StartTime.Ticks } catch { }
    $pid_key = "$($Process.Id)_$startTicks"

    $deltaTimeMs = ($CurrentTimestamp - $PreviousTimestamp).TotalMilliseconds

    if ($PreviousCpuTimes.ContainsKey($pid_key) -and $deltaTimeMs -gt 0) {
        $deltaCpuMs = $currentCpu - $PreviousCpuTimes[$pid_key]
        $PreviousCpuTimes[$pid_key] = $currentCpu

        if ($deltaCpuMs -lt 0) { return 0.0 }

        $cpuPercent = ($deltaCpuMs / ($deltaTimeMs * $LogicalProcessors)) * 100
        if ($cpuPercent -gt 100) { $cpuPercent = 100 }
        return [math]::Round($cpuPercent, 2)
    }
    else {
        # Pas de baseline = premier releve, on enregistre et on retourne 0
        # (pas null : le processus tourne, on a juste pas encore de delta)
        $PreviousCpuTimes[$pid_key] = $currentCpu
        return 0.0
    }
}

function Get-GpuUsageForProcess {
    <#
    .SYNOPSIS
        Recupere l'utilisation GPU d'un processus via les compteurs de performance.
        Retourne $null pour chaque metrique non disponible.
    #>
    param([int]$ProcessId)

    $gpuEngine = $null
    $gpuMemory = $null

    try {
        $counters = Get-Counter -Counter "\GPU Engine(pid_${ProcessId}_*)\Utilization Percentage" -ErrorAction Stop
        if ($counters -and $counters.CounterSamples) {
            $gpuEngine = 0.0
            foreach ($sample in $counters.CounterSamples) {
                $gpuEngine += $sample.CookedValue
            }
            $gpuEngine = [math]::Round($gpuEngine, 2)
        }
    }
    catch { }

    try {
        $memCounters = Get-Counter -Counter "\GPU Process Memory(pid_${ProcessId}_*)\Dedicated Usage" -ErrorAction Stop
        if ($memCounters -and $memCounters.CounterSamples) {
            $gpuMemory = [long]0
            foreach ($sample in $memCounters.CounterSamples) {
                $gpuMemory += $sample.CookedValue
            }
        }
    }
    catch { }

    return @{
        GpuEnginePercent = $gpuEngine
        GpuMemoryBytes   = $gpuMemory
    }
}

function Get-ProcessIOCounters {
    <#
    .SYNOPSIS
        Recupere les compteurs IO. Retourne $null pour chaque metrique non disponible.
    #>
    param([System.Diagnostics.Process]$Process)

    $readBytes = $null
    $writeBytes = $null

    try {
        $counter = Get-Counter -Counter "\Process($($Process.Name))\IO Read Bytes/sec", "\Process($($Process.Name))\IO Write Bytes/sec" -ErrorAction Stop
        if ($counter -and $counter.CounterSamples) {
            $readSample = ($counter.CounterSamples | Where-Object { $_.Path -like "*read*" })
            $writeSample = ($counter.CounterSamples | Where-Object { $_.Path -like "*write*" })
            if ($readSample) { $readBytes = [math]::Round($readSample.CookedValue, 0) }
            if ($writeSample) { $writeBytes = [math]::Round($writeSample.CookedValue, 0) }
        }
    }
    catch { }

    return @{
        IOReadBytesPerSec  = $readBytes
        IOWriteBytesPerSec = $writeBytes
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

# Nombre de processeurs logiques — essai WMI puis fallback .NET
$LogicalProcessors = 0
try {
    $LogicalProcessors = (Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop |
        Measure-Object -Property NumberOfLogicalProcessors -Sum).Sum
}
catch {
    $LogicalProcessors = [Environment]::ProcessorCount
}
if ($LogicalProcessors -le 0) { $LogicalProcessors = [Environment]::ProcessorCount }
if ($LogicalProcessors -le 0) { $LogicalProcessors = 1 }
Write-Host "Processeurs logiques : $LogicalProcessors"

# RAM totale — essai WMI
$TotalRamBytes = 0
try {
    $TotalRamBytes = (Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop).TotalPhysicalMemory
    Write-Host "RAM totale           : $([math]::Round($TotalRamBytes / 1GB, 2)) GB"
}
catch {
    Write-Warning "Impossible de determiner la RAM totale. RAM% sera null."
    $TotalRamBytes = 0
}

$RawSamples = [System.Collections.ArrayList]::new()
$PreviousCpuTimes = @{}
$PreviousTimestamp = Get-Date

# --- Phase de baseline CPU : on capture TotalProcessorTime avant le 1er echantillon ---
Write-Host "Initialisation des baselines CPU..." -ForegroundColor DarkGray
foreach ($procName in $ProcessNames) {
    $procs = Get-Process -Name $procName -ErrorAction SilentlyContinue
    if (-not $procs) {
        Write-Host "  $procName : non trouve (sera retente pendant la collecte)" -ForegroundColor DarkGray
        continue
    }
    foreach ($proc in $procs) {
        try {
            $proc.Refresh()
            $stTicks = 0
            try { $stTicks = $proc.StartTime.Ticks } catch { }
            $pid_key = "$($proc.Id)_$stTicks"
            $PreviousCpuTimes[$pid_key] = $proc.TotalProcessorTime.TotalMilliseconds
            Write-Host "  OK : $($proc.Name) (PID $($proc.Id)) - CPU baseline = $([math]::Round($PreviousCpuTimes[$pid_key]))ms" -ForegroundColor DarkGray
        }
        catch {
            Write-Host "  ECHEC : $($proc.Name) (PID $($proc.Id)) - $($_.Exception.Message)" -ForegroundColor Yellow
        }
    }
}
Start-Sleep -Seconds $IntervalSeconds
$PreviousTimestamp = Get-Date

$StartTime = Get-Date
$SampleIndex = 0

while ((Get-Date) -lt $StartTime.AddSeconds($DurationSeconds)) {
    $SampleTimestamp = Get-Date
    $SampleIndex++

    foreach ($procName in $ProcessNames) {
        $processes = Get-Process -Name $procName -ErrorAction SilentlyContinue

        if (-not $processes) {
            # Processus non trouve — tout a $null sauf les identifiants
            $sample = [PSCustomObject]@{
                SampleIndex         = $SampleIndex
                Timestamp           = $SampleTimestamp.ToString("yyyy-MM-dd HH:mm:ss.fff")
                TimestampUTC        = $SampleTimestamp.ToUniversalTime().ToString("o")
                ProcessName         = $procName
                PID                 = $null
                Status              = "NotRunning"
                CpuPercent          = $null
                RamMB               = $null
                RamPercent          = $null
                WorkingSetMB        = $null
                PrivateBytesMB      = $null
                VirtualMemoryMB     = $null
                ThreadCount         = $null
                HandleCount         = $null
                GpuEnginePercent    = $null
                GpuMemoryMB         = $null
                IOReadBytesPerSec   = $null
                IOWriteBytesPerSec  = $null
                PageFaults          = $null
            }
            [void]$RawSamples.Add($sample)
            continue
        }

        foreach ($proc in $processes) {
            # Refresh une seule fois — les proprietes .NET sont ensuite a jour
            try { $proc.Refresh() } catch { }

            # === CPU ===
            $cpuPercent = $null
            if ($null -ne $LogicalProcessors) {
                $cpuPercent = Get-ProcessCpuPercent -Process $proc `
                    -PreviousCpuTimes $PreviousCpuTimes `
                    -PreviousTimestamp $PreviousTimestamp `
                    -CurrentTimestamp $SampleTimestamp `
                    -LogicalProcessors $LogicalProcessors
            }

            # === RAM === (lectures directes, isolees)
            $ramMB          = try { [math]::Round($proc.WorkingSet64 / 1MB, 2) } catch { $null }
            $ramPercent     = $null
            if ($null -ne $ramMB -and $TotalRamBytes -gt 0) {
                $ramPercent = try { [math]::Round(($proc.WorkingSet64 / $TotalRamBytes) * 100, 2) } catch { $null }
            }
            $privateBytesMB = try { [math]::Round($proc.PrivateMemorySize64 / 1MB, 2) } catch { $null }
            $virtualMB      = try { [math]::Round($proc.VirtualMemorySize64 / 1MB, 2) } catch { $null }

            # === Threads / Handles === (lecture directe)
            $threadCount = try { $proc.Threads.Count } catch { $null }
            $handleCount = try { $proc.HandleCount } catch { $null }

            # === GPU === (compteurs perf — null si pas de GPU ou compteurs absents)
            $gpuInfo = Get-GpuUsageForProcess -ProcessId $proc.Id
            $gpuMemoryMB = $null
            if ($null -ne $gpuInfo.GpuMemoryBytes) {
                $gpuMemoryMB = [math]::Round($gpuInfo.GpuMemoryBytes / 1MB, 2)
            }

            # === IO === (compteurs perf — null si compteurs absents)
            $ioInfo = Get-ProcessIOCounters -Process $proc

            # === Page Faults === (compteur perf — null si absent)
            $pageFaults = $null
            try {
                $pfResult = Get-Counter -Counter "\Process($($proc.Name))\Page Faults/sec" -ErrorAction Stop
                if ($pfResult.CounterSamples[0]) {
                    $pageFaults = [math]::Round($pfResult.CounterSamples[0].CookedValue, 0)
                }
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
                ThreadCount         = $threadCount
                HandleCount         = $handleCount
                GpuEnginePercent    = $gpuInfo.GpuEnginePercent
                GpuMemoryMB         = $gpuMemoryMB
                IOReadBytesPerSec   = $ioInfo.IOReadBytesPerSec
                IOWriteBytesPerSec  = $ioInfo.IOWriteBytesPerSec
                PageFaults          = $pageFaults
            }
            [void]$RawSamples.Add($sample)
        }
    }

    # Mise a jour du timestamp precedent pour le calcul du delta CPU reel
    $PreviousTimestamp = $SampleTimestamp

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
# Fonctions d'agregation null-safe
# ============================================================================

function SafeAgg {
    <#
    .SYNOPSIS
        Agrege une propriete en ignorant les $null. Retourne $null si aucune valeur valide.
    #>
    param(
        [object[]]$Data,
        [string]$Property,
        [ValidateSet("Average","Maximum","Minimum","Sum")]
        [string]$Stat,
        [int]$Decimals = 2
    )
    $valid = $Data | Where-Object { $null -ne $_.$Property } | Select-Object -ExpandProperty $Property
    if (-not $valid -or @($valid).Count -eq 0) { return $null }
    $result = ($valid | Measure-Object -$Stat).$Stat
    if ($null -eq $result) { return $null }
    return [math]::Round($result, $Decimals)
}

function SafeP95 {
    param([object[]]$Data, [string]$Property)
    $valid = $Data | Where-Object { $null -ne $_.$Property } | Sort-Object $Property
    if (-not $valid -or @($valid).Count -eq 0) { return $null }
    $arr = @($valid)
    $idx = [math]::Floor($arr.Count * 0.95)
    if ($idx -ge $arr.Count) { $idx = $arr.Count - 1 }
    return [math]::Round($arr[$idx].$Property, 2)
}

function Format-Val {
    <#
    .SYNOPSIS
        Affiche une valeur ou "null" si $null.
    #>
    param($Value, [string]$Suffix = "")
    if ($null -eq $Value) { return "null" }
    return "$Value$Suffix"
}

# ============================================================================
# Rapport 1 : Stats par processus
# ============================================================================

Write-Host "Generation du rapport par processus..." -ForegroundColor Cyan

$StatsPerProcess = $RawSamples |
    Where-Object { $_.Status -eq "Running" } |
    Group-Object -Property ProcessName |
    ForEach-Object {
        $groupName = $_.Name
        $groupData = @($_.Group)
        $count = $groupData.Count

        [PSCustomObject]@{
            ReportType          = "PerProcess"
            ProcessName         = $groupName
            SampleCount         = $count
            AnalysisDurationSec = $DurationSeconds
            IntervalSec         = $IntervalSeconds
            # CPU
            CpuPercent_Avg      = SafeAgg $groupData "CpuPercent" "Average"
            CpuPercent_Max      = SafeAgg $groupData "CpuPercent" "Maximum"
            CpuPercent_Min      = SafeAgg $groupData "CpuPercent" "Minimum"
            CpuPercent_P95      = SafeP95 $groupData "CpuPercent"
            # RAM
            RamMB_Avg           = SafeAgg $groupData "RamMB" "Average"
            RamMB_Max           = SafeAgg $groupData "RamMB" "Maximum"
            RamPercent_Avg      = SafeAgg $groupData "RamPercent" "Average"
            PrivateBytesMB_Avg  = SafeAgg $groupData "PrivateBytesMB" "Average"
            VirtualMemoryMB_Avg = SafeAgg $groupData "VirtualMemoryMB" "Average"
            # GPU
            GpuEnginePercent_Avg = SafeAgg $groupData "GpuEnginePercent" "Average"
            GpuMemoryMB_Avg     = SafeAgg $groupData "GpuMemoryMB" "Average"
            # IO
            IOReadBytesPerSec_Avg  = SafeAgg $groupData "IOReadBytesPerSec" "Average" 0
            IOWriteBytesPerSec_Avg = SafeAgg $groupData "IOWriteBytesPerSec" "Average" 0
            # Threads / Handles
            ThreadCount_Avg     = SafeAgg $groupData "ThreadCount" "Average" 0
            HandleCount_Avg     = SafeAgg $groupData "HandleCount" "Average" 0
            # Page Faults
            PageFaults_Avg      = SafeAgg $groupData "PageFaults" "Average" 0
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
            $groupData = @($_.Group)
            $count = $groupData.Count

            [PSCustomObject]@{
                ReportType          = "Filtered"
                FilterPattern       = $FilterPattern
                ProcessName         = $groupName
                SampleCount         = $count
                AnalysisDurationSec = $DurationSeconds
                IntervalSec         = $IntervalSeconds
                CpuPercent_Avg      = SafeAgg $groupData "CpuPercent" "Average"
                CpuPercent_Max      = SafeAgg $groupData "CpuPercent" "Maximum"
                RamMB_Avg           = SafeAgg $groupData "RamMB" "Average"
                RamMB_Max           = SafeAgg $groupData "RamMB" "Maximum"
                RamPercent_Avg      = SafeAgg $groupData "RamPercent" "Average"
                GpuEnginePercent_Avg = SafeAgg $groupData "GpuEnginePercent" "Average"
                GpuMemoryMB_Avg     = SafeAgg $groupData "GpuMemoryMB" "Average"
                IOReadBytesPerSec_Avg  = SafeAgg $groupData "IOReadBytesPerSec" "Average" 0
                IOWriteBytesPerSec_Avg = SafeAgg $groupData "IOWriteBytesPerSec" "Average" 0
                ThreadCount_Avg     = SafeAgg $groupData "ThreadCount" "Average" 0
                HandleCount_Avg     = SafeAgg $groupData "HandleCount" "Average" 0
            }
        }
}

# ============================================================================
# Rapport 3 : Stats totales (tous processus confondus)
# ============================================================================

Write-Host "Generation du rapport total..." -ForegroundColor Cyan

$RunningData = @($RawSamples | Where-Object { $_.Status -eq "Running" })
$totalCount = $RunningData.Count

if ($totalCount -gt 0) {
    # Agreger par echantillon (somme des processus par intervalle), null-safe
    $perSampleSums = $RunningData | Group-Object SampleIndex | ForEach-Object {
        $g = @($_.Group)
        [PSCustomObject]@{
            CpuSum      = SafeAgg $g "CpuPercent" "Sum"
            RamMBSum    = SafeAgg $g "RamMB" "Sum"
            RamPctSum   = SafeAgg $g "RamPercent" "Sum"
            GpuEngSum   = SafeAgg $g "GpuEnginePercent" "Sum"
            GpuMemSum   = SafeAgg $g "GpuMemoryMB" "Sum"
            IOReadSum   = SafeAgg $g "IOReadBytesPerSec" "Sum" 0
            IOWriteSum  = SafeAgg $g "IOWriteBytesPerSec" "Sum" 0
            ThreadSum   = SafeAgg $g "ThreadCount" "Sum" 0
            HandleSum   = SafeAgg $g "HandleCount" "Sum" 0
        }
    }
    $pss = @($perSampleSums)

    $StatsTotal = [PSCustomObject]@{
        ReportType              = "Total"
        ProcessesMonitored      = ($ProcessNames -join ";")
        TotalSamples            = $totalCount
        UniqueProcesses         = ($RunningData | Select-Object -ExpandProperty ProcessName -Unique).Count
        AnalysisDurationSec     = $DurationSeconds
        IntervalSec             = $IntervalSeconds
        CpuPercent_Sum_Avg      = SafeAgg $pss "CpuSum" "Average"
        CpuPercent_Sum_Max      = SafeAgg $pss "CpuSum" "Maximum"
        RamMB_Sum_Avg           = SafeAgg $pss "RamMBSum" "Average"
        RamMB_Sum_Max           = SafeAgg $pss "RamMBSum" "Maximum"
        RamPercent_Sum_Avg      = SafeAgg $pss "RamPctSum" "Average"
        GpuEnginePercent_Sum_Avg = SafeAgg $pss "GpuEngSum" "Average"
        GpuMemoryMB_Sum_Avg     = SafeAgg $pss "GpuMemSum" "Average"
        IOReadBytesPerSec_Sum_Avg  = SafeAgg $pss "IOReadSum" "Average" 0
        IOWriteBytesPerSec_Sum_Avg = SafeAgg $pss "IOWriteSum" "Average" 0
        ThreadCount_Sum_Avg     = SafeAgg $pss "ThreadSum" "Average" 0
        HandleCount_Sum_Avg     = SafeAgg $pss "HandleSum" "Average" 0
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
            TotalRamGB        = if ($null -ne $TotalRamBytes) { [math]::Round($TotalRamBytes / 1GB, 2) } else { $null }
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
        Write-Host "    CPU  : Avg=$(Format-Val $stat.CpuPercent_Avg '%')  Max=$(Format-Val $stat.CpuPercent_Max '%')  P95=$(Format-Val $stat.CpuPercent_P95 '%')"
        Write-Host "    RAM  : Avg=$(Format-Val $stat.RamMB_Avg ' MB') ($(Format-Val $stat.RamPercent_Avg '%'))  Max=$(Format-Val $stat.RamMB_Max ' MB')"
        Write-Host "    GPU  : Engine=$(Format-Val $stat.GpuEnginePercent_Avg '%')  VRAM=$(Format-Val $stat.GpuMemoryMB_Avg ' MB')"
        Write-Host "    IO   : Read=$(Format-Val $stat.IOReadBytesPerSec_Avg ' B/s')  Write=$(Format-Val $stat.IOWriteBytesPerSec_Avg ' B/s')"
        Write-Host "    Misc : Threads=$(Format-Val $stat.ThreadCount_Avg)  Handles=$(Format-Val $stat.HandleCount_Avg)  PageFaults=$(Format-Val $stat.PageFaults_Avg '/s')"
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
    Write-Host "    CPU Total  : Avg=$(Format-Val $StatsTotal.CpuPercent_Sum_Avg '%')  Max=$(Format-Val $StatsTotal.CpuPercent_Sum_Max '%')"
    Write-Host "    RAM Total  : Avg=$(Format-Val $StatsTotal.RamMB_Sum_Avg ' MB') ($(Format-Val $StatsTotal.RamPercent_Sum_Avg '%'))  Max=$(Format-Val $StatsTotal.RamMB_Sum_Max ' MB')"
    Write-Host "    GPU Total  : Engine=$(Format-Val $StatsTotal.GpuEnginePercent_Sum_Avg '%')  VRAM=$(Format-Val $StatsTotal.GpuMemoryMB_Sum_Avg ' MB')"
    Write-Host "    IO Total   : Read=$(Format-Val $StatsTotal.IOReadBytesPerSec_Sum_Avg ' B/s')  Write=$(Format-Val $StatsTotal.IOWriteBytesPerSec_Sum_Avg ' B/s')"
    Write-Host "    Misc Total : Threads=$(Format-Val $StatsTotal.ThreadCount_Sum_Avg)  Handles=$(Format-Val $StatsTotal.HandleCount_Sum_Avg)"
}

Write-Host ""
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host " Analyse terminee. Fichiers exportes dans : $OutputDirectory" -ForegroundColor Green
Write-Host "============================================================" -ForegroundColor Cyan
