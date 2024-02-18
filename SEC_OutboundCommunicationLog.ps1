# Définition du répertoire de destination des logs
$LogFile = "C:\Logs\CommunicationSortante.csv"

# Vérification de l'existence du répertoire de logs, s'il n'existe pas, on le crée
if (-not (Test-Path -Path (Split-Path $LogFile))) {
    New-Item -ItemType Directory -Path (Split-Path $LogFile) | Out-Null
}

# Définition de l'en-tête CSV
$Header = "Timestamp,ProcessName,ProcessId,ProcessPath,LocalAddress,LocalPort,RemoteAddress,RemotePort,Protocol,VirusTotalHarmless,VirusTotalMalicious,VirusTotalSuspicious,VirusTotalUndetected,VirusTotalTimeout "

# Écriture de l'en-tête dans le fichier de log
Add-content -Path $LogFile -Value $Header

# Fonction pour obtenir le rapport VirusTotal pour une adresse IP
function GetVirusTotalReport($IPAddress) {
    $APIKey = "YOUR API KEY"
    $url = "https://www.virustotal.com/api/v3/ip_addresses/$IPAddress"
    $headers = @{
        "x-apikey" = $APIKey
    }

    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get
    return $response
}

# Début de la surveillance des communications sortantes
while ($true) {
    # Récupération des processus qui ont des connexions sortantes
    $OutboundConnections = Get-NetTCPConnection | Where-Object { $_.State -eq "Established" -and $_.LocalAddress -ne "127.0.0.1" }

    # Parcours des connexions sortantes
    foreach ($Connection in $OutboundConnections) {
        $ProcessId = $Connection.OwningProcess
        $Process = Get-Process -Id $ProcessId
        $LocalAddress = $Connection.LocalAddress
        $RemoteAddress = $Connection.RemoteAddress
        $ProtocolNumber = $Connection.Protocol
        $LocalPort = $Connection.LocalPort
        $RemotePort = $Connection.RemotePort

        # Récupération du chemin du processus
        $ProcessPath = $Process.Path

        # Obtention du nom du protocole
        $Protocol = GetProtocolName $ProtocolNumber

        # Analyse de l'adresse IP de destination avec VirusTotal
        $VirusTotalHarmless = (GetVirusTotalReport $RemoteAddress).data.attributes.last_analysis_stats.harmless
        $VirusTotalMalicious = (GetVirusTotalReport $RemoteAddress).data.attributes.last_analysis_stats.malicious
        $VirusTotalSuspicious = (GetVirusTotalReport $RemoteAddress).data.attributes.last_analysis_stats.suspicious
        $VirusTotalUndetected = (GetVirusTotalReport $RemoteAddress).data.attributes.last_analysis_stats.undetected
        $VirusTotalTimeout = (GetVirusTotalReport $RemoteAddress).data.attributes.last_analysis_stats.timeout

        # Construction du message à logger
        $LogMessage = "$((Get-Date).ToString('MM/dd/yyyy HH:mm:ss')), $($Process.Name), $ProcessId, $ProcessPath, $LocalAddress, $LocalPort, $RemoteAddress, $RemotePort, $Protocol, $VirusTotalHarmless, $VirusTotalMalicious, $VirusTotalSuspicious, $VirusTotalUndetected, $VirusTotalTimeout"

        # Écriture du message dans le fichier de log
        Add-content -Path $LogFile -Value $LogMessage
    }

    # Pause pour éviter une utilisation excessive du processeur
    Start-Sleep -Seconds 5
}
