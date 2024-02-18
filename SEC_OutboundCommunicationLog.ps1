clear
# Définition du répertoire de destination des logs
$LogFile = "C:\Logs\CommunicationSortante.csv"

# Vérification de l'existence du répertoire de logs, s'il n'existe pas, on le crée
if (-not (Test-Path -Path (Split-Path $LogFile))) {
    New-Item -ItemType Directory -Path (Split-Path $LogFile) | Out-Null
}

# Définition de l'en-tête CSV
$Header = "Timestamp,ProcessName,ProcessId,ProcessPath,LocalAddress,LocalPort,RemoteAddress,RemotePort,Protocol"

# Écriture de l'en-tête dans le fichier de log
Add-content -Path $LogFile -Value $Header

# Fonction pour vérifier si une adresse IP est de type 127.0.0.1
function IsLocalhost($ip) {
    return $ip -eq "127.0.0.1"
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
        $Protocol = $Connection.Protocol
        $LocalPort = $Connection.LocalPort
        $RemotePort = $Connection.RemotePort

        # Récupération du chemin du processus
        $ProcessPath = $Process.Path

        # Construction du message à logger
        $LogMessage = "$((Get-Date).ToString('MM/dd/yyyy HH:mm:ss')), $($Process.Name), $ProcessId, $ProcessPath, $LocalAddress, $LocalPort, $RemoteAddress, $RemotePort, $Protocol"

        # Écriture du message dans le fichier de log
        Add-content -Path $LogFile -Value $LogMessage
    }

    # Pause pour éviter une utilisation excessive du processeur
    Start-Sleep -Seconds 5
}
