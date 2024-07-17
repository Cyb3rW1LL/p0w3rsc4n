# P0w3r$c4n.ps1
# Author: Cyb3rW1LL
 

# Set-ExecutionPolicy Bypass/RemoteSigned
# Install-Module PSParallel
Import-Module PSParallel

# Function to send a TCP SYN packet and get the TTL value
function GET-TTL {
    param (
        [string]$Target,
        [int]$Ports = 443
    )
    try {
        # Send a TCP SYN packet to the target
        $tcpClient = New-Object System.Net.Sockets.TcpClient
        $tcpClient.Connect($Target, $Port)
        $tcpClient.Close()
        
        # Get the TTL value
        $ttl = $tcpClient.Client.Ttl
        return $ttl
	if ($ttl -ge 128) {
          return "Windows"
    } elseif ($ttl -le 64) {
        return "Linux/Unix"
    } else {
        return "Unknown"
    }
    } catch {
        Write-Host "Failed to connect to $Target on port $Port"
        return $null
    }
}

