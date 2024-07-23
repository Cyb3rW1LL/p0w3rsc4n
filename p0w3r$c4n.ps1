# P0w3r$c4n.ps1
# Author: Cyb3rW1LL
 

# Commandline parameters to run scan with
# EXAMPLE \.scanner.ps1 -ComputerName localhost 

$def_scan1 = @(1..1000)
$scan_1 = @(20,21,22,23,25,53,80,88,111,121,123,135,137,138,139,389,443,445,464,5044,5353,5601,8200,9200,9300,9800)
$min_port = 1
$max_port = 65535

[CmdletBinding()]
param(
    [Parameter(Position = 0, Mandatory = $true,
    Message = 'Hostname/IPv4/IPv6-Address of device')]
    [String]$HostName,

    [Parameter(Position = 1,
    Message = 'First port which should be scanned (Default=1)')]
    [ValidateRange(1, 65535)]
    [Int32]$StartPort = 1,

    [Parameter(Position = 2,
    Message = 'Last port which should be scanned (Default=65535)')]
    [ValidateRange(1, 65535)]
    [ValidateScript({
            if ($_ -lt $StartPort) {
                throw "Invalid Port-Range!"
            }
            else {
                return $true
            }
        })]
    [Int32]$EndPort = 65535,

    [Parameter(Position = 3,
        Message = 'Maximum number of threads at the same time (Default=100)')]
    [Int32]$Threads = 100,

    [Parameter(Position = 4,
        Message = 'Execute script without user interaction')]
    [switch]$Force
)


# Get the TTL of the target device
function GET-TTL {
    param (
        [string]$Target,
        [int]$Port = 443
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
    } elseif ($ttl -eq 255) {
    	return "Cisco Device"
    } else {
        return "Unknown"
    }
    } catch {
        Write-Host "Failed to connect to $Target on port $Port. Port may be closed"
        return $null
    }
}
