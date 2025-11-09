# P0w3r$c4n.ps1
# Author: Cyb3rW1LL

# --- Example Usage ---
# 1. Scan a single IP (Replace with an IP on your network)
# Invoke-NetworkScan with multiple ports: -Target "192.168.1.10" -Ports 80, 443, 3389
# 2. Scan a range (Replace with a range in your network)
# Note: For best results, keep ranges small (e.g., 1-50)
# Invoke-NetworkScan -Target "192.168.1.1-20"

<#
.SYNOPSIS:
    Performs a lightweight port scan on a single IP or a range of IPs within the local network.
.DESCRIPTION - :
    This function uses the System.Net.Sockets.TcpClient class to check for open ports.
    It supports a single IP (e.g., '192.168.1.10') or a range specified by the last octet
    (e.g., '192.168.1.1-254').
.PARAMETER Target
    The IP address or IP range to scan.
.PARAMETER Ports
    An array of ports to scan (e.g., 80, 443, 3389). Defaults to common ports if not specified.
.PARAMETER TimeoutMS
    The connection timeout in milliseconds. Default is 200ms for a quick scan.
.EXAMPLE
    Invoke-NetworkScan -Target 192.168.1.50 -Ports 21, 22, 80, 443
    # Scans a single IP for four specific ports.
.EXAMPLE
    Invoke-NetworkScan -Target 192.168.1.1-100
    # Scans the 192.168.1.x subnet from 1 to 100 for default common ports (80, 443, 3389, 22).
#>

function Invoke-NetworkScan {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Target,

        [int[]]$Ports = @(80, 443, 3389, 22, 21),

        [int]$TimeoutMS = 200
    )

    # Define the output array for open ports
    $OpenPorts = @()

    # --- IP Range Expansion Logic (Lightweight CIDR/Block Handling) ---
    $IPsToScan = @()
    if ($Target -match '(\d{1,3}\.\d{1,3}\.\d{1,3})\.(\d{1,3})-(\d{1,3})') {
        # Handles 192.168.1.1-254
        $BaseIP = $Matches[1]
        $Start = [int]$Matches[2]
        $End = [int]$Matches[3]

        for ($i = $Start; $i -le $End; $i++) {
            $IPsToScan += "$BaseIP.$i"
        }
    } else {
        # Handles single IP
        $IPsToScan += $Target
    }
    
    Write-Host "`nStarting Port Scan for $($IPsToScan.Count) IP(s)..." -ForegroundColor Yellow

    # --- Scanning Logic ---
    foreach ($IP in $IPsToScan) {
        Write-Host "Scanning $IP..." -ForegroundColor Cyan
        
        foreach ($Port in $Ports) {
            $TcpClient = New-Object System.Net.Sockets.TcpClient

            # Use asynchronous methods for timeout without blocking the script
            $Connect = $TcpClient.BeginConnect($IP, $Port, $null, $null)
            
            # Wait for connection to complete or for the timeout
            $WaitHandle = $Connect.AsyncWaitHandle
            if ($WaitHandle.WaitOne($TimeoutMS, $false)) {
                try {
                    $TcpClient.EndConnect($Connect) | Out-Null
                    # If EndConnect succeeds, the port is open
                    if ($TcpClient.Connected) {
                        $OpenPorts += [PSCustomObject]@{
                            IPAddress = $IP
                            Port = $Port
                            Status = "OPEN"
                        }
                        Write-Host "  Port $Port is OPEN" -ForegroundColor Green
                    }
                }
                catch {
                    # Connection failed or timed out (closed/filtered)
                }
            }
            
            $TcpClient.Close()
        }
    }

    Write-Host "`n--- Scan Complete ---" -ForegroundColor Yellow
    
    # Display results as a nicely formatted table
    return $OpenPorts | Format-Table -AutoSize
}
