# Requires -RunAsAdministrator # Best practice for running network scripts


# --- Example Usage ---

# 1. Scan a single IP with a custom port range
# Invoke-NetworkScan -Target "192.168.1.10" -Ports '80, 443, 8080-8085'

# 2. Scan an IP range with a common port list
# Invoke-NetworkScan -Target "192.168.1.1-20" -Ports '21, 22, 23, 80, 3389'

<#
.Usage:
    Performs a lightweight port scan on a single IP or a range of IPs within the local network.
.DESCRIPTION
    This function uses the System.Net.Sockets.TcpClient class to check for open ports.
    It supports a single IP (e.g., '192.168.1.10') or a range specified by the last octet
    (e.g., '192.168.1.1-254').
    It also supports scanning a single port, a comma-separated list of ports, or a port range (e.g., '1-1024').
.PARAMETER Target
    The IP address or IP range to scan (e.g., '192.168.1.50' or '192.168.1.1-10').
.PARAMETER Ports
    A string defining the ports to scan. Can be a list (e.g., '21, 22, 80') or a range (e.g., '1-1024').
    Defaults to common ports if not specified.
.PARAMETER TimeoutMS
    The connection timeout in milliseconds. Default is 200ms for a quick scan.
.EXAMPLE
    Invoke-NetworkScan -Target 192.168.1.50 -Ports '21, 22, 80, 443'
    # Scans a single IP for four specific ports.
.EXAMPLE
    Invoke-NetworkScan -Target 192.168.1.1-100 -Ports '1-1024'
    # Scans the 192.168.1.x subnet from 1 to 100 for all common system ports.
#>

function Invoke-NetworkScan {
    param(
        [Parameter(Mandatory=$true)]
        [string]$Target,

        [string]$Ports = "80, 443, 3389, 22, 21", # Changed type to string for range/list input

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

    # --- Port Range Expansion Logic ---
    $PortsToScan = @()
    $PortSegments = $Ports.Replace(' ', '').Split(',') # Handle multiple segments (e.g., '80, 8080-8088')

    foreach ($Segment in $PortSegments) {
        if ($Segment -match '(\d+)-(\d+)') {
            # Handle port range (e.g., 1-1024)
            $StartPort = [int]$Matches[1]
            $EndPort = [int]$Matches[2]
            
            for ($p = $StartPort; $p -le $EndPort; $p++) {
                $PortsToScan += $p
            }
        } elseif ($Segment -match '^\d+$') {
            # Handle single port
            $PortsToScan += [int]$Segment
        }
    }
    
    if ($PortsToScan.Count -eq 0) {
        Write-Error "No valid ports specified for scan: '$Ports'"
        return
    }
    
    Write-Host "`nStarting Port Scan for $($IPsToScan.Count) IP(s) and $($PortsToScan.Count) Port(s)..." -ForegroundColor Yellow

    # --- Scanning Logic ---
    foreach ($IP in $IPsToScan) {
        Write-Host "Scanning $IP..." -ForegroundColor Cyan
        
        # Use the new $PortsToScan array containing only integer ports
        foreach ($Port in $PortsToScan) {
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
