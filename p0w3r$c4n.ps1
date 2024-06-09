# P0w3r$c4n.ps1
# Author: Cyb3W1LL
# Created: 6/9/2024
# Revised: 

# Set-ExecutionPolicy Bypass/RemoreSigned
# Install-Module PSParallel
Import-Module PSParallel

# Standard Tcptarget scan
# Will either connect or potentially be filtered
function TCP-SCAN {
    param ([string]$targetIP, [int]$targetPort)
    $tcpscan = New-Object System.Net.Sockets.TcpClient
    try {
        $tcpscan.Connect($targetIP, $targetPort)
        if ($tcpscan.Connected){
            $tcpscan.Close()
            return "Open"
        }
    } catch {return "Closed/Filtered"}
    return "Closed/Filtered"
}

# UdpClient scan with response socket listener
# Will either get response or potentially be filtered
function UDP-SCAN {
    param ([string]$targetIP, [int]$targetPort)
    $udpscan = New-Object System.Net.Sockets.UdpClient
    try {
        $udpscan.Connect($targetIP, $targetPort)
        # Open a Listener socket on the localhost for "Any" UDP response on port 0
        $udplistener = New-Object System.Net.IPEndPoint([System.Net.IPAddress]::Any, 0)
        # Send empty byte array[] to the target to illicit response
        $udpscan.Send([byte[]]@(0), 0)
        # Timeout in miliseconds added by copilot* 
        $udpscan.Client.ReceiveTimeout = 300
        # Receive method is used to store the response information from the udplistener
	$udpscan.Receive([ref]$udplistener)
        $udpscan.Close()
        return "Open"
    } catch {return "Closed/Filtered"}
    return "Closed/Filtered"
}

# Change these to incoroporate custom known ports and adjust for CIDR input to scan ranges
# Not just a current targetIP
$portRange = 1..1000
$targetIP = "127.0.0.1"

$paralleljobs = 20
# Scan the port range in increments of 20 Parallel processes
# The HIGHER concurrent jobs running, the higher the resource utilization!
$scanby20 = $portRange | ForEach-Object -Begin{ $jobs = @()} -Process{
    $jobs += $_
    if ($jobs.Count -eq 20){
        $jobs
        $jobs = @()
    }
} -End{ if ($jobs.Count -gt 0) {$jobs}
}

# Now for the whole point of this project!
# Runs both the TCP and UDP scans concurrently (In Parallel)
$scanResults = $scanby20 | ForEach-Object -Parallel{
    param($targetIP, $ports)
    $jobResults = @()
    foreach ($targetPort in $ports){
        $tcpResponse = TCP-SCAN -targetIP $targetIP -targetPort $targetPort
        $udpResponse = UDP-SCAN -targetIP $targetIP -targetPort $targetPort
	# Results stored in object with port, tcp, and udp data populated from scans
        $jobResults += [PSCustomObject]@{
            Port        = $targetPort 
            TCPResponse = $tcpResponse
            UDPResponse = $udpResponse
         }
    }
    return $jobResults
} -ArgumentList $targetIP, $_ -ThrottleLimit $paralleljobs

# Scanning output formatting so we can review the results
# (Will eventully be output as .html, .csv, and .json)
$scanResults | ForEach-Object {
    $_ | ForEach-Object {
        Write-Output "Port $($_.Port): TCP=$($_.TCPResponse), UDP=$($_.UDPResponse)"
    }
}
