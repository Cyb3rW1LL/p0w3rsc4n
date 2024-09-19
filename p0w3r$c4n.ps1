# P0w3r$c4n.ps1
# Author: Cyb3rW1LL


# We will not use Test-Connecction as we do not want to alert on anomalous ICMP traffic
# Instead, we will leverage the New-Object System.Net.Sockets library to gather TCP, UDP,
# And TTL information about the target host(s)



# Commandline parameters to run scan with
# EXAMPLE \.scanner.ps1 -ComputerName localhost -p 80 -t -o "D:\test\localhost.csv"

