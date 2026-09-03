param(
    [Parameter(Mandatory = $true)][string]$AddressCidr,
    [Parameter(Mandatory = $true)][string]$ServerIp,
    [string]$InterfaceAlias = "hTun",
    [string]$DnsServer = "1.1.1.1"
)

$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}

$parts = $AddressCidr.Split("/")
if ($parts.Count -ne 2) { throw "AddressCidr must look like 10.66.0.2/24" }
$clientIp = $parts[0]
$prefixLength = [int]$parts[1]

$existingServerRoute = Get-NetRoute -AddressFamily IPv4 |
    Where-Object { $_.DestinationPrefix -eq "$ServerIp/32" -or $_.DestinationPrefix -eq "0.0.0.0/0" } |
    Sort-Object RouteMetric, InterfaceMetric |
    Select-Object -First 1
if (-not $existingServerRoute) { throw "Could not resolve an existing route for the gateway server." }

Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false
New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $clientIp -PrefixLength $prefixLength | Out-Null
Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DnsServer

New-NetRoute -DestinationPrefix "$ServerIp/32" -InterfaceIndex $existingServerRoute.InterfaceIndex `
    -NextHop $existingServerRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
New-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceAlias $InterfaceAlias -NextHop "0.0.0.0" `
    -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null
New-NetRoute -DestinationPrefix "128.0.0.0/1" -InterfaceAlias $InterfaceAlias -NextHop "0.0.0.0" `
    -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction SilentlyContinue | Out-Null

Write-Host "Configured $InterfaceAlias as $AddressCidr. The explicit $ServerIp route prevents tunnel recursion."

