param(
    [Parameter(Mandatory = $true)][string]$AddressCidr,
    [Parameter(Mandatory = $true)][string]$ServerIp,
    [string]$InterfaceAlias = "Porta",
    [string]$DnsServer = "1.1.1.1",
    [string]$StatePath = (Join-Path $env:LOCALAPPDATA "Porta\manual-network-state.json")
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

$parsedServer = [Net.IPAddress]::Parse($ServerIp)
if ($parsedServer.AddressFamily -ne [Net.Sockets.AddressFamily]::InterNetwork) {
    throw "ServerIp must be an IPv4 address."
}
$ServerIp = $parsedServer.ToString()
if (Test-Path -LiteralPath $StatePath) {
    & "$PSScriptRoot\windows-down.ps1" -StatePath $StatePath
}

$existingHostRoute = Get-NetRoute -DestinationPrefix "$ServerIp/32" -AddressFamily IPv4 -ErrorAction SilentlyContinue
$state = [ordered]@{
    interface = $InterfaceAlias
    server_ip = $ServerIp
    created_escape_route = $false
    escape_interface_index = 0
    escape_next_hop = ""
}
if (-not $existingHostRoute) {
    $existingServerRoute = Find-NetRoute -RemoteIPAddress $ServerIp |
        Where-Object { $_.DestinationPrefix } | Select-Object -First 1
    if (-not $existingServerRoute) { throw "Could not resolve an existing route for the gateway server." }
    $state.created_escape_route = $true
    $state.escape_interface_index = $existingServerRoute.InterfaceIndex
    $state.escape_next_hop = [string]$existingServerRoute.NextHop
}
$stateDirectory = Split-Path -Parent ([IO.Path]::GetFullPath($StatePath))
[IO.Directory]::CreateDirectory($stateDirectory) | Out-Null
$json = $state | ConvertTo-Json -Compress
[IO.File]::WriteAllText("$StatePath.pending", $json, (New-Object Text.UTF8Encoding($false)))
Move-Item -LiteralPath "$StatePath.pending" -Destination $StatePath -Force

try {
    if ($state.created_escape_route) {
        New-NetRoute -DestinationPrefix "$ServerIp/32" -InterfaceIndex $state.escape_interface_index `
            -NextHop $state.escape_next_hop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    }
    Get-NetRoute -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
        Remove-NetRoute -Confirm:$false -ErrorAction Stop
    Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
    New-NetIPAddress -InterfaceAlias $InterfaceAlias -IPAddress $clientIp -PrefixLength $prefixLength -ErrorAction Stop | Out-Null
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ServerAddresses $DnsServer -ErrorAction Stop
    New-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceAlias $InterfaceAlias -NextHop "0.0.0.0" `
        -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    New-NetRoute -DestinationPrefix "128.0.0.0/1" -InterfaceAlias $InterfaceAlias -NextHop "0.0.0.0" `
        -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
} catch {
    $failure = $_
    try { & "$PSScriptRoot\windows-down.ps1" -StatePath $StatePath } catch { Write-Warning $_ }
    throw $failure
}

Write-Host "Configured $InterfaceAlias as $AddressCidr. The explicit $ServerIp route prevents tunnel recursion."
