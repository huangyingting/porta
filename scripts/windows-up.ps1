param(
    [Parameter(Mandatory = $true)][string]$AddressCidr,
    [Parameter(Mandatory = $true)][string]$ServerIp,
    [ValidateRange(1, 65535)][int]$ServerPort = 443,
    [string]$InterfaceAlias = "Porta",
    [string]$DnsServer = "1.1.1.1",
    [ValidateRange(576, 9000)][int]$Mtu = 1100,
    [string]$StatePath = (Join-Path $env:LOCALAPPDATA "Porta\manual-network-state.json"),
    [string]$ClientExecutable = "porta-cli.exe"
)
$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}
$server = [Net.IPAddress]::Parse($ServerIp)
$endpoint = "$($server.ToString()):$ServerPort"
if ($server.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetworkV6) {
    $endpoint = "[$($server.ToString())]:$ServerPort"
}
# No route-only fallback: the client helper owns the tested WFP policy and
# crash-safe journal. Use this SAME executable for the transport connection.
$client = Get-Command -Name $ClientExecutable -CommandType Application -ErrorAction Stop
$result = @(& $client.Source network-up -state-path $StatePath -interface $InterfaceAlias `
    -address $AddressCidr -server-address $endpoint -dns $DnsServer -mtu $Mtu)
if ($LASTEXITCODE -ne 0 -or "PORTA_NETWORK_UP_OK" -notin $result) {
    throw "Protected network setup failed. Any activated guard remains in place; explicitly run windows-down.ps1 with the same state path and client executable to restore owned state. A client with network-up support is required."
}
Write-Host "Persistent full-tunnel protection activated. Physical DNS and IPv6 payload are blocked; IPv6 transport neighbor discovery is allowed. Run windows-down.ps1 for intentional Disconnect."
