param(
    [string]$InterfaceAlias = "Porta",
    [string]$StatePath = (Join-Path $env:LOCALAPPDATA "Porta\manual-network-state.json")
)

$ErrorActionPreference = "Stop"
$state = $null
if (Test-Path -LiteralPath $StatePath) {
    $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($PSBoundParameters.ContainsKey("InterfaceAlias") -and $InterfaceAlias -ne $state.interface) {
        throw "Saved network state belongs to interface $($state.interface)."
    }
    $InterfaceAlias = $state.interface
}
Get-NetRoute -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
    Remove-NetRoute -Confirm:$false -ErrorAction Stop
if ($state -and $state.created_escape_route) {
    Get-NetRoute -DestinationPrefix "$($state.server_ip)/32" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object { $_.InterfaceIndex -eq $state.escape_interface_index -and [string]$_.NextHop -eq $state.escape_next_hop } |
        Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
if (Get-NetIPInterface -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue) {
    Set-DnsClientServerAddress -InterfaceAlias $InterfaceAlias -ResetServerAddresses -ErrorAction Stop
    Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
}
if ($state) { Remove-Item -LiteralPath $StatePath -ErrorAction Stop }
Write-Host "Removed Porta routes, DNS settings, and interface address from $InterfaceAlias."
