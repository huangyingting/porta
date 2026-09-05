param(
    [string]$InterfaceAlias = "Porta",
    [string]$StatePath = (Join-Path $env:LOCALAPPDATA "Porta\manual-network-state.json"),
    [string]$ClientExecutable = "porta-cli.exe"
)
$ErrorActionPreference = "Stop"
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
    throw "Run this script from an elevated PowerShell session."
}
if (Test-Path -LiteralPath $StatePath) {
    $state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
    if ($PSBoundParameters.ContainsKey("InterfaceAlias") -and $InterfaceAlias -ne $state.interface) {
        throw "Saved network state belongs to interface $($state.interface)."
    }
    $InterfaceAlias = $state.interface
}
# Restoration must finish before the shared helper removes persistent WFP
# objects. Never delete the journal or manipulate global firewall policy here.
$client = Get-Command -Name $ClientExecutable -CommandType Application -ErrorAction Stop
$result = @(& $client.Source network-down -state-path $StatePath -interface $InterfaceAlias)
if ($LASTEXITCODE -ne 0 -or "PORTA_NETWORK_DOWN_OK" -notin $result) {
    throw "Intentional Disconnect was not confirmed. Review the error and retry with a client that supports network-down; do not delete any remaining ownership journal manually."
}
Write-Host "Intentional Disconnect completed: restored owned network state and removed Porta's persistent guard."
