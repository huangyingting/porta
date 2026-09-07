$ErrorActionPreference = "Stop"
$Operation = [string]$env:PORTA_NETWORK_OPERATION
$StatePath = [string]$env:PORTA_NETWORK_STATE_PATH
$AddressCidr = [string]$env:PORTA_NETWORK_ADDRESS_CIDR
$DnsServer = [string]$env:PORTA_NETWORK_DNS_SERVER
$Mtu = 0
if ($Operation -notin @("prepare", "configure-interface", "up", "down", "retire-interface")) {
    throw "Invalid network helper operation."
}
if (-not $StatePath -or -not [IO.Path]::IsPathRooted($StatePath)) {
    throw "Network state path must be absolute."
}
if (-not [int]::TryParse([string]$env:PORTA_NETWORK_MTU, [ref]$Mtu) -or $Mtu -lt 576 -or $Mtu -gt 9000) {
    throw "Invalid tunnel MTU."
}
$Icacls = Join-Path ([Environment]::SystemDirectory) "icacls.exe"
$state = Get-Content -LiteralPath $StatePath -Raw -Encoding UTF8 | ConvertFrom-Json
if ($state.version -notin @(2, 3)) {
    throw "Restore legacy journals with their original client; exact address/DNS ownership is unavailable."
}

function Set-StateField($name, $value) {
    $state | Add-Member -NotePropertyName $name -NotePropertyValue $value -Force
}
function Protect-StateFile($path) {
    & $Icacls $path /setowner "*S-1-5-32-544" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot set recovery journal owner." }
    & $Icacls $path /inheritance:r /grant:r "*S-1-5-18:F" "*S-1-5-32-544:F" /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot secure recovery journal permissions." }
    & $Icacls $path /setintegritylevel H /Q | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "Cannot set recovery journal integrity." }
}
function Save-State {
    $bytes = (New-Object Text.UTF8Encoding($false)).GetBytes(($state | ConvertTo-Json -Depth 10 -Compress))
    $file = [IO.File]::Open("$StatePath.pending", [IO.FileMode]::Create, [IO.FileAccess]::Write, [IO.FileShare]::None)
    try {
        $file.Write($bytes, 0, $bytes.Length)
        $file.Flush($true)
    } finally { $file.Dispose() }
    Protect-StateFile "$StatePath.pending"
    [IO.File]::Replace("$StatePath.pending", $StatePath, [NullString]::Value)
}
function Get-Routes {
    @(Get-NetRoute -PolicyStore ActiveStore -ErrorAction Stop)
}
function Test-Route($route, $owned) {
    $identity = -not $owned.interface_guid -or @($adapters | Where-Object {
        $_.InterfaceIndex -eq $route.InterfaceIndex -and ([guid]$_.InterfaceGuid).ToString("B") -eq $owned.interface_guid
    }).Count -eq 1
    $identity -and $route.DestinationPrefix -eq $owned.prefix -and
    $route.InterfaceIndex -eq $owned.interface_index -and
    [string]$route.NextHop -eq $owned.next_hop -and
    $route.RouteMetric -eq $owned.metric
}
function Test-Prefix($address, $prefix) {
    $pieces = $prefix.Split("/")
    $network = [Net.IPAddress]::Parse($pieces[0])
    if ($network.AddressFamily -ne $address.AddressFamily) { return $false }
    $a = $address.GetAddressBytes()
    $b = $network.GetAddressBytes()
    $remaining = [int]$pieces[1]
    for ($i = 0; $remaining -gt 0; $i++) {
        $take = [Math]::Min(8, $remaining)
        $mask = (255 -shl (8 - $take)) -band 255
        if (($a[$i] -band $mask) -ne ($b[$i] -band $mask)) { return $false }
        $remaining -= $take
    }
    return $true
}
function Remove-OwnedRoute($owned) {
    Get-Routes | Where-Object { Test-Route $_ $owned } | Remove-NetRoute -Confirm:$false -ErrorAction Stop
}
function Retire-OwnedRoute($owned) {
    Remove-OwnedRoute $owned
    Set-StateField "routes" @($state.routes | Where-Object { $_ -ne $owned })
    Save-State
}
function Add-OwnedRoute($kind, $prefix, $index, $nextHop, $metric) {
    $owner = @($adapters | Where-Object { $_.InterfaceIndex -eq $index })
    if ($owner.Count -ne 1) { throw "Cannot determine escape/tunnel route interface ownership." }
    $record = [PSCustomObject]@{
        kind=$kind; prefix=$prefix; interface_index=[int]$index; next_hop=[string]$nextHop; metric=[int]$metric
        interface_guid=([guid]$owner[0].InterfaceGuid).ToString("B")
    }
    $existing = @(Get-Routes | Where-Object { Test-Route $_ $record })
    if ($existing.Count -gt 0) { return }
    if (@($state.routes | Where-Object { $_ -and $_.prefix -eq $prefix -and $_.interface_index -eq $index -and $_.interface_guid -eq $record.interface_guid -and $_.next_hop -eq $nextHop -and $_.metric -eq $metric }).Count -eq 0) {
        Set-StateField "routes" (@($state.routes | Where-Object { $_ }) + @($record))
        Save-State
    }
    New-NetRoute -DestinationPrefix $prefix -InterfaceIndex $index -NextHop $nextHop -RouteMetric $metric -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
}

$adapters = @(Get-NetAdapter -IncludeHidden -ErrorAction Stop)
if ($Operation -eq "retire-interface") {
    if (-not $state.interface_guid -or @($adapters | Where-Object {
        ([guid]$_.InterfaceGuid).ToString("B") -eq $state.interface_guid
    }).Count -gt 0) {
        throw "The previous tunnel adapter still exists or its identity is unknown; explicit Disconnect is required."
    }
    foreach ($owned in @($state.routes | Where-Object { $_.kind -in @("tunnel", "dns") })) {
        Retire-OwnedRoute $owned
    }
    Set-StateField "interface_luid" 0
    Set-StateField "interface_index" 0
    Set-StateField "interface_guid" ""
    Set-StateField "addresses" @()
    Set-StateField "dns" $null
    Set-StateField "mtu" $null
    Set-StateField "original_dhcp" ""
    Save-State
    return
}
if ($Operation -eq "down") {
    foreach ($owned in @($state.routes | Where-Object { $_ })) {
        $owner = @($adapters | Where-Object { ([guid]$_.InterfaceGuid).ToString("B") -eq $owned.interface_guid })
        if ($owner.Count -eq 1) {
            $record = [PSCustomObject]@{
                prefix=$owned.prefix; interface_index=[int]$owner[0].InterfaceIndex
                next_hop=$owned.next_hop; metric=$owned.metric
            }
            Remove-OwnedRoute $record
        }
        Set-StateField "routes" @($state.routes | Where-Object { $_ -ne $owned })
        Save-State
    }
    $restoreAdapters = @($adapters | Where-Object {
        ([guid]$_.InterfaceGuid).ToString("B") -eq $state.interface_guid
    })
    $sameInterface = $restoreAdapters.Count -eq 1
    $restoreIndex = 0
    if ($sameInterface) { $restoreIndex = [int]$restoreAdapters[0].InterfaceIndex }
    if ($state.dns -and $sameInterface) {
        $interfaces = @(Get-DnsClientServerAddress -AddressFamily IPv4 -ErrorAction Stop | Where-Object { $_.InterfaceIndex -eq $restoreIndex })
        if ($interfaces.Count -gt 0) {
            $current = @($interfaces[0].ServerAddresses)
            if ($current.Count -eq 1 -and $current[0] -in @($state.dns.applied, $state.dns.pending)) {
                if ($state.dns.automatic) {
                    $interfaces[0] | Set-DnsClientServerAddress -ResetServerAddresses -ErrorAction Stop
                } else {
                    $interfaces[0] | Set-DnsClientServerAddress -ServerAddresses @($state.dns.original) -ErrorAction Stop
                }
            }
        }
    }
    if ($state.mtu -and $sameInterface) {
        $current = Get-NetIPInterface -InterfaceIndex $restoreIndex -AddressFamily IPv4 -ErrorAction Stop
        if ($current.NlMtuBytes -in @($state.mtu.applied, $state.mtu.pending)) {
            Set-NetIPInterface -InterfaceIndex $restoreIndex -AddressFamily IPv4 -NlMtuBytes $state.mtu.original -ErrorAction Stop
        }
    }
    Set-StateField "mtu" $null
    Set-StateField "dns" $null
    Save-State
    foreach ($owned in @($state.addresses | Where-Object { $_ -and $sameInterface })) {
        $parts = $owned.Split("/")
        Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
            Where-Object { $_.InterfaceIndex -eq $restoreIndex -and $_.IPAddress -eq $parts[0] -and $_.PrefixLength -eq [int]$parts[1] } |
            Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
        Set-StateField "addresses" @($state.addresses | Where-Object { $_ -ne $owned })
        Save-State
    }
    if ($sameInterface -and $state.original_dhcp -eq "Enabled") {
        Set-NetIPInterface -InterfaceIndex $restoreIndex -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
    }
    return
}

$server = [Net.IPAddress]::Parse($state.server_ip)
$v4 = $server.AddressFamily -eq [Net.Sockets.AddressFamily]::InterNetwork
$bits = 128
$family = "IPv6"
if ($v4) { $bits = 32; $family = "IPv4" }
$hostPrefix = "$($state.server_ip)/$bits"
$tun = @($adapters | Where-Object { $_.Name -eq $state.interface })
$tunIndex = 0
if ($tun.Count -gt 0) { $tunIndex = [int]$tun[0].InterfaceIndex }
$candidates = @()
$routes = @(Get-Routes)
foreach ($ipInterface in @(Get-NetIPInterface -AddressFamily $family -ErrorAction Stop | Where-Object {
    $_.InterfaceIndex -ne $tunIndex -and $_.ConnectionState -eq "Connected" -and $_.InterfaceAlias -ne "Loopback Pseudo-Interface 1"
})) {
    $matching = @($routes | Where-Object {
        $_.InterfaceIndex -eq $ipInterface.InterfaceIndex -and (Test-Prefix $server $_.DestinationPrefix)
    })
    foreach ($route in $matching) {
        $owned = @($state.routes | Where-Object { $_ -and (Test-Route $route $_) }).Count -gt 0
        if ($owned) { continue }
        $candidates += [PSCustomObject]@{ route=$route; prefix=[int]($route.DestinationPrefix.Split("/")[1]); cost=([int]$route.RouteMetric + [int]$ipInterface.InterfaceMetric) }
    }
}
$best = $candidates | Sort-Object @{Expression="prefix";Descending=$true}, cost | Select-Object -First 1
if (-not $best) { throw "No physical route to the pinned transport endpoint; leak protection remains active." }
Add-OwnedRoute "escape" $hostPrefix $best.route.InterfaceIndex ([string]$best.route.NextHop) 1
foreach ($owned in @($state.routes | Where-Object {
    $_ -and $_.kind -eq "escape" -and
    ($_.prefix -ne $hostPrefix -or $_.interface_index -ne $best.route.InterfaceIndex -or $_.next_hop -ne [string]$best.route.NextHop)
})) {
    Retire-OwnedRoute $owned
}

if ($Operation -eq "prepare") { return }
if ($tun.Count -ne 1) { throw "The dedicated tunnel interface is unavailable." }
$index = [int]$tun[0].InterfaceIndex
if ($state.interface_guid -and $state.interface_guid -ne ([guid]$tun[0].InterfaceGuid).ToString("B")) {
    throw "Tunnel adapter identity changed without a guarded retirement."
}
if ($state.interface_index -and $state.interface_index -ne $index -and (@($state.addresses).Count -gt 0 -or $state.dns)) {
    throw "Tunnel interface identity changed; explicit Disconnect is required to restore journaled state."
}
Set-StateField "interface_index" $index
Set-StateField "interface_guid" (([guid]$tun[0].InterfaceGuid).ToString("B"))
Save-State
$parts = $AddressCidr.Split("/")
$existing = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
    Where-Object { $_.InterfaceIndex -eq $index -and $_.IPAddress -eq $parts[0] -and $_.PrefixLength -eq [int]$parts[1] })
if ($existing.Count -eq 0) {
    if ($AddressCidr -notin @($state.addresses)) {
        Set-StateField "addresses" (@($state.addresses | Where-Object { $_ }) + @($AddressCidr))
    }
    if (-not $state.original_dhcp) {
        $originalInterface = Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop
        Set-StateField "original_dhcp" ([string]$originalInterface.Dhcp)
    }
    Save-State
    New-NetIPAddress -InterfaceIndex $index -IPAddress $parts[0] -PrefixLength ([int]$parts[1]) -ErrorAction Stop | Out-Null
}
if ($Operation -eq "configure-interface") { return }
if (-not ($state.mtu -and $state.mtu.applied -eq $Mtu -and -not $state.mtu.pending)) {
    if (-not $state.mtu) {
        $current = @(Get-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop)
        if ($current.Count -ne 1 -or -not $current[0].NlMtuBytes) {
            throw "Cannot snapshot the tunnel interface MTU."
        }
        Set-StateField "mtu" ([PSCustomObject]@{original=[uint32]$current[0].NlMtuBytes; applied=0; pending=$Mtu})
    } else {
        $state.mtu.pending = $Mtu
    }
    Save-State
    Set-NetIPInterface -InterfaceIndex $index -AddressFamily IPv4 -NlMtuBytes $Mtu -ErrorAction Stop
    $state.mtu.applied = $Mtu
    $state.mtu.pending = 0
    Save-State
}
Add-OwnedRoute "dns" "$DnsServer/32" $index "0.0.0.0" 1
if (-not $state.dns) {
    $current = @(Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop)
    $adapterGuid = ([guid]$tun[0].InterfaceGuid).ToString("B")
    $key = [Microsoft.Win32.Registry]::LocalMachine.OpenSubKey("SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\$adapterGuid")
    if (-not $key) { throw "Cannot snapshot the tunnel interface DNS configuration." }
    try { $static = [string]$key.GetValue("NameServer", "") } finally { $key.Dispose() }
    Set-StateField "dns" ([PSCustomObject]@{
        interface_index=$index; automatic=[string]::IsNullOrWhiteSpace($static)
        original=@($current[0].ServerAddresses); applied=""; pending=$DnsServer
    })
} else {
    $state.dns.pending = $DnsServer
}
Save-State
Get-DnsClientServerAddress -InterfaceIndex $index -AddressFamily IPv4 -ErrorAction Stop |
    Set-DnsClientServerAddress -ServerAddresses @($DnsServer) -ErrorAction Stop
$state.dns.applied = $DnsServer
$state.dns.pending = ""
Save-State
Add-OwnedRoute "tunnel" "0.0.0.0/1" $index "0.0.0.0" 5
Add-OwnedRoute "tunnel" "128.0.0.0/1" $index "0.0.0.0" 5
foreach ($owned in @($state.routes | Where-Object {
    $_ -and $_.kind -eq "dns" -and
    ($_.prefix -ne "$DnsServer/32" -or $_.interface_index -ne $index -or $_.interface_guid -ne $state.interface_guid)
})) {
    Retire-OwnedRoute $owned
}
foreach ($old in @($state.addresses | Where-Object { $_ -and $_ -ne $AddressCidr })) {
    $oldParts = $old.Split("/")
    Get-NetIPAddress -AddressFamily IPv4 -ErrorAction Stop |
        Where-Object { $_.InterfaceIndex -eq $index -and $_.IPAddress -eq $oldParts[0] -and $_.PrefixLength -eq [int]$oldParts[1] } |
        Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
    Set-StateField "addresses" @($state.addresses | Where-Object { $_ -ne $old })
    Save-State
}
