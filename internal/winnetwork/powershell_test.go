package winnetwork

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"unicode/utf16"
)

// Every networking command is replaced with an in-memory mock. This test is
// safe on Windows CI and never invokes the native guard or host networking.
func TestPowerShellJournalRestoresOnlyOwnedState(t *testing.T) {
	powerShell := testPowerShell(t)
	for _, scenario := range []struct{ endpoint, fail string }{
		{"192.0.2.1", ""}, {"192.0.2.1", "128.0.0.0/1"},
		{"2001:db8::1", ""}, {"2001:db8::1", "128.0.0.0/1"},
	} {
		t.Run(scenario.endpoint+"/failure="+scenario.fail, func(t *testing.T) {
			testPowerShellJournal(t, powerShell, scenario.endpoint, scenario.fail)
		})
	}
}

func encodeCommand(script string, arguments []string) string {
	for _, argument := range arguments {
		script += " '" + strings.ReplaceAll(argument, "'", "''") + "'"
	}
	words := utf16.Encode([]rune(script))
	encoded := make([]byte, len(words)*2)
	for index, word := range words {
		binary.LittleEndian.PutUint16(encoded[index*2:], word)
	}
	return base64.StdEncoding.EncodeToString(encoded)
}

func testPowerShell(t *testing.T) string {
	t.Helper()
	powerShell, err := exec.LookPath("pwsh")
	if err != nil && runtime.GOOS == "windows" {
		powerShell = filepath.Join(os.Getenv("SystemRoot"), "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
		_, err = os.Stat(powerShell)
	}
	if err != nil {
		t.Skip("PowerShell unavailable; portable runner/policy tests still run")
	}
	return powerShell
}

func TestExplicitHelperScriptsParseWithoutExecuting(t *testing.T) {
	powerShell := testPowerShell(t)
	for _, script := range []string{"windows-up.ps1", "windows-down.ps1"} {
		path, err := filepath.Abs(filepath.Join("..", "..", "scripts", script))
		if err != nil {
			t.Fatal(err)
		}
		command := encodeCommand(`& { param($path)
$tokens = $null
$errors = $null
[System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors) | Out-Null
if ($errors.Count -ne 0) { throw ($errors | Out-String) }
}`, []string{path})
		if output, err := exec.Command(powerShell, "-NoProfile", "-NonInteractive", "-EncodedCommand", command).CombinedOutput(); err != nil {
			t.Fatalf("parse %s: %v\n%s", script, err, output)
		}
	}
}

func TestExplicitHelperScriptsUsePackagedCLI(t *testing.T) {
	for _, script := range []string{"windows-up.ps1", "windows-down.ps1"} {
		data, err := os.ReadFile(filepath.Join("..", "..", "scripts", script))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(data), `[string]$ClientExecutable = "porta-cli.exe"`) {
			t.Fatalf("%s does not default to the packaged CLI", script)
		}
	}
}

func TestPowerShellMTURestorationWithoutDNS(t *testing.T) {
	testPowerShellJournal(t, testPowerShell(t), "192.0.2.1", "", "-MtuOnly")
}

func testPowerShellJournal(t *testing.T, powerShell, endpoint, fail string, extraArgs ...string) {
	dir := t.TempDir()
	state := networkState{
		Version: 2, Interface: "Porta", ServerIP: endpoint,
		GuardKey: "test", InterfaceIndex: 77, InterfaceGUID: "{77777777-7777-7777-7777-777777777777}",
		OriginalDHCP: "Disabled",
		DNS:          &dnsState{Interface: 77, Original: []string{"9.9.9.9"}},
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	statePath := filepath.Join(dir, "state.json")
	helper := filepath.Join(dir, "network.ps1")
	harness := filepath.Join(dir, "harness.ps1")
	for path, content := range map[string][]byte{statePath: data, helper: []byte(networkScript), harness: []byte(powerShellHarness)} {
		if err := os.WriteFile(path, content, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	args := []string{"-NoProfile", "-NonInteractive", "-File", harness, "-Helper", helper, "-StatePath", statePath}
	args = append(args, extraArgs...)
	if fail != "" {
		args = append(args, "-FailPrefix", fail)
	}
	output, err := exec.Command(powerShell, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("isolated PowerShell journal test: %v\n%s", err, output)
	}
}

const powerShellHarness = `
param($Helper, $StatePath, $FailPrefix = "", [switch]$MtuOnly)
$ErrorActionPreference = "Stop"
$global:adapters = @(
    [PSCustomObject]@{Name="Ethernet";InterfaceIndex=7;InterfaceGuid="11111111-1111-1111-1111-111111111111"},
    [PSCustomObject]@{Name="Porta";InterfaceIndex=77;InterfaceGuid="77777777-7777-7777-7777-777777777777"}
)
$global:routes = @(
    [PSCustomObject]@{DestinationPrefix="0.0.0.0/0";InterfaceIndex=7;NextHop="192.0.2.254";RouteMetric=10},
    [PSCustomObject]@{DestinationPrefix="203.0.113.0/24";InterfaceIndex=7;NextHop="192.0.2.254";RouteMetric=3},
    [PSCustomObject]@{DestinationPrefix="10.77.0.0/24";InterfaceIndex=7;NextHop="192.0.2.254";RouteMetric=1}
)
$initial = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
$defaultPrefix = "0.0.0.0/0"
$gateway = "192.0.2.254"
$hostPrefix = "$($initial.server_ip)/32"
if ($initial.server_ip.Contains(":")) {
    $defaultPrefix = "::/0"
    $gateway = "fe80::1"
    $hostPrefix = "$($initial.server_ip)/128"
    $global:routes += [PSCustomObject]@{DestinationPrefix=$defaultPrefix;InterfaceIndex=7;NextHop=$gateway;RouteMetric=10}
}
$baseline = @($global:routes)
$global:ips = @([PSCustomObject]@{IPAddress="10.0.0.99";PrefixLength=24;InterfaceIndex=77})
$global:dns = @("9.9.9.9")
$global:mtu = 1500
$global:routeAdds = 0
$global:failDNSApply = $false
$global:failMTUApply = $false
function Assert-DNSRoute($server) {
    $choices = @($global:routes | Where-Object {
        $_.DestinationPrefix -in @("0.0.0.0/0", "0.0.0.0/1", "10.77.0.0/24", "$server/32")
    })
    $bestDNS = $choices | Sort-Object @{Expression={[int]($_.DestinationPrefix.Split("/")[1])};Descending=$true}, RouteMetric | Select-Object -First 1
    if ($bestDNS.DestinationPrefix -ne "$server/32" -or $bestDNS.InterfaceIndex -ne 77 -or $bestDNS.NextHop -ne "0.0.0.0") {
        throw "Private DNS still selects its competing physical prefix."
    }
}
function Get-NetAdapter {
    [CmdletBinding()]param([switch]$IncludeHidden)
    $global:adapters
}
function Get-NetRoute {
    [CmdletBinding()]param($PolicyStore)
    $global:routes
}
function Get-NetIPInterface {
    [CmdletBinding()]param($AddressFamily, $InterfaceIndex)
    $global:adapters | Where-Object { -not $InterfaceIndex -or $_.InterfaceIndex -eq $InterfaceIndex } | ForEach-Object {
        $metric = 10
        if ($_.InterfaceIndex -eq 8) { $metric = 1 }
        [PSCustomObject]@{InterfaceIndex=$_.InterfaceIndex;InterfaceAlias=$_.Name;ConnectionState="Connected";InterfaceMetric=$metric;Dhcp="Disabled";NlMtuBytes=$global:mtu}
    }
}
function New-NetRoute {
    [CmdletBinding()]param($DestinationPrefix,$InterfaceIndex,$NextHop,$RouteMetric,$PolicyStore)
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    $kind = "escape"
    if ($DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1")) { $kind = "tunnel" }
    if ($DestinationPrefix -like "10.77.0.*/32") { $kind = "dns" }
    if (@($saved.routes | Where-Object { $_.kind -eq $kind -and $_.prefix -eq $DestinationPrefix -and $_.interface_index -eq $InterfaceIndex }).Count -eq 0) {
        throw "Route changed without ownership journal."
    }
    $global:routeAdds++
    if ($DestinationPrefix -eq $FailPrefix) { throw "Injected route failure." }
    $global:routes += [PSCustomObject]@{DestinationPrefix=$DestinationPrefix;InterfaceIndex=$InterfaceIndex;NextHop=$NextHop;RouteMetric=$RouteMetric}
}
function Remove-NetRoute {
    [CmdletBinding(SupportsShouldProcess)]param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        $target = $InputObject
        $global:routes = @($global:routes | Where-Object {
            -not ($_.DestinationPrefix -eq $target.DestinationPrefix -and $_.InterfaceIndex -eq $target.InterfaceIndex -and $_.NextHop -eq $target.NextHop -and $_.RouteMetric -eq $target.RouteMetric)
        })
    }
}
function Get-NetIPAddress {
    [CmdletBinding()]param($AddressFamily)
    $global:ips
}
function New-NetIPAddress {
    [CmdletBinding()]param($InterfaceIndex,$IPAddress,$PrefixLength)
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ("$IPAddress/$PrefixLength" -notin @($saved.addresses)) { throw "Address changed without journal." }
    $global:ips += [PSCustomObject]@{IPAddress=$IPAddress;PrefixLength=$PrefixLength;InterfaceIndex=$InterfaceIndex}
}
function Remove-NetIPAddress {
    [CmdletBinding(SupportsShouldProcess)]param([Parameter(ValueFromPipeline)]$InputObject)
    process {
        $target = $InputObject
        $global:ips = @($global:ips | Where-Object { $_.IPAddress -ne $target.IPAddress -or $_.InterfaceIndex -ne $target.InterfaceIndex })
    }
}
function Get-DnsClientServerAddress {
    [CmdletBinding()]param($InterfaceIndex,$AddressFamily)
    [PSCustomObject]@{InterfaceIndex=77;ServerAddresses=@($global:dns)}
}
function Set-DnsClientServerAddress {
    [CmdletBinding()]param([Parameter(ValueFromPipeline)]$InputObject,[string[]]$ServerAddresses,[switch]$ResetServerAddresses)
    process {
        if ($ResetServerAddresses) { throw "Static DNS incorrectly reset to DHCP." }
        if ($ServerAddresses[0] -like "10.77.0.*") { Assert-DNSRoute $ServerAddresses[0] }
        if ($global:failDNSApply) { throw "Injected DNS apply failure." }
        $global:dns = @($ServerAddresses)
    }
}
function Set-NetIPInterface {
    [CmdletBinding()]param($InterfaceIndex,$AddressFamily,$Dhcp,$NlMtuBytes)
    if ($Dhcp) { throw "Untouched DHCP state was changed." }
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if ($NlMtuBytes -ne $saved.mtu.pending -and $NlMtuBytes -ne $saved.mtu.original) {
        throw "OS MTU changed without recovery journal."
    }
    $global:mtu = $NlMtuBytes
    if ($global:failMTUApply) {
        $global:failMTUApply = $false
        throw "Injected MTU apply failure."
    }
}
if ($MtuOnly) {
    $initial | Add-Member -NotePropertyName dns -NotePropertyValue $null -Force
    $initial | Add-Member -NotePropertyName mtu -NotePropertyValue ([PSCustomObject]@{original=1500;applied=0;pending=1100}) -Force
    [IO.File]::WriteAllText($StatePath, ($initial | ConvertTo-Json -Depth 10 -Compress))
    $global:mtu = 1100
    & $Helper down $StatePath
    if ($global:mtu -ne 1500) { throw "MTU was not restored when setup failed before DNS configuration." }
    return
}
$failed = $false
try { & $Helper up $StatePath "10.0.0.2/24" "10.77.0.53" } catch {
    $failed = $true
    if (-not $FailPrefix -or $_.Exception.Message -notlike "*Injected route failure*") { throw }
}
if ($failed -ne [bool]$FailPrefix) { throw "Unexpected setup result." }
$saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($saved.routes.Count -ne 4 -or $global:routeAdds -ne 4) { throw "Crash recovery lost planned route ownership." }
Assert-DNSRoute "10.77.0.53"
if ($global:mtu -ne 1100 -or $saved.mtu.original -ne 1500) { throw "Negotiated MTU not applied to Windows IP interface." }
if (-not $FailPrefix) {
    & $Helper up $StatePath "10.0.0.3/24" "10.77.0.53"
    if (@($global:ips | Where-Object { $_.IPAddress -eq "10.0.0.2" }).Count -ne 0) { throw "Stale lease address retained." }
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    & $Helper prepare $StatePath
    Assert-DNSRoute "10.77.0.53"
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if (@($saved.addresses).Count -ne 1) { throw "Retired address remains in ownership journal." }
    & $Helper up $StatePath "10.0.0.3/24" "10.77.0.53" 1200
    if ($global:mtu -ne 1200) { throw "Changed MTU not applied." }
    $oldIPs = $global:ips | ConvertTo-Json -Compress
    $oldAdds = $global:routeAdds
    & $Helper up $StatePath "10.0.0.3/24" "10.77.0.54"
    Assert-DNSRoute "10.77.0.54"
    if (($global:ips | ConvertTo-Json -Compress) -ne $oldIPs -or $global:routeAdds -ne $oldAdds + 1) {
        throw "DNS-only update changed the TUN or unrelated routes."
    }
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if (@($global:routes | Where-Object { $_.DestinationPrefix -eq "10.77.0.53/32" }).Count -ne 0 -or
        @($saved.routes | Where-Object { $_.kind -eq "dns" }).Count -ne 1) {
        throw "Obsolete DNS route ownership was not retired."
    }
    $global:failDNSApply = $true
    $dnsFailed = $false
    try { & $Helper up $StatePath "10.0.0.3/24" "10.77.0.55" } catch {
        if ($_.Exception.Message -notlike "*Injected DNS apply failure*") { throw }
        $dnsFailed = $true
    }
    $global:failDNSApply = $false
    if (-not $dnsFailed -or $global:dns[0] -ne "10.77.0.54") { throw "Unexpected DNS update failure behavior." }
    & $Helper prepare $StatePath
    Assert-DNSRoute "10.77.0.54"
    Assert-DNSRoute "10.77.0.55"
    & $Helper up $StatePath "10.0.0.3/24" "10.77.0.54"
    if (@($global:routes | Where-Object { $_.DestinationPrefix -eq "10.77.0.55/32" }).Count -ne 0) { throw "Failed DNS update route was not retired on retry." }
    $global:adapters += [PSCustomObject]@{Name="New network";InterfaceIndex=8;InterfaceGuid="88888888-8888-8888-8888-888888888888"}
    $newDefault = [PSCustomObject]@{DestinationPrefix=$defaultPrefix;InterfaceIndex=8;NextHop=$gateway;RouteMetric=1}
    $global:routes += $newDefault
    $baseline += $newDefault
    & $Helper prepare $StatePath
    Assert-DNSRoute "10.77.0.54"
    $escape = @($global:routes | Where-Object { $_.DestinationPrefix -eq $hostPrefix })
    if ($escape.Count -ne 1 -or $escape[0].InterfaceIndex -ne 8) { throw "Escape route failed to follow changed physical network." }
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if (@($saved.routes | Where-Object { $_.kind -eq "escape" }).Count -ne 1) { throw "Retired escape remains in ownership journal." }
    $global:failMTUApply = $true
    $mtuFailed = $false
    try { & $Helper up $StatePath "10.0.0.3/24" "10.77.0.54" 1250 } catch {
        if ($_.Exception.Message -notlike "*Injected MTU apply failure*") { throw }
        $mtuFailed = $true
    }
    $saved = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
    if (-not $mtuFailed -or $global:mtu -ne 1250 -or $saved.mtu.pending -ne 1250) {
        throw "Partially applied MTU lost its recovery state."
    }
}
& $Helper down $StatePath
if (($global:routes | ConvertTo-Json -Compress) -ne ($baseline | ConvertTo-Json -Compress)) {
    throw "Restoration removed unrelated routes or retained owned routes."
}
if ($global:ips.Count -ne 1 -or $global:ips[0].IPAddress -ne "10.0.0.99") { throw "Restoration did not preserve unrelated addresses." }
if ($global:dns.Count -ne 1 -or $global:dns[0] -ne "9.9.9.9") { throw "Original static DNS was not restored." }
if ($global:mtu -ne 1500) { throw "Original MTU was not restored." }
& $Helper down $StatePath
if ($global:routes.Count -ne $baseline.Count -or $global:ips.Count -ne 1) { throw "Repeated restoration is not idempotent." }
$beforeRetirement = [IO.File]::ReadAllText($StatePath)
$retirementRejected = $false
try { & $Helper retire-interface $StatePath } catch {
    if ($_.Exception.Message -notlike "*previous tunnel adapter still exists*") { throw }
    $retirementRejected = $true
}
if (-not $retirementRejected -or [IO.File]::ReadAllText($StatePath) -ne $beforeRetirement) {
    throw "Retired an adapter which still exists."
}
$global:adapters = @($global:adapters | Where-Object { $_.InterfaceIndex -ne 77 })
& $Helper retire-interface $StatePath
$retired = Get-Content -LiteralPath $StatePath -Raw | ConvertFrom-Json
if ($retired.guard_key -ne "test" -or $retired.interface_luid -ne 0 -or $retired.interface_guid -ne "" -or $retired.dns -or @($retired.addresses).Count -ne 0) {
    throw "Deleted-adapter retirement lost guard ownership or retained obsolete interface configuration."
}
`
