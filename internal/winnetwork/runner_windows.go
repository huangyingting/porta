//go:build windows

package winnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"time"

	"github.com/huangyingting/porta/internal/tunnel"
)

type Runner struct {
	mu        sync.Mutex
	statePath string
	state     networkState
}

type networkState struct {
	Interface            string `json:"interface"`
	ServerIP             string `json:"server_ip"`
	CreatedEscapeRoute   bool   `json:"created_escape_route"`
	EscapeInterfaceIndex int    `json:"escape_interface_index,omitempty"`
	EscapeNextHop        string `json:"escape_next_hop,omitempty"`
}

func NewRunner(statePath string) (*Runner, error) {
	runner := &Runner{
		statePath: statePath,
	}
	data, err := os.ReadFile(statePath)
	if err == nil {
		_ = json.Unmarshal(data, &runner.state)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("read network state: %w", err)
	}
	return runner, nil
}

func (r *Runner) Up(ctx context.Context, interfaceName string, remoteAddr net.Addr, lease tunnel.Lease) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.Interface != "" {
		if _, err := r.invoke(ctx, downArguments(r.state)...); err != nil {
			return fmt.Errorf("clean stale network state: %w", err)
		}
		r.state = networkState{}
		_ = os.Remove(r.statePath)
	}
	if remoteAddr == nil {
		return errors.New("tunnel did not report its remote address")
	}
	serverIP, _, err := net.SplitHostPort(remoteAddr.String())
	if err != nil {
		return errors.New("tunnel remote address is invalid")
	}
	parsedServerIP := net.ParseIP(serverIP)
	if parsedServerIP == nil {
		return errors.New("tunnel remote address is invalid")
	}
	if parsedServerIP.To4() == nil {
		serverIP = ""
	}
	dns := ""
	if lease.DNS.IsValid() {
		dns = lease.DNS.String()
	}
	output, err := r.invoke(ctx, "up", interfaceName, lease.Address.String(), serverIP, dns)
	if err != nil {
		return err
	}
	var created struct {
		CreatedEscapeRoute   bool   `json:"created_escape_route"`
		EscapeInterfaceIndex int    `json:"escape_interface_index"`
		EscapeNextHop        string `json:"escape_next_hop"`
	}
	if err := json.Unmarshal([]byte(output), &created); err != nil {
		return fmt.Errorf("decode network helper result: %w", err)
	}
	r.state = networkState{
		Interface:            interfaceName,
		ServerIP:             serverIP,
		CreatedEscapeRoute:   created.CreatedEscapeRoute,
		EscapeInterfaceIndex: created.EscapeInterfaceIndex,
		EscapeNextHop:        created.EscapeNextHop,
	}
	if err := r.persistLocked(); err != nil {
		rollbackCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
		defer cancel()
		_, _ = r.invoke(rollbackCtx, downArguments(r.state)...)
		r.state = networkState{}
		return err
	}
	return nil
}

func (r *Runner) Down(ctx context.Context) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state.Interface == "" {
		return nil
	}
	if _, err := r.invoke(ctx, downArguments(r.state)...); err != nil {
		return err
	}
	r.state = networkState{}
	if err := os.Remove(r.statePath); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("remove network state: %w", err)
	}
	return nil
}

func (r *Runner) invoke(ctx context.Context, arguments ...string) (string, error) {
	if len(arguments) == 0 {
		return "", errors.New("network operation is required")
	}
	var script string
	switch arguments[0] {
	case "up":
		script = upScript
	case "down":
		script = downScript
	default:
		return "", errors.New("unsupported network operation")
	}
	systemRoot := os.Getenv("SystemRoot")
	if systemRoot == "" {
		return "", errors.New("SystemRoot is unavailable")
	}
	powerShell := filepath.Join(systemRoot, "System32", "WindowsPowerShell", "v1.0", "powershell.exe")
	commandArgs := []string{"-NoProfile", "-NonInteractive", "-Command", script}
	commandArgs = append(commandArgs, arguments[1:]...)
	output, err := exec.CommandContext(ctx, powerShell, commandArgs...).CombinedOutput()
	if err != nil {
		message := string(output)
		if message == "" {
			message = err.Error()
		}
		return "", fmt.Errorf("network helper failed: %s", message)
	}
	return string(output), nil
}

const upScript = `& {
param($interfaceName, $addressCidr, $serverIP, $dnsServer)
$ErrorActionPreference = "Stop"
$parts = $addressCidr.Split("/")
if ($parts.Count -ne 2) { throw "Invalid tunnel address" }
$existingHostRoute = $null
if ($serverIP) {
  $existingHostRoute = Get-NetRoute -DestinationPrefix "$serverIP/32" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
}
$createdEscape = $false
$escapeInterface = 0
$escapeNextHop = ""
try {
  if ($serverIP -and -not $existingHostRoute) {
    $existingRoute = Get-NetRoute -DestinationPrefix "0.0.0.0/0" -AddressFamily IPv4 |
      Sort-Object RouteMetric, InterfaceMetric | Select-Object -First 1
    if (-not $existingRoute) { throw "Could not determine the gateway escape route" }
    New-NetRoute -DestinationPrefix "$serverIP/32" -InterfaceIndex $existingRoute.InterfaceIndex -NextHop $existingRoute.NextHop -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
    $createdEscape = $true
    $escapeInterface = $existingRoute.InterfaceIndex
    $escapeNextHop = [string]$existingRoute.NextHop
  }
  Get-NetRoute -InterfaceAlias $interfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
    Remove-NetRoute -Confirm:$false -ErrorAction Stop
  Get-NetIPAddress -InterfaceAlias $interfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction Stop
  New-NetIPAddress -InterfaceAlias $interfaceName -IPAddress $parts[0] -PrefixLength ([int]$parts[1]) -ErrorAction Stop | Out-Null
  if ($dnsServer) { Set-DnsClientServerAddress -InterfaceAlias $interfaceName -ServerAddresses $dnsServer -ErrorAction Stop }
  New-NetRoute -DestinationPrefix "0.0.0.0/1" -InterfaceAlias $interfaceName -NextHop "0.0.0.0" -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
  New-NetRoute -DestinationPrefix "128.0.0.0/1" -InterfaceAlias $interfaceName -NextHop "0.0.0.0" -RouteMetric 5 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
  [pscustomobject]@{created_escape_route=$createdEscape;escape_interface_index=$escapeInterface;escape_next_hop=$escapeNextHop} | ConvertTo-Json -Compress
} catch {
  Get-NetRoute -InterfaceAlias $interfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  Set-DnsClientServerAddress -InterfaceAlias $interfaceName -ResetServerAddresses -ErrorAction SilentlyContinue
  Get-NetIPAddress -InterfaceAlias $interfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
  if ($createdEscape) {
    Get-NetRoute -DestinationPrefix "$serverIP/32" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
      Where-Object { $_.InterfaceIndex -eq $escapeInterface -and [string]$_.NextHop -eq $escapeNextHop } |
      Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
  }
  throw
}
}`

const downScript = `& {
param($interfaceName, $serverIP, $createdEscape, $escapeInterface, $escapeNextHop)
$ErrorActionPreference = "Stop"
Get-NetRoute -InterfaceAlias $interfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Where-Object { $_.DestinationPrefix -in @("0.0.0.0/1", "128.0.0.0/1") } |
  Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
if ($createdEscape -eq "true" -and $serverIP) {
  Get-NetRoute -DestinationPrefix "$serverIP/32" -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object { $_.InterfaceIndex -eq [int]$escapeInterface -and [string]$_.NextHop -eq $escapeNextHop } |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
}
Set-DnsClientServerAddress -InterfaceAlias $interfaceName -ResetServerAddresses -ErrorAction SilentlyContinue
Get-NetIPAddress -InterfaceAlias $interfaceName -AddressFamily IPv4 -ErrorAction SilentlyContinue |
  Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
}`

func downArguments(state networkState) []string {
	return []string{
		"down",
		state.Interface,
		state.ServerIP,
		fmt.Sprintf("%t", state.CreatedEscapeRoute),
		fmt.Sprintf("%d", state.EscapeInterfaceIndex),
		state.EscapeNextHop,
	}
}

func (r *Runner) persistLocked() error {
	data, err := json.Marshal(r.state)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(r.statePath), 0o700); err != nil {
		return fmt.Errorf("create network state directory: %w", err)
	}
	temp := r.statePath + ".tmp"
	if err := os.WriteFile(temp, data, 0o600); err != nil {
		return fmt.Errorf("write network state: %w", err)
	}
	if err := os.Rename(temp, r.statePath); err != nil {
		return fmt.Errorf("replace network state: %w", err)
	}
	return nil
}
