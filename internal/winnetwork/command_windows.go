package winnetwork

import (
	"context"
	"errors"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/windows"
)

func networkCommand(ctx context.Context, statePath string, arguments []string) (*exec.Cmd, error) {
	if len(arguments) < 2 || arguments[1] != statePath {
		return nil, errors.New("network helper state path does not match")
	}
	count := 2
	switch arguments[0] {
	case "up", "configure-interface":
		count = 5
	case "prepare", "down", "retire-interface":
	default:
		return nil, errors.New("invalid network helper operation")
	}
	if len(arguments) != count {
		return nil, errors.New("invalid network helper arguments")
	}
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return nil, err
	}
	root := filepath.Dir(system)
	shellDirectory := filepath.Join(system, "WindowsPowerShell", "v1.0")
	// The embedded script arrives over stdin, with arguments passed only as data.
	// Neither scripts nor modules are loaded from a user-writable search path.
	bootstrap := `$ErrorActionPreference='Stop'; $code=[Console]::In.ReadToEnd(); & ([ScriptBlock]::Create($code)) -Operation $env:PORTA_NETWORK_OPERATION -StatePath $env:PORTA_NETWORK_STATE_PATH -AddressCidr $env:PORTA_NETWORK_ADDRESS_CIDR -DnsServer $env:PORTA_NETWORK_DNS_SERVER -Mtu ([int]$env:PORTA_NETWORK_MTU)`
	command := exec.CommandContext(ctx, filepath.Join(shellDirectory, "powershell.exe"),
		"-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-Command", bootstrap)
	command.Dir = system
	command.Stdin = strings.NewReader(networkScript)
	command.Env = []string{
		"SystemRoot=" + root, "WINDIR=" + root, "SystemDrive=" + filepath.VolumeName(root), "OS=Windows_NT",
		"PATH=" + system + ";" + shellDirectory, "PATHEXT=.COM;.EXE;.BAT;.CMD",
		"ComSpec=" + filepath.Join(system, "cmd.exe"), "PSModulePath=" + filepath.Join(shellDirectory, "Modules"),
		"TEMP=" + filepath.Dir(statePath), "TMP=" + filepath.Dir(statePath),
		"PORTA_NETWORK_OPERATION=" + arguments[0], "PORTA_NETWORK_STATE_PATH=" + statePath,
	}
	address, dns, mtu := "", "", "1100"
	if count == 5 {
		address, dns, mtu = arguments[2], arguments[3], arguments[4]
	}
	command.Env = append(command.Env, "PORTA_NETWORK_ADDRESS_CIDR="+address, "PORTA_NETWORK_DNS_SERVER="+dns, "PORTA_NETWORK_MTU="+mtu)
	return command, nil
}

func hideNetworkCommand(command *exec.Cmd) {
	command.SysProcAttr = &syscall.SysProcAttr{
		HideWindow: true, CreationFlags: windows.CREATE_NO_WINDOW,
	}
}
