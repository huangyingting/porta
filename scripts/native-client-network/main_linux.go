//go:build linux && !android

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/huangyingting/porta/internal/device"
	"github.com/huangyingting/porta/internal/linuxnetwork"
	"github.com/huangyingting/porta/internal/tunnel"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: native-client-network NETWORK_STATE")
		os.Exit(2)
	}
	if err := run(os.Args[1]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(statePath string) (result error) {
	if os.Getenv("PORTA_NATIVE_CLIENT_NETWORK_TEST") != "1" {
		return errors.New("native client networking requires explicit namespace test opt-in")
	}
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		return err
	}
	host, err := os.Readlink("/proc/1/ns/net")
	if err != nil {
		return err
	}
	if current == host {
		return errors.New("native client networking must run in an isolated network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	lease := tunnel.Lease{
		Address: netip.MustParsePrefix("10.66.0.2/24"),
		Gateway: netip.MustParseAddr("10.66.0.1"),
		DNS:     netip.MustParseAddr("1.1.1.1"),
		MTU:     1280,
	}
	tun, err := device.OpenNative("porta0", lease.MTU)
	if err != nil {
		return err
	}
	defer func() { result = errors.Join(result, tun.Close()) }()
	network, err := linuxnetwork.NewRunner(statePath)
	if err != nil {
		return err
	}
	defer func() {
		cleanup, stop := context.WithTimeout(context.Background(), 10*time.Second)
		defer stop()
		result = errors.Join(result, network.Down(cleanup))
	}()
	endpoint := &net.UDPAddr{IP: net.ParseIP("198.51.100.10"), Port: 443}
	if err := network.Prepare(ctx, endpoint); err != nil {
		return fmt.Errorf("prepare fail-closed guard: %w", err)
	}
	data, err := os.ReadFile(statePath)
	if err != nil {
		return err
	}
	var journal struct{ Table string }
	if err := json.Unmarshal(data, &journal); err != nil {
		return err
	}
	if journal.Table == "" {
		return errors.New("native network journal has no firewall table")
	}
	if _, err := command(ctx, "nft", "list", "table", "inet", journal.Table); err != nil {
		return err
	}
	if err := network.Up(ctx, tun.Name(), endpoint, lease); err != nil {
		return fmt.Errorf("configure native client network: %w", err)
	}
	data, err = command(ctx, "ip", "-j", "-4", "route", "show", "proto", "186")
	if err != nil {
		return err
	}
	var routes []struct {
		Destination string `json:"dst"`
		Device      string `json:"dev"`
	}
	if err := json.Unmarshal(data, &routes); err != nil {
		return err
	}
	for _, prefix := range []string{"0.0.0.0/1", "128.0.0.0/1"} {
		found := false
		for _, route := range routes {
			found = found || route.Destination == prefix && route.Device == tun.Name()
		}
		if !found {
			return fmt.Errorf("native client route %s is missing", prefix)
		}
	}
	link, err := net.InterfaceByName(tun.Name())
	if err != nil {
		return err
	}
	if link.MTU != lease.MTU || link.Flags&net.FlagUp == 0 {
		return errors.New("native client TUN has the wrong MTU or link state")
	}
	if err := network.Down(ctx); err != nil {
		return fmt.Errorf("restore native client network: %w", err)
	}
	if _, err := os.Stat(statePath); !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("network journal was not removed: %v", err)
	}
	tables, err := command(ctx, "nft", "list", "tables")
	if err != nil {
		return err
	}
	if strings.Contains(string(tables), journal.Table) {
		return errors.New("native client firewall remains after disconnect")
	}
	fmt.Println("native client guard, full-tunnel routes, MTU and cleanup passed")
	return nil
}

func command(ctx context.Context, name string, args ...string) ([]byte, error) {
	output, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return nil, fmt.Errorf("%s %v: %w: %s", name, args, err, output)
	}
	return output, nil
}
