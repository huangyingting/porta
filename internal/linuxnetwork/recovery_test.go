//go:build linux

package linuxnetwork

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func recoverFake(t *testing.T, runner *Runner, system *fakeSystem) *Runner {
	t.Helper()
	if err := runner.releaseLock(); err != nil {
		t.Fatal(err)
	}
	recovered, err := NewRunner(runner.statePath)
	if err != nil {
		t.Fatal(err)
	}
	bindFake(recovered, system)
	t.Cleanup(func() { _ = recovered.releaseLock() })
	return recovered
}

func TestInterruptedSetupResumesWithoutRemovingProtection(t *testing.T) {
	baseline, baselineSystem := newFake(t)
	if err := baseline.Up(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	for failure := 1; failure <= baselineSystem.mutations; failure++ {
		t.Run(fmt.Sprintf("mutation_%d", failure), func(t *testing.T) {
			runner, system := newFake(t)
			system.failAt, system.failAfter = failure, true
			if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err == nil {
				t.Fatal("expected interrupted setup")
			}
			recovered := recoverFake(t, runner, system)
			system.failAt = 0
			if err := recovered.Up(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
				t.Fatal(err)
			}
			if len(system.addresses["porta0"]) != 1 || len(system.routes) != 4 || len(system.tables) != 1 {
				t.Fatal("recovery did not converge to one complete configuration")
			}
			for _, script := range system.scripts {
				if strings.Contains(script, "delete table") {
					t.Fatal("resume removed the persistent guard")
				}
			}
		})
	}
}

func TestEveryInterruptedCleanupCanBeRetriedAfterRestart(t *testing.T) {
	baseline, baselineSystem := newFake(t)
	ctx := context.Background()
	if err := baseline.Up(ctx, "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	baselineSystem.mutations = 0
	if err := baseline.Down(ctx); err != nil {
		t.Fatal(err)
	}
	for failure := 1; failure <= baselineSystem.mutations; failure++ {
		for _, after := range []bool{false, true} {
			t.Run(fmt.Sprintf("mutation_%d_after_%t", failure, after), func(t *testing.T) {
				runner, system := newFake(t)
				if err := runner.Up(ctx, "porta0", testEndpoint(), testLease()); err != nil {
					t.Fatal(err)
				}
				system.mutations, system.failAt, system.failAfter = 0, failure, after
				if err := runner.Down(ctx); err == nil {
					t.Fatal("expected interrupted cleanup")
				}
				if failure < baselineSystem.mutations && len(system.tables) != 1 {
					t.Fatal("cleanup removed the guard before other restoration completed")
				}
				recovered := recoverFake(t, runner, system)
				system.failAt = 0
				if err := recovered.Down(ctx); err != nil {
					t.Fatal(err)
				}
				if len(system.tables) != 0 || len(system.routes) != 0 || len(system.addresses["porta0"]) != 0 || len(system.dns) != 0 {
					t.Fatal("cleanup retry left owned mutations")
				}
			})
		}
	}
}

func TestRecoveryEndpointsRemainLiteralAndAllowProtocolFailover(t *testing.T) {
	runner, system := newFake(t)
	if err := runner.Prepare(context.Background(), testEndpoint()); err != nil {
		t.Fatal(err)
	}
	tcp := &net.TCPAddr{IP: net.ParseIP("198.51.100.10"), Port: 443}
	if err := runner.Prepare(context.Background(), tcp); err != nil {
		t.Fatal(err)
	}
	recovered := recoverFake(t, runner, system)
	endpoints := recovered.RecoveryEndpoints()
	if len(endpoints) != 1 || endpoints[0].String() != testEndpoint().String() {
		t.Fatalf("incorrect crash recovery endpoints: %v", endpoints)
	}
	endpoints[0].(*net.TCPAddr).IP[0] = 127
	if recovered.RecoveryEndpoints()[0].String() != testEndpoint().String() {
		t.Fatal("caller can mutate saved endpoint identity")
	}
	for _, protocol := range []string{"tcp", "udp"} {
		if !strings.Contains(system.scripts[len(system.scripts)-1], "ip daddr 198.51.100.10 "+protocol+" dport 443 accept") {
			t.Fatalf("missing narrow %s failover exception", protocol)
		}
	}
}

func TestRunnerReacquisitionReloadsInterveningRecoveryState(t *testing.T) {
	runner, system := newFake(t)
	if err := runner.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
	other, err := NewRunner(runner.statePath)
	if err != nil {
		t.Fatal(err)
	}
	bindFake(other, system)
	if err := other.Prepare(context.Background(), testEndpoint()); err != nil {
		t.Fatal(err)
	}
	originalTable := other.state.Table
	if err := other.releaseLock(); err != nil {
		t.Fatal(err)
	}
	if err := runner.Prepare(context.Background(), testEndpoint()); err != nil {
		t.Fatal(err)
	}
	if runner.state.Table != originalTable || len(system.tables) != 1 {
		t.Fatal("reusing a runner lost intervening crash recovery state")
	}
}

func TestInvalidJournalIsRejectedWithoutCommands(t *testing.T) {
	for _, mutation := range []string{"table", "action", "permissions", "symlink", "unknown-field"} {
		t.Run(mutation, func(t *testing.T) {
			runner, system := newFake(t)
			if err := runner.Prepare(context.Background(), testEndpoint()); err != nil {
				t.Fatal(err)
			}
			if err := runner.releaseLock(); err != nil {
				t.Fatal(err)
			}
			data, err := os.ReadFile(runner.statePath)
			if err != nil {
				t.Fatal(err)
			}
			var state map[string]any
			if err := json.Unmarshal(data, &state); err != nil {
				t.Fatal(err)
			}
			switch mutation {
			case "table":
				state["table"] = "filter; flush ruleset"
			case "action":
				state["undo"] = []any{map[string]any{"kind": "execute", "interface": "eth0", "index": 2}}
			case "unknown-field":
				state["execute"] = "not allowed"
			case "permissions":
				if err := os.Chmod(runner.statePath, 0644); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				target := filepath.Join(filepath.Dir(runner.statePath), "saved.json")
				if err := os.Rename(runner.statePath, target); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(target, runner.statePath); err != nil {
					t.Fatal(err)
				}
			}
			if mutation == "table" || mutation == "action" || mutation == "unknown-field" {
				data, err = json.Marshal(state)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(runner.statePath, data, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if invalid, err := NewRunner(runner.statePath); err == nil {
				_ = invalid.releaseLock()
				t.Fatal("invalid recovery journal accepted")
			}
			if len(system.tables) != 1 {
				t.Fatal("invalid journal handling removed protection")
			}
		})
	}
}

func TestCanceledReconfigureKeepsProtection(t *testing.T) {
	runner, system := newFake(t)
	if err := runner.Up(context.Background(), "porta0", testEndpoint(), testLease()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runner.Reconfigure(ctx, "porta0", testEndpoint(), testLease()); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
	if len(system.tables) != 1 {
		t.Fatal("cancellation silently disabled protection")
	}
	if err := runner.Down(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestConcurrentPreparationIsSerialized(t *testing.T) {
	runner, system := newFake(t)
	var workers sync.WaitGroup
	for index := 0; index < 8; index++ {
		workers.Go(func() {
			if err := runner.Prepare(context.Background(), testEndpoint()); err != nil {
				t.Error(err)
			}
			_ = runner.RecoveryEndpoints()
		})
	}
	workers.Wait()
	if len(system.tables) != 1 || len(system.routes) != 1 || len(runner.RecoveryEndpoints()) != 1 {
		t.Fatal("concurrent preparation duplicated owned state")
	}
}
