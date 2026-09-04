package winnetwork

import (
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unicode/utf16"

	"github.com/huangyingting/porta/internal/tunnel"
)

func TestEncodedCommandPreservesLiteralArguments(t *testing.T) {
	arguments := []string{"Porta work", "", "a'b", "$env:Path; Write-Host wrong", "日本語"}
	encoded := encodeCommand("& { param($a, $b, $c, $d, $e) }", arguments)
	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatal(err)
	}
	words := make([]uint16, len(data)/2)
	for i := range words {
		words[i] = binary.LittleEndian.Uint16(data[i*2:])
	}
	got := string(utf16.Decode(words))
	want := "& { param($a, $b, $c, $d, $e) } 'Porta work' '' 'a''b' '$env:Path; Write-Host wrong' '日本語'"
	if got != want {
		t.Fatalf("decoded command = %q, want %q", got, want)
	}
}

func TestUpCancellationRollsBackJournaledRoutes(t *testing.T) {
	for _, rollbackFails := range []bool{false, true} {
		t.Run(map[bool]string{false: "cleanup-succeeds", true: "cleanup-retried"}[rollbackFails], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "network-state.json")
			runner, err := NewRunner(path)
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			owned := networkState{Interface: "Porta work", ServerIP: "192.0.2.1", CreatedEscapeRoute: true, EscapeInterfaceIndex: 7, EscapeNextHop: "192.0.2.254"}
			downCalls := 0
			runner.runCommand = func(ctx context.Context, args ...string) (string, error) {
				if args[0] == "up" {
					var initial networkState
					data, err := os.ReadFile(path)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(data, &initial); err != nil {
						t.Fatal(err)
					}
					if initial.Interface != owned.Interface || initial.CreatedEscapeRoute {
						t.Fatalf("invalid initial journal: %+v", initial)
					}
					data, err = json.Marshal(owned)
					if err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(path, data, 0o600); err != nil {
						t.Fatal(err)
					}
					cancel()
					return "", context.Canceled
				}
				downCalls++
				if ctx.Err() != nil {
					t.Fatal("rollback used canceled context")
				}
				if !reflect.DeepEqual(args, downArguments(owned)) {
					t.Fatalf("lost route ownership: %v", args)
				}
				if rollbackFails && downCalls == 1 {
					return "", errors.New("cleanup denied")
				}
				return "", nil
			}
			err = runner.Up(ctx, owned.Interface, &net.TCPAddr{IP: net.ParseIP(owned.ServerIP), Port: 443}, tunnel.Lease{Address: netip.MustParsePrefix("10.0.0.2/24"), MTU: 1280})
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("error = %v", err)
			}
			if downCalls != 1 {
				t.Fatalf("rollback calls = %d", downCalls)
			}
			if rollbackFails {
				if runner.state != owned {
					t.Fatal("failed rollback forgot in-memory state")
				}
				reopened, err := NewRunner(path)
				if err != nil || reopened.state != owned {
					t.Fatalf("failed rollback forgot persistent state: %v", err)
				}
				if err := runner.Down(context.Background()); err != nil {
					t.Fatal(err)
				}
			}
			if runner.state.Interface != "" {
				t.Fatal("successful rollback retained active state")
			}
			if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("journal remains: %v", err)
			}
		})
	}
}

func TestUpDoesNotChangeNetworkWhenJournalCannotBeWritten(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	runner := &Runner{statePath: filepath.Join(blocker, "state.json")}
	runner.runCommand = func(context.Context, ...string) (string, error) {
		t.Fatal("network changed without journal")
		return "", nil
	}
	err := runner.Up(context.Background(), "Porta", &net.TCPAddr{IP: net.ParseIP("192.0.2.1"), Port: 443}, tunnel.Lease{})
	if err == nil {
		t.Fatal("unwritable journal accepted")
	}
	if runner.state.Interface != "" {
		t.Fatal("failed initial journal retained state")
	}
}

func TestDownPreservesStateOnCleanupFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "state.json")
	runner := &Runner{statePath: path, state: networkState{Interface: "Porta"}}
	if err := runner.persistLocked(); err != nil {
		t.Fatal(err)
	}
	runner.runCommand = func(context.Context, ...string) (string, error) { return "", errors.New("access denied") }
	if err := runner.Down(context.Background()); err == nil {
		t.Fatal("cleanup error hidden")
	}
	if runner.state.Interface == "" {
		t.Fatal("cleanup retry state lost")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal("persistent cleanup state lost")
	}
}
