package winnetwork

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRecoveryJournalRejectsIncompleteOwnership(t *testing.T) {
	for name, damage := range map[string]func(*networkState){
		"missing version":  func(s *networkState) { s.Version = 0 },
		"future version":   func(s *networkState) { s.Version = 3 },
		"interface":        func(s *networkState) { s.Interface = "" },
		"guard identity":   func(s *networkState) { s.GuardKey = "" },
		"adapter identity": func(s *networkState) { s.InterfaceGUID = "" },
		"endpoint":         func(s *networkState) { s.Endpoint = endpoint{} },
		"endpoint mismatch": func(s *networkState) {
			s.ServerIP = "203.0.113.1"
		},
		"missing route identity": func(s *networkState) {
			s.Routes = []routeState{{Kind: "escape", Prefix: "192.0.2.1/32", Interface: 7, NextHop: "192.0.2.254"}}
		},
		"MTU snapshot": func(s *networkState) { s.MTU = &mtuState{Applied: 1100} },
		"DNS snapshot": func(s *networkState) { s.DNS = &dnsState{Pending: "invalid"} },
	} {
		t.Run(name, func(t *testing.T) {
			runner := testRunner(t)
			if err := runner.Up(context.Background(), "Porta", testRemote(), testLease()); err != nil {
				t.Fatal(err)
			}
			state := runner.state
			damage(&state)
			data, err := json.Marshal(state)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(runner.statePath, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := NewRunner(runner.statePath); err == nil {
				t.Fatal("incomplete ownership accepted for network mutation")
			}
		})
	}
}

func TestRecoveryJournalRejectsOversizedOrEmptyObjects(t *testing.T) {
	runner := testRunner(t)
	for _, data := range []string{"{}", strings.Repeat(" ", (1<<20)+1)} {
		if err := os.WriteFile(runner.statePath, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := NewRunner(runner.statePath); err == nil {
			t.Fatal("invalid recovery journal treated as a fresh connection")
		}
	}
}
