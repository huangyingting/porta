package main

import (
	"context"
	"errors"
	"testing"

	"github.com/huangyingting/porta/internal/winnetwork"
)

func TestExitRequiresSuccessfulNetworkRestoration(t *testing.T) {
	for _, test := range []struct {
		err     error
		pending bool
		exit    bool
	}{
		{nil, false, true},
		{context.Canceled, false, true},
		{nil, true, false},
		{context.Canceled, true, false},
		{errors.New("failed to restore routes"), true, false},
		{errors.New("failed to delete journal"), false, false},
		{errors.Join(context.Canceled, errors.New("cleanup failed")), false, false},
		{winnetwork.ErrStateInUse, true, true},
	} {
		if got := canExitAfterDisconnect(test.err, test.pending); got != test.exit {
			t.Fatalf("err=%v pending=%t: exit=%t", test.err, test.pending, got)
		}
	}
}
