package main

import (
	"context"
	"errors"

	"github.com/huangyingting/porta/internal/winnetwork"
)

func canExitAfterDisconnect(err error, pendingRecovery bool) bool {
	if errors.Is(err, winnetwork.ErrStateInUse) {
		return true
	}
	return !pendingRecovery && (err == nil || err == context.Canceled)
}
