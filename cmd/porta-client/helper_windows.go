package main

import (
	"context"

	"github.com/huangyingting/porta/internal/winnetwork"
)

func runNetworkHelper(ctx context.Context, args []string) (bool, error) {
	return winnetwork.RunHelper(ctx, args)
}
