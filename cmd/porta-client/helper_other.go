//go:build !windows

package main

import "context"

func runNetworkHelper(context.Context, []string) (bool, error) {
	return false, nil
}
