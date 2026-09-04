package buildinfo

import (
	_ "embed"
	"strings"
)

//go:embed VERSION
var rawVersion string

var Version = strings.TrimSpace(rawVersion)

func IsVersionRequest(args []string) bool {
	return len(args) == 1 && (args[0] == "--version" || args[0] == "-version")
}
