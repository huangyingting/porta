package clientid

import (
	"os"
	"regexp"
	"strings"
)

var invalid = regexp.MustCompile(`[^A-Za-z0-9._-]+`)

func Default(fallback string) string {
	hostname, err := os.Hostname()
	if err != nil {
		return fallback
	}
	return FromHostname(hostname, fallback)
}

func FromHostname(hostname, fallback string) string {
	value := strings.Trim(invalid.ReplaceAllString(hostname, "-"), "-._")
	if value == "" {
		return fallback
	}
	if len(value) > 64 {
		value = value[:64]
	}
	return value
}
