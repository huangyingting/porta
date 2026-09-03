package main

import (
	_ "embed"
	"net/http"
	"strconv"
)

const (
	portaMarkPath = "/assets/porta-mark.svg"
	faviconPath   = "/favicon.ico"
)

//go:embed assets/porta-mark.svg
var portaMark []byte

func serveBrandAsset(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != portaMarkPath && r.URL.Path != faviconPath {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Type", "image/svg+xml")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(portaMark)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(portaMark)
	}
	return true
}
