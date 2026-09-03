package main

import (
	_ "embed"
	"net/http"
	"strconv"
)

const webFontPath = "/assets/mona-sans.woff2"

//go:embed assets/MonaSans.woff2
var monaSans []byte

func serveWebFont(w http.ResponseWriter, r *http.Request) bool {
	if r.URL.Path != webFontPath {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return true
	}
	w.Header().Set("Content-Type", "font/woff2")
	w.Header().Set("Cache-Control", "public, max-age=31536000, immutable")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Length", strconv.Itoa(len(monaSans)))
	if r.Method == http.MethodGet {
		_, _ = w.Write(monaSans)
	}
	return true
}
