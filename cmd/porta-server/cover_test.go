package main

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPublicSiteServesBrowserCoverPage(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("ordinary browser request reached the tunnel handler")
	})
	handler := publicSiteHandler(next, true)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://vpn.example.com/", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("content type = %q, want HTML", contentType)
	}
	if !strings.Contains(response.Body.String(), "<h1>") {
		t.Fatal("cover page has no visible heading")
	}
	if !strings.Contains(response.Body.String(), "Ideas made <em>clear.</em>") {
		t.Fatal("cover page is missing its primary visual message")
	}
	if strings.Contains(strings.ToLower(response.Body.String()), "porta") {
		t.Fatal("cover page identifies the tunnel service")
	}
	if !strings.Contains(response.Body.String(), `font-family:"Mona Sans"`) {
		t.Fatal("cover page does not use the bundled Mona Sans font")
	}
	if policy := response.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "font-src 'self'") {
		t.Fatalf("cover CSP = %q", policy)
	}
}

func TestPublicSiteConcealsOperationalEndpoints(t *testing.T) {
	nextCalled := false
	handler := publicSiteHandler(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		nextCalled = true
	}), true)

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://vpn.example.com"+path, nil))
		if !strings.Contains(response.Body.String(), "<h1>") {
			t.Fatalf("%s did not receive the cover page", path)
		}
	}
	if nextCalled {
		t.Fatal("public operational request reached the gateway handler")
	}
}

func TestPublicSitePreservesTunnelRequests(t *testing.T) {
	handler := publicSiteHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusAccepted)
	}), true)
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "https://vpn.example.com/v1/tunnel", nil))

	if response.Code != http.StatusAccepted {
		t.Fatalf("tunnel status = %d, want 202", response.Code)
	}
}

func TestPublicSiteServesBundledFont(t *testing.T) {
	handler := publicSiteHandler(http.NotFoundHandler(), true)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://vpn.example.com"+webFontPath, nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "font/woff2" {
		t.Fatalf("font response = %d %q", response.Code, response.Header().Get("Content-Type"))
	}
	if response.Body.Len() != len(monaSans) {
		t.Fatalf("font length = %d, want %d", response.Body.Len(), len(monaSans))
	}
	if cacheControl := response.Header().Get("Cache-Control"); !strings.Contains(cacheControl, "immutable") {
		t.Fatalf("font Cache-Control = %q", cacheControl)
	}
}

func TestAdminSiteServesBundledFont(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handler := adminHandler(http.NotFoundHandler(), registry, "admin-token-01234567890123456789")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodHead, "http://127.0.0.1:9090"+webFontPath, nil))
	if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "font/woff2" {
		t.Fatalf("font response = %d %q", response.Code, response.Header().Get("Content-Type"))
	}
	if response.Header().Get("Content-Length") != strconv.Itoa(len(monaSans)) {
		t.Fatalf("font Content-Length = %q", response.Header().Get("Content-Length"))
	}
}

func TestPublicSiteCanDisableCoverWithoutExposingOperations(t *testing.T) {
	handler := publicSiteHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), false)

	root := httptest.NewRecorder()
	handler.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "https://vpn.example.com/", nil))
	if root.Code != http.StatusTeapot {
		t.Fatalf("disabled cover status = %d, want 418", root.Code)
	}

	health := httptest.NewRecorder()
	handler.ServeHTTP(health, httptest.NewRequest(http.MethodGet, "https://vpn.example.com/healthz", nil))
	if health.Code != http.StatusNotFound {
		t.Fatalf("public health status = %d, want 404", health.Code)
	}
}

func TestAdminHandlerAllowsOnlyOperationalGETs(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handler := adminHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(r.URL.Path))
	}), registry, "admin-token-01234567890123456789")

	for _, path := range []string{"/healthz", "/readyz", "/metrics"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1:9090"+path, nil))
		if response.Body.String() != path {
			t.Fatalf("%s response = %q", path, response.Body.String())
		}
	}

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "http://127.0.0.1:9090/v1/tunnel", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("admin tunnel status = %d, want 404", response.Code)
	}
}
