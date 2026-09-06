package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestPublicSiteServesPortaLandingPage(t *testing.T) {
	next := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("ordinary browser request reached the tunnel handler")
	})
	handler := publicSiteHandlerWithTemplates(next, true, newLandingTemplateSet([]string{landingHTML}))
	response := httptest.NewRecorder()

	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://vpn.example.com/", nil))

	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if contentType := response.Header().Get("Content-Type"); !strings.HasPrefix(contentType, "text/html") {
		t.Fatalf("content type = %q, want HTML", contentType)
	}
	if !strings.Contains(response.Body.String(), "<h1>") {
		t.Fatal("landing page has no visible heading")
	}
	if !strings.Contains(response.Body.String(), "Thoughtful work.") {
		t.Fatal("landing page is missing its primary message")
	}
	if !strings.Contains(response.Body.String(), "<title>Porta · Digital product studio</title>") {
		t.Fatal("landing page is not branded as Porta")
	}
	for _, term := range []string{"network", "vpn", "gateway", "tunnel", "http/3", "self-hosted"} {
		if strings.Contains(strings.ToLower(response.Body.String()), term) {
			t.Fatalf("landing page exposes service term %q", term)
		}
	}
	if !strings.Contains(response.Body.String(), `font-family:"Mona Sans"`) {
		t.Fatal("landing page does not use the bundled Mona Sans font")
	}
	if !strings.Contains(response.Body.String(), `src="/assets/porta-mark.svg"`) {
		t.Fatal("landing page does not use the Porta mark")
	}
	if !strings.Contains(response.Body.String(), `class="access-link" href="/access">Get access</a>`) {
		t.Fatal("landing page does not expose the hero access action")
	}
	if policy := response.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "font-src 'self'") {
		t.Fatalf("landing CSP = %q", policy)
	}
	if directives := response.Header().Get("X-Robots-Tag"); directives != robotsDirectives {
		t.Fatalf("X-Robots-Tag = %q", directives)
	}
	if !strings.Contains(response.Body.String(), `<meta name="robots" content="`+robotsDirectives+`">`) {
		t.Fatal("landing page is missing crawler directives")
	}
}

func TestPublicSiteSelectsFromLandingTemplatePool(t *testing.T) {
	call := 0
	templates := landingTemplateSet{
		pages: []string{"<html><h1>first</h1></html>", "<html><h1>second</h1></html>"},
		randomIndex: func(limit int) int {
			index := call % limit
			call++
			return index
		},
	}
	handler := publicSiteHandlerWithTemplates(http.NotFoundHandler(), true, templates)
	for _, expected := range []string{"first", "second", "first"} {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://vpn.example.com/", nil))
		if !strings.Contains(response.Body.String(), expected) {
			t.Fatalf("response %d = %q, want template %q", call, response.Body.String(), expected)
		}
		if cacheControl := response.Header().Get("Cache-Control"); cacheControl != "no-store" {
			t.Fatalf("Cache-Control = %q, want no-store", cacheControl)
		}
		if directives := response.Header().Get("X-Robots-Tag"); directives != robotsDirectives {
			t.Fatalf("X-Robots-Tag = %q", directives)
		}
	}
}

func TestLoadLandingTemplateSetUsesCustomHTMLFiles(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "b.html"), []byte("<h1>second custom page</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "a.HTML"), []byte("<h1>first custom page</h1>"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "notes.txt"), []byte("ignored"), 0o600); err != nil {
		t.Fatal(err)
	}
	templates, err := loadLandingTemplateSet(directory)
	if err != nil {
		t.Fatal(err)
	}
	if len(templates.pages) != 2 {
		t.Fatalf("template count = %d, want 2", len(templates.pages))
	}
	if !strings.Contains(templates.pages[0], "first custom page") ||
		!strings.Contains(templates.pages[1], "second custom page") {
		t.Fatalf("templates were not loaded in filename order: %#v", templates.pages)
	}
}

func TestLoadLandingTemplateSetFallsBackToBundledPages(t *testing.T) {
	templates, err := loadLandingTemplateSet(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(templates.pages) != 6 {
		t.Fatalf("bundled template count = %d, want 6", len(templates.pages))
	}
	seen := make(map[string]struct{}, len(templates.pages))
	for index, page := range templates.pages {
		if !strings.Contains(page, "<title>Porta") ||
			!strings.Contains(page, "<h1>") ||
			!strings.Contains(page, `src="/assets/porta-mark.svg"`) ||
			!strings.Contains(page, `href="/access"`) ||
			!strings.Contains(page, `font-family:"Mona Sans"`) ||
			!strings.Contains(page, "@media") ||
			!strings.Contains(page, `<meta name="robots" content="`+robotsDirectives+`">`) {
			t.Fatalf("bundled template %d is missing required landing content", index)
		}
		for _, term := range []string{"network", "vpn", "gateway", "tunnel", "http/3", "self-hosted"} {
			if strings.Contains(strings.ToLower(page), term) {
				t.Fatalf("bundled template %d exposes service term %q", index, term)
			}
		}
		if _, exists := seen[page]; exists {
			t.Fatalf("bundled template %d duplicates another page", index)
		}
		seen[page] = struct{}{}
	}
}

func TestLoadLandingTemplateSetRejectsEmptyHTML(t *testing.T) {
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "empty.html"), []byte(" \n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLandingTemplateSet(directory); err == nil || !strings.Contains(err.Error(), "is empty") {
		t.Fatalf("load error = %v, want empty template error", err)
	}
}

func TestLoadLandingTemplateSetRejectsOversizedHTML(t *testing.T) {
	directory := t.TempDir()
	content := make([]byte, maxLandingTemplateSize+1)
	if err := os.WriteFile(filepath.Join(directory, "large.html"), content, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := loadLandingTemplateSet(directory); err == nil || !strings.Contains(err.Error(), "exceeds the 1 MiB limit") {
		t.Fatalf("load error = %v, want size limit error", err)
	}
}

func TestPublicSiteDisallowsCrawlersWhenLandingIsDisabled(t *testing.T) {
	handler := publicSiteHandler(http.NotFoundHandler(), false)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "https://vpn.example.com/robots.txt", nil))
	if response.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", response.Code)
	}
	if response.Body.String() != robotsText {
		t.Fatalf("robots.txt = %q", response.Body.String())
	}
	if directives := response.Header().Get("X-Robots-Tag"); directives != robotsDirectives {
		t.Fatalf("X-Robots-Tag = %q", directives)
	}

	head := httptest.NewRecorder()
	handler.ServeHTTP(head, httptest.NewRequest(http.MethodHead, "https://vpn.example.com/robots.txt", nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Fatalf("HEAD response = %d with %d body bytes", head.Code, head.Body.Len())
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
			t.Fatalf("%s did not receive the landing page", path)
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
	if directives := response.Header().Get("X-Robots-Tag"); directives != "" {
		t.Fatalf("tunnel response received crawler directives %q", directives)
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

func TestWebSitesServePortaMark(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handlers := []http.Handler{
		publicSiteHandler(http.NotFoundHandler(), true),
		adminHandler(http.NotFoundHandler(), registry, "admin-token-01234567890123456789"),
	}
	for _, handler := range handlers {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, portaMarkPath, nil))
		if response.Code != http.StatusOK || response.Header().Get("Content-Type") != "image/svg+xml" {
			t.Fatalf("mark response = %d %q", response.Code, response.Header().Get("Content-Type"))
		}
		if response.Body.Len() != len(portaMark) {
			t.Fatalf("mark length = %d, want %d", response.Body.Len(), len(portaMark))
		}
	}
}

func TestPublicSiteCanDisableLandingWithoutExposingOperations(t *testing.T) {
	handler := publicSiteHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), false)

	root := httptest.NewRecorder()
	handler.ServeHTTP(root, httptest.NewRequest(http.MethodGet, "https://vpn.example.com/", nil))
	if root.Code != http.StatusTeapot {
		t.Fatalf("disabled landing status = %d, want 418", root.Code)
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
