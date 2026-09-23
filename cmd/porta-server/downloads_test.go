package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestClientDownloadHandlerServesOnlyPublishedArtifacts(t *testing.T) {
	directory := t.TempDir()
	artifact := "porta-client-linux-amd64"
	content := []byte("porta-client")
	if err := os.WriteFile(filepath.Join(directory, artifact), content, 0o600); err != nil {
		t.Fatal(err)
	}
	handler := clientDownloadHandler(http.NotFoundHandler(), directory)

	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, clientDownloadPrefix+artifact, nil))
	if response.Code != http.StatusOK || response.Body.String() != string(content) {
		t.Fatalf("download response = %d %q", response.Code, response.Body.String())
	}
	if response.Header().Get("Content-Type") != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", response.Header().Get("Content-Type"))
	}
	if disposition := response.Header().Get("Content-Disposition"); !strings.Contains(disposition, artifact) {
		t.Fatalf("Content-Disposition = %q", disposition)
	}

	for _, path := range []string{
		clientDownloadPrefix,
		clientDownloadPrefix + "../porta.env",
		clientDownloadPrefix + "unknown",
		clientDownloadPrefix + artifact + "/extra",
	} {
		blocked := httptest.NewRecorder()
		handler.ServeHTTP(blocked, httptest.NewRequest(http.MethodGet, path, nil))
		if blocked.Code != http.StatusNotFound {
			t.Fatalf("%s status = %d, want 404", path, blocked.Code)
		}
	}
}

func TestClientDownloadHandlerFallsThroughOutsideDownloadPath(t *testing.T) {
	handler := clientDownloadHandler(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	}), t.TempDir())
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusTeapot {
		t.Fatalf("fallback status = %d, want %d", response.Code, http.StatusTeapot)
	}
}

func TestClientDownloadHandlerRejectsSymlinks(t *testing.T) {
	directory := t.TempDir()
	outside := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(directory, "SHA256SUMS")); err != nil {
		t.Fatal(err)
	}
	handler := clientDownloadHandler(http.NotFoundHandler(), directory)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, clientDownloadPrefix+"SHA256SUMS", nil))
	if response.Code != http.StatusNotFound {
		t.Fatalf("symlink status = %d, want 404", response.Code)
	}
}

func TestClientDownloadHandlerReleaseMetadata(t *testing.T) {
	directory := t.TempDir()
	for _, artifact := range []struct{ name, contentType string }{
		{"SHA256SUMS", "text/plain; charset=utf-8"},
		{"SHA256SUMS.sig", "application/octet-stream"},
		{"release-signing-cert.der", "application/pkix-cert"},
	} {
		t.Run(artifact.name, func(t *testing.T) {
			if err := os.WriteFile(filepath.Join(directory, artifact.name), []byte("metadata"), 0o600); err != nil {
				t.Fatal(err)
			}
			handler := clientDownloadHandler(http.NotFoundHandler(), directory)
			for _, method := range []string{http.MethodGet, http.MethodHead, http.MethodPost} {
				response := httptest.NewRecorder()
				handler.ServeHTTP(response, httptest.NewRequest(method, clientDownloadPrefix+artifact.name, nil))
				if method == http.MethodPost {
					if response.Code != http.StatusNotFound {
						t.Fatalf("POST status = %d", response.Code)
					}
					continue
				}
				if response.Code != http.StatusOK || response.Header().Get("Content-Type") != artifact.contentType ||
					response.Header().Get("Cache-Control") != "private, no-store" ||
					response.Header().Get("X-Content-Type-Options") != "nosniff" {
					t.Fatalf("%s metadata response = %d %v", method, response.Code, response.Header())
				}
				if method == http.MethodHead && response.Body.Len() != 0 {
					t.Fatal("HEAD returned a body")
				}
			}
		})
	}
}
