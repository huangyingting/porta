package main

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
)

const testAdminToken = "admin-token-01234567890123456789"

func TestAdminAPIRequiresTokenAndManagesClients(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handler := adminHandler(http.NotFoundHandler(), registry, testAdminToken)

	unauthorized := httptest.NewRecorder()
	handler.ServeHTTP(unauthorized, httptest.NewRequest(http.MethodGet, "/api/clients", nil))
	if unauthorized.Code != http.StatusUnauthorized {
		t.Fatalf("unauthorized status = %d", unauthorized.Code)
	}

	created := adminRequest(t, handler, http.MethodPost, "/api/clients", `{"name":"Operations","max_devices":4}`)
	if created.Code != http.StatusCreated {
		t.Fatalf("create status = %d: %s", created.Code, created.Body.String())
	}
	var createResponse struct {
		Client clientSummary `json:"client"`
		Token  string        `json:"token"`
	}
	if err := json.Unmarshal(created.Body.Bytes(), &createResponse); err != nil {
		t.Fatal(err)
	}
	if createResponse.Token == "" || createResponse.Client.Name != "Operations" {
		t.Fatalf("create response = %#v", createResponse)
	}

	listed := adminRequest(t, handler, http.MethodGet, "/api/clients", "")
	if listed.Code != http.StatusOK || !strings.Contains(listed.Body.String(), "Operations") {
		t.Fatalf("list response = %d: %s", listed.Code, listed.Body.String())
	}

	deleted := adminRequest(t, handler, http.MethodDelete, "/api/clients/"+createResponse.Client.ID, "")
	if deleted.Code != http.StatusNoContent {
		t.Fatalf("delete status = %d: %s", deleted.Code, deleted.Body.String())
	}
}

func TestAdminPageIsProfessionalAndDoesNotEmbedSecrets(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handler := adminHandler(http.NotFoundHandler(), registry, testAdminToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	body := response.Body.String()
	if response.Code != http.StatusOK || !strings.Contains(body, "Porta Control") ||
		!strings.Contains(body, "Client overview") ||
		!strings.Contains(body, "Search clients or devices") {
		t.Fatalf("admin page is incomplete: %d", response.Code)
	}
	if strings.Contains(body, testAdminToken) || strings.Contains(body, "bootstrap-token") {
		t.Fatal("admin page embedded a credential")
	}
	if policy := response.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "frame-ancestors 'none'") {
		t.Fatalf("admin CSP = %q", policy)
	}
	if policy := response.Header().Get("Content-Security-Policy"); !strings.Contains(policy, "font-src 'self'") {
		t.Fatalf("admin CSP = %q", policy)
	}
	if !strings.Contains(body, `font-family:"Mona Sans"`) {
		t.Fatal("admin page does not use the bundled Mona Sans font")
	}
}

func adminRequest(t *testing.T, handler http.Handler, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	request := httptest.NewRequest(method, path, bytes.NewBufferString(body))
	request.Header.Set("Authorization", "Bearer "+testAdminToken)
	if body != "" {
		request.Header.Set("Content-Type", "application/json")
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
