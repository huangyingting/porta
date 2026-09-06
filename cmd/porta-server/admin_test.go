package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/huangyingting/porta/internal/usage"
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

func TestAdminAPIDoesNotExposePersistenceFailuresAsClientErrors(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	var logs bytes.Buffer
	registry.logger = slog.New(slog.NewTextHandler(&logs, nil))
	registry.writeState = func([]byte) error {
		return errors.New("injected private filesystem path")
	}
	handler := adminHandler(http.NotFoundHandler(), registry, testAdminToken)

	response := adminRequest(t, handler, http.MethodPost, "/api/clients", `{"name":"Operations","max_devices":4}`)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("create status = %d: %s", response.Code, response.Body.String())
	}
	if strings.Contains(response.Body.String(), "filesystem") || !strings.Contains(response.Body.String(), "Internal server error") {
		t.Fatalf("internal error was exposed: %s", response.Body.String())
	}
	if !strings.Contains(logs.String(), "injected private filesystem path") {
		t.Fatalf("internal failure was not logged: %s", logs.String())
	}

	response = adminRequest(t, handler, http.MethodPost, "/api/clients", `{"name":"","max_devices":4}`)
	if response.Code != http.StatusBadRequest || !strings.Contains(response.Body.String(), "client name") {
		t.Fatalf("validation status = %d: %s", response.Code, response.Body.String())
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
	if !strings.Contains(body, `class="client-table"`) ||
		!strings.Contains(body, "Active sessions") ||
		!strings.Contains(body, "Highest traffic") ||
		strings.Contains(body, `class="card"`) {
		t.Fatal("admin page does not provide the compact operational table")
	}
	if !strings.Contains(body, `id="disconnect-client"`) || !strings.Contains(body, "Disconnect now") ||
		!strings.Contains(body, "/disconnect") {
		t.Fatal("admin page does not offer explicit non-revoking disconnect")
	}
}

func TestAdminAPIIncludesLiveClientAndDeviceUsage(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "bootstrap-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := authenticateTestDevice(registry, "bootstrap-token-0123456789", "phone")
	if err != nil {
		t.Fatal(err)
	}
	usageStore, err := usage.Open("", nil)
	if err != nil {
		t.Fatal(err)
	}
	session := usageStore.Begin("vpn:test", identity.AccountID, testDeviceID("phone"), "masque-h3-datagram", "10.66.0.2", "")
	session.AddUploaded(512, 2)
	session.AddDownloaded(1024, 4)
	handler := adminHandlerWithUsage(http.NotFoundHandler(), registry, usageStore, testAdminToken)

	response := adminRequest(t, handler, http.MethodGet, "/api/clients", "")
	var payload struct {
		Clients []clientSummary `json:"clients"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	client := payload.Clients[0]
	if client.ActiveSessions != 1 || client.BytesUploaded != 512 || client.BytesDownloaded != 1024 {
		t.Fatalf("client usage = %#v", client)
	}
	if len(client.Devices) != 1 || client.Devices[0].Transport != "masque-h3-datagram" ||
		client.Devices[0].AssignedAddress != "10.66.0.2" {
		t.Fatalf("device usage = %#v", client.Devices)
	}
	session.Close()
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
