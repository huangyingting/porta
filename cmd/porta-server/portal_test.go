package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestPortalRoutesAdminAndClientTokens(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "client-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	if err := os.WriteFile(filepath.Join(directory, "SHA256SUMS"), []byte("checksums"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(directory, "CLIENT_VERSION"), []byte("v1.2.3\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	handler, err := newPortalHandler(portalConfig{
		Next:               http.NotFoundHandler(),
		Registry:           registry,
		AdminToken:         testAdminToken,
		Admin:              adminHandler(http.NotFoundHandler(), registry, testAdminToken),
		DownloadsDirectory: directory,
	})
	if err != nil {
		t.Fatal(err)
	}
	accessPage := portalRequest(handler, http.MethodGet, "/access", nil)
	if accessPage.Code != http.StatusOK || !strings.Contains(accessPage.Body.String(), `action="/access"`) {
		t.Fatalf("access page = %d %q", accessPage.Code, accessPage.Body.String())
	}

	adminCookie := portalSignIn(t, handler, testAdminToken, "/portal/admin")
	adminPage := portalRequest(handler, http.MethodGet, "/portal/admin", adminCookie)
	if adminPage.Code != http.StatusOK || !strings.Contains(adminPage.Body.String(), "Client overview") {
		t.Fatalf("admin page = %d %q", adminPage.Code, adminPage.Body.String())
	}
	adminAPI := portalRequest(handler, http.MethodGet, "/api/clients", adminCookie)
	if adminAPI.Code != http.StatusOK {
		t.Fatalf("admin API status = %d", adminAPI.Code)
	}
	crossOrigin := httptest.NewRequest(http.MethodPost, "/api/clients", strings.NewReader(`{"name":"Blocked","max_devices":1}`))
	crossOrigin.AddCookie(adminCookie)
	crossOrigin.Header.Set("Origin", "https://other.example")
	crossOrigin.Header.Set("Content-Type", "application/json")
	crossOriginResponse := httptest.NewRecorder()
	handler.ServeHTTP(crossOriginResponse, crossOrigin)
	if crossOriginResponse.Code != http.StatusForbidden {
		t.Fatalf("cross-origin admin status = %d", crossOriginResponse.Code)
	}

	clientCookie := portalSignIn(t, handler, "client-token-0123456789", "/portal/downloads")
	downloads := portalRequest(handler, http.MethodGet, "/portal/downloads", clientCookie)
	if downloads.Code != http.StatusOK || !strings.Contains(downloads.Body.String(), "/download/SHA256SUMS") ||
		!strings.Contains(downloads.Body.String(), "v1.2.3") {
		t.Fatalf("downloads page = %d %q", downloads.Code, downloads.Body.String())
	}
	ticketURL := regexp.MustCompile(`href="(/download/SHA256SUMS\?ticket=[^"]+)"`).FindStringSubmatch(downloads.Body.String())
	if len(ticketURL) != 2 {
		t.Fatalf("downloads page has no signed checksum URL: %q", downloads.Body.String())
	}
	externalDownload := portalRequest(handler, http.MethodGet, ticketURL[1], nil)
	if externalDownload.Code != http.StatusOK || externalDownload.Body.String() != "checksums" {
		t.Fatalf("ticket download = %d %q", externalDownload.Code, externalDownload.Body.String())
	}
	tamperedDownload := portalRequest(handler, http.MethodGet, ticketURL[1]+"x", nil)
	if tamperedDownload.Code != http.StatusNotFound {
		t.Fatalf("tampered ticket status = %d, want 404", tamperedDownload.Code)
	}
	artifact := portalRequest(handler, http.MethodGet, "/download/SHA256SUMS", clientCookie)
	if artifact.Code != http.StatusOK || artifact.Body.String() != "checksums" {
		t.Fatalf("artifact = %d %q", artifact.Code, artifact.Body.String())
	}
	clientAdmin := portalRequest(handler, http.MethodGet, "/api/clients", clientCookie)
	if clientAdmin.Code != http.StatusNotFound {
		t.Fatalf("client admin status = %d, want 404", clientAdmin.Code)
	}
}

func TestPortalRejectsInvalidTokensAndUnauthenticatedDownloads(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "client-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newPortalHandler(portalConfig{
		Next:       http.NotFoundHandler(),
		Registry:   registry,
		AdminToken: testAdminToken,
		Admin:      adminHandler(http.NotFoundHandler(), registry, testAdminToken),
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"token": {"wrong-token"}}
	request := httptest.NewRequest(http.MethodPost, "/access", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized || strings.Contains(response.Body.String(), "wrong-token") {
		t.Fatalf("invalid sign-in = %d %q", response.Code, response.Body.String())
	}
	download := portalRequest(handler, http.MethodGet, "/download/SHA256SUMS", nil)
	if download.Code != http.StatusNotFound {
		t.Fatalf("unauthenticated download status = %d", download.Code)
	}
}

func TestPortalClientSessionRevokedWhenClientDisabled(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "client-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newPortalHandler(portalConfig{
		Next:       http.NotFoundHandler(),
		Registry:   registry,
		AdminToken: testAdminToken,
		Admin:      adminHandler(http.NotFoundHandler(), registry, testAdminToken),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := portalSignIn(t, handler, "client-token-0123456789", "/portal/downloads")
	client := registry.List()[0]
	if _, err := registry.Update(client.ID, client.Name, client.MaxDevices, false); err != nil {
		t.Fatal(err)
	}
	response := portalRequest(handler, http.MethodGet, "/portal/downloads", cookie)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
		t.Fatalf("disabled client response = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestPortalClientSessionRevokedWhenTokenRotates(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "client-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newPortalHandler(portalConfig{
		Next:       http.NotFoundHandler(),
		Registry:   registry,
		AdminToken: testAdminToken,
		Admin:      adminHandler(http.NotFoundHandler(), registry, testAdminToken),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := portalSignIn(t, handler, "client-token-0123456789", "/portal/downloads")
	client := registry.List()[0]
	if _, err := registry.RotateToken(client.ID); err != nil {
		t.Fatal(err)
	}
	response := portalRequest(handler, http.MethodGet, "/portal/downloads", cookie)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != "/" {
		t.Fatalf("rotated client response = %d %q", response.Code, response.Header().Get("Location"))
	}
}

func TestPortalTrustsForwardedHostOnlyInBehindProxyMode(t *testing.T) {
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:8080/api/clients", nil)
	request.Host = "127.0.0.1:8080"
	request.Header.Set("Origin", "https://porta.example.com")
	request.Header.Set("X-Forwarded-Host", "porta.example.com")
	if sameOriginPortalRequest(request, false) {
		t.Fatal("forwarded host was trusted outside behind-proxy mode")
	}
	if !sameOriginPortalRequest(request, true) {
		t.Fatal("trusted forwarded host was rejected in behind-proxy mode")
	}
}

func TestPortalBoundsSessionsPerLogin(t *testing.T) {
	handler := &portalHandler{sessions: make(map[string]portalSession)}
	session := portalSession{Role: portalRoleClient, ClientID: "client", ExpiresAt: time.Now().Add(time.Hour)}
	for index := 0; index < maxPortalSessionsPerLogin; index++ {
		handler.sessions[strconv.Itoa(index)] = session
	}
	handler.limitSessionsLocked(session)
	if len(handler.sessions) != maxPortalSessionsPerLogin-1 {
		t.Fatalf("session count = %d", len(handler.sessions))
	}
}

func portalSignIn(t *testing.T, handler http.Handler, token, destination string) *http.Cookie {
	t.Helper()
	form := url.Values{"token": {token}}
	request := httptest.NewRequest(http.MethodPost, "/access", strings.NewReader(form.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusSeeOther || response.Header().Get("Location") != destination {
		t.Fatalf("sign-in = %d %q, want %q", response.Code, response.Header().Get("Location"), destination)
	}
	cookies := response.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode {
		t.Fatalf("session cookies = %#v", cookies)
	}
	return cookies[0]
}

func portalRequest(handler http.Handler, method, path string, cookie *http.Cookie) *httptest.ResponseRecorder {
	request := httptest.NewRequest(method, path, nil)
	if cookie != nil {
		request.AddCookie(cookie)
	}
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	return response
}
