package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"

	"github.com/huangyingting/porta/internal/usage"
)

type adminAPI struct {
	next       http.Handler
	registry   *clientRegistry
	usage      *usage.Store
	adminToken string
}

type clientInput struct {
	Name       string `json:"name"`
	MaxDevices int    `json:"max_devices"`
	Enabled    *bool  `json:"enabled,omitempty"`
}

func adminHandler(next http.Handler, registry *clientRegistry, adminToken string) http.Handler {
	usageStore, _ := usage.Open("", nil)
	return adminHandlerWithUsage(next, registry, usageStore, adminToken)
}

func adminHandlerWithUsage(next http.Handler, registry *clientRegistry, usageStore *usage.Store, adminToken string) http.Handler {
	return &adminAPI{next: next, registry: registry, usage: usageStore, adminToken: adminToken}
}

func (a *adminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setAdminSecurityHeaders(w)
	if serveWebFont(w, r) {
		return
	}
	if serveBrandAsset(w, r) {
		return
	}
	if r.Method == http.MethodGet && isOperationalPath(r.URL.Path) {
		a.next.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, adminHTML)
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if !adminAuthorized(r.Header.Get("Authorization"), a.adminToken) && !portalAdminAuthorized(r.Context()) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="porta-admin"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid admin token"})
		return
	}
	switch {
	case r.URL.Path == "/api/clients" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"clients": a.registry.List(a.usage.Snapshot())})
	case r.URL.Path == "/api/clients" && r.Method == http.MethodPost:
		var input clientInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		client, token, err := a.registry.Create(input.Name, input.MaxDevices)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"client": client, "token": token})
	default:
		a.serveClientAction(w, r)
	}
}

func (a *adminAPI) serveClientAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	clientID, err := url.PathUnescape(parts[0])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodPut:
		var input clientInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		client, err := a.registry.Update(clientID, input.Name, input.MaxDevices, enabled)
		a.writeMutation(w, client, err)
	case len(parts) == 1 && r.Method == http.MethodDelete:
		if err := a.registry.Delete(clientID); err != nil {
			a.writeError(w, err)
			return
		}
		a.usage.DeleteClient(clientID)
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2 && parts[1] == "token" && r.Method == http.MethodPost:
		token, err := a.registry.RotateToken(clientID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	case len(parts) == 3 && parts[1] == "devices" && r.Method == http.MethodDelete:
		deviceID, err := url.PathUnescape(parts[2])
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if err := a.registry.DeleteDevice(clientID, deviceID); err != nil {
			a.writeError(w, err)
			return
		}
		a.usage.DeleteDevice(clientID, deviceID)
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (a *adminAPI) writeMutation(w http.ResponseWriter, client clientSummary, err error) {
	if err != nil {
		a.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client": client})
}

func (a *adminAPI) writeError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Client or device not found"})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func decodeJSON(r *http.Request, target any) error {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 16<<10))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("Invalid request body")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("Invalid request body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func adminAuthorized(header, expected string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || expected == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(strings.TrimPrefix(header, prefix)), []byte(expected)) == 1
}

func setAdminSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; font-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}
