package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"image/png"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestProfileQRBrowserLogic(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("Node.js is required for admin JavaScript regression tests")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	command := exec.CommandContext(ctx, node, "../../scripts/tests/profile_qr_ui.cjs", "admin_page.go")
	if output, err := command.CombinedOutput(); err != nil {
		t.Fatalf("admin QR behavior: %v\n%s", err, output)
	}
}

func TestProfileQRInteroperability(t *testing.T) {
	data, err := os.ReadFile("../../android/app/src/test/resources/profile-qr.properties")
	if err != nil {
		t.Fatal(err)
	}
	fixture := make(map[string]string)
	for _, line := range strings.Split(string(data), "\n") {
		if key, value, ok := strings.Cut(line, "="); ok {
			fixture[key] = value
		}
	}
	input := profileQRInput{Name: fixture["name"], Server: fixture["server"], Token: fixture["token"]}
	payload, err := profileQRPayload(input)
	if err != nil || payload != fixture["uri"] {
		t.Fatalf("fixture payload differs: %v", err)
	}
	uri, err := url.Parse(payload)
	if err != nil || uri.Scheme != "porta" || uri.Host != "profile" {
		t.Fatal("invalid profile URI")
	}
	values := uri.Query()
	if values.Get("v") != "1" || values.Get("server") != input.Server ||
		values.Get("token") != input.Token || values.Get("name") != input.Name || len(values) != 4 {
		t.Fatal("profile fields did not round-trip")
	}
	image, err := profileQRCode(input)
	if err != nil {
		t.Fatal(err)
	}
	const prefix = "data:image/png;base64,"
	if !strings.HasPrefix(image, prefix) {
		t.Fatal("QR response is not an inline PNG")
	}
	generated, err := base64.StdEncoding.DecodeString(strings.TrimPrefix(image, prefix))
	if err != nil {
		t.Fatal(err)
	}
	golden, err := base64.StdEncoding.DecodeString(fixture["png"])
	if err != nil {
		t.Fatal(err)
	}
	generatedImage, err := png.Decode(bytes.NewReader(generated))
	if err != nil {
		t.Fatal(err)
	}
	goldenImage, err := png.Decode(bytes.NewReader(golden))
	if err != nil {
		t.Fatal(err)
	}
	if generatedImage.Bounds() != goldenImage.Bounds() || generatedImage.Bounds().Dx() != 512 {
		t.Fatal("QR image dimensions differ from the Android interoperability fixture")
	}
	for y := 0; y < 512; y++ {
		for x := 0; x < 512; x++ {
			r, g, b, a := generatedImage.At(x, y).RGBA()
			wantR, wantG, wantB, wantA := goldenImage.At(x, y).RGBA()
			if r != wantR || g != wantG || b != wantB || a != wantA {
				t.Fatal("QR pixels differ from the fixture decoded by Android's scanner tests")
			}
		}
	}
}

func TestProfileQRValidation(t *testing.T) {
	valid := profileQRInput{Name: "Phone", Server: "https://porta.example.com:8443", Token: "example-token-not-a-secret"}
	tests := []struct {
		name   string
		change func(*profileQRInput)
	}{
		{"http", func(p *profileQRInput) { p.Server = "http://porta.example.com" }},
		{"mixed case scheme", func(p *profileQRInput) { p.Server = "HTTPS://porta.example.com" }},
		{"relative", func(p *profileQRInput) { p.Server = "//porta.example.com" }},
		{"host missing", func(p *profileQRInput) { p.Server = "https://" }},
		{"credentials", func(p *profileQRInput) { p.Server = "https://user:private@porta.example.com" }},
		{"path", func(p *profileQRInput) { p.Server += "/private" }},
		{"query", func(p *profileQRInput) { p.Server += "?token=private" }},
		{"empty query", func(p *profileQRInput) { p.Server += "?" }},
		{"fragment", func(p *profileQRInput) { p.Server += "#private" }},
		{"empty fragment", func(p *profileQRInput) { p.Server += "#" }},
		{"bad port", func(p *profileQRInput) { p.Server = "https://porta.example.com:65536" }},
		{"zero port", func(p *profileQRInput) { p.Server = "https://porta.example.com:0" }},
		{"empty port", func(p *profileQRInput) { p.Server = "https://porta.example.com:" }},
		{"invalid IPv4", func(p *profileQRInput) { p.Server = "https://127.0.0.999" }},
		{"bracketed IPv4", func(p *profileQRInput) { p.Server = "https://[127.0.0.1]" }},
		{"unbracketed IPv6", func(p *profileQRInput) { p.Server = "https://2001:db8::1:443" }},
		{"bracketed DNS", func(p *profileQRInput) { p.Server = "https://[porta.example.com]" }},
		{"invalid DNS", func(p *profileQRInput) { p.Server = "https://porta_test.example.com" }},
		{"empty label", func(p *profileQRInput) { p.Server = "https://porta..example.com" }},
		{"server whitespace", func(p *profileQRInput) { p.Server += " " }},
		{"long server", func(p *profileQRInput) { p.Server = "https://" + strings.Repeat("a", 513) }},
		{"empty token", func(p *profileQRInput) { p.Token = "" }},
		{"long token", func(p *profileQRInput) { p.Token = strings.Repeat("a", 513) }},
		{"token whitespace", func(p *profileQRInput) { p.Token += " " }},
		{"control token", func(p *profileQRInput) { p.Token += "\n" }},
		{"non-ASCII token", func(p *profileQRInput) { p.Token += "\u00e9" }},
		{"long name", func(p *profileQRInput) { p.Name = strings.Repeat("a", 81) }},
		{"long UTF-8 name", func(p *profileQRInput) { p.Name = strings.Repeat("\u00e9", 41) }},
		{"invalid UTF-8 name", func(p *profileQRInput) { p.Name = "\xff" }},
		{"control name", func(p *profileQRInput) { p.Name += "\u0085" }},
		{"name whitespace", func(p *profileQRInput) { p.Name += " " }},
		{"long payload", func(p *profileQRInput) {
			p.Name = strings.Repeat("?", 80)
			p.Token = strings.Repeat("?", 512)
			p.Server = "https://" + strings.Repeat("a", 63) + "." + strings.Repeat("b", 63) +
				"." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 55) + ":8443"
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			input := valid
			test.change(&input)
			payload, err := profileQRPayload(input)
			if err == nil || payload != "" {
				t.Fatal("invalid configuration was encoded")
			}
			if input.Token != "" && strings.Contains(err.Error(), input.Token) {
				t.Fatal("validation error exposed the supplied token")
			}
		})
	}
	for _, origin := range []string{"https://porta.example.com", "https://localhost:8443", "https://192.0.2.1:443/", "https://[2001:db8::1]:8443"} {
		input := valid
		input.Name = ""
		input.Server = origin
		input.Token = strings.Repeat("a", 512)
		if _, err := profileQRPayload(input); err != nil {
			t.Fatalf("valid origin %q rejected: %v", origin, err)
		}
	}
}

func TestProfileQRAPIRequiresAdminAndStrictBody(t *testing.T) {
	handler := adminHandler(http.NotFoundHandler(), nil, testAdminToken)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/client-access", strings.NewReader("{}")))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated QR request = %d", response.Code)
	}
	if response := adminRequest(t, handler, http.MethodGet, "/api/client-access", ""); response.Code != http.StatusNotFound {
		t.Fatalf("GET QR request = %d", response.Code)
	}
	for _, body := range []string{
		`{`, `{}`, `{"origin":"https://porta.example.com","token":"private","insecure":true}`,
		`{"origin":"https://porta.example.com","token":"private"}{}`,
		`{"origin":"https://porta.example.com","token":"private` + strings.Repeat("a", 16<<10) + `"}`,
		`{"origin":"http://porta.example.com","token":"private"}`,
	} {
		response := adminRequest(t, handler, http.MethodPost, "/api/client-access", body)
		if response.Code != http.StatusBadRequest || strings.Contains(response.Body.String(), "private") {
			t.Fatalf("invalid QR body status/error = %d %q", response.Code, response.Body.String())
		}
	}
}

func TestProfileQRPortalAuthorizationAndOrigin(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), "client-token-0123456789")
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newPortalHandler(portalConfig{
		Next: http.NotFoundHandler(), Registry: registry, AdminToken: testAdminToken,
		Admin: adminHandler(http.NotFoundHandler(), registry, testAdminToken),
	})
	if err != nil {
		t.Fatal(err)
	}
	admin := portalSignIn(t, handler, testAdminToken, "/portal/admin")
	client := portalSignIn(t, handler, "client-token-0123456789", "/portal/downloads")
	for _, test := range []struct {
		name   string
		cookie *http.Cookie
		origin string
		status int
	}{
		{"anonymous", nil, "https://porta.example.com", http.StatusNotFound},
		{"client", client, "https://porta.example.com", http.StatusNotFound},
		{"cross origin admin", admin, "https://other.example.com", http.StatusForbidden},
		{"same origin admin", admin, "https://porta.example.com", http.StatusOK},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, "https://porta.example.com/api/client-access",
				strings.NewReader(`{"origin":"https://porta.example.com","token":"client-token-0123456789"}`))
			request.Header.Set("Content-Type", "application/json")
			request.Header.Set("Origin", test.origin)
			if test.cookie != nil {
				request.AddCookie(test.cookie)
			}
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != test.status {
				t.Fatalf("status = %d, want %d", response.Code, test.status)
			}
		})
	}
}
