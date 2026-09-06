package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"html"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skip2/go-qrcode"
)

const accessTestToken = "client-access-test-token-0123456789"
const accessTestOrigin = "https://porta.example.com:8443"

func accessTestPortal(t *testing.T) (*portalHandler, *clientRegistry) {
	t.Helper()
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), accessTestToken)
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
	return handler.(*portalHandler), registry
}

func accessTestRedeem(p *portalHandler, ticket, origin string) *httptest.ResponseRecorder {
	request := httptest.NewRequest(http.MethodPost, origin+"/join/redeem",
		strings.NewReader(url.Values{"ticket": {ticket}}.Encode()))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", origin)
	response := httptest.NewRecorder()
	p.ServeHTTP(response, request)
	return response
}

func TestInvitationRedemptionFailuresAreRateLimited(t *testing.T) {
	registry, err := openClientRegistry(filepath.Join(t.TempDir(), "clients.json"), accessTestToken)
	if err != nil {
		t.Fatal(err)
	}
	handler, err := newPortalHandler(portalConfig{
		Next:       http.NotFoundHandler(),
		Registry:   registry,
		AdminToken: testAdminToken,
		Admin:      http.NotFoundHandler(),
		Abuse:      newTestAbuseGuard(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	request := func() *http.Request {
		r := httptest.NewRequest(http.MethodPost, accessTestOrigin+"/join/redeem",
			strings.NewReader(url.Values{"ticket": {"invalid-invitation-ticket"}}.Encode()))
		r.RemoteAddr = "192.0.2.42:1234"
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		r.Header.Set("Origin", accessTestOrigin)
		return r
	}
	first := httptest.NewRecorder()
	handler.ServeHTTP(first, request())
	if first.Code != http.StatusUnauthorized {
		t.Fatalf("first failure status = %d", first.Code)
	}
	second := httptest.NewRecorder()
	handler.ServeHTTP(second, request())
	if second.Code != http.StatusTooManyRequests || second.Header().Get("Retry-After") == "" {
		t.Fatalf("limited failure = %d %v", second.Code, second.Header())
	}
}

func TestClientAccessDownloadThenProfileQR(t *testing.T) {
	portal, registry := accessTestPortal(t)
	body, err := json.Marshal(clientAccessInput{Origin: accessTestOrigin, Token: accessTestToken})
	if err != nil {
		t.Fatal(err)
	}
	issued := adminRequest(t, portal.admin, http.MethodPost, "/api/client-access", string(body))
	if issued.Code != http.StatusOK || issued.Header().Get("Cache-Control") != "no-store" {
		t.Fatalf("access invitation status/headers = %d %v", issued.Code, issued.Header())
	}
	var invitation struct {
		URL   string `json:"url"`
		Image string `json:"image"`
	}
	if err := json.Unmarshal(issued.Body.Bytes(), &invitation); err != nil {
		t.Fatal(err)
	}
	link, err := url.Parse(invitation.URL)
	if err != nil || link.Scheme != "https" || link.Host != "porta.example.com:8443" ||
		link.Path != "/join" || link.RawQuery != "" || strings.Contains(invitation.URL, accessTestToken) {
		t.Fatal("invitation is not a private, fragment-only download access link")
	}
	ticket := strings.TrimPrefix(link.Fragment, "invite=")
	if ticket == link.Fragment || ticket == "" {
		t.Fatal("access invitation has no fragment credential")
	}
	png, err := qrcode.Encode(invitation.URL, qrcode.Medium, 512)
	if err != nil || invitation.Image != "data:image/png;base64,"+base64.StdEncoding.EncodeToString(png) {
		t.Fatal("first QR does not encode the HTTPS download access link")
	}
	if bytes.Contains(issued.Body.Bytes(), []byte(`"expires_at"`)) {
		t.Fatal("access invitation unexpectedly contains a fixed expiry")
	}
	landing := httptest.NewRecorder()
	portal.ServeHTTP(landing, httptest.NewRequest(http.MethodGet, accessTestOrigin+"/join", nil))
	if landing.Code != http.StatusOK || strings.Contains(landing.Body.String(), `name="token"`) ||
		!strings.Contains(landing.Body.String(), "/assets/portal-join.js") {
		t.Fatal("invitation landing page requests an access key or lacks auto-redemption")
	}
	if landing.Header().Get("Referrer-Policy") != "same-origin" {
		t.Fatal("join page must preserve the same-origin form POST Origin without cross-origin referrers")
	}
	redeemed := accessTestRedeem(portal, ticket, accessTestOrigin)
	if redeemed.Code != http.StatusSeeOther || redeemed.Header().Get("Location") != "/portal/downloads" {
		t.Fatalf("redemption status = %d", redeemed.Code)
	}
	cookies := redeemed.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || !cookies[0].HttpOnly ||
		cookies[0].SameSite != http.SameSiteStrictMode || cookies[0].MaxAge != int(portalSessionTTL.Seconds()) {
		t.Fatal("redemption did not create the bounded secure client session")
	}
	session := portal.sessions[cookies[0].Value]
	if session.Role != portalRoleClient || session.EncryptedToken == "" ||
		strings.Contains(session.EncryptedToken, accessTestToken) {
		t.Fatal("client session retained a plaintext token or granted another role")
	}
	stored, err := os.ReadFile(registry.path)
	if err != nil || bytes.Contains(stored, []byte(accessTestToken)) || bytes.Contains(stored, []byte(ticket)) {
		t.Fatal("registry persisted a recoverable client credential or access invitation")
	}
	request := httptest.NewRequest(http.MethodGet, accessTestOrigin+"/portal/downloads", nil)
	request.AddCookie(cookies[0])
	page := httptest.NewRecorder()
	portal.ServeHTTP(page, request)
	expectedQR, err := profileQRCode(profileQRInput{Name: session.ClientName, Server: accessTestOrigin, Token: accessTestToken})
	if err != nil || !strings.Contains(html.UnescapeString(page.Body.String()), expectedQR) ||
		!strings.Contains(page.Body.String(), "Scan QR code") || page.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("authenticated download page does not contain the second, client-profile QR")
	}
	if !strings.Contains(page.Header().Get("Content-Security-Policy"), "img-src 'self' data:") {
		t.Fatal("portal CSP prevents displaying its profile QR")
	}
	second := accessTestRedeem(portal, ticket, accessTestOrigin)
	if second.Code != http.StatusSeeOther || second.Result().Cookies()[0].Value == cookies[0].Value {
		t.Fatal("valid shared invitation cannot enroll another independent browser session")
	}
}

func TestClientAccessCryptographicBoundaries(t *testing.T) {
	now := time.Now()
	claim := clientAccessClaim{ClientID: "client", Token: accessTestToken}
	ticket, err := sealClientAccess(testAdminToken, accessTestOrigin, claim)
	if err != nil {
		t.Fatal(err)
	}
	second, err := sealClientAccess(testAdminToken, accessTestOrigin, claim)
	if err != nil || ticket == second {
		t.Fatal("invitation encryption reused its nonce")
	}
	opened, err := openClientAccess(testAdminToken, accessTestOrigin, ticket)
	if err != nil || opened != claim {
		t.Fatalf("valid invitation did not decrypt: %v", err)
	}
	legacy := clientAccessClaim{ClientID: "client", Token: accessTestToken, ExpiresAt: now.Add(-time.Hour).Unix()}
	legacyTicket, err := sealClientAccess(testAdminToken, accessTestOrigin, legacy)
	if err != nil {
		t.Fatal(err)
	}
	if opened, err := openClientAccess(testAdminToken, accessTestOrigin, legacyTicket); err != nil || opened != legacy {
		t.Fatalf("previously expired invitation was not restored: %#v, %v", opened, err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil {
		t.Fatal(err)
	}
	raw[len(raw)-1] ^= 1
	for _, test := range []struct {
		name, secret, origin, ticket string
	}{
		{"tampered", testAdminToken, accessTestOrigin, base64.RawURLEncoding.EncodeToString(raw)},
		{"wrong origin", testAdminToken, "https://other.example.com", ticket},
		{"wrong port", testAdminToken, "https://porta.example.com", ticket},
		{"rotated admin", testAdminToken + "-new", accessTestOrigin, ticket},
		{"oversized", testAdminToken, accessTestOrigin, strings.Repeat("a", 4097)},
		{"malformed", testAdminToken, accessTestOrigin, "not!an!invitation"},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := openClientAccess(test.secret, test.origin, test.ticket); err != errClientAccess {
				t.Fatalf("invalid invitation accepted or detailed error exposed: %v", err)
			}
		})
	}
}

func TestClientAccessRevocationAndRoleBinding(t *testing.T) {
	for _, action := range []string{"disable", "rotate", "delete", "wrong-client", "admin-token"} {
		t.Run(action, func(t *testing.T) {
			portal, registry := accessTestPortal(t)
			client := registry.List()[0]
			claim := clientAccessClaim{ClientID: client.ID, Token: accessTestToken}
			var mutationErr error
			switch action {
			case "disable":
				_, mutationErr = registry.Update(client.ID, client.Name, client.MaxDevices, false)
			case "rotate":
				_, mutationErr = registry.RotateToken(client.ID)
			case "delete":
				mutationErr = registry.Delete(client.ID)
			case "wrong-client":
				claim.ClientID = "another-client"
			case "admin-token":
				claim.Token = testAdminToken
			}
			if mutationErr != nil {
				t.Fatal(mutationErr)
			}
			ticket, err := sealClientAccess(testAdminToken, accessTestOrigin, claim)
			if err != nil {
				t.Fatal(err)
			}
			response := accessTestRedeem(portal, ticket, accessTestOrigin)
			if response.Code != http.StatusUnauthorized || len(response.Result().Cookies()) != 0 ||
				strings.Contains(response.Body.String(), ticket) || strings.Contains(response.Body.String(), claim.Token) {
				t.Fatal("revoked or role-confused invitation created a session or leaked its credential")
			}
		})
	}
}

func TestClientAccessSurvivesRestartButPortalCredentialsDoNotTransfer(t *testing.T) {
	first, registry := accessTestPortal(t)
	client := registry.List()[0]
	ticket, err := sealClientAccess(testAdminToken, accessTestOrigin, clientAccessClaim{
		ClientID: client.ID, Token: accessTestToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh, err := newPortalHandler(portalConfig{
		Next: http.NotFoundHandler(), Registry: registry, AdminToken: testAdminToken, Admin: first.admin,
	})
	if err != nil {
		t.Fatal(err)
	}
	if response := accessTestRedeem(fresh.(*portalHandler), ticket, accessTestOrigin); response.Code != http.StatusSeeOther {
		t.Fatal("invitation stopped working after a same-key server restart")
	}
	session, err := first.clientSession(accessTestToken)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := openClientAccess(testAdminToken, accessTestOrigin, session.EncryptedToken); err == nil {
		t.Fatal("encrypted in-memory profile token was accepted as a public invitation")
	}
	if _, err := openPortalCredential(first.tokenCipher, session.EncryptedToken, "another-client\n"+session.TokenHash); err == nil {
		t.Fatal("profile token was not bound to its client session")
	}
}

func TestClientAccessRejectsUnsafeOriginAndNeverForwardsCredentials(t *testing.T) {
	for _, origin := range []string{"http://example.com", "https://user:pass@example.com", "https://example.com/path", "https://example.com?next=x", "https://example.com#x"} {
		if _, err := clientAccessOrigin(origin); err == nil {
			t.Fatalf("unsafe origin accepted: %s", origin)
		}
	}
	for input, want := range map[string]string{
		"https://EXAMPLE.com:443/":    "https://example.com",
		"https://[2001:db8::1]:8443/": "https://[2001:db8::1]:8443",
	} {
		if got, err := clientAccessOrigin(input); err != nil || got != want {
			t.Fatalf("origin normalization = %s, %v", got, err)
		}
	}
	portal, _ := accessTestPortal(t)
	forwarded := false
	portal.next = http.HandlerFunc(func(http.ResponseWriter, *http.Request) { forwarded = true })
	request := httptest.NewRequest(http.MethodPost, accessTestOrigin+"/api/client-access", strings.NewReader(`{"token":"private"}`))
	response := httptest.NewRecorder()
	portal.ServeHTTP(response, request)
	if forwarded || response.Code != http.StatusNotFound {
		t.Fatal("unauthenticated credential-bearing API request reached the camouflage handler")
	}
	request = httptest.NewRequest(http.MethodPost, accessTestOrigin+"/join/redeem", strings.NewReader("ticket=private"))
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.Header.Set("Origin", "https://other.example.com")
	response = httptest.NewRecorder()
	portal.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden || strings.Contains(response.Body.String(), "private") {
		t.Fatal("cross-origin redemption was accepted or echoed its credential")
	}
}

func TestClientAccessStrictRedemptionForm(t *testing.T) {
	portal, registry := accessTestPortal(t)
	ticket, err := sealClientAccess(testAdminToken, accessTestOrigin, clientAccessClaim{
		ClientID: registry.List()[0].ID, Token: accessTestToken,
	})
	if err != nil {
		t.Fatal(err)
	}
	form := url.Values{"ticket": {ticket}}.Encode()
	for _, test := range []struct {
		name, query, body string
	}{
		{"missing", "", ""},
		{"duplicate", "", form + "&" + form},
		{"unknown", "", form + "&next=private"},
		{"query", "?" + form, form},
		{"invalid encoding", "", "ticket=%ZZ"},
		{"too large", "", "ticket=" + strings.Repeat("a", 4096)},
	} {
		t.Run(test.name, func(t *testing.T) {
			request := httptest.NewRequest(http.MethodPost, accessTestOrigin+"/join/redeem"+test.query, strings.NewReader(test.body))
			request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			request.Header.Set("Origin", accessTestOrigin)
			response := httptest.NewRecorder()
			portal.ServeHTTP(response, request)
			if response.Code != http.StatusBadRequest || len(response.Result().Cookies()) != 0 ||
				strings.Contains(response.Body.String(), ticket) {
				t.Fatalf("invalid redemption form status = %d", response.Code)
			}
		})
	}
}

func TestClientAccessDownloadProfileBoundaries(t *testing.T) {
	for _, action := range []string{"corrupt", "expired", "rotate", "disable", "admin"} {
		t.Run(action, func(t *testing.T) {
			portal, registry := accessTestPortal(t)
			token, destination := accessTestToken, "/portal/downloads"
			if action == "admin" {
				token, destination = testAdminToken, "/portal/admin"
			}
			cookie := portalSignIn(t, portal, token, destination)
			wantStatus := http.StatusSeeOther
			var err error
			switch action {
			case "corrupt":
				session := portal.sessions[cookie.Value]
				session.EncryptedToken = "invalid"
				portal.sessions[cookie.Value] = session
				wantStatus = http.StatusServiceUnavailable
			case "expired":
				session := portal.sessions[cookie.Value]
				session.ExpiresAt = time.Now().Add(-time.Second)
				portal.sessions[cookie.Value] = session
			case "rotate":
				_, err = registry.RotateToken(registry.List()[0].ID)
			case "disable":
				client := registry.List()[0]
				_, err = registry.Update(client.ID, client.Name, client.MaxDevices, false)
			case "admin":
				wantStatus = http.StatusOK
			}
			if err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodGet, accessTestOrigin+"/portal/downloads", nil)
			request.AddCookie(cookie)
			response := httptest.NewRecorder()
			portal.ServeHTTP(response, request)
			page := response.Body.String()
			if response.Code != wantStatus || strings.Contains(page, accessTestToken) ||
				strings.Contains(page, testAdminToken) || strings.Contains(page, "data:image/png;base64,") {
				t.Fatalf("unavailable profile leaked configuration or returned status %d, want %d", response.Code, wantStatus)
			}
		})
	}
}
