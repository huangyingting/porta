package main

import (
	"context"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	portalCookieName          = "porta_session"
	portalSessionTTL          = 8 * time.Hour
	maxPortalSessions         = 4096
	maxPortalSessionsPerLogin = 8
	downloadTicketTTL         = 10 * time.Minute
)

type portalRole uint8

const (
	portalRoleClient portalRole = iota + 1
	portalRoleAdmin
)

type portalSession struct {
	Role           portalRole
	ClientID       string
	ClientName     string
	TokenHash      string
	EncryptedToken string
	ExpiresAt      time.Time
}

type portalConfig struct {
	Next               http.Handler
	Registry           *clientRegistry
	AdminToken         string
	Admin              http.Handler
	DownloadsDirectory string
	TrustProxyHeaders  bool
	Logger             *slog.Logger
}

type portalHandler struct {
	next               http.Handler
	registry           *clientRegistry
	admin              http.Handler
	downloads          http.Handler
	downloadsDirectory string
	adminToken         string
	logger             *slog.Logger
	trustProxyHeaders  bool
	downloadTicketKey  [32]byte
	tokenCipher        cipher.AEAD
	mu                 sync.Mutex
	sessions           map[string]portalSession
}

type portalAdminContextKey struct{}

func newPortalHandler(config portalConfig) (http.Handler, error) {
	if config.Next == nil || config.Registry == nil || config.Admin == nil {
		return nil, errors.New("portal handlers and client registry are required")
	}
	if config.Logger == nil {
		config.Logger = slog.Default()
	}
	var downloadTicketKey [32]byte
	if _, err := rand.Read(downloadTicketKey[:]); err != nil {
		return nil, fmt.Errorf("generate download ticket key: %w", err)
	}
	tokenCipher, err := portalCredentialCipher(downloadTicketKey[:], "session-token-v1")
	if err != nil {
		return nil, fmt.Errorf("initialize portal credential protection: %w", err)
	}
	return &portalHandler{
		next:               config.Next,
		registry:           config.Registry,
		admin:              config.Admin,
		downloads:          clientDownloadHandler(http.NotFoundHandler(), config.DownloadsDirectory),
		downloadsDirectory: config.DownloadsDirectory,
		adminToken:         config.AdminToken,
		logger:             config.Logger,
		trustProxyHeaders:  config.TrustProxyHeaders,
		downloadTicketKey:  downloadTicketKey,
		tokenCipher:        tokenCipher,
		sessions:           make(map[string]portalSession),
	}, nil
}

func (p *portalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
	case r.URL.Path == "/assets/portal-join.js":
		servePortalScript(w, r, portalJoinScript)
	case r.URL.Path == "/assets/portal-client.js":
		servePortalScript(w, r, portalClientScript)
	case r.URL.Path == "/join":
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		p.serveJoin(w, r, "", http.StatusOK)
	case r.URL.Path == "/join/redeem":
		if r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}
		p.redeemClientAccess(w, r)
	case r.URL.Path == "/access" && (r.Method == http.MethodGet || r.Method == http.MethodHead):
		p.serveAccessPage(w, r, false)
	case r.URL.Path == "/access" && r.Method == http.MethodPost:
		p.signIn(w, r)
	case r.URL.Path == "/portal/logout" && r.Method == http.MethodPost:
		p.signOut(w, r)
	case r.URL.Path == "/portal/admin":
		p.serveAdminPage(w, r)
	case strings.HasPrefix(r.URL.Path, "/api/"):
		p.serveAdminAPI(w, r)
	case r.URL.Path == "/portal/downloads":
		p.serveDownloadsPage(w, r)
	case strings.HasPrefix(r.URL.Path, clientDownloadPrefix):
		p.serveDownload(w, r)
	default:
		p.next.ServeHTTP(w, r)
	}
}

func (p *portalHandler) signIn(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil {
		serveLandingError(w, r)
		return
	}
	token := strings.TrimSpace(r.FormValue("token"))
	if len(token) < 16 || len(token) > 512 {
		serveLandingError(w, r)
		return
	}
	session := portalSession{ExpiresAt: time.Now().Add(portalSessionTTL)}
	destination := "/portal/downloads"
	if adminAuthorized("Bearer "+token, p.adminToken) {
		session.Role = portalRoleAdmin
		destination = "/portal/admin"
	} else {
		var err error
		session, err = p.clientSession(token)
		if err != nil {
			if !errors.Is(err, errClientUnauthorized) && !errors.Is(err, errClientDisabled) {
				p.logger.Error("portal session creation failed", "error", err)
				http.Error(w, "service unavailable", http.StatusServiceUnavailable)
				return
			}
			p.logger.Warn("portal sign-in rejected", "remote", r.RemoteAddr)
			serveLandingError(w, r)
			return
		}
	}
	p.startSession(w, r, session, destination)
}

func (p *portalHandler) clientSession(token string) (portalSession, error) {
	identity, err := p.registry.AuthenticatePortal(token)
	if err != nil {
		return portalSession{}, err
	}
	session := portalSession{
		Role: portalRoleClient, ClientID: identity.ID, ClientName: identity.Name,
		TokenHash: hashToken(token), ExpiresAt: time.Now().Add(portalSessionTTL),
	}
	session.EncryptedToken, err = sealPortalCredential(p.tokenCipher, []byte(token), session.ClientID+"\n"+session.TokenHash)
	if err != nil {
		return portalSession{}, err
	}
	return session, nil
}

func (p *portalHandler) startSession(w http.ResponseWriter, r *http.Request, session portalSession, destination string) {
	id, err := randomPortalSessionID()
	if err != nil {
		http.Error(w, "service unavailable", http.StatusServiceUnavailable)
		return
	}
	p.mu.Lock()
	p.pruneSessionsLocked(time.Now())
	p.limitSessionsLocked(session)
	p.sessions[id] = session
	p.mu.Unlock()
	w.Header().Set("Cache-Control", "no-store")
	http.SetCookie(w, &http.Cookie{
		Name:     portalCookieName,
		Value:    id,
		Path:     "/",
		MaxAge:   int(portalSessionTTL.Seconds()),
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, destination, http.StatusSeeOther)
}

func (p *portalHandler) signOut(w http.ResponseWriter, r *http.Request) {
	if cookie, err := r.Cookie(portalCookieName); err == nil {
		p.mu.Lock()
		delete(p.sessions, cookie.Value)
		p.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{
		Name:     portalCookieName,
		Path:     "/",
		MaxAge:   -1,
		Secure:   true,
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
	})
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (p *portalHandler) serveAdminPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	if session, ok := p.session(r); !ok || session.Role != portalRoleAdmin {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	request := r.Clone(context.WithValue(r.Context(), portalAdminContextKey{}, true))
	request.URL.Path = "/"
	p.admin.ServeHTTP(w, request)
}

func (p *portalHandler) serveAdminAPI(w http.ResponseWriter, r *http.Request) {
	session, ok := p.session(r)
	if !ok || session.Role != portalRoleAdmin {
		// Never forward credential-bearing API bodies to camouflage handlers.
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		p.next.ServeHTTP(w, r)
		return
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead && !sameOriginPortalRequest(r, p.trustProxyHeaders) {
		http.Error(w, "invalid request origin", http.StatusForbidden)
		return
	}
	p.admin.ServeHTTP(w, r.Clone(context.WithValue(r.Context(), portalAdminContextKey{}, true)))
}

func (p *portalHandler) serveDownloadsPage(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	session, ok := p.session(r)
	if !ok {
		http.Redirect(w, r, "/", http.StatusSeeOther)
		return
	}
	name := session.ClientName
	if session.Role == portalRoleAdmin {
		name = "Administrator"
	}
	setPortalSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		var profile *downloadProfile
		if session.Role == portalRoleClient {
			token, err := openPortalCredential(p.tokenCipher, session.EncryptedToken, session.ClientID+"\n"+session.TokenHash)
			if err != nil || hashToken(string(token)) != session.TokenHash {
				http.Error(w, "profile configuration unavailable; sign in again", http.StatusServiceUnavailable)
				return
			}
			origin, err := clientAccessOrigin("https://" + portalRequestHost(r, p.trustProxyHeaders))
			if err != nil {
				http.Error(w, "public server address is invalid", http.StatusServiceUnavailable)
				return
			}
			profile = &downloadProfile{Server: origin, Token: string(token)}
			input := profileQRInput{Name: session.ClientName, Server: origin, Token: string(token)}
			profile.SetupURI, err = profileQRPayload(input)
			if err == nil {
				profile.QRCode, err = profileQRCode(input)
			}
			if err != nil {
				profile.Notice = "QR setup is unavailable for this credential. Use the server and token for manual setup."
			}
		}
		artifacts := availableDownloads(p.downloadsDirectory)
		tickets := make(map[string]string, len(artifacts))
		for _, artifact := range artifacts {
			tickets[artifact.Name] = p.issueDownloadTicket(artifact.Name, time.Now().Add(downloadTicketTTL))
		}
		tickets["SHA256SUMS"] = p.issueDownloadTicket("SHA256SUMS", time.Now().Add(downloadTicketTTL))
		_, _ = io.WriteString(w, downloadsPageHTML(
			name,
			portalRequestHost(r, p.trustProxyHeaders),
			readDownloadVersion(p.downloadsDirectory),
			artifacts,
			tickets,
			profile,
		))
	}
}

func (p *portalHandler) serveDownload(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.session(r); !ok {
		name := strings.TrimPrefix(r.URL.Path, clientDownloadPrefix)
		if !p.validDownloadTicket(name, r.URL.Query().Get("ticket"), time.Now()) {
			p.next.ServeHTTP(w, r)
			return
		}
	}
	p.downloads.ServeHTTP(w, r)
}

func (p *portalHandler) issueDownloadTicket(name string, expiresAt time.Time) string {
	var expires [8]byte
	binary.BigEndian.PutUint64(expires[:], uint64(expiresAt.Unix()))
	mac := hmac.New(sha256.New, p.downloadTicketKey[:])
	_, _ = mac.Write([]byte(name))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(expires[:])
	payload := append(expires[:], mac.Sum(nil)...)
	return base64.RawURLEncoding.EncodeToString(payload)
}

func (p *portalHandler) validDownloadTicket(name, ticket string, now time.Time) bool {
	payload, err := base64.RawURLEncoding.DecodeString(ticket)
	if err != nil || len(payload) != 8+sha256.Size {
		return false
	}
	expiresAt := int64(binary.BigEndian.Uint64(payload[:8]))
	if now.Unix() > expiresAt {
		return false
	}
	mac := hmac.New(sha256.New, p.downloadTicketKey[:])
	_, _ = mac.Write([]byte(name))
	_, _ = mac.Write([]byte{0})
	_, _ = mac.Write(payload[:8])
	return hmac.Equal(payload[8:], mac.Sum(nil))
}

func (p *portalHandler) session(r *http.Request) (portalSession, bool) {
	cookie, err := r.Cookie(portalCookieName)
	if err != nil {
		return portalSession{}, false
	}
	now := time.Now()
	p.mu.Lock()
	session, ok := p.sessions[cookie.Value]
	if !ok || !session.ExpiresAt.After(now) {
		delete(p.sessions, cookie.Value)
		p.mu.Unlock()
		return portalSession{}, false
	}
	p.mu.Unlock()
	if session.Role == portalRoleClient && !p.registry.PortalClientActive(session.ClientID, session.TokenHash) {
		p.mu.Lock()
		delete(p.sessions, cookie.Value)
		p.mu.Unlock()
		return portalSession{}, false
	}
	return session, true
}

func (p *portalHandler) pruneSessionsLocked(now time.Time) {
	for id, session := range p.sessions {
		if !session.ExpiresAt.After(now) {
			delete(p.sessions, id)
		}
	}
}

func (p *portalHandler) limitSessionsLocked(incoming portalSession) {
	for p.sessionCountLocked(incoming) >= maxPortalSessionsPerLogin {
		p.deleteOldestSessionLocked(func(session portalSession) bool {
			return session.Role == incoming.Role && session.ClientID == incoming.ClientID
		})
	}
	for len(p.sessions) >= maxPortalSessions {
		p.deleteOldestSessionLocked(func(portalSession) bool { return true })
	}
}

func (p *portalHandler) sessionCountLocked(target portalSession) int {
	count := 0
	for _, session := range p.sessions {
		if session.Role == target.Role && session.ClientID == target.ClientID {
			count++
		}
	}
	return count
}

func (p *portalHandler) deleteOldestSessionLocked(matches func(portalSession) bool) {
	var oldestID string
	var oldestExpiry time.Time
	for id, session := range p.sessions {
		if !matches(session) || oldestID != "" && !session.ExpiresAt.Before(oldestExpiry) {
			continue
		}
		oldestID = id
		oldestExpiry = session.ExpiresAt
	}
	if oldestID != "" {
		delete(p.sessions, oldestID)
	}
}

func randomPortalSessionID() (string, error) {
	value := make([]byte, 32)
	if _, err := rand.Read(value); err != nil {
		return "", fmt.Errorf("create portal session: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func portalAdminAuthorized(ctx context.Context) bool {
	authorized, _ := ctx.Value(portalAdminContextKey{}).(bool)
	return authorized
}

func serveLandingError(w http.ResponseWriter, r *http.Request) {
	serveAccessPageResponse(w, r, true, http.StatusUnauthorized)
}

func setPortalSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

func (p *portalHandler) serveAccessPage(w http.ResponseWriter, r *http.Request, invalid bool) {
	serveAccessPageResponse(w, r, invalid, http.StatusOK)
}

func serveAccessPageResponse(w http.ResponseWriter, r *http.Request, invalid bool, status int) {
	setPortalSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if r.Method == http.MethodGet || r.Method == http.MethodPost {
		message := ""
		if invalid {
			message = `<p class="error" role="alert">Access could not be verified.</p>`
		}
		_, _ = io.WriteString(w, accessPageHTML(message))
	}
}

func accessPageHTML(message string) string {
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml"><title>Get access · Porta</title><style>
	@font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-weight:200 900;font-display:swap}:root{font-family:"Mona Sans",sans-serif;color:#171923;background:#f5f6fa}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 75% 15%,rgba(115,217,208,.3),transparent 24rem),radial-gradient(circle at 10% 90%,rgba(102,92,246,.16),transparent 28rem),#f5f6fa}.card{width:min(430px,100%);padding:30px;border:1px solid rgba(255,255,255,.9);border-radius:22px;background:rgba(255,255,255,.86);box-shadow:0 28px 80px rgba(35,40,68,.12)}.brand{display:flex;align-items:center;gap:10px;color:inherit;text-decoration:none;font-size:15px;font-weight:800}.brand img{width:32px}h1{margin:44px 0 10px;font-size:38px;letter-spacing:-.05em}p{color:#747987;font-size:14px;line-height:1.6}.field{display:grid;gap:7px;margin-top:24px}.field label{font-size:11px;font-weight:750;letter-spacing:.09em;text-transform:uppercase}.field input{width:100%;border:1px solid #dfe1e8;border-radius:11px;background:white;padding:13px 14px;outline:none;font:14px inherit}.field input:focus{border-color:#8f86ef;box-shadow:0 0 0 3px rgba(102,92,246,.1)}button{width:100%;margin-top:12px;border:0;border-radius:11px;background:#171923;color:white;padding:13px;font:750 13px inherit;cursor:pointer}.note{margin:14px 0 0;font-size:11px}.error{margin:14px 0 0;color:#b44858;font-weight:650}@media(max-width:430px){body{place-items:start center;padding:14px}.card{margin-top:8vh;padding:23px;border-radius:18px}h1{margin-top:32px;font-size:34px}.field{margin-top:20px}}</style></head><body><main class="card"><a class="brand" href="/"><img src="/assets/porta-mark.svg" alt="">Porta</a><h1>Get access.</h1><p>Enter the token provided for your account.</p><form method="post" action="/access"><div class="field"><label for="token">Access token</label><input id="token" name="token" type="password" autocomplete="current-password" autofocus required></div><button type="submit">Continue</button></form>` + message + `<p class="note">Credentials are exchanged for a secure, temporary browser session.</p></main></body></html>`
}

func sameOriginPortalRequest(r *http.Request, trustProxyHeaders bool) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		return true
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return false
	}
	return parsed.Scheme == "https" && strings.EqualFold(parsed.Host, portalRequestHost(r, trustProxyHeaders))
}

func portalRequestHost(r *http.Request, trustProxyHeaders bool) string {
	if trustProxyHeaders {
		forwardedHost := strings.TrimSpace(r.Header.Get("X-Forwarded-Host"))
		if forwardedHost != "" && !strings.Contains(forwardedHost, ",") {
			return forwardedHost
		}
	}
	return r.Host
}

type downloadArtifact struct {
	Name         string
	Platform     string
	Architecture string
	Description  string
	Size         int64
	Recommended  bool
}

var downloadCatalog = []downloadArtifact{
	{Name: "porta-client-windows-amd64.zip", Platform: "Windows", Architecture: "x86-64", Description: "Desktop app, command line client, and Wintun runtime", Recommended: true},
	{Name: "porta-android-arm64-v8a.apk", Platform: "Android", Architecture: "ARM64", Description: "For most modern Android phones and tablets"},
	{Name: "porta-client-linux-amd64", Platform: "Linux", Architecture: "x86-64", Description: "Command line client for Intel and AMD systems"},
	{Name: "porta-client-linux-arm64", Platform: "Linux", Architecture: "ARM64", Description: "Command line client for ARM servers and devices"},
	{Name: "porta-android-armeabi-v7a.apk", Platform: "Android", Architecture: "ARMv7", Description: "For older 32-bit Android devices"},
	{Name: "porta-android-x86_64.apk", Platform: "Android", Architecture: "x86-64", Description: "For Android emulators and x86-64 devices"},
}

func availableDownloads(directory string) []downloadArtifact {
	artifacts := make([]downloadArtifact, 0, len(downloadCatalog))
	for _, artifact := range downloadCatalog {
		file, err := openDownloadFile(directory, artifact.Name)
		if err != nil {
			continue
		}
		info, statErr := file.Stat()
		_ = file.Close()
		if statErr != nil || !info.Mode().IsRegular() {
			continue
		}
		artifact.Size = info.Size()
		artifacts = append(artifacts, artifact)
	}
	return artifacts
}

func readDownloadVersion(directory string) string {
	file, err := openDownloadFile(directory, "CLIENT_VERSION")
	if err != nil {
		return "Unknown"
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return "Unknown"
	}
	version := strings.TrimSpace(string(value))
	if version == "" {
		return "Unknown"
	}
	return version
}

func formatDownloadSize(size int64) string {
	const (
		kib = 1024
		mib = 1024 * kib
	)
	if size >= mib {
		return fmt.Sprintf("%.1f MB", float64(size)/mib)
	}
	if size >= kib {
		return fmt.Sprintf("%.0f KB", float64(size)/kib)
	}
	return fmt.Sprintf("%d B", size)
}

func downloadsPageHTML(clientName, host, version string, artifacts []downloadArtifact, tickets map[string]string, profile *downloadProfile) string {
	var rows strings.Builder
	for _, artifact := range artifacts {
		recommended := ""
		if artifact.Recommended {
			recommended = `<span class="recommended">Recommended</span>`
		}
		fmt.Fprintf(&rows, `<article class="download-row"><div class="platform-icon">%s</div><div class="package"><div class="platform-line"><h2>%s</h2>%s</div><p>%s</p></div><div class="meta"><span>%s</span><span>%s</span></div><a class="download-button" href="/download/%s?ticket=%s" download>Download <span>↓</span></a></article>`,
			string([]rune(artifact.Platform)[0]), artifact.Platform, recommended, artifact.Description,
			artifact.Architecture, formatDownloadSize(artifact.Size), artifact.Name, html.EscapeString(tickets[artifact.Name]))
	}
	if len(artifacts) == 0 {
		rows.WriteString(`<div class="empty"><strong>Downloads are being prepared.</strong><span>Check back shortly.</span></div>`)
	}
	rows.WriteString(clientSetupHTML(profile))
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml"><title>Porta downloads</title><style>
	@font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-weight:200 900;font-display:swap}:root{font-family:"Mona Sans",sans-serif;color:#171923;background:#f5f6fa;--violet:#6558ed;--line:#e2e4ea}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 85% 0,rgba(115,217,208,.3),transparent 25rem),#f5f6fa}.page{width:min(900px,calc(100% - 28px));margin:auto;padding:24px 0 44px}.top{display:flex;justify-content:space-between;align-items:center}.brand{display:flex;align-items:center;gap:9px;font-size:15px;font-weight:800}.brand img{width:29px}.logout{border:1px solid var(--line);border-radius:8px;background:rgba(255,255,255,.8);padding:8px 11px;font-size:11px;cursor:pointer}.hero{display:grid;grid-template-columns:1fr auto;gap:24px;align-items:end;margin:38px 0 22px}.eyebrow{color:var(--violet);font-size:10px;font-weight:800;letter-spacing:.12em;text-transform:uppercase}.version{display:inline-flex;margin-left:7px;padding:3px 7px;border-radius:999px;background:#ece9ff;color:#594ed6;letter-spacing:0;text-transform:none}h1{margin:8px 0 8px;font-size:clamp(36px,5vw,48px);line-height:1;letter-spacing:-.05em}.lead{max-width:560px;margin:0;color:#747987;font-size:13px;line-height:1.6}.endpoint{min-width:240px;padding:12px 14px;border:1px solid rgba(255,255,255,.95);border-radius:11px;background:rgba(255,255,255,.78)}.endpoint small{display:block;margin-bottom:4px;color:#969aa5;font-size:10px;font-weight:750;letter-spacing:.08em;text-transform:uppercase}.endpoint code{font-size:12px}.files{display:grid;gap:8px}.download-row{display:grid;grid-template-columns:40px minmax(0,1fr) auto 118px;gap:13px;align-items:center;padding:13px 14px;border:1px solid rgba(255,255,255,.96);border-radius:13px;background:rgba(255,255,255,.88);box-shadow:0 5px 18px rgba(35,40,68,.035)}.platform-icon{display:grid;place-items:center;width:40px;height:40px;border-radius:11px;background:linear-gradient(145deg,#ece9ff,#e5f8f5);color:#584bd7;font-size:13px;font-weight:850}.platform-line{display:flex;align-items:center;gap:7px}.platform-line h2{margin:0;font-size:15px;letter-spacing:-.02em}.package p{margin:3px 0 0;color:#7d828f;font-size:11px;line-height:1.4}.recommended{padding:3px 6px;border-radius:5px;background:#e6f7f2;color:#218568;font-size:9px;font-weight:800}.meta{display:flex;gap:5px}.meta span{padding:5px 7px;border-radius:6px;background:#f1f2f6;color:#686e7b;font-size:10px;white-space:nowrap}.download-button{display:flex;align-items:center;justify-content:space-between;border-radius:8px;background:#171923;color:white;padding:9px 10px;text-decoration:none;font-size:11px;font-weight:750}.download-button span{font-size:13px}.support{display:flex;justify-content:space-between;gap:18px;margin-top:15px;padding-top:15px;border-top:1px solid rgba(25,29,45,.1);color:#7d828f;font-size:11px}.support a{color:#665cf6;text-decoration:none}.empty{padding:34px;border:1px dashed #ccd0da;border-radius:13px;text-align:center}.empty strong,.empty span{display:block}.empty span{margin-top:5px;color:#888d99}@media(max-width:680px){.hero{grid-template-columns:1fr;margin-top:32px}.endpoint{min-width:0}.download-row{grid-template-columns:40px minmax(0,1fr) 104px}.meta{display:none}}@media(max-width:430px){.page{width:min(100% - 20px,900px)}.download-row{grid-template-columns:36px minmax(0,1fr)}.platform-icon{width:36px;height:36px}.download-button{grid-column:1/-1}.support{align-items:flex-start;flex-direction:column}}</style></head><body><main class="page"><div class="top"><div class="brand"><img src="/assets/porta-mark.svg" alt="">Porta</div><form method="post" action="/portal/logout"><button class="logout">Sign out</button></form></div><section class="hero"><div><div class="eyebrow">Client version <span class="version">` + html.EscapeString(version) + `</span></div><h1>Downloads</h1><p class="lead">Welcome, ` + html.EscapeString(clientName) + `. Choose the package for your device and use your existing Porta token to connect.</p></div><div class="endpoint"><small>Server address</small><code>https://` + html.EscapeString(host) + `</code></div></section><section class="files">` + rows.String() + `</section><div class="support"><span>Verify package integrity before installation.</span><a href="/download/SHA256SUMS?ticket=` + html.EscapeString(tickets["SHA256SUMS"]) + `" download>SHA256 checksums</a></div></main></body></html>`
}
