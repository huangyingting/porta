package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
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
)

type portalRole uint8

const (
	portalRoleClient portalRole = iota + 1
	portalRoleAdmin
)

type portalSession struct {
	Role       portalRole
	ClientID   string
	ClientName string
	TokenHash  string
	ExpiresAt  time.Time
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
	return &portalHandler{
		next:               config.Next,
		registry:           config.Registry,
		admin:              config.Admin,
		downloads:          clientDownloadHandler(http.NotFoundHandler(), config.DownloadsDirectory),
		downloadsDirectory: config.DownloadsDirectory,
		adminToken:         config.AdminToken,
		logger:             config.Logger,
		trustProxyHeaders:  config.TrustProxyHeaders,
		sessions:           make(map[string]portalSession),
	}, nil
}

func (p *portalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
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
		identity, err := p.registry.AuthenticatePortal(token)
		if err != nil {
			p.logger.Warn("portal sign-in rejected", "remote", r.RemoteAddr)
			serveLandingError(w, r)
			return
		}
		session.Role = portalRoleClient
		session.ClientID = identity.ID
		session.ClientName = identity.Name
		session.TokenHash = hashToken(token)
	}
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
		_, _ = io.WriteString(w, downloadsPageHTML(
			name,
			portalRequestHost(r, p.trustProxyHeaders),
			readDownloadVersion(p.downloadsDirectory),
			availableDownloads(p.downloadsDirectory),
		))
	}
}

func (p *portalHandler) serveDownload(w http.ResponseWriter, r *http.Request) {
	if _, ok := p.session(r); !ok {
		p.next.ServeHTTP(w, r)
		return
	}
	p.downloads.ServeHTTP(w, r)
}

func (p *portalHandler) session(r *http.Request) (portalSession, bool) {
	cookie, err := r.Cookie(portalCookieName)
	if err != nil {
		return portalSession{}, false
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	session, ok := p.sessions[cookie.Value]
	if !ok || !session.ExpiresAt.After(now) {
		delete(p.sessions, cookie.Value)
		return portalSession{}, false
	}
	if session.Role == portalRoleClient && !p.registry.PortalClientActive(session.ClientID, session.TokenHash) {
		delete(p.sessions, cookie.Value)
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
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
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
	@font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-weight:200 900;font-display:swap}:root{font-family:"Mona Sans",sans-serif;color:#171923;background:#f5f6fa}*{box-sizing:border-box}body{margin:0;min-height:100vh;display:grid;place-items:center;padding:24px;background:radial-gradient(circle at 75% 15%,rgba(115,217,208,.3),transparent 24rem),radial-gradient(circle at 10% 90%,rgba(102,92,246,.16),transparent 28rem),#f5f6fa}.card{width:min(430px,100%);padding:30px;border:1px solid rgba(255,255,255,.9);border-radius:22px;background:rgba(255,255,255,.86);box-shadow:0 28px 80px rgba(35,40,68,.12)}.brand{display:flex;align-items:center;gap:10px;color:inherit;text-decoration:none;font-weight:800}.brand img{width:32px}h1{margin:48px 0 10px;font-size:42px;letter-spacing:-.055em}p{color:#747987;font-size:13px;line-height:1.6}.field{display:grid;gap:7px;margin-top:24px}.field label{font-size:10px;font-weight:750;letter-spacing:.1em;text-transform:uppercase}.field input{width:100%;border:1px solid #dfe1e8;border-radius:11px;background:white;padding:13px 14px;outline:none;font:13px inherit}.field input:focus{border-color:#8f86ef;box-shadow:0 0 0 3px rgba(102,92,246,.1)}button{width:100%;margin-top:12px;border:0;border-radius:11px;background:#171923;color:white;padding:13px;font:750 12px inherit;cursor:pointer}.note{margin:14px 0 0;font-size:10px}.error{margin:14px 0 0;color:#b44858;font-weight:650}</style></head><body><main class="card"><a class="brand" href="/"><img src="/assets/porta-mark.svg" alt="">Porta</a><h1>Get access.</h1><p>Enter the token provided for your account.</p><form method="post" action="/access"><div class="field"><label for="token">Access token</label><input id="token" name="token" type="password" autocomplete="current-password" autofocus required></div><button type="submit">Continue</button></form>` + message + `<p class="note">Credentials are exchanged for a secure, temporary browser session.</p></main></body></html>`
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
	file, err := openDownloadFile(directory, "VERSION")
	if err != nil {
		return "Development"
	}
	defer file.Close()
	value, err := io.ReadAll(io.LimitReader(file, 128))
	if err != nil {
		return "Development"
	}
	version := strings.TrimSpace(string(value))
	if version == "" {
		return "Development"
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

func downloadsPageHTML(clientName, host, version string, artifacts []downloadArtifact) string {
	var cards strings.Builder
	for _, artifact := range artifacts {
		recommended := ""
		if artifact.Recommended {
			recommended = `<span class="recommended">Recommended</span>`
		}
		fmt.Fprintf(&cards, `<article class="download-card"><div class="card-top"><div class="platform-icon">%s</div><div><div class="platform-line"><h2>%s</h2>%s</div><p>%s</p></div></div><div class="meta"><span>%s</span><span>%s</span></div><a class="download-button" href="/download/%s">Download <span>↓</span></a></article>`,
			string([]rune(artifact.Platform)[0]), artifact.Platform, recommended, artifact.Description,
			artifact.Architecture, formatDownloadSize(artifact.Size), artifact.Name)
	}
	if len(artifacts) == 0 {
		cards.WriteString(`<div class="empty"><strong>Downloads are being prepared.</strong><span>Check back shortly.</span></div>`)
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml"><title>Porta downloads</title><style>
	@font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-weight:200 900;font-display:swap}:root{font-family:"Mona Sans",sans-serif;color:#171923;background:#f5f6fa;--violet:#6558ed;--line:#e2e4ea}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 82% 2%,rgba(115,217,208,.34),transparent 29rem),radial-gradient(circle at 4% 70%,rgba(101,88,237,.11),transparent 32rem),#f5f6fa}.page{width:min(1040px,calc(100% - 32px));margin:auto;padding:30px 0 70px}.top{display:flex;justify-content:space-between;align-items:center}.brand{display:flex;align-items:center;gap:10px;font-weight:800}.brand img{width:32px}.logout{border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.8);padding:8px 12px;cursor:pointer}.hero{display:grid;grid-template-columns:1fr auto;gap:28px;align-items:end;margin:72px 0 34px}.eyebrow{color:var(--violet);font-size:10px;font-weight:800;letter-spacing:.15em;text-transform:uppercase}.version{display:inline-flex;margin-left:9px;padding:4px 8px;border-radius:999px;background:#ece9ff;color:#594ed6;letter-spacing:0;text-transform:none}h1{margin:12px 0 12px;font-size:clamp(44px,7vw,72px);line-height:.95;letter-spacing:-.065em}.lead{max-width:620px;margin:0;color:#707584;line-height:1.65}.endpoint{min-width:270px;padding:15px 17px;border:1px solid rgba(255,255,255,.9);border-radius:13px;background:rgba(255,255,255,.75);box-shadow:0 8px 30px rgba(35,40,68,.06)}.endpoint small{display:block;margin-bottom:5px;color:#969aa5;font-size:9px;font-weight:750;letter-spacing:.1em;text-transform:uppercase}.endpoint code{font-size:12px}.files{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:12px}.download-card{display:flex;flex-direction:column;min-height:245px;padding:22px;border:1px solid rgba(255,255,255,.95);border-radius:18px;background:rgba(255,255,255,.86);box-shadow:0 12px 38px rgba(35,40,68,.06)}.card-top{display:flex;gap:15px}.platform-icon{display:grid;place-items:center;flex:0 0 auto;width:42px;height:42px;border-radius:13px;background:linear-gradient(145deg,#ece9ff,#e5f8f5);color:#584bd7;font-weight:850}.platform-line{display:flex;align-items:center;gap:8px}.platform-line h2{margin:0;font-size:18px;letter-spacing:-.03em}.platform-line p,.card-top p{margin:5px 0 0;color:#7b7f8b;font-size:11px;line-height:1.5}.recommended{padding:3px 6px;border-radius:6px;background:#e6f7f2;color:#218568;font-size:8px;font-weight:800}.meta{display:flex;gap:7px;margin-top:auto;padding:22px 0 13px}.meta span{padding:5px 8px;border-radius:7px;background:#f1f2f6;color:#6f7481;font-size:9px}.download-button{display:flex;align-items:center;justify-content:space-between;border-radius:10px;background:#171923;color:white;padding:11px 13px;text-decoration:none;font-size:11px;font-weight:750}.download-button span{font-size:15px}.support{display:flex;justify-content:space-between;gap:18px;margin-top:20px;padding-top:20px;border-top:1px solid rgba(25,29,45,.1);color:#858995;font-size:10px}.support a{color:#665cf6;text-decoration:none}.empty{grid-column:1/-1;padding:50px;border:1px dashed #ccd0da;border-radius:18px;text-align:center}.empty strong,.empty span{display:block}.empty span{margin-top:6px;color:#888d99}@media(max-width:760px){.hero{grid-template-columns:1fr;margin-top:48px}.endpoint{min-width:0}.files{grid-template-columns:1fr}} </style></head><body><main class="page"><div class="top"><div class="brand"><img src="/assets/porta-mark.svg" alt="">Porta</div><form method="post" action="/portal/logout"><button class="logout">Sign out</button></form></div><section class="hero"><div><div class="eyebrow">Client release <span class="version">` + html.EscapeString(version) + `</span></div><h1>Ready when you are.</h1><p class="lead">Welcome, ` + html.EscapeString(clientName) + `. Choose the package that matches your device, then sign in to the app with your existing Porta token.</p></div><div class="endpoint"><small>Server address</small><code>https://` + html.EscapeString(host) + `</code></div></section><section class="files">` + cards.String() + `</section><div class="support"><span>Need to verify a package?</span><a href="/download/SHA256SUMS">View SHA256 checksums</a></div></main></body></html>`
}
