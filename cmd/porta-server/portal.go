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
	"sort"
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
	next              http.Handler
	registry          *clientRegistry
	admin             http.Handler
	downloads         http.Handler
	adminToken        string
	logger            *slog.Logger
	trustProxyHeaders bool
	mu                sync.Mutex
	sessions          map[string]portalSession
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
		next:              config.Next,
		registry:          config.Registry,
		admin:             config.Admin,
		downloads:         clientDownloadHandler(http.NotFoundHandler(), config.DownloadsDirectory),
		adminToken:        config.AdminToken,
		logger:            config.Logger,
		trustProxyHeaders: config.TrustProxyHeaders,
		sessions:          make(map[string]portalSession),
	}, nil
}

func (p *portalHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch {
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
		_, _ = io.WriteString(w, downloadsPageHTML(name, portalRequestHost(r, p.trustProxyHeaders)))
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
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(http.StatusUnauthorized)
	if r.Method == http.MethodPost {
		_, _ = io.WriteString(w, strings.Replace(landingHTML, "{{ACCESS_ERROR}}", `<p class="access-error" role="alert">Access could not be verified.</p>`, 1))
	}
}

func setPortalSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; img-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
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

func downloadsPageHTML(clientName, host string) string {
	names := make([]string, 0, len(clientDownloadTypes))
	for name := range clientDownloadTypes {
		names = append(names, name)
	}
	sort.Strings(names)
	var links strings.Builder
	for _, name := range names {
		fmt.Fprintf(&links, `<a class="file" href="/download/%s"><strong>%s</strong><span>Download</span></a>`, name, name)
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml"><title>Porta downloads</title><style>
	@font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-weight:200 900;font-display:swap}:root{font-family:"Mona Sans",sans-serif;color:#171923;background:#f5f6fa}*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 80% 0,#dff8f4,transparent 30rem),#f5f6fa}.page{width:min(820px,calc(100% - 32px));margin:auto;padding:34px 0 60px}.top{display:flex;justify-content:space-between;align-items:center}.brand{display:flex;align-items:center;gap:10px;font-weight:800}.brand img{width:32px}.logout{border:1px solid #dfe1e8;border-radius:9px;background:white;padding:8px 12px}h1{margin:76px 0 10px;font-size:clamp(40px,7vw,66px);letter-spacing:-.06em}.lead{color:#707584;line-height:1.6}.endpoint{margin:25px 0;padding:14px 16px;border:1px solid #dddff0;border-radius:12px;background:#fff;font:13px ui-monospace,monospace}.files{display:grid;gap:9px;margin-top:28px}.file{display:flex;justify-content:space-between;align-items:center;padding:16px 18px;border:1px solid #e1e3e9;border-radius:13px;background:#fff;color:inherit;text-decoration:none}.file:hover{border-color:#8c83ef}.file span{color:#6558ed;font-size:12px;font-weight:750}@media(max-width:560px){h1{margin-top:48px}.file{align-items:flex-start;gap:14px}.file strong{overflow-wrap:anywhere}}</style></head><body><main class="page"><div class="top"><div class="brand"><img src="/assets/porta-mark.svg" alt="">Porta</div><form method="post" action="/portal/logout"><button class="logout">Sign out</button></form></div><h1>Client downloads</h1><p class="lead">Signed in as ` + html.EscapeString(clientName) + `. Choose the package for your device, then use your existing client token when configuring Porta.</p><div class="endpoint">Server: https://` + html.EscapeString(host) + `</div><section class="files">` + links.String() + `</section></main></body></html>`
}
