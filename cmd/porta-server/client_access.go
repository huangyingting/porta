package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/huangyingting/porta/internal/abuse"
	"github.com/huangyingting/porta/internal/clientip"
	"github.com/skip2/go-qrcode"
)

var errClientAccess = errors.New("This access link is invalid or no longer authorized. Ask your administrator for a new link.")

type clientAccessInput struct {
	Origin string `json:"origin"`
	Token  string `json:"token"`
}

type clientAccessClaim struct {
	ClientID  string `json:"client_id"`
	Token     string `json:"token"`
	ExpiresAt int64  `json:"expires_at,omitempty"`
}

func (a *adminAPI) serveClientAccess(w http.ResponseWriter, r *http.Request) {
	var input clientAccessInput
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	origin, err := clientAccessOrigin(input.Origin)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "A valid public HTTPS origin is required"})
		return
	}
	if len(input.Token) < 16 || len(input.Token) > 512 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Invalid client token"})
		return
	}
	identity, err := a.registry.AuthenticatePortal(input.Token)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Client access is not available for this token"})
		return
	}
	if _, err := profileQRPayload(profileQRInput{Name: identity.Name, Server: origin, Token: input.Token}); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	ticket, err := sealClientAccess(a.adminToken, origin, clientAccessClaim{
		ClientID: identity.ID, Token: input.Token,
	})
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Unable to create client access"})
		return
	}
	link := origin + "/join#invite=" + ticket
	if len(link) > 2048 {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "Client access link is too large for a QR code"})
		return
	}
	image, err := qrcode.Encode(link, qrcode.Medium, 512)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Unable to create access QR code"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"url": link, "image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(image),
	})
}

func clientAccessOrigin(origin string) (string, error) {
	if !validProfileQRServer(origin) {
		return "", errClientAccess
	}
	parsed, err := url.Parse(origin)
	if err != nil {
		return "", errClientAccess
	}
	host := strings.ToLower(parsed.Hostname())
	port := parsed.Port()
	if port != "" {
		number, err := strconv.Atoi(port)
		if err != nil {
			return "", errClientAccess
		}
		if number != 443 {
			return "https://" + net.JoinHostPort(host, strconv.Itoa(number)), nil
		}
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	return "https://" + host, nil
}

func portalCredentialCipher(secret []byte, purpose string) (cipher.AEAD, error) {
	key := hmac.New(sha256.New, secret)
	_, _ = key.Write([]byte("porta/portal-credentials/" + purpose))
	block, err := aes.NewCipher(key.Sum(nil))
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func sealPortalCredential(aead cipher.AEAD, value []byte, binding string) (string, error) {
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(aead.Seal(nonce, nonce, value, []byte(binding))), nil
}

func openPortalCredential(aead cipher.AEAD, encoded, binding string) ([]byte, error) {
	if len(encoded) == 0 || len(encoded) > 4096 {
		return nil, errClientAccess
	}
	value, err := base64.RawURLEncoding.Strict().DecodeString(encoded)
	if err != nil || len(value) < aead.NonceSize()+aead.Overhead() {
		return nil, errClientAccess
	}
	plain, err := aead.Open(nil, value[:aead.NonceSize()], value[aead.NonceSize():], []byte(binding))
	if err != nil {
		return nil, errClientAccess
	}
	return plain, nil
}

func sealClientAccess(adminToken, origin string, claim clientAccessClaim) (string, error) {
	if len(adminToken) < 16 {
		return "", errClientAccess
	}
	aead, err := portalCredentialCipher([]byte(adminToken), "client-access-v1")
	if err != nil {
		return "", err
	}
	value, err := json.Marshal(claim)
	if err != nil {
		return "", err
	}
	return sealPortalCredential(aead, value, "client-access-v1\n"+origin)
}

func openClientAccess(adminToken, origin, ticket string) (clientAccessClaim, error) {
	if len(adminToken) < 16 {
		return clientAccessClaim{}, errClientAccess
	}
	aead, err := portalCredentialCipher([]byte(adminToken), "client-access-v1")
	if err != nil {
		return clientAccessClaim{}, err
	}
	value, err := openPortalCredential(aead, ticket, "client-access-v1\n"+origin)
	if err != nil {
		return clientAccessClaim{}, errClientAccess
	}
	var claim clientAccessClaim
	decoder := json.NewDecoder(bytes.NewReader(value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&claim); err != nil {
		return clientAccessClaim{}, errClientAccess
	}
	if err := decoder.Decode(new(any)); err != io.EOF || claim.ClientID == "" ||
		len(claim.Token) < 16 || len(claim.Token) > 512 {
		return clientAccessClaim{}, errClientAccess
	}
	return claim, nil
}

func (p *portalHandler) serveJoin(w http.ResponseWriter, r *http.Request, message string, status int) {
	setPortalSecurityHeaders(w)
	// no-referrer turns browser form POST origins into "null"; the fragment is cleared before submission.
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(status)
	if r.Method != http.MethodHead {
		_, _ = io.WriteString(w, joinPageHTML(message))
	}
}

func (p *portalHandler) redeemClientAccess(w http.ResponseWriter, r *http.Request) {
	if !sameOriginPortalRequest(r, p.trustProxyHeaders) {
		p.serveJoin(w, r, errClientAccess.Error(), http.StatusForbidden)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 4<<10)
	if err := r.ParseForm(); err != nil || r.URL.RawQuery != "" || len(r.PostForm) != 1 || len(r.PostForm["ticket"]) != 1 {
		p.serveJoin(w, r, errClientAccess.Error(), http.StatusBadRequest)
		return
	}
	origin, err := clientAccessOrigin("https://" + portalRequestHost(r, p.trustProxyHeaders))
	if err != nil {
		p.serveJoin(w, r, errClientAccess.Error(), http.StatusBadRequest)
		return
	}
	refund := func() {}
	if p.abuse != nil {
		var allowed bool
		refund, allowed = p.abuse.Reserve(
			abuse.InvitationRedemption,
			clientip.Address(r, p.trustProxyHeaders),
		)
		if !allowed {
			w.Header().Set("Retry-After", "5")
			p.serveJoin(w, r, errClientAccess.Error(), http.StatusTooManyRequests)
			return
		}
	}
	claim, err := openClientAccess(p.adminToken, origin, r.PostForm.Get("ticket"))
	if err != nil {
		p.serveJoin(w, r, errClientAccess.Error(), http.StatusUnauthorized)
		return
	}
	session, err := p.clientSession(claim.Token)
	if err != nil && !errors.Is(err, errClientUnauthorized) && !errors.Is(err, errClientDisabled) {
		p.logger.Error("portal session creation failed", "error", err)
		p.serveJoin(w, r, "Service unavailable. Please try again later.", http.StatusServiceUnavailable)
		return
	}
	if err != nil || session.ClientID != claim.ClientID {
		p.serveJoin(w, r, errClientAccess.Error(), http.StatusUnauthorized)
		return
	}
	refund()
	p.startSession(w, r, session, "/portal/downloads")
}

func servePortalScript(w http.ResponseWriter, r *http.Request, script string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.NotFound(w, r)
		return
	}
	setPortalSecurityHeaders(w)
	w.Header().Set("Content-Type", "text/javascript; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, script)
	}
}
