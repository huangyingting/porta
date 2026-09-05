package main

import (
	"encoding/base64"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/skip2/go-qrcode"
)

type profileQRInput struct {
	Name   string `json:"name"`
	Server string `json:"server"`
	Token  string `json:"token"`
}

func (a *adminAPI) serveProfileQR(w http.ResponseWriter, r *http.Request) {
	var input profileQRInput
	if err := decodeJSON(r, &input); err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	payload, err := profileQRPayload(input)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
		return
	}
	image, err := qrcode.Encode(payload, qrcode.Medium, 512)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "Unable to generate profile QR code"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{
		"image": "data:image/png;base64," + base64.StdEncoding.EncodeToString(image),
	})
}

func profileQRPayload(input profileQRInput) (string, error) {
	if !validProfileQRServer(input.Server) {
		return "", errors.New("Enter a valid HTTPS server origin, without a path, credentials, query, or fragment")
	}
	if len(input.Token) == 0 || len(input.Token) > 512 || strings.TrimSpace(input.Token) != input.Token {
		return "", errors.New("Invalid client token")
	}
	for _, character := range input.Token {
		if character < ' ' || character > '~' {
			return "", errors.New("Invalid client token")
		}
	}
	if len(input.Name) > 80 || !utf8.ValidString(input.Name) || strings.TrimSpace(input.Name) != input.Name {
		return "", errors.New("Invalid profile name")
	}
	for _, character := range input.Name {
		if unicode.IsControl(character) {
			return "", errors.New("Invalid profile name")
		}
	}
	parameters := url.Values{
		"v":      {"1"},
		"server": {input.Server},
		"token":  {input.Token},
	}
	if input.Name != "" {
		parameters.Set("name", input.Name)
	}
	payload := "porta://profile?" + parameters.Encode()
	if len(payload) > 2048 {
		return "", errors.New("Profile is too large for a QR code")
	}
	return payload, nil
}

func validProfileQRServer(server string) bool {
	if !strings.HasPrefix(server, "https://") || len(server) > 512 ||
		strings.TrimSpace(server) != server || strings.ContainsAny(server, "?#") {
		return false
	}
	parsed, err := url.Parse(server)
	if err != nil || parsed.Scheme != "https" || parsed.Opaque != "" || parsed.User != nil ||
		(parsed.Path != "" && parsed.Path != "/") || !validProfileQRHost(parsed.Hostname()) {
		return false
	}
	if strings.HasPrefix(parsed.Host, "[") != strings.Contains(parsed.Hostname(), ":") {
		return false
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return false
	}
	if port := parsed.Port(); port != "" {
		number, err := strconv.Atoi(port)
		if err != nil || number < 1 || number > 65535 {
			return false
		}
	}
	return true
}

func validProfileQRHost(host string) bool {
	if net.ParseIP(host) != nil {
		return true
	}
	host = strings.TrimSuffix(host, ".")
	if len(host) == 0 || len(host) > 253 {
		return false
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, character := range label {
			if !asciiLetter(character) && (character < '0' || character > '9') && character != '-' {
				return false
			}
		}
	}
	// Android's URI parser treats a numeric final label as an IPv4 address.
	return len(labels) == 1 || asciiLetter(rune(labels[len(labels)-1][0]))
}

func asciiLetter(character rune) bool {
	return character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z'
}
