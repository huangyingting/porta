package main

import (
	"io"
	"net/http"
)

const coverHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Welcome</title>
  <style>
    :root { color-scheme: light; font-family: Inter, ui-sans-serif, system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f5f7fb; color: #182230; }
    main { width: min(560px, calc(100% - 48px)); padding: 48px; border: 1px solid #e4e9f1; border-radius: 24px; background: white; box-shadow: 0 24px 70px rgba(30, 50, 80, .09); }
    span { display: inline-block; margin-bottom: 18px; color: #3972d5; font-size: 13px; font-weight: 700; letter-spacing: .12em; text-transform: uppercase; }
    h1 { margin: 0 0 14px; font-size: clamp(34px, 7vw, 54px); line-height: 1.05; letter-spacing: -.04em; }
    p { margin: 0; color: #637083; font-size: 17px; line-height: 1.7; }
  </style>
</head>
<body>
  <main>
    <span>Welcome</span>
    <h1>Your next idea starts here.</h1>
    <p>This website is being prepared. Please check back again soon.</p>
  </main>
</body>
</html>
`

func publicSiteHandler(next http.Handler, coverEnabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if isOperationalPath(r.URL.Path) {
			if coverEnabled && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				serveCoverPage(w, r)
			} else {
				http.NotFound(w, r)
			}
			return
		}
		if !coverEnabled {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}

		serveCoverPage(w, r)
	})
}

func adminHandler(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || !isOperationalPath(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func isOperationalPath(path string) bool {
	return path == "/healthz" || path == "/readyz" || path == "/metrics"
}

func serveCoverPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.URL.Path {
	case "/favicon.ico":
		w.WriteHeader(http.StatusNoContent)
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "User-agent: *\nDisallow:\n")
		}
	default:
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, coverHTML)
		}
	}
}
