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
  <title>Northline</title>
  <style>
    :root{color-scheme:light;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;color:#152033;background:#f6f8fc}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 84% 8%,#dff4ff 0,transparent 28%),radial-gradient(circle at 8% 78%,#ece6ff 0,transparent 32%),#f7f9fc}
    header{width:min(1180px,calc(100% - 40px));height:90px;margin:auto;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:11px;font-weight:780;letter-spacing:-.025em}.mark{width:34px;height:34px;border-radius:11px;background:linear-gradient(140deg,#695cff,#39c6da);box-shadow:0 9px 25px #655cff38}.nav{display:flex;gap:28px;color:#68748a;font-size:14px}
    main{width:min(1180px,calc(100% - 40px));min-height:calc(100vh - 170px);margin:auto;display:grid;grid-template-columns:1.1fr .9fr;gap:70px;align-items:center}.eyebrow{color:#6357ed;font-size:12px;font-weight:800;letter-spacing:.17em;text-transform:uppercase}h1{max-width:720px;margin:14px 0 22px;font-size:clamp(48px,7.4vw,88px);line-height:.98;letter-spacing:-.065em;color:#111a2b}p{max-width:610px;margin:0;color:#667287;font-size:18px;line-height:1.72}.pill{display:inline-flex;align-items:center;gap:8px;margin-top:30px;padding:10px 14px;border:1px solid #dce2ed;border-radius:999px;background:#ffffffaa;color:#59677d;font-size:13px;box-shadow:0 10px 35px #3b50600d}.dot{width:7px;height:7px;border-radius:50%;background:#35c68b;box-shadow:0 0 0 5px #35c68b1c}
    .visual{position:relative;aspect-ratio:1;border:1px solid #dce2ed;border-radius:36px;background:linear-gradient(145deg,#fff,#edf2f9);box-shadow:0 35px 90px #39507022;overflow:hidden}.orb{position:absolute;border-radius:50%;filter:blur(1px)}.one{width:64%;height:64%;left:18%;top:18%;background:linear-gradient(135deg,#6c5cff,#48cfe0);box-shadow:inset -30px -28px 70px #2f38a955,0 30px 70px #6259ed4d}.two{width:28%;height:28%;right:-5%;top:5%;background:#dff9f8}.three{width:23%;height:23%;left:2%;bottom:3%;background:#eee5ff}.glass{position:absolute;left:13%;right:13%;bottom:10%;padding:18px 20px;border:1px solid #ffffffb8;border-radius:18px;background:#ffffffa8;backdrop-filter:blur(18px);box-shadow:0 18px 50px #28364c24}.glass strong{display:block;font-size:15px}.glass span{display:block;margin-top:5px;color:#748095;font-size:12px}
    footer{width:min(1180px,calc(100% - 40px));height:80px;margin:auto;display:flex;align-items:center;justify-content:space-between;border-top:1px solid #e3e7ee;color:#8a94a6;font-size:12px}
    @media(max-width:760px){header{height:74px}.nav{display:none}main{grid-template-columns:1fr;gap:36px;padding:54px 0 70px}.visual{max-width:480px;width:100%;margin:auto}footer{height:68px}h1{font-size:clamp(45px,15vw,68px)}}
  </style>
</head>
<body>
  <header><div class="brand"><span class="mark"></span>Northline</div><nav class="nav"><span>Studio</span><span>Research</span><span>Contact</span></nav></header>
  <main><section><div class="eyebrow">Independent digital studio</div><h1>Thoughtful systems for modern teams.</h1><p>We shape clear digital experiences at the intersection of design, technology, and human insight.</p><div class="pill"><span class="dot"></span>New work arriving soon</div></section><section class="visual"><div class="orb one"></div><div class="orb two"></div><div class="orb three"></div><div class="glass"><strong>Clarity in every layer</strong><span>Strategy · Design · Engineering</span></div></section></main>
  <footer><span>Northline Studio</span><span>Built with intention</span></footer>
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
