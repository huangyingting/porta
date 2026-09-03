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
  <meta name="theme-color" content="#f5f6fa">
  <title>Northline</title>
  <style>
    @font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-style:normal;font-weight:200 900;font-display:swap}
    :root{color-scheme:light;font-family:"Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ink:#121522;--muted:#686d7c;--line:rgba(25,29,45,.1);--violet:#665cf6;--aqua:#73d9d0;font-feature-settings:"cv11","ss01","ss03";font-synthesis:none}
    *{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-height:100vh;color:var(--ink);background:#f5f6fa;overflow-x:hidden}
    body:before{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(circle at 74% 12%,rgba(116,216,208,.24),transparent 25rem),radial-gradient(circle at 12% 84%,rgba(109,94,246,.13),transparent 32rem)}
    .page{position:relative;width:min(1240px,calc(100% - 40px));min-height:100vh;margin:auto;display:grid;grid-template-rows:auto 1fr auto}
    header{height:88px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
    .brand{display:flex;align-items:center;gap:12px;font-size:15px;font-weight:760;letter-spacing:-.025em}.brand-mark{position:relative;width:32px;height:32px;border-radius:10px;background:#171a27;box-shadow:0 8px 22px rgba(23,26,39,.16)}.brand-mark:after{content:"";position:absolute;width:10px;height:10px;right:5px;top:5px;border-radius:50%;background:linear-gradient(135deg,var(--aqua),#b8f3e5)}
    nav{display:flex;align-items:center;gap:32px;color:#747987;font-size:13px}.availability{display:flex;align-items:center;gap:8px;padding:8px 12px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.56);color:#4f5564}.availability:before{content:"";width:7px;height:7px;border-radius:50%;background:#44bf87;box-shadow:0 0 0 4px rgba(68,191,135,.12)}
    main{display:grid;grid-template-columns:minmax(0,1.08fr) minmax(380px,.92fr);gap:clamp(48px,8vw,120px);align-items:center;padding:72px 0}
    .copy{max-width:720px}.eyebrow{display:flex;align-items:center;gap:12px;color:#707584;font-size:11px;font-weight:750;letter-spacing:.17em;text-transform:uppercase}.eyebrow:before{content:"";width:34px;height:1px;background:#9ba0ad}
    h1{margin:23px 0 25px;font-size:clamp(55px,7.5vw,100px);font-weight:670;line-height:.94;letter-spacing:-.072em}h1 em{font-style:normal;color:var(--violet)}
    .lead{max-width:600px;margin:0;color:var(--muted);font-size:clamp(17px,1.7vw,20px);line-height:1.68;letter-spacing:-.012em}.principles{display:flex;gap:25px;margin-top:40px;color:#4f5462;font-size:12px;font-weight:650}.principles span{display:flex;align-items:center;gap:9px}.principles span:before{content:"";width:4px;height:4px;border-radius:50%;background:var(--violet)}
    .canvas{position:relative;min-height:560px;border:1px solid rgba(255,255,255,.76);border-radius:34px;background:linear-gradient(145deg,rgba(255,255,255,.82),rgba(238,240,247,.68));box-shadow:0 40px 110px rgba(38,43,70,.13),inset 0 1px 0 #fff;overflow:hidden}
    .mesh{position:absolute;inset:0;background-image:linear-gradient(rgba(34,40,65,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(34,40,65,.045) 1px,transparent 1px);background-size:48px 48px;mask-image:linear-gradient(to bottom,black,transparent 92%)}
    .halo{position:absolute;width:350px;height:350px;left:50%;top:45%;translate:-50% -50%;border-radius:50%;background:radial-gradient(circle at 35% 28%,#c8fff2 0,#74d9d0 25%,#6a61f2 68%,#4640c4 100%);box-shadow:inset -35px -40px 80px rgba(38,29,132,.32),0 45px 95px rgba(93,82,230,.35);animation:float 7s ease-in-out infinite}
    .ring{position:absolute;left:50%;top:45%;translate:-50% -50%;border:1px solid rgba(88,79,215,.17);border-radius:50%}.ring.one{width:430px;height:430px}.ring.two{width:510px;height:510px}.node{position:absolute;width:9px;height:9px;border:2px solid #fff;border-radius:50%;background:#6d61ef;box-shadow:0 5px 16px rgba(80,70,190,.35)}.n1{left:18%;top:30%}.n2{right:16%;top:59%}.n3{left:28%;bottom:12%;background:#50cbb9}
    .note{position:absolute;left:28px;right:28px;bottom:28px;display:flex;justify-content:space-between;gap:18px;padding:18px 20px;border:1px solid rgba(255,255,255,.85);border-radius:18px;background:rgba(255,255,255,.72);backdrop-filter:blur(18px);box-shadow:0 18px 45px rgba(35,43,67,.12)}.note strong{display:block;font-size:14px;letter-spacing:-.01em}.note small{display:block;margin-top:5px;color:#7a7f8d;font-size:11px}.number{align-self:center;color:#7d72f5;font-size:12px;font-weight:800;letter-spacing:.12em}
    footer{min-height:78px;display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--line);color:#888d99;font-size:11px;letter-spacing:.03em}
    @keyframes float{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-13px) rotate(2deg)}}@media(prefers-reduced-motion:reduce){.halo{animation:none}}
    @media(max-width:880px){nav>span:not(.availability){display:none}main{grid-template-columns:1fr;padding:64px 0}.copy{max-width:none}.canvas{min-height:480px}.halo{width:290px;height:290px}.ring.one{width:355px;height:355px}.ring.two{width:420px;height:420px}}
    @media(max-width:520px){.page{width:min(100% - 24px,1240px)}header{height:72px}.availability{padding:7px 10px}.availability span{display:none}main{padding:48px 0;gap:44px}h1{font-size:clamp(48px,15vw,72px)}.principles{flex-wrap:wrap;margin-top:30px}.canvas{min-height:410px;border-radius:26px}.halo{width:235px;height:235px}.ring.one{width:290px;height:290px}.ring.two{width:345px;height:345px}.note{left:16px;right:16px;bottom:16px}.number{display:none}}
  </style>
</head>
<body>
  <div class="page">
    <header>
      <div class="brand"><span class="brand-mark"></span>Northline</div>
      <nav><span>Approach</span><span>Journal</span><span class="availability"><span>Available for selected work</span></span></nav>
    </header>
    <main>
      <section class="copy">
        <div class="eyebrow">Independent digital practice</div>
        <h1>Ideas made <em>clear.</em></h1>
        <p class="lead">We create focused digital products and thoughtful brand systems for teams building what comes next.</p>
        <div class="principles"><span>Strategy</span><span>Design</span><span>Technology</span></div>
      </section>
      <section class="canvas" aria-label="Abstract geometric artwork">
        <div class="mesh"></div><div class="ring two"></div><div class="ring one"></div><div class="halo"></div>
        <span class="node n1"></span><span class="node n2"></span><span class="node n3"></span>
        <div class="note"><div><strong>Designed around the essential.</strong><small>Quiet systems. Clear outcomes.</small></div><span class="number">01 / 03</span></div>
      </section>
    </main>
    <footer><span>Northline Studio</span><span>Digital systems · 2026</span></footer>
  </div>
</body>
</html>
`

func publicSiteHandler(next http.Handler, coverEnabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveWebFont(w, r) {
			return
		}
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
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; base-uri 'none'; frame-ancestors 'none'")
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
