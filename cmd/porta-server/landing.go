package main

import (
	"io"
	"net/http"
	"strings"
)

const landingHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="theme-color" content="#f5f6fa">
  <link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml">
  <title>Porta · Digital product studio</title>
  <style>
    @font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-style:normal;font-weight:200 900;font-display:swap}
    :root{color-scheme:light;font-family:"Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ink:#121522;--muted:#686d7c;--line:rgba(25,29,45,.1);--violet:#665cf6;--aqua:#73d9d0;font-feature-settings:"cv11","ss01","ss03";font-synthesis:none}
    *{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;min-height:100vh;color:var(--ink);background:#f5f6fa;overflow-x:hidden}
    body:before{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(circle at 74% 12%,rgba(116,216,208,.24),transparent 25rem),radial-gradient(circle at 12% 84%,rgba(109,94,246,.13),transparent 32rem)}
    .page{position:relative;width:min(1120px,calc(100% - 40px));min-height:100vh;margin:auto;display:grid;grid-template-rows:auto 1fr auto}
    header{height:68px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
    .brand{display:flex;align-items:center;gap:12px;font-size:15px;font-weight:760;letter-spacing:-.025em}.brand-mark{width:32px;height:32px;filter:drop-shadow(0 8px 11px rgba(23,26,39,.16))}
    nav{display:flex;align-items:center;gap:24px;color:#747987;font-size:12px}.availability{display:flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.56);color:#4f5564}.availability:before{content:"";width:7px;height:7px;border-radius:50%;background:#44bf87;box-shadow:0 0 0 4px rgba(68,191,135,.12)}
    main{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(350px,.95fr);gap:clamp(42px,6vw,78px);align-items:center;padding:36px 0}
    .copy{max-width:720px}.eyebrow{display:flex;align-items:center;gap:12px;color:#707584;font-size:11px;font-weight:750;letter-spacing:.17em;text-transform:uppercase}.eyebrow:before{content:"";width:34px;height:1px;background:#9ba0ad}
    h1{margin:18px 0 18px;font-size:clamp(48px,6.2vw,76px);font-weight:670;line-height:.94;letter-spacing:-.067em}h1 em{font-style:normal;color:var(--violet)}
    .lead{max-width:550px;margin:0;color:var(--muted);font-size:clamp(15px,1.5vw,18px);line-height:1.58;letter-spacing:-.012em}.principles{display:flex;gap:20px;margin-top:28px;color:#4f5462;font-size:11px;font-weight:650}.principles span{display:flex;align-items:center;gap:8px}.principles span:before{content:"";width:4px;height:4px;border-radius:50%;background:var(--violet)}
    .canvas{position:relative;min-height:420px;border:1px solid rgba(255,255,255,.76);border-radius:28px;background:linear-gradient(145deg,rgba(255,255,255,.82),rgba(238,240,247,.68));box-shadow:0 30px 80px rgba(38,43,70,.12),inset 0 1px 0 #fff;overflow:hidden}
    .mesh{position:absolute;inset:0;background-image:linear-gradient(rgba(34,40,65,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(34,40,65,.045) 1px,transparent 1px);background-size:48px 48px;mask-image:linear-gradient(to bottom,black,transparent 92%)}
    .halo{position:absolute;width:265px;height:265px;left:50%;top:44%;translate:-50% -50%;border-radius:50%;background:radial-gradient(circle at 35% 28%,#c8fff2 0,#74d9d0 25%,#6a61f2 68%,#4640c4 100%);box-shadow:inset -28px -32px 65px rgba(38,29,132,.32),0 34px 70px rgba(93,82,230,.32);animation:float 7s ease-in-out infinite}
    .ring{position:absolute;left:50%;top:44%;translate:-50% -50%;border:1px solid rgba(88,79,215,.17);border-radius:50%}.ring.one{width:330px;height:330px}.ring.two{width:390px;height:390px}.node{position:absolute;width:8px;height:8px;border:2px solid #fff;border-radius:50%;background:#6d61ef;box-shadow:0 5px 16px rgba(80,70,190,.35)}.n1{left:18%;top:28%}.n2{right:16%;top:58%}.n3{left:28%;bottom:12%;background:#50cbb9}
    .note{position:absolute;left:20px;right:20px;bottom:20px;display:flex;justify-content:space-between;gap:16px;padding:14px 16px;border:1px solid rgba(255,255,255,.85);border-radius:15px;background:rgba(255,255,255,.72);backdrop-filter:blur(18px);box-shadow:0 14px 36px rgba(35,43,67,.11)}.note strong{display:block;font-size:13px;letter-spacing:-.01em}.note small{display:block;margin-top:3px;color:#7a7f8d;font-size:10px}.number{align-self:center;color:#7d72f5;font-size:11px;font-weight:800;letter-spacing:.12em}
    .access{display:flex;align-items:center;gap:8px}.access input{width:170px;border:1px solid var(--line);border-radius:9px;background:rgba(255,255,255,.72);padding:8px 10px;color:var(--ink);font:11px inherit;outline:none}.access input:focus{border-color:#8f86ef;box-shadow:0 0 0 3px rgba(102,92,246,.1)}.access button{border:0;border-radius:9px;background:#171923;color:#fff;padding:8px 12px;font:700 10px inherit;cursor:pointer}.access-error{margin:8px 0 0;color:#b44858;font-size:10px}
    footer{min-height:62px;display:flex;align-items:center;justify-content:space-between;gap:20px;border-top:1px solid var(--line);color:#888d99;font-size:10px;letter-spacing:.03em}
    @keyframes float{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-13px) rotate(2deg)}}@media(prefers-reduced-motion:reduce){.halo{animation:none}}
    @media(max-width:880px){nav>span:not(.availability){display:none}main{grid-template-columns:1fr;padding:38px 0;gap:32px}.copy{max-width:none}.canvas{min-height:360px}.halo{width:230px;height:230px}.ring.one{width:285px;height:285px}.ring.two{width:340px;height:340px}}
    @media(max-width:520px){.page{width:min(100% - 24px,1120px)}header{height:60px}.availability{padding:6px 9px}.availability span{display:none}main{padding:30px 0;gap:28px}h1{font-size:clamp(44px,13vw,58px)}.principles{flex-wrap:wrap;margin-top:22px}.canvas{min-height:320px;border-radius:22px}.halo{width:185px;height:185px}.ring.one{width:230px;height:230px}.ring.two{width:275px;height:275px}.note{left:13px;right:13px;bottom:13px}.number{display:none}footer{align-items:flex-start;flex-direction:column;padding:14px 0}.access{width:100%}.access input{flex:1}}
  </style>
</head>
<body>
  <div class="page">
    <header>
      <div class="brand"><img class="brand-mark" src="/assets/porta-mark.svg" alt="">Porta</div>
      <nav><span>Selected work</span><span class="availability"><span>Available for new projects</span></span></nav>
    </header>
    <main>
      <section class="copy">
        <div class="eyebrow">Independent digital studio</div>
        <h1>Thoughtful work.<br><em>Clearly made.</em></h1>
        <p class="lead">Porta shapes focused digital products and distinctive brand experiences for ambitious teams.</p>
        <div class="principles"><span>Strategy</span><span>Design</span><span>Technology</span></div>
      </section>
      <section class="canvas" aria-label="Abstract geometric artwork">
        <div class="mesh"></div><div class="ring two"></div><div class="ring one"></div><div class="halo"></div>
        <span class="node n1"></span><span class="node n2"></span><span class="node n3"></span>
        <div class="note"><div><strong>Designed around what matters.</strong><small>Clear thinking. Considered outcomes.</small></div><span class="number">PORTA</span></div>
      </section>
    </main>
    <footer><span>Porta Studio</span><div><form class="access" method="post" action="/access"><input name="token" type="password" autocomplete="current-password" aria-label="Access token" placeholder="Client access"><button type="submit">Continue</button></form>{{ACCESS_ERROR}}</div></footer>
  </div>
</body>
</html>
`

func publicSiteHandler(next http.Handler, landingEnabled bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if serveWebFont(w, r) {
			return
		}
		if serveBrandAsset(w, r) {
			return
		}
		if isOperationalPath(r.URL.Path) {
			if landingEnabled && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				serveLandingPage(w, r)
			} else {
				http.NotFound(w, r)
			}
			return
		}
		if !landingEnabled {
			next.ServeHTTP(w, r)
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			next.ServeHTTP(w, r)
			return
		}
		serveLandingPage(w, r)
	})
}

func isOperationalPath(path string) bool {
	return path == "/healthz" || path == "/readyz" || path == "/metrics"
}

func serveLandingPage(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	switch r.URL.Path {
	case "/robots.txt":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, "User-agent: *\nDisallow:\n")
		}
	default:
		serveLandingPageContent(w, r, "")
	}
}

func serveLandingPageContent(w http.ResponseWriter, r *http.Request, accessError string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet || r.Method == http.MethodPost {
		_, _ = io.WriteString(w, strings.Replace(landingHTML, "{{ACCESS_ERROR}}", accessError, 1))
	}
}
