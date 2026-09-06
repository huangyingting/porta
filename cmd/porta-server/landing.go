package main

import (
	"fmt"
	"io"
	"math/rand/v2"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

const landingHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
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
    nav{display:flex;align-items:center;gap:18px;color:#747987;font-size:12px}.availability{display:flex;align-items:center;gap:8px;padding:7px 11px;border:1px solid var(--line);border-radius:999px;background:rgba(255,255,255,.56);color:#4f5564}.availability:before{content:"";width:7px;height:7px;border-radius:50%;background:#44bf87;box-shadow:0 0 0 4px rgba(68,191,135,.12)}
    main{display:grid;grid-template-columns:minmax(0,1.05fr) minmax(350px,.95fr);gap:clamp(42px,6vw,78px);align-items:center;padding:36px 0}
    .copy{max-width:720px}.eyebrow{display:flex;align-items:center;gap:12px;color:#707584;font-size:11px;font-weight:750;letter-spacing:.17em;text-transform:uppercase}.eyebrow:before{content:"";width:34px;height:1px;background:#9ba0ad}
    h1{margin:18px 0 18px;font-size:clamp(44px,5.7vw,68px);font-weight:670;line-height:.96;letter-spacing:-.062em}h1 em{font-style:normal;color:var(--violet)}
    .lead{max-width:550px;margin:0;color:var(--muted);font-size:clamp(15px,1.35vw,17px);line-height:1.6;letter-spacing:-.012em}.principles{display:flex;gap:20px;margin-top:28px;color:#4f5462;font-size:12px;font-weight:650}.principles span{display:flex;align-items:center;gap:8px}.principles span:before{content:"";width:4px;height:4px;border-radius:50%;background:var(--violet)}.access-link{display:inline-flex;align-items:center;gap:9px;margin-top:30px;border-radius:11px;background:#171923;color:white;padding:12px 17px;text-decoration:none;font-size:12px;font-weight:750;box-shadow:0 10px 24px rgba(23,25,35,.17)}.access-link:after{content:"→";font-size:14px}
    .canvas{position:relative;min-height:420px;border:1px solid rgba(255,255,255,.76);border-radius:28px;background:linear-gradient(145deg,rgba(255,255,255,.82),rgba(238,240,247,.68));box-shadow:0 30px 80px rgba(38,43,70,.12),inset 0 1px 0 #fff;overflow:hidden}
    .mesh{position:absolute;inset:0;background-image:linear-gradient(rgba(34,40,65,.045) 1px,transparent 1px),linear-gradient(90deg,rgba(34,40,65,.045) 1px,transparent 1px);background-size:48px 48px;mask-image:linear-gradient(to bottom,black,transparent 92%)}
    .halo{position:absolute;width:265px;height:265px;left:50%;top:44%;translate:-50% -50%;border-radius:50%;background:radial-gradient(circle at 35% 28%,#c8fff2 0,#74d9d0 25%,#6a61f2 68%,#4640c4 100%);box-shadow:inset -28px -32px 65px rgba(38,29,132,.32),0 34px 70px rgba(93,82,230,.32);animation:float 7s ease-in-out infinite}
    .ring{position:absolute;left:50%;top:44%;translate:-50% -50%;border:1px solid rgba(88,79,215,.17);border-radius:50%}.ring.one{width:330px;height:330px}.ring.two{width:390px;height:390px}.node{position:absolute;width:8px;height:8px;border:2px solid #fff;border-radius:50%;background:#6d61ef;box-shadow:0 5px 16px rgba(80,70,190,.35)}.n1{left:18%;top:28%}.n2{right:16%;top:58%}.n3{left:28%;bottom:12%;background:#50cbb9}
    .note{position:absolute;left:20px;right:20px;bottom:20px;display:flex;justify-content:space-between;gap:16px;padding:14px 16px;border:1px solid rgba(255,255,255,.85);border-radius:15px;background:rgba(255,255,255,.72);backdrop-filter:blur(18px);box-shadow:0 14px 36px rgba(35,43,67,.11)}.note strong{display:block;font-size:13px;letter-spacing:-.01em}.note small{display:block;margin-top:3px;color:#7a7f8d;font-size:10px}.number{align-self:center;color:#7d72f5;font-size:11px;font-weight:800;letter-spacing:.12em}
    footer{min-height:54px;display:flex;align-items:center;justify-content:space-between;gap:20px;border-top:1px solid var(--line);color:#888d99;font-size:10px;letter-spacing:.03em}
    @keyframes float{0%,100%{transform:translateY(0) rotate(-2deg)}50%{transform:translateY(-13px) rotate(2deg)}}@media(prefers-reduced-motion:reduce){.halo{animation:none}}
    @media(max-width:880px){nav>span:not(.availability){display:none}main{grid-template-columns:1fr;padding:38px 0;gap:32px}.copy{max-width:none}.canvas{min-height:360px}.halo{width:230px;height:230px}.ring.one{width:285px;height:285px}.ring.two{width:340px;height:340px}}
    @media(max-width:520px){.page{width:min(100% - 24px,1120px)}header{height:60px}.availability span{display:none}main{padding:30px 0;gap:28px}h1{font-size:clamp(40px,12vw,52px)}.principles{flex-wrap:wrap;margin-top:22px}.access-link{margin-top:25px}.canvas{min-height:320px;border-radius:22px}.halo{width:185px;height:185px}.ring.one{width:230px;height:230px}.ring.two{width:275px;height:275px}.note{left:13px;right:13px;bottom:13px}.number{display:none}}
  </style>
</head>
<body>
  <div class="page">
    <header>
      <div class="brand"><img class="brand-mark" src="/assets/porta-mark.svg" alt="">Porta</div>
      <nav><span class="availability"><span>Available for new projects</span></span></nav>
    </header>
    <main>
      <section class="copy">
        <div class="eyebrow">Independent digital studio</div>
        <h1>Thoughtful work.<br><em>Clearly made.</em></h1>
        <p class="lead">Porta shapes focused digital products and distinctive brand experiences for ambitious teams.</p>
        <div class="principles"><span>Strategy</span><span>Design</span><span>Technology</span></div>
        <a class="access-link" href="/access">Get access</a>
      </section>
      <section class="canvas" aria-label="Abstract geometric artwork">
        <div class="mesh"></div><div class="ring two"></div><div class="ring one"></div><div class="halo"></div>
        <span class="node n1"></span><span class="node n2"></span><span class="node n3"></span>
        <div class="note"><div><strong>Designed around what matters.</strong><small>Clear thinking. Considered outcomes.</small></div><span class="number">PORTA</span></div>
      </section>
    </main>
    <footer><span>Porta Studio</span><span>Digital products and experiences</span></footer>
  </div>
</body>
</html>
`

const landingAccessHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
  <meta name="theme-color" content="#10131d">
  <link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml">
  <title>Porta · Focused access</title>
  <style>
    @font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-style:normal;font-weight:200 900;font-display:swap}
    :root{color-scheme:dark;font-family:"Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ink:#f4f5fb;--muted:#a5a9b8;--line:rgba(255,255,255,.11);--violet:#9b91ff;--mint:#77e2cc;font-feature-settings:"cv11","ss01","ss03";font-synthesis:none}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);background:#10131d;overflow-x:hidden}
    body:before{content:"";position:fixed;inset:0;pointer-events:none;background:radial-gradient(circle at 14% 18%,rgba(119,226,204,.14),transparent 28rem),radial-gradient(circle at 88% 72%,rgba(116,97,255,.2),transparent 34rem)}
    .page{position:relative;width:min(1060px,calc(100% - 40px));min-height:100vh;margin:auto;display:grid;grid-template-rows:auto 1fr auto}
    header{height:72px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}
    .brand{display:flex;align-items:center;gap:11px;font-size:15px;font-weight:780;letter-spacing:-.025em}.brand img{width:31px;height:31px}.edition{color:#858b9c;font-size:10px;font-weight:700;letter-spacing:.13em;text-transform:uppercase}
    main{display:grid;grid-template-columns:minmax(0,1fr) minmax(320px,.72fr);gap:clamp(42px,8vw,100px);align-items:center;padding:48px 0}
    .eyebrow{color:var(--mint);font-size:11px;font-weight:760;letter-spacing:.16em;text-transform:uppercase}
    h1{max-width:650px;margin:18px 0;font-size:clamp(50px,7.2vw,84px);font-weight:630;line-height:.92;letter-spacing:-.065em}h1 em{font-style:normal;color:var(--violet)}
    .lead{max-width:540px;margin:0;color:var(--muted);font-size:clamp(15px,1.5vw,18px);line-height:1.65;letter-spacing:-.01em}
    .access-link{display:inline-flex;align-items:center;gap:12px;margin-top:31px;border:1px solid rgba(255,255,255,.16);border-radius:999px;background:#f3f4f8;color:#171923;padding:12px 18px;text-decoration:none;font-size:12px;font-weight:780;box-shadow:0 16px 34px rgba(0,0,0,.24)}.access-link:after{content:"→";font-size:14px}
    .panel{position:relative;min-height:390px;border:1px solid var(--line);border-radius:30px;background:linear-gradient(155deg,rgba(255,255,255,.08),rgba(255,255,255,.025));box-shadow:0 32px 80px rgba(0,0,0,.22);overflow:hidden}
    .panel:before,.panel:after{content:"";position:absolute;border-radius:50%}.panel:before{width:230px;height:230px;right:-50px;top:-58px;border:1px solid rgba(155,145,255,.32);box-shadow:0 0 0 44px rgba(155,145,255,.045),0 0 0 88px rgba(155,145,255,.025)}.panel:after{width:140px;height:140px;left:42px;bottom:44px;background:linear-gradient(145deg,var(--mint),#7365ff);box-shadow:0 25px 55px rgba(82,73,201,.34);animation:drift 7s ease-in-out infinite}
    .panel-copy{position:absolute;left:24px;right:24px;top:24px;z-index:1;padding:17px;border:1px solid rgba(255,255,255,.1);border-radius:15px;background:rgba(13,16,25,.62);backdrop-filter:blur(16px)}.panel-copy small{display:block;color:#7f8597;font-size:9px;font-weight:760;letter-spacing:.15em;text-transform:uppercase}.panel-copy strong{display:block;margin-top:7px;font-size:15px;letter-spacing:-.02em}
    .index{position:absolute;right:24px;bottom:22px;z-index:1;color:#b2accf;font-size:10px;font-weight:800;letter-spacing:.16em}
    footer{min-height:58px;display:flex;align-items:center;justify-content:space-between;gap:20px;border-top:1px solid var(--line);color:#747a8c;font-size:10px}
    @keyframes drift{0%,100%{transform:translateY(0) rotate(-5deg)}50%{transform:translateY(-14px) rotate(4deg)}}@media(prefers-reduced-motion:reduce){.panel:after{animation:none}}
    @media(max-width:780px){main{grid-template-columns:1fr;gap:34px;padding:40px 0}.panel{min-height:320px}h1{font-size:clamp(47px,12vw,68px)}}
    @media(max-width:520px){.page{width:min(100% - 24px,1060px)}header{height:62px}.edition{display:none}main{padding:32px 0;gap:28px}.panel{min-height:280px;border-radius:23px}.panel:after{width:112px;height:112px;left:30px}.access-link{margin-top:25px}footer{align-items:flex-start;flex-direction:column;justify-content:center;gap:4px}}
  </style>
</head>
<body>
  <div class="page">
    <header><div class="brand"><img src="/assets/porta-mark.svg" alt="">Porta</div><span class="edition">Private workspace</span></header>
    <main>
      <section>
        <div class="eyebrow">Welcome to Porta</div>
        <h1>A clear way <em>in.</em></h1>
        <p class="lead">Approved users can continue to their Porta workspace from one focused, carefully designed starting point.</p>
        <a class="access-link" href="/access">Get access</a>
      </section>
      <section class="panel" aria-label="Abstract geometric artwork">
        <div class="panel-copy"><small>Designed for focus</small><strong>Everything begins with a clear entry point.</strong></div>
        <span class="index">PORTA / 02</span>
      </section>
    </main>
    <footer><span>Porta</span><span>Focused access for approved users</span></footer>
  </div>
</body>
</html>
`

const (
	robotsText             = "User-agent: *\nDisallow: /\n"
	robotsDirectives       = "noindex, nofollow, noarchive, nosnippet, noimageindex"
	maxLandingTemplateSize = 1 << 20
)

type landingTemplateSet struct {
	pages       []string
	randomIndex func(int) int
}

var bundledLandingTemplates = newLandingTemplateSet([]string{
	landingHTML,
	landingAccessHTML,
	landingEditorialHTML,
	landingGridHTML,
	landingGalleryHTML,
	landingMinimalHTML,
})

func newLandingTemplateSet(pages []string) landingTemplateSet {
	return landingTemplateSet{
		pages:       append([]string(nil), pages...),
		randomIndex: rand.IntN,
	}
}

func loadLandingTemplateSet(directory string) (landingTemplateSet, error) {
	if strings.TrimSpace(directory) == "" {
		return bundledLandingTemplates, nil
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		return landingTemplateSet{}, fmt.Errorf("read landing template directory: %w", err)
	}
	pages := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.Type().IsRegular() || !strings.EqualFold(filepath.Ext(entry.Name()), ".html") {
			continue
		}
		path := filepath.Join(directory, entry.Name())
		info, err := entry.Info()
		if err != nil {
			return landingTemplateSet{}, fmt.Errorf("inspect landing template %q: %w", entry.Name(), err)
		}
		if info.Size() > maxLandingTemplateSize {
			return landingTemplateSet{}, fmt.Errorf("landing template %q exceeds the 1 MiB limit", entry.Name())
		}
		content, err := os.ReadFile(path)
		if err != nil {
			return landingTemplateSet{}, fmt.Errorf("read landing template %q: %w", entry.Name(), err)
		}
		if len(content) > maxLandingTemplateSize {
			return landingTemplateSet{}, fmt.Errorf("landing template %q exceeds the 1 MiB limit", entry.Name())
		}
		if len(strings.TrimSpace(string(content))) == 0 {
			return landingTemplateSet{}, fmt.Errorf("landing template %q is empty", entry.Name())
		}
		pages = append(pages, string(content))
	}
	if len(pages) == 0 {
		return bundledLandingTemplates, nil
	}
	return newLandingTemplateSet(pages), nil
}

func (templates landingTemplateSet) selectPage() string {
	if len(templates.pages) == 0 {
		panic("landing template set is empty")
	}
	if len(templates.pages) == 1 {
		return templates.pages[0]
	}
	return templates.pages[templates.randomIndex(len(templates.pages))]
}

func publicSiteHandler(next http.Handler, landingEnabled bool) http.Handler {
	return publicSiteHandlerWithTemplates(next, landingEnabled, bundledLandingTemplates)
}

func publicSiteHandlerWithTemplates(next http.Handler, landingEnabled bool, templates landingTemplateSet) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/robots.txt" && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
			serveRobots(w, r)
			return
		}
		if serveWebFont(w, r) {
			return
		}
		if serveBrandAsset(w, r) {
			return
		}
		if isOperationalPath(r.URL.Path) {
			if landingEnabled && (r.Method == http.MethodGet || r.Method == http.MethodHead) {
				serveLandingPage(w, r, templates.selectPage())
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
		serveLandingPage(w, r, templates.selectPage())
	})
}

func isOperationalPath(path string) bool {
	return path == "/healthz" || path == "/readyz" || path == "/metrics"
}

func serveLandingPage(w http.ResponseWriter, r *http.Request, content string) {
	setCrawlerPolicy(w)
	w.Header().Set("Content-Security-Policy", "default-src 'none'; style-src 'unsafe-inline'; font-src 'self'; img-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	serveLandingPageContent(w, r, content)
}

func serveRobots(w http.ResponseWriter, r *http.Request) {
	setCrawlerPolicy(w)
	w.Header().Set("Cache-Control", "public, max-age=300")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, robotsText)
	}
}

func setCrawlerPolicy(w http.ResponseWriter) {
	w.Header().Set("X-Robots-Tag", robotsDirectives)
}

func serveLandingPageContent(w http.ResponseWriter, r *http.Request, content string) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	if r.Method == http.MethodGet {
		_, _ = io.WriteString(w, content)
	}
}
