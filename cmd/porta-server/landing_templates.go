package main

const landingEditorialHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
  <meta name="theme-color" content="#f3efe6">
  <link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml">
  <title>Porta · Quietly useful</title>
  <style>
    @font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-style:normal;font-weight:200 900;font-display:swap}
    :root{color-scheme:light;font-family:"Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ink:#1d1b18;--muted:#777168;--paper:#f3efe6;--line:rgba(29,27,24,.16);--red:#e4634d;font-feature-settings:"cv11","ss01","ss03";font-synthesis:none}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:var(--paper);color:var(--ink)}
    .page{width:min(1180px,calc(100% - 48px));min-height:100vh;margin:auto;display:grid;grid-template-rows:auto 1fr auto}
    header{height:74px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:11px;font-size:15px;font-weight:800}.brand img{width:31px}.issue{font-size:10px;font-weight:750;letter-spacing:.16em;text-transform:uppercase}
    main{display:grid;grid-template-columns:minmax(0,1.25fr) minmax(280px,.55fr);gap:clamp(42px,8vw,110px);align-items:center;padding:48px 0}
    .kicker{font-size:10px;font-weight:800;letter-spacing:.18em;text-transform:uppercase}.kicker span{color:var(--red)}
    h1{max-width:760px;margin:20px 0 24px;font-size:clamp(58px,8.5vw,110px);font-weight:560;line-height:.82;letter-spacing:-.075em}
    .lead{max-width:570px;margin:0;color:var(--muted);font-size:clamp(15px,1.5vw,18px);line-height:1.65}
    .access-link{display:inline-flex;align-items:center;gap:13px;margin-top:30px;color:var(--ink);font-size:12px;font-weight:800;text-decoration:none}.access-link:before{content:"";width:38px;height:38px;border-radius:50%;background:var(--red);box-shadow:inset 0 0 0 10px rgba(255,255,255,.2)}.access-link:after{content:"→";font-size:15px}
    .folio{position:relative;min-height:430px;border-left:1px solid var(--line);padding-left:32px;display:flex;align-items:flex-end}.folio:before{content:"03";position:absolute;top:0;right:0;color:rgba(29,27,24,.08);font-size:170px;font-weight:800;line-height:.8;letter-spacing:-.08em}.card{position:relative;width:100%;padding:24px;border:1px solid var(--line);background:rgba(255,255,255,.25)}.card small{font-size:9px;font-weight:800;letter-spacing:.15em;text-transform:uppercase}.card strong{display:block;margin-top:70px;font-size:24px;line-height:1.1;letter-spacing:-.04em}.rule{width:44px;height:3px;margin-top:20px;background:var(--red)}
    footer{min-height:58px;display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--line);color:#858077;font-size:10px}
    @media(max-width:760px){.page{width:min(100% - 28px,1180px)}main{grid-template-columns:1fr;gap:38px;padding:38px 0}h1{font-size:clamp(58px,16vw,84px)}.folio{min-height:260px;border-left:0;border-top:1px solid var(--line);padding:28px 0 0}.folio:before{font-size:120px}.card strong{margin-top:46px}}
    @media(max-width:430px){header{height:62px}.issue{display:none}h1{font-size:clamp(52px,18vw,70px)}footer{align-items:flex-start;flex-direction:column;justify-content:center;gap:3px}}
  </style>
</head>
<body>
  <div class="page">
    <header><div class="brand"><img src="/assets/porta-mark.svg" alt="">Porta</div><span class="issue">Edition 03</span></header>
    <main>
      <section><div class="kicker">A place for <span>considered work</span></div><h1>Ideas need room.</h1><p class="lead">Porta gives approved users a composed starting point for shared work, useful releases, and the next clear step.</p><a class="access-link" href="/access">Get access</a></section>
      <aside class="folio"><div class="card"><small>Porta / 03</small><strong>Quiet structure.<br>Useful outcomes.</strong><div class="rule"></div></div></aside>
    </main>
    <footer><span>Porta</span><span>Made with clarity and care</span></footer>
  </div>
</body>
</html>
`

const landingGridHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
  <meta name="theme-color" content="#dce7ff">
  <link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml">
  <title>Porta · Clear beginnings</title>
  <style>
    @font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-style:normal;font-weight:200 900;font-display:swap}
    :root{color-scheme:light;font-family:"Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ink:#122047;--muted:#536080;--blue:#3457e8;--line:rgba(18,32,71,.13);font-feature-settings:"cv11","ss01","ss03";font-synthesis:none}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);background:#dce7ff;background-image:linear-gradient(rgba(18,32,71,.07) 1px,transparent 1px),linear-gradient(90deg,rgba(18,32,71,.07) 1px,transparent 1px);background-size:52px 52px}
    .page{width:min(1050px,calc(100% - 40px));min-height:100vh;margin:auto;display:grid;grid-template-rows:auto 1fr auto}
    header{height:70px;display:flex;align-items:center;justify-content:space-between}.brand{display:flex;align-items:center;gap:10px;font-size:15px;font-weight:820}.brand img{width:30px}.tag{padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:rgba(255,255,255,.45);font-size:10px;font-weight:720}
    main{display:grid;place-items:center;padding:44px 0;text-align:center}.hero{max-width:830px}.eyebrow{display:inline-flex;padding:7px 11px;border-radius:999px;background:var(--ink);color:white;font-size:9px;font-weight:800;letter-spacing:.14em;text-transform:uppercase}
    h1{margin:23px 0 20px;font-size:clamp(54px,9vw,104px);font-weight:700;line-height:.88;letter-spacing:-.072em}h1 span{color:var(--blue)}
    .lead{max-width:600px;margin:auto;color:var(--muted);font-size:clamp(15px,1.5vw,18px);line-height:1.65}
    .access-link{display:inline-flex;align-items:center;gap:10px;margin-top:30px;border-radius:12px;background:var(--blue);color:white;padding:13px 19px;text-decoration:none;font-size:12px;font-weight:800;box-shadow:0 14px 30px rgba(52,87,232,.25)}.access-link:after{content:"↗";font-size:14px}
    .blocks{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;width:min(640px,100%);margin:48px auto 0}.block{height:84px;border:1px solid rgba(255,255,255,.75);border-radius:16px;background:rgba(255,255,255,.4);box-shadow:0 10px 28px rgba(26,52,117,.07)}.block:nth-child(2){background:var(--blue)}.block:nth-child(3){background:linear-gradient(135deg,#9eafff,#78dfd2)}
    footer{min-height:58px;display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--line);color:#687493;font-size:10px}
    @media(max-width:600px){.page{width:min(100% - 24px,1050px)}header{height:62px}.tag{display:none}main{padding:34px 0}h1{font-size:clamp(52px,17vw,78px)}.blocks{margin-top:36px}.block{height:62px}}
    @media(max-width:400px){.blocks{grid-template-columns:1fr}.block{height:44px}.block:nth-child(n+2){display:none}footer{align-items:flex-start;flex-direction:column;justify-content:center;gap:3px}}
  </style>
</head>
<body>
  <div class="page">
    <header><div class="brand"><img src="/assets/porta-mark.svg" alt="">Porta</div><span class="tag">A focused starting point</span></header>
    <main><section class="hero"><div class="eyebrow">Porta / 04</div><h1>Start somewhere <span>clear.</span></h1><p class="lead">A simple, welcoming entry point for approved Porta users to continue with confidence.</p><a class="access-link" href="/access">Get access</a><div class="blocks"><div class="block"></div><div class="block"></div><div class="block"></div></div></section></main>
    <footer><span>Porta</span><span>Clarity from the first step</span></footer>
  </div>
</body>
</html>
`

const landingGalleryHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
  <meta name="theme-color" content="#f7d7cb">
  <link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml">
  <title>Porta · Work in view</title>
  <style>
    @font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-style:normal;font-weight:200 900;font-display:swap}
    :root{color-scheme:light;font-family:"Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ink:#2a1718;--muted:#765f60;--coral:#ef745f;--cream:#fff8ef;--line:rgba(42,23,24,.13);font-feature-settings:"cv11","ss01","ss03";font-synthesis:none}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);background:#f7d7cb}
    .page{width:min(1140px,calc(100% - 42px));min-height:100vh;margin:auto;display:grid;grid-template-rows:auto 1fr auto}
    header{height:70px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:11px;font-size:15px;font-weight:820}.brand img{width:31px}.place{font-size:10px;font-weight:760;letter-spacing:.12em;text-transform:uppercase}
    main{display:grid;grid-template-columns:minmax(330px,.78fr) minmax(0,1.22fr);gap:clamp(30px,6vw,80px);align-items:center;padding:40px 0}
    .art{position:relative;min-height:520px;border-radius:180px 180px 24px 24px;background:var(--cream);overflow:hidden;box-shadow:0 30px 70px rgba(82,40,38,.13)}.sun{position:absolute;width:210px;height:210px;left:50%;top:34%;translate:-50% -50%;border-radius:50%;background:var(--coral);box-shadow:0 0 0 42px rgba(239,116,95,.14),0 0 0 84px rgba(239,116,95,.07)}.line{position:absolute;left:14%;right:14%;bottom:25%;height:1px;background:var(--ink)}.caption{position:absolute;left:28px;right:28px;bottom:25px;display:flex;justify-content:space-between;font-size:9px;font-weight:780;letter-spacing:.12em;text-transform:uppercase}
    .eyebrow{color:#a24237;font-size:10px;font-weight:800;letter-spacing:.17em;text-transform:uppercase}h1{margin:18px 0 20px;font-size:clamp(54px,7vw,88px);font-weight:640;line-height:.9;letter-spacing:-.068em}
    .lead{max-width:510px;margin:0;color:var(--muted);font-size:clamp(15px,1.5vw,18px);line-height:1.65}.access-link{display:inline-flex;align-items:center;justify-content:space-between;min-width:150px;margin-top:30px;border:1px solid var(--ink);border-radius:0;color:var(--ink);padding:12px 14px;text-decoration:none;font-size:11px;font-weight:800}.access-link:after{content:"→";font-size:15px}
    footer{min-height:58px;display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--line);color:#866f70;font-size:10px}
    @media(max-width:780px){.page{width:min(100% - 26px,1140px)}main{grid-template-columns:1fr;gap:34px;padding:32px 0}.copy{order:-1}.art{min-height:340px;border-radius:120px 120px 20px 20px}.sun{width:150px;height:150px}h1{font-size:clamp(52px,15vw,76px)}}
    @media(max-width:430px){header{height:62px}.place{display:none}.art{min-height:290px}.caption{left:20px;right:20px}footer{align-items:flex-start;flex-direction:column;justify-content:center;gap:3px}}
  </style>
</head>
<body>
  <div class="page">
    <header><div class="brand"><img src="/assets/porta-mark.svg" alt="">Porta</div><span class="place">Collection 05</span></header>
    <main>
      <section class="art" aria-label="Abstract sunrise artwork"><div class="sun"></div><div class="line"></div><div class="caption"><span>Porta</span><span>05 / 06</span></div></section>
      <section class="copy"><div class="eyebrow">Everything in its place</div><h1>Work,<br>gathered.</h1><p class="lead">One calm place for approved Porta users to continue with the people and resources that matter.</p><a class="access-link" href="/access">Get access</a></section>
    </main>
    <footer><span>Porta</span><span>A considered place to begin</span></footer>
  </div>
</body>
</html>
`

const landingMinimalHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="robots" content="noindex, nofollow, noarchive, nosnippet, noimageindex">
  <meta name="theme-color" content="#f8f8f5">
  <link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml">
  <title>Porta · Less, but better</title>
  <style>
    @font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-style:normal;font-weight:200 900;font-display:swap}
    :root{color-scheme:light;font-family:"Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;--ink:#121212;--muted:#71716c;--lime:#c9ee48;--line:#d8d8d2;font-feature-settings:"cv11","ss01","ss03";font-synthesis:none}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;color:var(--ink);background:#f8f8f5}
    .page{width:min(1160px,calc(100% - 48px));min-height:100vh;margin:auto;display:grid;grid-template-rows:auto 1fr auto}
    header{height:74px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--line)}.brand{display:flex;align-items:center;gap:11px;font-size:15px;font-weight:820}.brand img{width:31px}.number{font:800 10px/1 "Mona Sans",sans-serif;letter-spacing:.16em}
    main{position:relative;display:flex;align-items:center;padding:50px 0;overflow:hidden}.copy{position:relative;z-index:2;max-width:800px}.eyebrow{font-size:10px;font-weight:820;letter-spacing:.18em;text-transform:uppercase}
    h1{margin:20px 0 22px;font-size:clamp(62px,9vw,116px);font-weight:590;line-height:.82;letter-spacing:-.078em}.accent{display:inline-block;padding:0 .08em;background:var(--lime);transform:rotate(-1deg)}
    .lead{max-width:530px;margin:0;color:var(--muted);font-size:clamp(15px,1.45vw,18px);line-height:1.65}.access-link{display:inline-flex;align-items:center;gap:28px;margin-top:32px;border-bottom:1px solid var(--ink);color:var(--ink);padding:0 0 7px;text-decoration:none;font-size:12px;font-weight:820}.access-link:after{content:"→";font-size:16px}
    .orbit{position:absolute;width:min(44vw,500px);height:min(44vw,500px);right:-3%;top:50%;translate:0 -50%;border:1px solid #bdbdb7;border-radius:50%}.orbit:before,.orbit:after{content:"";position:absolute;border-radius:50%}.orbit:before{width:52%;height:52%;left:24%;top:24%;border:1px solid #bdbdb7}.orbit:after{width:22px;height:22px;left:8%;top:26%;background:var(--lime);box-shadow:0 0 0 10px #f8f8f5}
    footer{min-height:58px;display:flex;align-items:center;justify-content:space-between;border-top:1px solid var(--line);color:#777772;font-size:10px}
    @media(max-width:760px){.page{width:min(100% - 28px,1160px)}main{align-items:flex-start;padding:52px 0 330px}.orbit{width:310px;height:310px;right:-80px;top:auto;bottom:16px;translate:0}h1{font-size:clamp(58px,17vw,84px)}}
    @media(max-width:430px){header{height:62px}.number{display:none}main{padding-top:40px;padding-bottom:285px}.orbit{width:265px;height:265px}footer{align-items:flex-start;flex-direction:column;justify-content:center;gap:3px}}
  </style>
</head>
<body>
  <div class="page">
    <header><div class="brand"><img src="/assets/porta-mark.svg" alt="">Porta</div><span class="number">06 / 06</span></header>
    <main><section class="copy"><div class="eyebrow">Purposefully simple</div><h1>Less noise.<br><span class="accent">More direction.</span></h1><p class="lead">Porta keeps the next step close for approved users, with a clear beginning and nothing unnecessary.</p><a class="access-link" href="/access">Get access</a></section><div class="orbit" aria-hidden="true"></div></main>
    <footer><span>Porta</span><span>Useful by design</span></footer>
  </div>
</body>
</html>
`
