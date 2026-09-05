package main

import "html"

func joinPageHTML(message string) string {
	state, heading, detail := "auto", "Opening downloads", "Preparing your private access. No access key needed."
	if message != "" {
		state, heading, detail = "error", "Link unavailable", message
	}
	return `<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta name="theme-color" content="#f5f6fa"><title>Porta · Client access</title><link rel="icon" href="/assets/porta-mark.svg" type="image/svg+xml"><style>
	@font-face{font-family:"Mona Sans";src:url("/assets/mona-sans.woff2") format("woff2-variations");font-weight:200 900;font-display:swap}:root{font-family:"Mona Sans",-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif;color:#171923;background:#f5f6fa;font-synthesis:none}*{box-sizing:border-box}body{margin:0;min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:20px;background:radial-gradient(circle at 80% 10%,rgba(115,217,208,.22),transparent 25rem),#f5f6fa}.join-card{width:min(420px,100%);padding:26px;border:1px solid #e2e4ea;border-radius:20px;background:#fff;box-shadow:0 18px 50px rgba(35,40,68,.07)}.join-brand{display:flex;align-items:center;gap:9px;font-size:15px;font-weight:800;color:inherit;text-decoration:none}.join-brand img{width:30px;height:30px}.join-heading{margin:27px 0 10px;font-size:29px;line-height:1.1;letter-spacing:-.045em}.join-detail{margin:0;color:#717684;font-size:13px;line-height:1.6;overflow-wrap:anywhere}.join-loader{width:23px;height:23px;margin-top:20px;border:3px solid #eeecff;border-top-color:#6558ed;border-radius:50%;animation:join-spin 1s linear infinite}.join-access{display:inline-flex;align-items:center;justify-content:center;min-height:40px;margin-top:20px;padding:10px 13px;border:1px solid #e2e4ea;border-radius:9px;color:#444957;text-decoration:none;font-size:12px;font-weight:650}.join-note{margin:18px 0 0;color:#717684;font-size:12px;line-height:1.5}[data-join-state="error"] .join-loader{display:none}[data-join-state="auto"] .join-access{display:none}@keyframes join-spin{to{transform:rotate(360deg)}}@media(prefers-reduced-motion:reduce){.join-loader{animation:none}}@media(max-width:380px),(max-height:480px){body{padding:14px}.join-card{padding:20px}.join-heading{margin-top:22px;font-size:27px}}</style><script defer src="/assets/portal-join.js"></script></head><body><main id="portal-join" class="join-card" data-join-state="` + state + `"><a class="join-brand" href="/"><img src="/assets/porta-mark.svg" alt="">Porta</a><h1 id="join-heading" class="join-heading">` + heading + `</h1><p id="join-detail" class="join-detail" role="status">` + html.EscapeString(detail) + `</p><div class="join-loader" aria-hidden="true"></div><a class="join-access" href="/access">Use an access token instead</a><noscript><p class="join-note">Enable JavaScript and reopen your invitation to continue automatically, or <a href="/access">use your access token</a>.</p></noscript></main></body></html>`
}

const portalJoinScript = `(()=>{
  const root=document.getElementById('portal-join');
  addEventListener('hashchange',()=>{if(location.hash)location.reload()});
  let fragment=location.hash;
  try{history.replaceState(null,'','/join')}catch{fragment=''}
  if(!root||root.dataset.joinState!=='auto')return;
  function invalid(){
    root.dataset.joinState='error';
    document.getElementById('join-heading').textContent='Link unavailable';
    document.getElementById('join-detail').textContent='This access link is invalid or expired. Ask your administrator for a new link.';
  }
  const params=new URLSearchParams(fragment.slice(1));
  fragment='';
  const values=params.getAll('invite'),keys=[...params.keys()];
  if(keys.length!==1||keys[0]!=='invite'||values.length!==1||!values[0].trim()||values[0].length>4096){invalid();return}
  const form=document.createElement('form'),ticket=document.createElement('input');
  form.method='POST';form.action='/join/redeem';form.hidden=true;form.autocomplete='off';
  ticket.type='hidden';ticket.name='ticket';ticket.value=values[0];
  form.appendChild(ticket);document.body.appendChild(form);
  addEventListener('pagehide',()=>{ticket.value='';ticket.removeAttribute('value');form.remove()});
  addEventListener('pageshow',event=>{if(event.persisted){ticket.value='';form.remove();invalid()}});
  form.submit();
})();`
