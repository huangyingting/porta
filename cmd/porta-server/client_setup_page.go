package main

import (
	"encoding/base64"
	"html"
	"strings"
)

type downloadProfile struct {
	Server   string
	Token    string
	QRCode   string
	Notice   string
	SetupURI string
}

func clientSetupHTML(profile *downloadProfile) string {
	if profile == nil {
		return ""
	}
	qr := ""
	if encoded, ok := strings.CutPrefix(profile.QRCode, "data:image/png;base64,"); ok {
		if image, err := base64.StdEncoding.DecodeString(encoded); err == nil && len(image) > 0 {
			qr = `<img id="setup-qr" class="setup-qr" src="` + html.EscapeString(profile.QRCode) + `" alt="Private Porta profile QR code containing your server and token">`
		}
	}
	if qr == "" {
		qr = `<p class="setup-unavailable">Profile QR unavailable. Use the server and token below to add your profile manually.</p>`
	}
	notice := ""
	if profile.Notice != "" {
		notice = `<p class="setup-notice">` + html.EscapeString(profile.Notice) + `</p>`
	}
	setupCopy := ""
	if profile.SetupURI != "" {
		setupCopy = `<div class="setup-phone"><p>On this phone: copy setup, then <strong>Add profile &gt; Paste setup</strong> in Porta. Review and save.</p><input id="setup-uri" type="hidden" value="` + html.EscapeString(profile.SetupURI) + `"><button id="setup-copy-uri" type="button">Copy setup</button></div>`
	}
	return `<style>
	.client-setup{margin-top:20px;padding:20px;border:1px solid #e2e4ea;border-radius:16px;background:#fff;color:#171923}.client-setup *{box-sizing:border-box}.client-setup h2{margin:0;font-size:22px;line-height:1.2;letter-spacing:-.035em}.client-setup .setup-intro{margin:8px 0 16px;color:#747987;font-size:13px;line-height:1.55}.client-setup .setup-grid{display:grid;grid-template-columns:minmax(180px,240px) minmax(0,1fr);gap:24px;align-items:center}.client-setup .setup-qr{display:block;width:100%;max-width:240px;height:auto;margin:0 auto;background:#fff}.client-setup .setup-steps{margin:0 0 14px;padding-left:20px;font-size:13px;line-height:1.6}.client-setup .setup-steps li+li{margin-top:5px}.client-setup .setup-field{margin-top:12px;min-width:0}.client-setup label{display:block;margin-bottom:6px;font-size:10px;font-weight:750;letter-spacing:.07em;text-transform:uppercase}.client-setup .setup-value{display:flex;gap:6px;min-width:0}.client-setup input{width:100%;min-width:0;border:1px solid #e2e4ea;border-radius:9px;padding:9px;background:#f8f8fc;color:#363a46;font:16px/1.25 ui-monospace,SFMono-Regular,Menlo,monospace}.client-setup button{flex-shrink:0;min-height:38px;border:1px solid #e2e4ea;border-radius:8px;padding:8px 10px;background:#fff;color:#444957;font:650 12px "Mona Sans",sans-serif;cursor:pointer}.client-setup button:focus-visible,.client-setup input:focus-visible{outline:2px solid #6558ed;outline-offset:2px}.client-setup .setup-token-actions{display:flex;gap:6px;margin-top:6px}.client-setup .setup-manual,.client-setup .setup-private,.client-setup .setup-notice,.client-setup .setup-unavailable{font-size:12px;line-height:1.55;color:#747987}.client-setup .setup-manual{margin:14px 0 0}.client-setup .setup-private{margin:16px 0 0;padding-top:12px;border-top:1px solid #e2e4ea}.client-setup .setup-notice,.client-setup .setup-unavailable{color:#965326}.client-setup .setup-status{min-height:18px;margin:8px 0 0;color:#5549da;font-size:12px;line-height:1.5}.client-setup [hidden]{display:none!important}@media(max-width:580px){.client-setup{padding:16px}.client-setup .setup-grid{grid-template-columns:minmax(0,1fr);gap:16px}.client-setup .setup-qr{max-width:260px}.client-setup h2{font-size:21px}}
	.client-setup .setup-phone{margin:0 0 16px;padding:12px;border:1px solid #e4e0ff;border-radius:10px;background:#f7f6ff}.client-setup .setup-phone p{margin:0 0 9px;color:#55506b;font-size:12px;line-height:1.55}
	</style><section id="client-setup" class="client-setup" aria-labelledby="setup-title"><h2 id="setup-title">2. Set up your profile</h2><p class="setup-intro">After installing Porta, add this server to your app.</p>` + notice + `<div class="setup-grid"><div>` + qr + `</div><div>` + setupCopy + `<ol class="setup-steps"><li>Open <strong>Porta</strong> on Android and tap <strong>Add profile</strong>.</li><li>Choose <strong>Scan QR code</strong> and scan this profile QR from another screen.</li><li>Review the server and tap <strong>Save</strong>. Connect when you are ready.</li></ol><p class="setup-manual">For manual setup, including Windows / Linux, enter the server and token below.</p><div class="setup-field"><label for="setup-server">Server</label><div class="setup-value"><input id="setup-server" value="` + html.EscapeString(profile.Server) + `" readonly autocomplete="off" spellcheck="false"><button id="setup-copy-server" type="button">Copy</button></div></div><div class="setup-field"><label for="setup-token">Token</label><input id="setup-token" type="password" value="` + html.EscapeString(profile.Token) + `" readonly autocomplete="off" spellcheck="false"><div class="setup-token-actions"><button id="setup-reveal-token" type="button" aria-controls="setup-token" aria-pressed="false">Reveal token</button><button id="setup-copy-token" type="button">Copy token</button></div></div><p id="setup-status" class="setup-status" role="status"></p></div></div><p class="setup-private">Your profile QR, copied setup, and token grant account access. Keep them private and share only with your own devices.</p><noscript><p class="setup-manual">Enable JavaScript to copy setup or reveal your token. If a profile QR is shown, you can scan it without JavaScript.</p></noscript></section><script defer src="/assets/portal-client.js"></script>`
}

const portalClientScript = `(()=>{
  const root=document.getElementById('client-setup');
  if(!root)return;
  const server=document.getElementById('setup-server'),token=document.getElementById('setup-token'),setup=document.getElementById('setup-uri'),reveal=document.getElementById('setup-reveal-token'),status=document.getElementById('setup-status');
  let active=true;
  async function copy(field,label){
    if(!active||!field.value)return;
    try{await navigator.clipboard.writeText(field.value);if(active)status.textContent=label+' copied. Keep your credentials private.'}
    catch{if(active){if(field===setup){status.textContent='Clipboard unavailable. Use the server and token below instead.';return}if(field===token){token.type='text';reveal.textContent='Hide token';reveal.setAttribute('aria-pressed','true')}field.select();status.textContent='Select and copy the '+label.toLowerCase()+' above.'}}
  }
  document.getElementById('setup-copy-server').addEventListener('click',()=>copy(server,'Server'));
  document.getElementById('setup-copy-token').addEventListener('click',()=>copy(token,'Token'));
  if(setup)document.getElementById('setup-copy-uri').addEventListener('click',()=>copy(setup,'Setup'));
  reveal.addEventListener('click',()=>{if(!active)return;const visible=token.type==='password';token.type=visible?'text':'password';reveal.textContent=visible?'Hide token':'Reveal token';reveal.setAttribute('aria-pressed',String(visible))});
  addEventListener('pagehide',()=>{
    active=false;
    for(const field of [server,token,setup].filter(Boolean)){field.value='';field.defaultValue='';field.removeAttribute('value')}
    token.type='password';reveal.textContent='Reveal token';reveal.setAttribute('aria-pressed','false');
    const qr=document.getElementById('setup-qr');if(qr){qr.removeAttribute('src');qr.hidden=true}
    root.querySelectorAll('button').forEach(button=>button.disabled=true);
    status.textContent='';
  });
  addEventListener('pageshow',event=>{if(event.persisted)location.reload()});
})();`
