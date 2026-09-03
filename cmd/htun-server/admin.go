package main

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
)

type adminAPI struct {
	next       http.Handler
	registry   *clientRegistry
	adminToken string
}

type clientInput struct {
	Name       string `json:"name"`
	MaxDevices int    `json:"max_devices"`
	Enabled    *bool  `json:"enabled,omitempty"`
}

func adminHandler(next http.Handler, registry *clientRegistry, adminToken string) http.Handler {
	return &adminAPI{next: next, registry: registry, adminToken: adminToken}
}

func (a *adminAPI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	setAdminSecurityHeaders(w)
	if r.Method == http.MethodGet && isOperationalPath(r.URL.Path) {
		a.next.ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/" {
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if r.Method == http.MethodGet {
			_, _ = io.WriteString(w, adminHTML)
		}
		return
	}
	if !strings.HasPrefix(r.URL.Path, "/api/") {
		http.NotFound(w, r)
		return
	}
	if !adminAuthorized(r.Header.Get("Authorization"), a.adminToken) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="htun-admin"`)
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "Invalid admin token"})
		return
	}
	switch {
	case r.URL.Path == "/api/clients" && r.Method == http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]any{"clients": a.registry.List()})
	case r.URL.Path == "/api/clients" && r.Method == http.MethodPost:
		var input clientInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		client, token, err := a.registry.Create(input.Name, input.MaxDevices)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusCreated, map[string]any{"client": client, "token": token})
	default:
		a.serveClientAction(w, r)
	}
}

func (a *adminAPI) serveClientAction(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/clients/"), "/")
	if len(parts) == 0 || parts[0] == "" {
		http.NotFound(w, r)
		return
	}
	clientID, err := url.PathUnescape(parts[0])
	if err != nil {
		http.NotFound(w, r)
		return
	}
	switch {
	case len(parts) == 1 && r.Method == http.MethodPut:
		var input clientInput
		if err := decodeJSON(r, &input); err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		enabled := true
		if input.Enabled != nil {
			enabled = *input.Enabled
		}
		client, err := a.registry.Update(clientID, input.Name, input.MaxDevices, enabled)
		a.writeMutation(w, client, err)
	case len(parts) == 1 && r.Method == http.MethodDelete:
		if err := a.registry.Delete(clientID); err != nil {
			a.writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	case len(parts) == 2 && parts[1] == "token" && r.Method == http.MethodPost:
		token, err := a.registry.RotateToken(clientID)
		if err != nil {
			a.writeError(w, err)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"token": token})
	case len(parts) == 3 && parts[1] == "devices" && r.Method == http.MethodDelete:
		deviceID, err := url.PathUnescape(parts[2])
		if err != nil {
			http.NotFound(w, r)
			return
		}
		if err := a.registry.DeleteDevice(clientID, deviceID); err != nil {
			a.writeError(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func (a *adminAPI) writeMutation(w http.ResponseWriter, client clientSummary, err error) {
	if err != nil {
		a.writeError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"client": client})
}

func (a *adminAPI) writeError(w http.ResponseWriter, err error) {
	if errors.Is(err, os.ErrNotExist) {
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "Client or device not found"})
		return
	}
	writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
}

func decodeJSON(r *http.Request, target any) error {
	body := io.LimitReader(r.Body, 16<<10)
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return errors.New("Invalid request body")
	}
	if err := decoder.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		return errors.New("Invalid request body")
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func adminAuthorized(header, expected string) bool {
	const prefix = "Bearer "
	if !strings.HasPrefix(header, prefix) || expected == "" {
		return false
	}
	provided := strings.TrimPrefix(header, prefix)
	return subtle.ConstantTimeCompare([]byte(provided), []byte(expected)) == 1
}

func setAdminSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Referrer-Policy", "no-referrer")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
}

var adminHTML = `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>hTun Control</title>
  <style>
    :root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,sans-serif;--bg:#070b14;--panel:#0e1525;--soft:#151e31;--line:#24304a;--text:#f5f7ff;--muted:#8f9bb3;--accent:#8b7cff;--cyan:#48d7e8;--danger:#ff6b81}
    *{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(circle at 20% 0,#1d1a4b 0,transparent 36%),radial-gradient(circle at 90% 20%,#0d4150 0,transparent 30%),var(--bg);color:var(--text)}
    button,input{font:inherit}button{cursor:pointer}.shell{width:min(1180px,calc(100% - 32px));margin:auto;padding:32px 0 64px}.topbar{display:flex;align-items:center;justify-content:space-between;margin-bottom:42px}.brand{display:flex;align-items:center;gap:12px;font-weight:750;letter-spacing:-.02em}.mark{display:grid;place-items:center;width:38px;height:38px;border-radius:12px;background:linear-gradient(135deg,var(--accent),var(--cyan));box-shadow:0 10px 30px #7d70ff55}.badge{padding:7px 11px;border:1px solid var(--line);border-radius:999px;color:var(--muted);font-size:12px}
    .hero{display:grid;grid-template-columns:1fr auto;gap:28px;align-items:end;margin-bottom:28px}.eyebrow{color:var(--cyan);font-size:12px;font-weight:800;letter-spacing:.16em;text-transform:uppercase}.hero h1{font-size:clamp(38px,7vw,68px);line-height:1;margin:10px 0 14px;letter-spacing:-.055em}.hero p{max-width:650px;margin:0;color:var(--muted);font-size:17px;line-height:1.65}.primary{border:0;border-radius:13px;padding:13px 18px;background:linear-gradient(135deg,var(--accent),#6b8cff);color:white;font-weight:750;box-shadow:0 12px 35px #756dff44}.secondary,.danger{border:1px solid var(--line);border-radius:10px;padding:9px 12px;background:#10192a;color:var(--text)}.danger{color:#ff9cab;border-color:#593044}
    .stats{display:grid;grid-template-columns:repeat(3,1fr);gap:14px;margin-bottom:24px}.stat{padding:20px;border:1px solid var(--line);border-radius:18px;background:#0d1422cc;backdrop-filter:blur(18px)}.stat span{display:block;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.12em}.stat strong{display:block;margin-top:8px;font-size:28px}
    .grid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:16px}.card{border:1px solid var(--line);border-radius:20px;background:linear-gradient(145deg,#111a2b,#0b111e);padding:22px;box-shadow:0 18px 50px #0005}.card-head{display:flex;justify-content:space-between;gap:16px}.card h2{margin:0;font-size:20px;letter-spacing:-.025em}.meta{margin-top:6px;color:var(--muted);font-size:13px}.status{width:9px;height:9px;border-radius:50%;background:#38d99a;box-shadow:0 0 18px #38d99a}.status.off{background:#70809d;box-shadow:none}.devices{margin:20px 0 16px;border-top:1px solid var(--line)}.device{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:12px 0;border-bottom:1px solid #1c263a}.device-name{font-size:13px;font-weight:650}.device-time{color:var(--muted);font-size:11px;margin-top:3px}.icon{border:0;background:transparent;color:var(--muted);font-size:18px}.actions{display:flex;gap:8px;flex-wrap:wrap}.empty{grid-column:1/-1;padding:70px 24px;text-align:center;border:1px dashed var(--line);border-radius:22px;color:var(--muted)}
    dialog{width:min(480px,calc(100% - 28px));border:1px solid var(--line);border-radius:22px;background:#0e1626;color:var(--text);padding:0;box-shadow:0 30px 100px #000b}dialog::backdrop{background:#02050bba;backdrop-filter:blur(7px)}.modal{padding:26px}.modal h2{margin:0 0 8px}.modal p{color:var(--muted);line-height:1.55}.field{display:grid;gap:7px;margin:17px 0}.field label{font-size:12px;color:var(--muted);font-weight:700}.field input{width:100%;border:1px solid var(--line);border-radius:12px;background:#090f1c;color:var(--text);padding:12px 13px;outline:none}.field input:focus{border-color:var(--accent);box-shadow:0 0 0 3px #8b7cff22}.modal-actions{display:flex;justify-content:flex-end;gap:9px;margin-top:22px}.token{padding:14px;border:1px solid #395066;border-radius:12px;background:#07111c;color:#8de9f4;word-break:break-all;font-family:ui-monospace,monospace}.notice{position:fixed;right:20px;bottom:20px;max-width:360px;padding:13px 16px;border:1px solid var(--line);border-radius:12px;background:#131d30;box-shadow:0 15px 50px #0008;display:none}.notice.show{display:block}
    .login{max-width:470px;margin:12vh auto;padding:34px;border:1px solid var(--line);border-radius:24px;background:#0d1525dd;box-shadow:0 30px 100px #0008}.login h1{font-size:34px;margin:18px 0 8px;letter-spacing:-.04em}.login p{color:var(--muted);line-height:1.6}.hidden{display:none!important}
    @media(max-width:760px){.shell{width:min(100% - 22px,1180px);padding-top:20px}.hero{grid-template-columns:1fr}.hero .primary{width:100%}.stats{grid-template-columns:1fr}.grid{grid-template-columns:1fr}.topbar{margin-bottom:28px}}
  </style>
</head>
<body>
  <section id="login" class="login">
    <div class="mark">H</div><h1>Gateway control</h1>
    <p>Enter the admin token from the server to manage client access. It stays only in this browser tab.</p>
    <div class="field"><label>ADMIN TOKEN</label><input id="admin-token" type="password" autocomplete="current-password" placeholder="Paste token"></div>
    <button class="primary" style="width:100%" onclick="login()">Continue</button>
  </section>
  <main id="app" class="shell hidden">
    <header class="topbar"><div class="brand"><div class="mark">H</div>hTun Control</div><div class="badge">Loopback admin</div></header>
    <section class="hero"><div><div class="eyebrow">Access management</div><h1>Clients, without complexity.</h1><p>Create one secure token per client, set how many devices it may enroll, and control future access without restarting the gateway.</p></div><button class="primary" onclick="openCreate()">New client</button></section>
    <section class="stats"><div class="stat"><span>Clients</span><strong id="client-count">0</strong></div><div class="stat"><span>Enabled</span><strong id="enabled-count">0</strong></div><div class="stat"><span>Devices</span><strong id="device-count">0</strong></div></section>
    <section id="clients" class="grid"></section>
  </main>
  <dialog id="client-dialog"><form class="modal" onsubmit="saveClient(event)"><h2 id="dialog-title">New client</h2><p>Tokens can be shared only with devices that belong to this client.</p><input id="edit-id" type="hidden"><div class="field"><label>CLIENT NAME</label><input id="client-name" maxlength="80" required placeholder="Design team"></div><div class="field"><label>DEVICE LIMIT</label><input id="device-limit" type="number" min="1" max="100" value="5" required></div><div class="modal-actions"><button class="secondary" type="button" onclick="closeDialog()">Cancel</button><button class="primary" type="submit">Save client</button></div></form></dialog>
  <dialog id="token-dialog"><div class="modal"><h2>Copy this token now</h2><p>For security, it cannot be displayed again. Rotating it immediately invalidates the previous token.</p><div id="token-value" class="token"></div><div class="modal-actions"><button class="secondary" onclick="copyToken()">Copy token</button><button class="primary" onclick="document.getElementById('token-dialog').close()">Done</button></div></div></dialog>
  <div id="notice" class="notice"></div>
  <script>
    let token=sessionStorage.getItem('htun-admin-token')||'',clients=[];
    const esc=s=>String(s).replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
    const api=async(path,options={})=>{const r=await fetch(path,{...options,headers:{'Authorization':'Bearer '+token,'Content-Type':'application/json',...(options.headers||{})}});if(r.status===204)return null;const body=await r.json().catch(()=>({error:'Request failed'}));if(!r.ok)throw new Error(body.error||'Request failed');return body};
    async function login(){const entered=document.getElementById('admin-token').value.trim();if(entered)token=entered;if(!token){show('Enter the admin token');return}try{await load();sessionStorage.setItem('htun-admin-token',token);document.getElementById('login').classList.add('hidden');document.getElementById('app').classList.remove('hidden')}catch(e){sessionStorage.removeItem('htun-admin-token');show(e.message)}}
    async function load(){const data=await api('/api/clients');clients=data.clients;render()}
    function render(){document.getElementById('client-count').textContent=clients.length;document.getElementById('enabled-count').textContent=clients.filter(c=>c.enabled).length;document.getElementById('device-count').textContent=clients.reduce((n,c)=>n+c.device_count,0);const root=document.getElementById('clients');if(!clients.length){root.innerHTML='<div class="empty">No clients yet. Create the first access token.</div>';return}root.innerHTML=clients.map(c=>'<article class="card"><div class="card-head"><div><h2>'+esc(c.name)+'</h2><div class="meta">'+c.device_count+' of '+c.max_devices+' devices · '+(c.enabled?'Access enabled':'Access disabled')+'</div></div><span class="status '+(c.enabled?'':'off')+'"></span></div><div class="devices">'+(c.devices.length?c.devices.map(d=>'<div class="device"><div><div class="device-name">'+esc(d.id)+'</div><div class="device-time">Last seen '+new Date(d.last_seen).toLocaleString()+'</div></div><button class="icon" title="Forget enrollment" data-action="device" data-client="'+c.id+'" data-device="'+encodeURIComponent(d.id)+'">×</button></div>').join(''):'<div class="device"><div class="device-time">No enrolled devices</div></div>')+'</div><div class="actions"><button class="secondary" data-action="edit" data-client="'+c.id+'">Edit</button><button class="secondary" data-action="rotate" data-client="'+c.id+'">Rotate token</button><button class="secondary" data-action="toggle" data-client="'+c.id+'">'+(c.enabled?'Disable':'Enable')+'</button><button class="danger" data-action="delete" data-client="'+c.id+'">Delete</button></div></article>').join('')}
    function openCreate(){document.getElementById('edit-id').value='';document.getElementById('dialog-title').textContent='New client';document.getElementById('client-name').value='';document.getElementById('device-limit').value='5';document.getElementById('client-dialog').showModal()}
    function openEdit(id){const c=clients.find(x=>x.id===id);document.getElementById('edit-id').value=id;document.getElementById('dialog-title').textContent='Edit client';document.getElementById('client-name').value=c.name;document.getElementById('device-limit').value=c.max_devices;document.getElementById('client-dialog').showModal()}
    function closeDialog(){document.getElementById('client-dialog').close()}
    async function saveClient(e){e.preventDefault();const id=document.getElementById('edit-id').value,name=document.getElementById('client-name').value,max_devices=Number(document.getElementById('device-limit').value);try{if(id){const c=clients.find(x=>x.id===id);await api('/api/clients/'+id,{method:'PUT',body:JSON.stringify({name,max_devices,enabled:c.enabled})})}else{const result=await api('/api/clients',{method:'POST',body:JSON.stringify({name,max_devices})});showToken(result.token)}closeDialog();await load()}catch(e){show(e.message)}}
    async function toggle(id){const c=clients.find(x=>x.id===id);try{await api('/api/clients/'+id,{method:'PUT',body:JSON.stringify({name:c.name,max_devices:c.max_devices,enabled:!c.enabled})});await load()}catch(e){show(e.message)}}
    async function rotate(id){if(!confirm('Rotate this token? Existing devices will need the new token on their next connection.'))return;try{const r=await api('/api/clients/'+id+'/token',{method:'POST'});showToken(r.token)}catch(e){show(e.message)}}
    async function removeClient(id){if(!confirm('Delete this client and revoke future connections?'))return;try{await api('/api/clients/'+id,{method:'DELETE'});await load()}catch(e){show(e.message)}}
    async function removeDevice(client,id){try{await api('/api/clients/'+client+'/devices/'+id,{method:'DELETE'});await load()}catch(e){show(e.message)}}
    function showToken(value){document.getElementById('token-value').textContent=value;document.getElementById('token-dialog').showModal()}
    async function copyToken(){await navigator.clipboard.writeText(document.getElementById('token-value').textContent);show('Token copied')}
    function show(message){const n=document.getElementById('notice');n.textContent=message;n.classList.add('show');setTimeout(()=>n.classList.remove('show'),3200)}
    document.getElementById('clients').addEventListener('click',e=>{const b=e.target.closest('button[data-action]');if(!b)return;const id=b.dataset.client;({edit:()=>openEdit(id),rotate:()=>rotate(id),toggle:()=>toggle(id),delete:()=>removeClient(id),device:()=>removeDevice(id,b.dataset.device)}[b.dataset.action]||(()=>{}))()});
    if(token)login();
  </script>
</body>
</html>`
