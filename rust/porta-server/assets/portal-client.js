(()=>{
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
})();