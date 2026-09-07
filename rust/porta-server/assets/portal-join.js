(()=>{
  const root=document.getElementById('portal-join');
  addEventListener('hashchange',()=>{if(location.hash)location.reload()});
  let fragment=location.hash;
  try{history.replaceState(null,'','/join')}catch{fragment=''}
  if(!root||root.dataset.joinState!=='auto')return;
  function invalid(){
    root.dataset.joinState='error';
    document.getElementById('join-heading').textContent='Link unavailable';
    document.getElementById('join-detail').textContent='This access link is invalid or no longer authorized. Ask your administrator for a new link.';
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
})();