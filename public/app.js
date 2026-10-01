const $=id=>document.getElementById(id);
let model=null,selectedHost=null,page='overview',auth=null,pendingConfirmation=null,busy=false;
const esc=v=>String(v??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const when=t=>t?new Date(t).toLocaleString(): 'Not checked yet';
const time=t=>new Date(t).toLocaleTimeString([],{hour:'2-digit',minute:'2-digit'});
async function api(path,data) {
  const response=await fetch('/api'+path,{method:data===undefined?'GET':'POST',headers:{'Content-Type':'application/json','X-Mainframe-Request':'1'},body:data===undefined?undefined:JSON.stringify(data)});
  const result=await response.json();
  if(!response.ok){if(response.status===401){auth.authenticated=false;renderAuth();}throw new Error(result.error??'Request failed.');}return result;
}
function notice(message){$('notice').textContent=message;$('notice').hidden=!message;}
function host(){return model.hosts.find(h=>h.id===selectedHost);}
function currentServices(){return model.services.filter(s=>s.hostId===selectedHost);}
function showPage(next){page=next;for(const p of ['overview','settings','incidents'])$(p).hidden=p!==next;document.querySelectorAll('[data-page]').forEach(b=>b.classList.toggle('active',b.dataset.page===next));}
function renderAuth(){ $('auth').hidden=auth.authenticated;$('workspace').hidden=!auth.authenticated;$('logout').hidden=!auth.authenticated||auth.demo;$('demo-label').hidden=!auth.demo;$('auth-title').textContent=auth.setupRequired?'Set thy dashboard password':'Sign in';$('auth-description').textContent=auth.setupRequired?'Choose a password of at least 12 characters to protect this dashboard.':'Enter thy dashboard password.';$('auth-submit').textContent=auth.setupRequired?'Create dashboard password':'Sign in'; }
function incidentHTML(i){return `<div class="incident-body"><div class="incident-title">${esc(i.name)} / <span class="${i.resolved?'green':'amber'}">${i.resolved?'Resolved':'Open'}</span><small>${esc(when(i.started))}</small></div><div class="timeline">${i.events.slice(-8).map(e=>`<div><time>${esc(time(e.time))}</time>${esc(e.text)}</div>`).join('')}</div></div>`;}
function render(){
  if(!model)return;
  if(!model.hosts.some(h=>h.id===selectedHost))selectedHost=model.hosts[0]?.id;
  $('host-selector').innerHTML=model.hosts.map(h=>`<option value="${esc(h.id)}" ${h.id===selectedHost?'selected':''}>${esc(h.name)}</option>`).join('');
  const h=host();
  $('host-name').textContent=h?.name??'No PCs configured';$('ssh-status').textContent=h?.ssh??'unconfigured';$('docker-status').textContent=h?.docker??'unknown';
  $('ssh-status').className=h?.ssh==='connected'?'green':'amber';$('docker-status').className=h?.docker==='running'?'green':'amber';
  $('host-os').textContent=h?`OS  ${h.os==='windows'?'Windows':'Linux'}`:'';$('host-address').textContent=h?`SSH  ${h.address}:${h.port}`:'';$('host-time').textContent=when(h?.lastChecked);
  $('host-detail').textContent=h?.detail??(!h?.enabled?'Configure this PC in Settings to begin monitoring.':'');$('docker-alert').hidden=h?.docker!=='offline';
  $('check-host').disabled=model.demo||!h;$('edit-host').disabled=model.demo||!h;$('trust-host').disabled=model.demo||!h;$('discover-host').disabled=model.demo||!h?.hasPassword||!h?.fingerprint;
  $('service-rows').innerHTML=currentServices().map(s=>{
    const label={online:'Online',offline:'Offline',unknown:'Unknown',recovering:'Recovering',stopped:'Manually stopped'}[s.status]??'Unknown';
    return `<tr><td>${esc(s.name)}</td><td><span class="status ${esc(s.status)}" title="${esc(s.detail)}"><span class="dot"></span>${label}</span></td><td>${s.uptime===null?'—':esc(s.uptime)+'%'}<span class="coverage">${esc(s.coverage)}% observed</span></td><td><div class="history" aria-label="24 hour availability history">${s.buckets.map(b=>`<i class="${esc(b)}" title="${esc(b)}"></i>`).join('')}</div></td><td class="${s.approvalRequired?'amber':''}">${s.desired==='stopped'?'Paused':s.approvalRequired?'Approval required':s.autoRecover?'On':'Off'}</td><td><button data-action="${s.desired==='stopped'?'start':'stop'}" data-id="${s.id}" ${model.demo||!s.target?'disabled':''}>${s.desired==='stopped'?'Start':'Stop'}</button><button data-action="restart" data-id="${s.id}" ${model.demo||!s.target?'disabled':''}>Restart</button></td></tr>`;
  }).join('')||'<tr><td colspan="6" class="empty">Add a service to this PC to begin.</td></tr>';
  const incidents=model.incidents.filter(i=>i.hostId===selectedHost);$('incident-count').textContent=incidents.filter(i=>!i.resolved).length||'';
  $('recent-incident').innerHTML=incidents[0]?incidentHTML(incidents[0]):'<div class="empty">No incidents recorded. Failures and repair attempts will appear here.</div>';
  $('incident-list').innerHTML=incidents.map(i=>`<section class="panel">${incidentHTML(i)}</section>`).join('')||'<section class="panel empty">No incidents recorded for this PC.</section>';
  $('settings-host-name').textContent=h?.name??'Add thy first PC';$('settings-host-info').textContent=h?`${h.address}:${h.port} · ${h.os} · ${h.enabled?'Monitoring enabled':'Monitoring paused'}`:'';
  $('settings-trust').textContent=h?.fingerprint?`Trusted SSH identity: ${h.fingerprint}`:'SSH identity has not been verified.';
  $('settings-services').innerHTML=currentServices().map(s=>`<section class="panel setting-service"><div><strong>${esc(s.name)}</strong><p class="muted">${esc(s.target||'Target not configured')} · ${s.kind==='container'?'Docker container':'Windows service'} · ${esc(s.checkType)} check</p><p class="muted">${esc(s.detail)}</p></div><button data-edit-service="${s.id}">Configure</button></section>`).join('');
  $('footer-mode').textContent=model.demo?'Concept preview · sample data':'mainframe-dashboard · checks every 30 seconds';
  for(const id of ['add-host','add-service','settings-add-service'])$(id).disabled=model.demo||(id!=='add-host'&&!h);
  showPage(page);
}
async function refresh(){if(busy||!auth?.authenticated)return;try{model=await api('/state');render();}catch(e){notice(e.message);}}
function fill(form,values){form.reset();for(const [key,value] of Object.entries(values)){const field=form.elements.namedItem(key);if(!field)continue;if(field.type==='checkbox')field.checked=!!value;else if(field.multiple){for(const option of field.options)option.selected=(value??[]).includes(option.value);}else field.value=value??'';}form.querySelector('.form-error')?.replaceChildren();}
function openHost(h){fill($('host-form'),h?{...h,password:''}:{os:'windows',port:22,enabled:true});$('host-dialog-title').textContent=h?'Edit PC':'Add PC';$('delete-host').hidden=!h;$('host-dialog').showModal();}
function showCheckFields(){const type=$('service-form').elements.checkType.value;document.querySelectorAll('[data-http]').forEach(el=>el.hidden=type!=='http');document.querySelectorAll('[data-tcp]').forEach(el=>el.hidden=type!=='tcp');}
function openService(s){
  const form=$('service-form');form.elements.dependsOn.innerHTML=currentServices().filter(d=>d.id!==s?.id).map(d=>`<option value="${d.id}">${esc(d.name)}</option>`).join('');
  fill(form,s??{hostId:selectedHost,kind:'container',checkType:'none',failureThreshold:3,maxAttempts:3,cooldownSeconds:120,autoRecover:false});
  $('service-dialog-title').textContent=s?.id?'Configure service':'Add service';$('delete-service').hidden=!s?.id;showCheckFields();$('service-dialog').showModal();
}
function confirmAction(title,description,callback){pendingConfirmation=callback;$('confirm-title').textContent=title;$('confirm-description').textContent=description;$('confirm-form').querySelector('.form-error').textContent='';$('confirm-dialog').showModal();}
async function runForm(form,callback){const submit=form.querySelector('[type="submit"]');submit.disabled=true;busy=true;form.querySelector('.form-error')?.replaceChildren();try{await callback();notice('');}catch(e){const error=form.querySelector('.form-error');if(error)error.textContent=e.message;else notice(e.message);}finally{submit.disabled=false;busy=false;await refresh();}}
document.querySelectorAll('[data-page]').forEach(b=>b.addEventListener('click',()=>showPage(b.dataset.page)));
document.querySelectorAll('[data-close]').forEach(b=>b.addEventListener('click',()=>$(b.dataset.close).close()));
$('settings-shortcut').onclick=()=>showPage('settings');
$('host-selector').onchange=e=>{selectedHost=e.target.value;$('discovery').hidden=true;render();};
$('add-host').onclick=()=>openHost();$('edit-host').onclick=()=>openHost(host());
for(const id of ['add-service','settings-add-service'])$(id).onclick=()=>openService();
$('service-form').elements.checkType.onchange=showCheckFields;
$('auth-form').onsubmit=async e=>{e.preventDefault();await runForm(e.target,async()=>{await api(auth.setupRequired?'/setup':'/login',{password:e.target.elements.password.value});e.target.reset();auth=await api('/auth');renderAuth();});};
$('logout').onclick=async()=>{try{await api('/logout',{});auth=await api('/auth');renderAuth();}catch(e){notice(e.message);}};
$('host-form').onsubmit=async e=>{e.preventDefault();await runForm(e.target,async()=>{const b=Object.fromEntries(new FormData(e.target));b.port=Number(b.port);b.enabled=e.target.elements.enabled.checked;const h=await api('/hosts',b);selectedHost=h.id;$('host-dialog').close();showPage('settings');});};
$('service-form').onsubmit=async e=>{e.preventDefault();await runForm(e.target,async()=>{const b=Object.fromEntries(new FormData(e.target));for(const key of ['checkPort','failureThreshold','maxAttempts','cooldownSeconds'])b[key]=Number(b[key]);for(const key of ['autoRecover','approvalRequired'])b[key]=e.target.elements[key].checked;b.dependsOn=Array.from(e.target.elements.dependsOn.selectedOptions).map(o=>o.value);await api('/services',b);$('service-dialog').close();});};
$('settings-services').onclick=e=>{const b=e.target.closest('[data-edit-service]');if(b&&!model.demo)openService(model.services.find(s=>s.id===b.dataset.editService));};
$('service-rows').onclick=e=>{const b=e.target.closest('[data-action]');if(!b||model.demo)return;const s=model.services.find(s=>s.id===b.dataset.id),action=b.dataset.action;confirmAction(`${action[0].toUpperCase()+action.slice(1)} ${s.name}?`,action==='stop'?'This issues a stop command and keeps automatic recovery paused until thou choosest Start.':`This ${action}s only the configured target on ${host().name}. Recovery is then enabled according to its settings.`,async()=>api(`/services/${s.id}/${action}`,{confirm:true}));};
$('confirm-form').onsubmit=async e=>{e.preventDefault();await runForm(e.target,async()=>{await pendingConfirmation();$('confirm-dialog').close();});};
$('restart-docker').onclick=()=>{const h=host();confirmAction('Approve Docker Desktop restart?',`This may interrupt every container on ${h.name}. Approval applies to this single restart only. Mainframe will verify Docker afterward.`,async()=>api(`/hosts/${h.id}/restart-docker`,{approve:true}));};
$('check-host').onclick=async()=>{busy=true;$('check-host').disabled=true;try{await api(`/hosts/${selectedHost}/check`,{});notice('');}catch(e){notice(e.message);}finally{busy=false;await refresh();}};
$('trust-host').onclick=async()=>{const h=host();busy=true;$('trust-host').disabled=true;try{const result=await api(`/hosts/${h.id}/probe`,{});confirmAction('Verify SSH server identity',`Compare this fingerprint with the SSH server on ${h.name} before trusting it:\n\n${result.fingerprint}\n\nThis verifies the computer's identity; thy login still uses username and password.`,async()=>api(`/hosts/${h.id}/trust`,{challenge:result.challenge}));}catch(e){notice(e.message);}finally{busy=false;await refresh();}};
$('discover-host').onclick=async()=>{busy=true;$('discover-host').disabled=true;try{const snapshot=await api(`/hosts/${selectedHost}/discover`,{});$('discovery').innerHTML=`<h3>Docker containers ${snapshot.docker?'':'— Docker unavailable'}</h3>${snapshot.containers.map(c=>`<div class="discovered"><code>${esc(c.target)}</code><span class="muted">${c.running?'Running':'Stopped'}</span><button data-import-target="${esc(c.target)}" data-kind="container">Add</button></div>`).join('')||'<p class="muted">No containers found.</p>'}<h3>Windows services</h3>${snapshot.services.map(c=>`<div class="discovered"><code>${esc(c.target)}</code><span class="muted">${esc(c.displayName)}</span><button data-import-target="${esc(c.target)}" data-kind="service">Add</button></div>`).join('')||'<p class="muted">No Windows services available.</p>'}`;$('target-names').innerHTML=[...snapshot.containers,...snapshot.services].map(c=>`<option value="${esc(c.target)}"></option>`).join('');$('discovery').hidden=false;notice('');}catch(e){notice(e.message);}finally{busy=false;await refresh();}};
$('discovery').onclick=e=>{const b=e.target.closest('[data-import-target]');if(b)openService({name:b.dataset.importTarget,target:b.dataset.importTarget,kind:b.dataset.kind,hostId:selectedHost,checkType:'none',failureThreshold:3,maxAttempts:3,cooldownSeconds:120,approvalRequired:/tailscale/i.test(b.dataset.importTarget)});};
$('delete-service').onclick=()=>{const id=$('service-form').elements.id.value;$('service-dialog').close();confirmAction('Remove this service?','This removes monitoring configuration. It does not stop or delete the remote program.',async()=>api(`/services/${id}/delete`,{}));};
$('delete-host').onclick=()=>{const id=$('host-form').elements.id.value;$('host-dialog').close();confirmAction('Remove this PC?','This removes its credentials and service configurations. Remote programs remain unchanged.',async()=>api(`/hosts/${id}/delete`,{}));};
$('password-form').onsubmit=async e=>{e.preventDefault();await runForm(e.target,async()=>{await api('/password',Object.fromEntries(new FormData(e.target)));e.target.reset();});};
try{auth=await api('/auth');renderAuth();await refresh();}catch(e){notice(e.message);}
setInterval(refresh,5000);
