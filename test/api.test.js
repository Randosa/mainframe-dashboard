import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtempSync,rmSync,readFileSync } from 'node:fs';
import { resolve,join } from 'node:path';
import net from 'node:net';

async function freePort(){const s=net.createServer();await new Promise(r=>s.listen(0,'127.0.0.1',r));const port=s.address().port;await new Promise(r=>s.close(r));return port;}
async function start(dir,port,demo=false){
  const child=spawn(process.execPath,['src/server.js',...(demo?['--demo']:[])],{env:{...process.env,HOST:'127.0.0.1',PORT:String(port),DATA_DIR:dir,KEY_FILE:join(dir,'key.bin')},stdio:['ignore','pipe','pipe']});
  await new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Server startup timed out')),10000);child.once('exit',()=>{clearTimeout(timer);reject(new Error('Server exited'));});child.stdout.on('data',chunk=>{if(chunk.toString().includes('listening')){clearTimeout(timer);resolve();}});});return child;
}
async function stop(child){const exited=new Promise(r=>child.once('exit',r));child.kill();await exited;}
test('API authentication, multi-PC configuration, encryption, CSRF, dependency validation and persistence',async t=>{
  const dir=mkdtempSync(resolve('test-output-api-')),port=await freePort();let child=await start(dir,port),cookie='';
  t.after(async()=>{if(child.exitCode===null)await stop(child);rmSync(dir,{recursive:true,force:true});});
  const base=`http://127.0.0.1:${port}`;
  const call=async(path,data,extra={})=>{const response=await fetch(base+path,{method:data===undefined?'GET':'POST',headers:{'Content-Type':'application/json','X-Mainframe-Request':'1',Cookie:cookie,...extra},body:data===undefined?undefined:JSON.stringify(data)});const next=response.headers.get('set-cookie');if(next)cookie=next.split(';')[0];return {status:response.status,data:await response.json()};};
  assert.equal((await call('/api/state')).status,401);
  assert.equal((await call('/api/setup',{password:'test-dashboard-password'},{'X-Mainframe-Request':''})).status,400);
  assert.equal((await call('/api/setup',{password:'test-dashboard-password'},{Origin:'http://evil.example'})).status,400);
  assert.equal((await call('/api/setup',{password:'test-dashboard-password'})).status,200);
  const original=(await call('/api/state')).data;assert.equal(original.hosts.length,1);assert.equal(original.services.length,7);
  let h=(await call('/api/hosts',{name:'Second PC',address:'127.0.0.1',port:22,username:'operator',os:'windows',enabled:false,password:'fake-only-ssh-password'})).data;
  assert(h.hasPassword);assert.equal(h.password,undefined);
  const config={hostId:h.id,name:'Caddy',target:'caddy',kind:'container',checkType:'none',autoRecover:true,approvalRequired:false,failureThreshold:3,maxAttempts:3,cooldownSeconds:120,dependsOn:[]};
  const saved=(await call('/api/services',config)).data;assert(saved.id);
  assert.equal((await call('/api/services',{...config,target:'$(bad)'})).status,400);
  const second=(await call('/api/services',{...config,name:'Dependent',target:'dependent',dependsOn:[saved.id]})).data;
  assert.equal((await call('/api/services',{...config,id:saved.id,dependsOn:[second.id]})).status,400);
  assert.equal((await call('/api/hosts',{...h,name:'Renamed PC',password:''})).status,200);
  const updated=(await call('/api/state')).data;assert.equal(updated.services.filter(s=>s.hostId===h.id).length,2);assert.equal(updated.hosts.find(host=>host.id===h.id).name,'Renamed PC');
  assert.equal((await call(`/api/hosts/${h.id}/restart-docker`,{})).status,400);
  assert.equal((await call(`/api/services/${saved.id}/stop`,{})).status,400);
  const failedStop=await call(`/api/services/${saved.id}/stop`,{confirm:true});assert.equal(failedStop.status,400);
  assert.equal((await call('/api/state')).data.services.find(s=>s.id===saved.id).desired,'stopped');
  assert(!readFileSync(join(dir,'mainframe.sqlite')).includes(Buffer.from('fake-only-ssh-password')));
  assert.equal((await fetch(base+'/styles.css')).status,200);
  // Read CSS as text; all bundled WebTUI modules must be present in deployment.
  for(const path of ['base.css','utils/box.css','components/button.css','components/dialog.css'])assert.equal((await fetch(base+'/webtui/'+path)).status,200);
  await stop(child);child=await start(dir,port);cookie='';assert.equal((await call('/api/state')).status,401);assert.equal((await call('/api/login',{password:'test-dashboard-password'})).status,200);
  const restarted=(await call('/api/state')).data;assert.equal(restarted.hosts.length,2);assert.equal(restarted.services.find(s=>s.id===saved.id).desired,'stopped');
  assert.equal((await call(`/api/services/${saved.id}/delete`,{})).status,400);
  assert.equal((await call('/api/logout',{})).status,200);assert.equal((await call('/api/state')).status,401);
});
test('preview mode refuses writes even without authentication',async t=>{
  const dir=mkdtempSync(resolve('test-output-preview-')),port=await freePort(),child=await start(dir,port,true);
  t.after(async()=>{await stop(child);rmSync(dir,{recursive:true,force:true});});
  const base=`http://127.0.0.1:${port}`,response=await fetch(base+'/api/state');assert((await response.json()).demo);
  for(const path of ['/api/hosts','/api/services','/api/setup']){const r=await fetch(base+path,{method:'POST',headers:{'Content-Type':'application/json','X-Mainframe-Request':'1'},body:'{}'});assert.equal(r.status,400);assert.match((await r.json()).error,/read-only/);}
});
