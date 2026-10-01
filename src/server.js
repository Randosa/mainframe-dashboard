import http from 'node:http';
import { readFile, stat } from 'node:fs/promises';
import { resolve, join, extname } from 'node:path';
import { randomUUID, randomBytes, createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { Store, passwordHash, verifyPassword } from './store.js';
import { Remote, validTarget } from './remote.js';
import { Monitor } from './monitor.js';
import { assert, text, address, number, validateHost } from './validation.js';

const root=resolve(fileURLToPath(new URL('..',import.meta.url)));
const demo=process.argv.includes('--demo');
const store=new Store(resolve(process.env.DATA_DIR??join(root,demo?'data/demo':'data')),resolve(process.env.KEY_FILE??join(root,demo?'secrets/demo.key':'secrets/vault.key')));
const remote=new Remote(store), monitor=new Monitor(store,remote);
const sessions=new Map(), challenges=new Map(), attempts=new Map();
const cookieSecure=process.env.COOKIE_SECURE==='true';
const sha=v=>createHash('sha256').update(v).digest('hex');
const safeHost=h=>{const {password,...result}=h;return {...result,hasPassword:!!password};};
if(!store.hosts().length) {
  const host={id:randomUUID(),name:'Windows PC',address:'WINDOWS-PC',port:22,os:'windows',username:'',enabled:false,ssh:'unconfigured',docker:'unknown'};store.saveHost(host);
  for(const name of ['Caddy','Immich','Homepage','Minecraft','Crafty','playit','Tailscale']) store.saveService({id:randomUUID(),hostId:host.id,name,kind:'container',target:'',checkType:'none',dependsOn:[],desired:'running',autoRecover:false,approvalRequired:name==='Tailscale',failureThreshold:3,maxAttempts:3,cooldownSeconds:120,status:'unknown',detail:'Select the actual target in Settings.'});
}
function state() {
  const hosts=store.hosts().map(safeHost),services=store.services().map(s=>({...s,...store.history(s.id)}));
  if(demo){hosts.forEach(h=>{h.ssh='connected';h.docker='running';h.enabled=true;h.lastChecked=Date.now();h.detail='Read-only preview — sample data.';});services.forEach((s,i)=>{s.status='online';s.detail='Preview data';s.autoRecover=true;s.uptime=i===0?99.8:100;s.coverage=100;s.buckets=Array(40).fill('online');if(i===0)s.buckets[35]='offline';});}
  return {demo,hosts,services,incidents:demo?[{id:'demo',hostId:hosts[0]?.id,name:'Caddy',started:Date.now()-600000,resolved:Date.now()-540000,events:[{time:Date.now()-600000,text:'Website checks failed.'},{time:Date.now()-560000,text:'Caddy container restarted.'},{time:Date.now()-540000,text:'Response verified — service restored.'}]}]:store.incidents()};
}
function json(res,status,value) {res.writeHead(status,{'Content-Type':'application/json','Cache-Control':'no-store'});res.end(JSON.stringify(value));}
async function body(req) {let data='';for await(const chunk of req){data+=chunk;assert(data.length<=32768,'Request too large.');}try{return JSON.parse(data||'{}');}catch{assert(false,'Invalid JSON.');}}
function session(req) {const token=(req.headers.cookie??'').split(';').map(v=>v.trim()).find(v=>v.startsWith('mainframe='))?.slice(10);const s=token?sessions.get(sha(token)):null;if(!s||s.expires<Date.now())return null;return s;}
function login(res) {const token=randomBytes(32).toString('base64url');sessions.set(sha(token),{expires:Date.now()+12*3600000});res.setHeader('Set-Cookie',`mainframe=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=43200${cookieSecure?'; Secure':''}`);}
function mutation(req) {assert(req.headers['x-mainframe-request']==='1','Request header missing.');if(req.headers.origin){const origin=new URL(req.headers.origin);assert(origin.host===req.headers.host,'Cross-origin requests are refused.');}}
function rateLimit(req) {const id=req.socket.remoteAddress;const now=Date.now(),recent=(attempts.get(id)??[]).filter(t=>t>now-600000);assert(recent.length<10,'Too many attempts. Wait ten minutes.');recent.push(now);attempts.set(id,recent);}
function hostBy(id){const host=store.host(id);assert(host,'PC not found.');return host;}
const server=http.createServer(async(req,res)=>{
  res.setHeader('Content-Security-Policy',"default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'");
  res.setHeader('X-Content-Type-Options','nosniff');res.setHeader('Referrer-Policy','no-referrer');
  try {
    const url=new URL(req.url,'http://localhost'),path=url.pathname;
    if(path==='/healthz')return json(res,200,{ok:true});
    if(path==='/api/auth'&&req.method==='GET')return json(res,200,{setupRequired:!store.get('admin'),authenticated:demo||!!session(req),demo});
    if(['/api/setup','/api/login'].includes(path)&&req.method==='POST') {
      mutation(req);assert(!demo,'Preview mode is read-only.');rateLimit(req);const b=await body(req);
      assert(typeof b.password==='string'&&b.password.length>=12&&b.password.length<=512,'Use a dashboard password of 12–512 characters.');
      if(path==='/api/setup'){assert(!store.get('admin'),'Dashboard already configured.');store.set('admin',passwordHash(b.password));}
      else assert(verifyPassword(b.password,store.get('admin')),'Incorrect dashboard password.');
      login(res);return json(res,200,{ok:true});
    }
    if(path.startsWith('/api/')) {
      if(!demo&&!session(req))return json(res,401,{error:'Sign in to the dashboard.'});
      if(req.method!=='GET'){mutation(req);assert(!demo,'Preview mode is read-only.');}
      if(path==='/api/state'&&req.method==='GET')return json(res,200,state());
      if(path==='/api/logout'&&req.method==='POST') {const token=(req.headers.cookie??'').match(/(?:^|;\s*)mainframe=([^;]+)/)?.[1];if(token)sessions.delete(sha(token));res.setHeader('Set-Cookie','mainframe=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return json(res,200,{ok:true});}
      const b=req.method==='GET'?{}:await body(req);
      if(path==='/api/hosts'&&req.method==='POST') {
        validateHost(b);const old=b.id?hostBy(b.id):null;
        assert(!old||!monitor.busy.has(old.id),'PC is busy; try again shortly.');
        const host={id:old?.id??randomUUID(),name:b.name.trim(),address:b.address,port:b.port,username:b.username,os:b.os,enabled:b.enabled,password:old?.password,fingerprint:old?.fingerprint,ssh:'unconfigured',docker:'unknown'};
        if(b.password){assert(typeof b.password==='string'&&b.password.length<=512,'Invalid SSH password.');host.password=store.seal(b.password);}
        if(old&&(old.address!==host.address||old.port!==host.port))host.fingerprint=null;
        store.saveHost(host);return json(res,200,safeHost(host));
      }
      const hm=path.match(/^\/api\/hosts\/([^/]+)\/(probe|trust|discover|check|restart-docker|delete)$/);
      if(hm&&req.method==='POST') {
        const host=hostBy(hm[1]),action=hm[2];
        assert(!monitor.busy.has(host.id),'PC is busy; try again shortly.');
        if(action==='probe'){const print=await remote.probe(host),challenge=randomBytes(24).toString('hex');challenges.set(challenge,{id:host.id,address:host.address,port:host.port,print,expires:Date.now()+300000});return json(res,200,{fingerprint:print,challenge});}
        if(action==='trust'){const c=challenges.get(b.challenge);assert(c&&c.id===host.id&&c.address===host.address&&c.port===host.port&&c.expires>Date.now(),'Fingerprint confirmation expired; probe again.');host.fingerprint=c.print;store.saveHost(host);challenges.delete(b.challenge);return json(res,200,{ok:true});}
        if(action==='discover'){const snapshot=await remote.inspect(host);return json(res,200,snapshot);}
        if(action==='check'){await monitor.tickHost(host.id);return json(res,200,{ok:true});}
        if(action==='restart-docker') {
          assert(b.approve===true,'Explicit approval is required for this Docker restart.');monitor.busy.add(host.id);
          try {const item={id:randomUUID(),hostId:host.id,serviceId:'docker:'+host.id,name:'Docker Desktop',started:Date.now(),events:[{time:Date.now(),text:'Docker restart explicitly approved through dashboard.'}]};store.saveIncident(item);try{await remote.restartDocker(host);item.events.push({time:Date.now(),text:'Restart command completed. Check host to verify Docker availability.'});}catch{item.events.push({time:Date.now(),text:'Docker restart failed. Check Desktop version and Windows session permissions.'});store.saveIncident(item);throw new Error('Docker restart failed. Check Desktop version and Windows session permissions.');}store.saveIncident(item);}
          finally{monitor.busy.delete(host.id);}await monitor.tickHost(host.id);if(store.host(host.id).docker==='running'){const i=store.incidents().find(i=>i.serviceId==='docker:'+host.id&&!i.resolved);if(i){i.resolved=Date.now();i.events.push({time:Date.now(),text:'Docker availability verified.'});store.saveIncident(i);}}return json(res,200,{ok:true});
        }
        if(action==='delete'){store.removeHost(host.id);return json(res,200,{ok:true});}
      }
      if(path==='/api/services'&&req.method==='POST') {
        const host=hostBy(b.hostId);assert(!monitor.busy.has(host.id),'PC is busy; try again shortly.');
        assert(text(b.name)&&validTarget(b.target),'Service name and actual target are required.');assert(['container','service'].includes(b.kind),'Select a container or Windows service.');assert(b.kind!=='service'||host.os==='windows','Windows services require a Windows PC.');
        assert(['none','http','tcp'].includes(b.checkType),'Invalid check type.');
        if(b.checkType==='http'){let parsed;try{parsed=new URL(b.url);}catch{}assert(parsed&&['http:','https:'].includes(parsed.protocol)&&!parsed.username&&!parsed.password,'Use an HTTP(S) URL without embedded credentials.');}
        if(b.checkType==='tcp')assert(address(b.checkAddress)&&number(b.checkPort,1,65535),'Valid TCP address and port required.');
        assert(number(b.failureThreshold,1,20)&&number(b.maxAttempts,1,10)&&number(b.cooldownSeconds,30,3600),'Recovery limits are out of range.');
        assert(typeof b.autoRecover==='boolean'&&typeof b.approvalRequired==='boolean','Invalid recovery settings.');
        const old=b.id?store.service(b.id):null;assert(!b.id||old,'Service not found.');assert(!old||old.hostId===host.id,'A service cannot be moved between PCs.');
        const dependsOn=b.dependsOn??[];assert(Array.isArray(dependsOn)&&dependsOn.every(id=>{const d=store.service(id);return d&&d.hostId===host.id&&d.id!==old?.id;}),'Select dependencies on this PC.');
        const visit=(id,seen=new Set())=>{if(id===old?.id)return false;if(seen.has(id))return true;seen.add(id);return (store.service(id)?.dependsOn??[]).every(next=>visit(next,seen));};assert(dependsOn.every(id=>visit(id)),'Dependencies must not form a cycle.');
        const s={id:old?.id??randomUUID(),hostId:host.id,name:b.name.trim(),target:b.target,kind:b.kind,checkType:b.checkType,url:b.url??'',checkAddress:b.checkAddress??'',checkPort:b.checkPort??0,dependsOn,autoRecover:b.autoRecover,approvalRequired:b.approvalRequired,failureThreshold:b.failureThreshold,maxAttempts:b.maxAttempts,cooldownSeconds:b.cooldownSeconds,desired:old?.desired??'running',status:'unknown',detail:'Awaiting check.',failures:0,attempts:0};
        store.saveService(s);return json(res,200,s);
      }
      const sm=path.match(/^\/api\/services\/([^/]+)\/(start|stop|restart|delete)$/);
      if(sm&&req.method==='POST') {
        const s=store.service(sm[1]);assert(s,'Service not found.');assert(!monitor.busy.has(s.hostId),'PC is busy; try again shortly.');
        if(sm[2]==='delete'){assert(!store.services().some(d=>d.dependsOn?.includes(s.id)),'Remove this service from dependencies first.');store.removeService(s.id);}
        else {assert(b.confirm===true,'Confirm this service action.');await monitor.manual(s.id,sm[2]);}return json(res,200,{ok:true});
      }
      if(path==='/api/password'&&req.method==='POST'){assert(typeof b.current==='string'&&verifyPassword(b.current,store.get('admin')),'Current dashboard password is incorrect.');assert(typeof b.password==='string'&&b.password.length>=12&&b.password.length<=512,'Use 12–512 characters.');store.set('admin',passwordHash(b.password));sessions.clear();login(res);return json(res,200,{ok:true});}
      return json(res,404,{error:'Not found.'});
    }
    if(req.method!=='GET')return json(res,405,{error:'Method not allowed.'});
    const files={'/':'public/index.html','/app.js':'public/app.js','/styles.css':'public/styles.css'};
    let file=files[path]?join(root,files[path]):null;
    if(path.startsWith('/webtui/')){const relative=path.slice(8);assert(/^(base\.css|utils\/box\.css|components\/(button|input|typography|table|checkbox|dialog)\.css)$/.test(relative),'Unknown stylesheet.');file=join(root,'node_modules/@webtui/css/dist',relative);}
    if(!file)return json(res,404,{error:'Not found.'});
    await stat(file);res.setHeader('Content-Type',({'.html':'text/html; charset=utf-8','.js':'text/javascript; charset=utf-8','.css':'text/css; charset=utf-8'})[extname(file)]);res.setHeader('Cache-Control','no-cache');res.end(await readFile(file));
  } catch(error) {json(res,error.status??400,{error:error.message??'Request failed.'});}
});
if(!demo)monitor.start();
const cleanup=setInterval(()=>{const now=Date.now();for(const [id,s] of sessions)if(s.expires<now)sessions.delete(id);for(const [id,c] of challenges)if(c.expires<now)challenges.delete(id);for(const [id,t] of attempts)if(!t.some(time=>time>now-600000))attempts.delete(id);},60000);cleanup.unref();
server.listen(Number(process.env.PORT??3000),process.env.HOST??'0.0.0.0',()=>console.log(`MAINFRAME ${demo?'read-only preview':'dashboard'} listening on port ${process.env.PORT??3000}`));
for(const sig of ['SIGINT','SIGTERM'])process.on(sig,()=>{monitor.stop();clearInterval(cleanup);server.close(()=>{store.close();process.exit(0);});});
