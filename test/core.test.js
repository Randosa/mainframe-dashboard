import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, existsSync, unlinkSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { Store, passwordHash, verifyPassword } from '../src/store.js';
import { Monitor } from '../src/monitor.js';
import { actionCommand, validTarget, Remote, fingerprint } from '../src/remote.js';
import { generateKeyPairSync } from 'node:crypto';
import ssh2 from 'ssh2';

function fixture(t) {
  const dir=mkdtempSync(resolve('test-output-')),key=join(dir,'vault.key'),store=new Store(dir,key);
  t.after(()=>{store.close();rmSync(dir,{recursive:true,force:true});});
  const host={id:'pc1',name:'PC',os:'windows',address:'localhost',port:22,username:'operator',password:store.seal('not-a-real-password'),fingerprint:'verified',enabled:true};store.saveHost(host);
  const service={id:'caddy',hostId:host.id,name:'Caddy',target:'caddy',kind:'container',desired:'running',autoRecover:true,approvalRequired:false,failureThreshold:3,maxAttempts:2,cooldownSeconds:120,dependsOn:[],status:'unknown'};store.saveService(service);
  const calls=[];const remote={inspect:async()=>({docker:true,containers:[{target:'caddy',running:true,health:'unhealthy'}],services:[]}),action:async(h,s,a)=>calls.push({host:h.id,service:s.id,action:a})};
  return {dir,key,store,host,service,remote,calls,monitor:new Monitor(store,remote,async()=>true)};
}
test('vault encrypts passwords, authenticates ciphertext, and unlocks with original binary key',t=>{
  const f=fixture(t),sealed=f.store.host('pc1').password;
  assert(!sealed.includes('not-a-real-password'));assert.equal(f.store.unseal(sealed),'not-a-real-password');assert.equal(readFileSync(f.key).length,32);
  const bytes=Buffer.from(sealed,'base64');bytes[30]^=1;assert.throws(()=>f.store.unseal(bytes.toString('base64')));
  const reopened=new Store(f.dir,f.key);assert.equal(reopened.unseal(sealed),'not-a-real-password');reopened.close();
});
test('missing vault key refuses to generate a replacement',t=>{const f=fixture(t);unlinkSync(f.key);assert.throws(()=>new Store(f.dir,f.key),/key missing/);assert(!existsSync(f.key));});
test('dashboard passwords are salted and verified',()=>{const hash=passwordHash('long-test-password');assert(verifyPassword('long-test-password',hash));assert(!verifyPassword('wrong',hash));assert.notEqual(passwordHash('long-test-password').hash,hash.hash);});
test('repair requires repeated failures, has a cooldown, and awaits readiness verification',async t=>{
  const f=fixture(t);await f.monitor.tickHost('pc1');await f.monitor.tickHost('pc1');assert.equal(f.calls.length,0);await f.monitor.tickHost('pc1');assert.equal(f.calls.length,1);assert.equal(f.store.service('caddy').status,'recovering');await f.monitor.tickHost('pc1');assert.equal(f.calls.length,1);
  f.remote.inspect=async()=>({docker:true,containers:[{target:'caddy',running:true,health:'healthy'}],services:[]});await f.monitor.tickHost('pc1');assert.equal(f.store.service('caddy').status,'online');assert(f.store.incidents()[0].resolved);
});
test('repair attempt budget persists and prevents endless restarts',async t=>{
  const f=fixture(t);f.service.failureThreshold=1;f.service.attempts=2;f.store.saveService(f.service);await f.monitor.tickHost('pc1');assert.equal(f.calls.length,0);assert.match(f.store.service('caddy').detail,/limit reached/);
});
test('dashboard Stop persists intent before remote failure and survives a new monitor',async t=>{
  const f=fixture(t);f.remote.action=async()=>{assert.equal(f.store.service('caddy').desired,'stopped');throw new Error('offline');};await assert.rejects(()=>f.monitor.manual('caddy','stop'));
  const m=new Monitor(f.store,f.remote,async()=>true);await m.tickHost('pc1');assert.equal(f.store.service('caddy').status,'stopped');assert.equal(f.store.service('caddy').desired,'stopped');assert.equal(f.calls.length,0);
});
test('SSH loss reports unknown and never attempts service or Docker repair',async t=>{
  const f=fixture(t);f.remote.inspect=async()=>{throw new Error('network');};f.remote.restartDocker=async()=>assert.fail('Docker restart must not occur');await f.monitor.tickHost('pc1');assert.equal(f.store.service('caddy').status,'unknown');assert.equal(f.store.host('pc1').docker,'unknown');assert.equal(f.calls.length,0);
});
test('Docker loss blocks container repair and requests approval',async t=>{const f=fixture(t);f.remote.inspect=async()=>({docker:false,containers:[],services:[]});await f.monitor.tickHost('pc1');assert.equal(f.calls.length,0);assert.match(f.store.service('caddy').detail,/approval/);});
test('approval-required services never recover automatically',async t=>{const f=fixture(t);f.service.approvalRequired=true;f.service.failureThreshold=1;f.store.saveService(f.service);await f.monitor.tickHost('pc1');assert.equal(f.calls.length,0);});
test('dependency checks run before dependants even if configured later',async t=>{
  const f=fixture(t);f.service.failureThreshold=1;f.service.dependsOn=['gateway'];f.store.saveService(f.service);
  f.store.saveService({...f.service,id:'gateway',name:'Gateway',target:'gateway',dependsOn:[]});
  f.remote.inspect=async()=>({docker:true,containers:[{target:'caddy',running:false},{target:'gateway',running:false}],services:[]});
  await f.monitor.tickHost('pc1');assert.deepEqual(f.calls.map(c=>c.service),['gateway']);assert.match(f.store.service('caddy').detail,/dependency/);
});
test('PC recovery and deliberate stops are isolated by host',async t=>{
  const f=fixture(t);f.store.saveHost({...f.host,id:'pc2'});f.store.saveService({...f.service,id:'other',hostId:'pc2',desired:'stopped'});await f.monitor.tickHost('pc2');assert.equal(f.store.service('caddy').status,'unknown');assert.equal(f.store.service('other').status,'stopped');assert.equal(f.calls.length,0);
});
test('uptime is duration-weighted and monitoring gaps are not credited',t=>{
  const f=fixture(t),now=Date.now();f.store.sample(f.service,'online',now-600000);f.store.sample(f.service,'offline',now-60000);
  const h=f.store.history('caddy',now);assert.equal(h.uptime,60);assert(h.coverage<1);assert(h.buckets.includes('unknown'));assert(h.buckets.includes('offline'));
});
test('remote actions are restricted and target names cannot inject shell syntax',()=>{
  for(const target of ["x'; Remove-Item C:\\",'$(evil)','-all','x\ncommand'])assert(!validTarget(target));
  assert.match(actionCommand({os:'linux'},{kind:'container',target:'caddy'},'stop'),/^docker stop -- 'caddy'$/);
  assert.throws(()=>actionCommand({os:'windows'},{kind:'container',target:'caddy'},'delete'));
  const encoded=actionCommand({os:'windows'},{kind:'service',target:'Tailscale'},'restart').split(' ').at(-1);assert.match(Buffer.from(encoded,'base64').toString('utf16le'),/Restart-Service -Name 'Tailscale'/);
});
test('SSH integration verifies host identity and uses password authentication',async t=>{
  const f=fixture(t),{privateKey}=generateKeyPairSync('rsa',{modulusLength:2048,privateKeyEncoding:{type:'pkcs1',format:'pem'},publicKeyEncoding:{type:'pkcs1',format:'pem'}});
  const server=new ssh2.Server({hostKeys:[privateKey]},client=>{
    client.on('error',()=>{}); // Expected when probe or wrong fingerprint refuses the handshake.
    client.on('authentication',ctx=>ctx.method==='password'&&ctx.username==='operator'&&ctx.password==='not-a-real-password'?ctx.accept():ctx.reject());
    client.on('ready',()=>client.on('session',accept=>accept().on('exec',(accept,reject,info)=>{const stream=accept();stream.write('verified');stream.exit(0);stream.end();})));
  });await new Promise(resolve=>server.listen(0,'127.0.0.1',resolve));t.after(()=>server.close());
  const host={...f.host,address:'127.0.0.1',port:server.address().port};const remote=new Remote(f.store);host.fingerprint=await remote.probe(host);assert.match(host.fingerprint,/^SHA256:/);assert.equal(await remote.exec(host,'read-only-check'),'verified');host.fingerprint='SHA256:wrong';await assert.rejects(()=>remote.exec(host,'read-only-check'));
});
