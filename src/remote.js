import ssh2 from 'ssh2';
import { createHash } from 'node:crypto';
import net from 'node:net';
const { Client } = ssh2;
export const fingerprint = key => 'SHA256:'+createHash('sha256').update(key).digest('base64').replace(/=+$/,'');
const targetPattern=/^[A-Za-z0-9][A-Za-z0-9_.@ -]{0,127}$/;
export function validTarget(target) { return typeof target==='string' && targetPattern.test(target); }
function quote(value) { return "'"+value.replaceAll("'","''")+"'"; }
export function ps(script) { return 'powershell.exe -NoLogo -NoProfile -NonInteractive -EncodedCommand '+Buffer.from("$ErrorActionPreference='Stop'; "+script,'utf16le').toString('base64'); }
export function actionCommand(host, service, action) {
  if(!['start','stop','restart'].includes(action)) throw new Error('Invalid action');
  if(!validTarget(service.target)) throw new Error('Invalid target');
  if(service.kind==='container') {
    const cmd=`docker ${action} -- ${quote(service.target)}`;
    return host.os==='windows' ? ps(cmd+`; if ($LASTEXITCODE -ne 0) { exit 1 }`) : cmd;
  }
  if(host.os!=='windows') throw new Error('Windows service actions require a Windows host');
  return ps(`${{start:'Start',stop:'Stop',restart:'Restart'}[action]}-Service -Name ${quote(service.target)}`);
}
export class Remote {
  constructor(store) { this.store=store; }
  probe(host) {
    return new Promise((resolve,reject)=>{
      const c=new Client(); let found;
      c.on('error',()=>found?resolve(found):reject(new Error('SSH host could not be reached. Check address and port.')));
      c.on('close',()=>{if(found) resolve(found);});
      c.connect({host:host.address,port:host.port,username:host.username||'mainframe',readyTimeout:10000,hostVerifier:key=>{found=fingerprint(key); return false;}});
    });
  }
  exec(host, command) {
    if(!host.fingerprint) return Promise.reject(new Error('Trust this host fingerprint first.'));
    return new Promise((resolve,reject)=>{
      const c=new Client(); let done=false, output='';
      const finish=(error,value)=>{if(done)return;done=true;clearTimeout(timer);c.end();error?reject(error):resolve(value);};
      const timer=setTimeout(()=>finish(new Error('SSH command timed out.')),25000);
      c.on('error',()=>finish(new Error('SSH connection failed. Check credentials, connectivity, and trusted fingerprint.')));
      c.on('close',()=>{if(!done) finish(new Error('SSH connection closed before the command completed.'));});
      c.on('ready',()=>c.exec(command,(err,stream)=>{
        if(err) return finish(new Error('Remote command could not start.'));
        stream.on('data',data=>{output+=data.toString();if(output.length>2e6)finish(new Error('Remote response too large.'));});
        // Do not retain stderr: remote messages may contain credentials or private paths.
        stream.stderr.on('data',()=>{});
        stream.on('close',code=>code===0?finish(null,output):finish(new Error('Remote command failed. Check the target and account permissions.')));
      }));
      c.connect({host:host.address,port:host.port,username:host.username,password:this.store.unseal(host.password),authHandler:['password'],hostVerifier:key=>fingerprint(key)===host.fingerprint,readyTimeout:10000,keepaliveInterval:5000});
    });
  }
  async inspect(host) {
    if(host.os==='windows') {
      const script=`$containers=@(); $dockerOk=$false; $info=& docker info --format '{{.ServerVersion}}' 2>$null; if ($LASTEXITCODE -eq 0) { $dockerOk=$true; $ids=@(& docker ps -aq); if ($ids.Count -gt 0) { $raw=& docker inspect @ids; if ($LASTEXITCODE -eq 0) { $containers=@($raw | ConvertFrom-Json | ForEach-Object { @{target=$_.Name.TrimStart('/'); running=$_.State.Running; health=$_.State.Health.Status; exitCode=$_.State.ExitCode} }) } } }; $services=@(Get-Service | ForEach-Object { @{target=$_.Name; displayName=$_.DisplayName; running=($_.Status -eq 'Running')} }); @{docker=$dockerOk; containers=$containers; services=$services} | ConvertTo-Json -Depth 6 -Compress`;
      return JSON.parse((await this.exec(host,ps(script))).trim());
    }
    const raw=await this.exec(host,"if docker info >/dev/null 2>&1; then printf 'true\\n'; docker ps -aq | xargs -r docker inspect --format '{{json .}}'; else printf 'false\\n'; fi");
    const lines=raw.trim().split('\n');
    return {docker:lines.shift()==='true',containers:lines.filter(Boolean).map(line=>{const c=JSON.parse(line);return {target:c.Name.replace(/^\//,''),running:c.State.Running,health:c.State.Health?.Status,exitCode:c.State.ExitCode};}),services:[]};
  }
  action(host,service,action) { return this.exec(host,actionCommand(host,service,action)); }
  restartDocker(host) {
    return this.exec(host,host.os==='windows'?ps('docker desktop restart; if ($LASTEXITCODE -ne 0) { exit 1 }'):'docker desktop restart');
  }
}
export async function endpointCheck(service) {
  if(!service.checkType || service.checkType==='none') return true;
  if(service.checkType==='http') {
    try { const response=await fetch(service.url,{signal:AbortSignal.timeout(5000),redirect:'manual'}); await response.body?.cancel(); return response.status>=200 && response.status<400; } catch { return false; }
  }
  return new Promise(resolve=>{
    const socket=net.createConnection({host:service.checkAddress,port:service.checkPort});
    let done=false; const finish=ok=>{if(done)return;done=true;socket.destroy();resolve(ok);};
    socket.setTimeout(5000); socket.once('connect',()=>finish(true));socket.once('error',()=>finish(false));socket.once('timeout',()=>finish(false));
  });
}
