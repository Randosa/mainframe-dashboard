import { randomUUID } from 'node:crypto';
import { endpointCheck } from './remote.js';
export class Monitor {
  constructor(store, remote, checkEndpoint=endpointCheck) { this.store=store; this.remote=remote; this.checkEndpoint=checkEndpoint; this.busy=new Set(); this.timer=null; }
  event(service, text) {
    let incident=this.store.incidents().find(i=>i.serviceId===service.id && !i.resolved);
    if(!incident) incident={id:randomUUID(),serviceId:service.id,hostId:service.hostId,name:service.name,started:Date.now(),events:[]};
    incident.events.push({time:Date.now(),text});this.store.saveIncident(incident);return incident;
  }
  resolve(service, text='Response verified — service restored.') {
    const i=this.store.incidents().find(i=>i.serviceId===service.id&&!i.resolved);
    if(i){i.events.push({time:Date.now(),text});i.resolved=Date.now();this.store.saveIncident(i);}
  }
  async tickHost(hostId) {
    if(this.busy.has(hostId))return;
    this.busy.add(hostId);
    try {
      const host=this.store.host(hostId);if(!host)return;
      const configured=this.store.services(host.id),services=[],visited=new Set();
      const add=s=>{if(visited.has(s.id))return;visited.add(s.id);for(const id of s.dependsOn??[]){const d=configured.find(c=>c.id===id);if(d)add(d);}services.push(s);};
      configured.forEach(add);
      if(!host.enabled || !host.fingerprint || !host.password) {
        host.ssh='unconfigured';host.docker='unknown';this.store.saveHost(host);
        for(const s of services){s.status=s.desired==='stopped'?'stopped':'unknown';s.detail='Configure and trust this host to begin monitoring.';this.store.saveService(s);}
        return;
      }
      let snapshot;
      try { snapshot=await this.remote.inspect(host);host.ssh='connected';host.docker=snapshot.docker?'running':'offline';host.lastChecked=Date.now();host.detail=''; }
      catch { host.ssh='offline';host.docker='unknown';host.lastChecked=Date.now();host.detail='SSH unavailable. No repair attempted.'; }
      this.store.saveHost(host);
      const connection={id:'ssh:'+host.id,hostId:host.id,name:host.name+' / SSH'};
      const engine={id:'docker:'+host.id,hostId:host.id,name:host.name+' / Docker'};
      if(snapshot) {
        this.resolve(connection,'SSH connection restored.');
        if(snapshot.docker)this.resolve(engine,'Docker availability verified.');
        else if(!this.store.incidents().some(i=>i.serviceId===engine.id&&!i.resolved))this.event(engine,'Docker unavailable. Container repairs paused; Docker restart requires approval.');
      } else if(!this.store.incidents().some(i=>i.serviceId===connection.id&&!i.resolved))this.event(connection,'SSH connection unavailable. Service state unknown; no automatic repair attempted.');
      for(const s of services) {
        s.lastChecked=Date.now();
        if(s.desired==='stopped') { s.status='stopped';s.detail='Manually stopped — automatic recovery paused.';this.store.sample(s,'stopped');this.store.saveService(s);continue; }
        if(!snapshot || (s.kind==='container' && !snapshot.docker)) {
          s.status='unknown';s.detail=!snapshot?'SSH unavailable — service state unknown.':'Docker unavailable — approval required to restart Docker.';
          s.failures=0;this.store.sample(s,'unknown');this.store.saveService(s);continue;
        }
        const actual=(s.kind==='container'?snapshot.containers:snapshot.services).find(c=>c.target===s.target);
        if(!actual){s.status='unknown';s.detail='Target not found. Check configuration; no repair attempted.';s.failures=0;this.store.sample(s,'unknown');this.store.saveService(s);continue;}
        const ready=actual.running && actual.health!=='unhealthy' && await this.checkEndpoint(s);
        if(ready) {
          if(s.status==='offline'||s.status==='recovering')this.resolve(s);
          s.status='online';s.detail=s.checkType&&s.checkType!=='none'?'Application check passed.':'Target running; no separate application check configured.';s.failures=0;
          // Successful stability for ten minutes allows a new bounded recovery episode.
          s.healthySince??=Date.now();if(Date.now()-s.healthySince>=600000){s.attempts=0;s.lastAttempt=0;}
          this.store.sample(s,'online');this.store.saveService(s);continue;
        }
        s.healthySince=null;s.status='offline';s.detail=!actual.running?'Target is stopped.':actual.health==='unhealthy'?'Docker health check failed.':'Application check failed.';
        s.failures=(s.failures??0)+1;
        if(s.failures===1)this.event(s,s.detail);
        this.store.sample(s,'offline');
        const dependencies=(s.dependsOn??[]).map(id=>this.store.service(id));
        if(dependencies.some(d=>!d||d.status!=='online'))s.detail='Recovery waiting for a configured dependency.';
        else if(s.autoRecover && !s.approvalRequired && s.failures>=s.failureThreshold && Date.now()-(s.lastAttempt??0)>=s.cooldownSeconds*1000 && (s.attempts??0)<s.maxAttempts) {
          s.attempts=(s.attempts??0)+1;s.lastAttempt=Date.now();s.status='recovering';s.detail='Restart attempted; awaiting a successful check.';
          this.store.saveService(s);this.event(s,`Automatic restart attempt ${s.attempts} of ${s.maxAttempts}.`);
          try { await this.remote.action(host,s,'restart');this.event(s,'Restart command completed; recovery will be verified on the next check.'); }
          catch { s.status='offline';s.detail='Restart failed. Check remote permissions and target.';this.event(s,s.detail); }
        } else if((s.attempts??0)>=s.maxAttempts)s.detail='Recovery limit reached. Manual attention required.';
        else if(s.approvalRequired)s.detail='Repair requires approval through the Restart button.';
        this.store.saveService(s);
      }
    } finally { this.busy.delete(hostId); }
  }
  async tick() { await Promise.allSettled(this.store.hosts().map(h=>this.tickHost(h.id)));this.store.prune(); }
  start() { this.timer=setInterval(()=>this.tick().catch(()=>{}),30000);this.tick().catch(()=>{}); }
  stop() { clearInterval(this.timer); }
  async manual(serviceId,action) {
    const s=this.store.service(serviceId);if(!s)throw new Error('Service not found');
    const host=this.store.host(s.hostId);if(this.busy.has(host.id))throw new Error('This PC is being checked. Try again shortly.');
    this.busy.add(host.id);
    try {
      if(action==='stop') {
        // Persist intent before the remote action. A failed stop must not re-enable recovery.
        s.desired='stopped';s.status='stopped';s.detail='Stop requested — automatic recovery paused.';
      } else { s.desired='running';s.status='recovering';s.detail='Manual action requested; awaiting verification.';s.attempts=0;s.failures=0;s.lastAttempt=Date.now(); }
      this.store.saveService(s);this.event(s,`Manual ${action} requested.`);
      try { await this.remote.action(host,s,action);this.event(s,`Manual ${action} command completed.`);if(action==='stop')this.resolve(s,'Intentionally stopped; automatic recovery paused.'); }
      catch { s.detail=`Manual ${action} failed. Check remote permissions; ${action==='stop'?'recovery remains paused.':'recovery is enabled.'}`;this.store.saveService(s);this.event(s,s.detail);throw new Error(s.detail); }
    } finally { this.busy.delete(host.id); }
  }
}
