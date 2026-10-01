import { DatabaseSync } from 'node:sqlite';
import { mkdirSync, existsSync, readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { randomBytes, createCipheriv, createDecipheriv, scryptSync, timingSafeEqual } from 'node:crypto';

export class Store {
  constructor(dir, keyFile) {
    mkdirSync(dir, { recursive: true, mode: 0o700 });
    mkdirSync(dirname(keyFile), { recursive: true, mode: 0o700 });
    // Losing the key must never silently replace it when encrypted credentials exist.
    this.db = new DatabaseSync(join(dir, 'mainframe.sqlite'));
    this.db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
      CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS hosts (id TEXT PRIMARY KEY, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS services (id TEXT PRIMARY KEY, host_id TEXT NOT NULL REFERENCES hosts(id) ON DELETE CASCADE, value TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS samples (id INTEGER PRIMARY KEY, service_id TEXT NOT NULL, time INTEGER NOT NULL, status TEXT NOT NULL);
      CREATE INDEX IF NOT EXISTS samples_service_time ON samples(service_id,time);
      CREATE TABLE IF NOT EXISTS incidents (id TEXT PRIMARY KEY, service_id TEXT NOT NULL, host_id TEXT NOT NULL, started INTEGER NOT NULL, resolved INTEGER, value TEXT NOT NULL);`);
    if (!existsSync(keyFile)) {
      if (this.db.prepare('SELECT count(*) AS n FROM hosts').get().n) { this.db.close(); throw new Error('Vault key missing. Restore the original key before starting.'); }
      writeFileSync(keyFile, randomBytes(32), { mode: 0o600, flag: 'wx' });
    }
    chmodSync(keyFile, 0o600);
    this.key = readFileSync(keyFile);
    if (this.key.length !== 32) { this.db.close(); throw new Error('Vault key must contain 32 binary bytes.'); }
  }
  seal(value) {
    const iv = randomBytes(12), cipher = createCipheriv('aes-256-gcm', this.key, iv);
    const bytes = Buffer.concat([cipher.update(value, 'utf8'), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), bytes]).toString('base64');
  }
  unseal(value) {
    const bytes = Buffer.from(value, 'base64'), cipher = createDecipheriv('aes-256-gcm', this.key, bytes.subarray(0,12));
    cipher.setAuthTag(bytes.subarray(12,28));
    return Buffer.concat([cipher.update(bytes.subarray(28)), cipher.final()]).toString('utf8');
  }
  get(key) { const row = this.db.prepare('SELECT value FROM settings WHERE key=?').get(key); return row ? JSON.parse(row.value) : null; }
  set(key, value) { this.db.prepare('INSERT OR REPLACE INTO settings VALUES (?,?)').run(key, JSON.stringify(value)); }
  hosts() { return this.db.prepare('SELECT value FROM hosts').all().map(r=>JSON.parse(r.value)); }
  host(id) { return this.hosts().find(h=>h.id===id); }
  saveHost(host) { this.db.prepare('INSERT INTO hosts VALUES (?,?) ON CONFLICT(id) DO UPDATE SET value=excluded.value').run(host.id, JSON.stringify(host)); }
  services(hostId) { return this.db.prepare('SELECT value FROM services').all().map(r=>JSON.parse(r.value)).filter(s=>!hostId || s.hostId===hostId); }
  service(id) { return this.services().find(s=>s.id===id); }
  saveService(s) { this.db.prepare('INSERT INTO services VALUES (?,?,?) ON CONFLICT(id) DO UPDATE SET host_id=excluded.host_id,value=excluded.value').run(s.id, s.hostId, JSON.stringify(s)); }
  removeService(id) { this.db.prepare('DELETE FROM services WHERE id=?').run(id); }
  removeHost(id) { this.db.prepare('DELETE FROM hosts WHERE id=?').run(id); }
  sample(s, status, now=Date.now()) {
    this.db.prepare('INSERT INTO samples(service_id,time,status) VALUES (?,?,?)').run(s.id, now, status);
  }
  history(id, now=Date.now()) {
    const start=now-86400000;
    const rows = this.db.prepare('SELECT time,status FROM samples WHERE service_id=? AND time>=? ORDER BY time').all(id,start);
    // Duration-weighted availability. Gaps beyond 90s are unknown, never credited as uptime.
    let online=0, observed=0; const buckets=Array(40).fill('unknown'), weights=Array.from({length:40},()=>({online:0,offline:0,unknown:0,stopped:0}));
    for(let i=0;i<rows.length;i++) {
      const r=rows[i], end=Math.min(rows[i+1]?.time??now,r.time+90000,now);
      const duration=Math.max(0,end-r.time);
      if(['online','offline'].includes(r.status)) observed+=duration;
      if(r.status==='online') online+=duration;
      for(let b=Math.max(0,Math.floor((r.time-start)/2160000));b<40;b++) {
        const left=Math.max(r.time,start+b*2160000), right=Math.min(end,start+(b+1)*2160000);
        if(right>left) weights[b][r.status]=(weights[b][r.status]??0)+right-left;
        if(start+(b+1)*2160000>=end) break;
      }
    }
    weights.forEach((w,i)=>{buckets[i]=w.offline?'offline':w.online?'online':w.stopped?'stopped':'unknown';});
    return { uptime: observed ? +(online/observed*100).toFixed(2) : null, coverage: +(observed/86400000*100).toFixed(1), buckets };
  }
  incidents() { return this.db.prepare('SELECT * FROM incidents ORDER BY started DESC LIMIT 200').all().map(r=>({...JSON.parse(r.value),id:r.id,serviceId:r.service_id,hostId:r.host_id,started:r.started,resolved:r.resolved})); }
  saveIncident(i) { this.db.prepare('INSERT OR REPLACE INTO incidents VALUES (?,?,?,?,?,?)').run(i.id,i.serviceId,i.hostId,i.started,i.resolved??null,JSON.stringify({name:i.name,events:i.events})); }
  prune(now=Date.now()) { this.db.prepare('DELETE FROM samples WHERE time<?').run(now-30*86400000); this.db.prepare('DELETE FROM incidents WHERE resolved IS NOT NULL AND resolved<?').run(now-90*86400000); }
  close() { this.db.close(); }
}
export function passwordHash(password) { const salt=randomBytes(16).toString('hex'); return {salt,hash:scryptSync(password,salt,64).toString('hex')}; }
export function verifyPassword(password, stored) { if(!stored) return false; return timingSafeEqual(scryptSync(password,stored.salt,64),Buffer.from(stored.hash,'hex')); }
