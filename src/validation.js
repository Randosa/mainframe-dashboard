export function assert(condition,message) { if(!condition) { const e=new Error(message);e.status=400;throw e; } }
export function text(value,max=128) { return typeof value==='string'&&value.trim().length>0&&value.length<=max&&!/[\x00-\x1f]/.test(value); }
export function address(value) { return text(value,253)&&/^[A-Za-z0-9_.:\-]+$/.test(value); }
export function number(value,min,max) { return Number.isInteger(value)&&value>=min&&value<=max; }
export function validateHost(b) {
  assert(text(b.name)&&address(b.address)&&text(b.username),'Host name, address and SSH username are required.');
  assert(['windows','linux'].includes(b.os),'Select Windows or Linux.');
  assert(number(b.port,1,65535),'SSH port must be between 1 and 65535.');
  assert(typeof b.enabled==='boolean','Host enabled must be a boolean.');
}
