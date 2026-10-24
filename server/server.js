// SKIMMS Kavach server: Express REST + ws WebSocket. Team HEXACREW, Univ. of Calcutta, SIH26039
const express=require('express'),http=require('http'),path=require('path'),fs=require('fs'),crypto=require('crypto'),{WebSocketServer}=require('ws');
const app=express(),server=http.createServer(app),wss=new WebSocketServer({server,path:'/ws'});
app.set('trust proxy',1);app.use(express.json({limit:'20kb'}));app.use(express.static(path.join(__dirname,'public')));
const PROD=process.env.NODE_ENV==='production',PORT=process.env.PORT||3000;
const DATA_DIR=process.env.DATA_DIR||path.join(__dirname,'data'),DB_FILE=path.join(DATA_DIR,'skimms_db.json');
const ADMIN_USER=process.env.ADMIN_USER||'admin',ADMIN_PASS=process.env.ADMIN_PASS||(PROD?'':'dev-admin-pass');
const SECRET=process.env.SECRET||(PROD?'':crypto.randomBytes(32).toString('hex'));
if(PROD&&(!ADMIN_PASS||!SECRET)){console.error('Set ADMIN_PASS and SECRET environment variables');process.exit(1)}
const ESC_MS=(+process.env.ESCALATE_S||120)*1000,LEVELS=['SAFE','CAUTION','DANGER','CRITICAL'];
let db={workers:{},alerts:[]};const live={},hist={},deb=new Map(),rl=new Map();
// ---- persistence (free hosts wipe files: restore workers from WORKERS_JSON = output of /api/admin/export) ----
function load(){try{fs.mkdirSync(DATA_DIR,{recursive:true});if(fs.existsSync(DB_FILE)){const d=JSON.parse(fs.readFileSync(DB_FILE,'utf8'));db.workers=d.workers||{};db.alerts=d.alerts||[]}}catch(e){console.error('DB load failed:',e.message)}
  if(process.env.WORKERS_JSON)try{for(const[k,w]of Object.entries(JSON.parse(process.env.WORKERS_JSON)))if(!db.workers[k])db.workers[k]=w}catch{console.error('WORKERS_JSON invalid')}}
function save(){try{fs.mkdirSync(DATA_DIR,{recursive:true});const t=DB_FILE+'.tmp';fs.writeFileSync(t,JSON.stringify({workers:db.workers,alerts:db.alerts.slice(0,500)}));fs.renameSync(t,DB_FILE)}catch(e){console.error('DB save failed:',e.message)}}
// ---- security ----
const safeEq=(a,b)=>{const x=Buffer.from(String(a)),y=Buffer.from(String(b));return x.length===y.length&&crypto.timingSafeEqual(x,y)};
const hashPin=p=>{const salt=crypto.randomBytes(16).toString('hex');return{salt,hash:crypto.scryptSync(String(p),salt,64).toString('hex')}};
const verifyPin=(p,salt,h)=>safeEq(crypto.scryptSync(String(p),salt,64).toString('hex'),h);
const hm=d=>crypto.createHmac('sha256',SECRET).update(d).digest('hex');
const sign=o=>{const d=Buffer.from(JSON.stringify({...o,exp:Date.now()+864e5})).toString('base64url');return d+'.'+hm(d)};
const verify=t=>{try{const[d,s]=String(t||'').split('.');if(!d||!s||!safeEq(s,hm(d)))return null;const o=JSON.parse(Buffer.from(d,'base64url'));return o.exp>Date.now()?o:null}catch{return null}};
const auth=role=>(q,r,n)=>{const u=verify((q.headers.authorization||'').split(' ')[1]);if(!u)return r.status(401).json({error:'Login required'});if(role&&u.role!==role)return r.status(403).json({error:'Not allowed'});q.user=u;n()};
const locked=k=>{const i=rl.get(k);return i&&i.until>Date.now()?Math.ceil((i.until-Date.now())/1000):0};
const fail=k=>{const i=rl.get(k)||{n:0,until:0};if(++i.n>=10){i.until=Date.now()+6e5;i.n=0}rl.set(k,i)};
const csvCell=v=>{let s=String(v??'').replace(/"/g,'""');if(/^[=+\-@\t\r]/.test(s))s="'"+s;return `"${s}"`};
// ---- explainable AI rules ----
function evaluate(p,h){const s=p.sensors,st=p.status,mq4=s.mq4,mq135=s.mq135,accel=s.accel||9.8,ir=s.ir,miss=st.missing,R=[];let sev=0;const up=n=>{sev=Math.max(sev,n)};
  if(miss>0){R.push(`${miss} sensor(s) offline or disconnected`);up(1)}
  const weak=ir>=1000&&ir<=20000;if(weak){R.push('Weak optical skin contact: helmet may be loose');up(1)}
  const impact=accel>=24.5;if(impact||st.health_hazard){R.push(`High impact/acceleration: ${accel.toFixed(1)} m/s2 (limit 24.5)`);up(2)}
  if(mq4>=2200){R.push(`Methane (MQ-4) ${mq4} >= 2200`);up(2)}if(mq135>=2000){R.push(`Air quality (MQ-135) ${mq135} >= 2000`);up(2)}
  const env=st.env_hazard||mq4>=2200||mq135>=2000;
  if(h.length>=4){const r=h.slice(-6),a=r[0],b=r[r.length-1],dt=(b.ts-a.ts)/1000;if(dt>1){const rate=(b.mq4-a.mq4)/dt;if(rate>15&&b.mq4<2200&&b.mq4+rate*60>=2200){R.push(`Predictive: methane rising +${rate.toFixed(1)}/s, may pass 2200 within 60 s`);up(1)}}}
  const hi=h.map(e=>e.accel>=24.5).lastIndexOf(true);
  if(hi>=0){const after=h.slice(hi+1);if(after.length>=5&&h[h.length-1].ts-h[hi].ts>=15000&&after.every(e=>Math.abs(e.accel-9.8)<0.6)){R.push('MAN DOWN: impact followed by 15 s of no movement');up(3)}}
  if(env&&(st.health_hazard||impact||weak)){R.push('COMBINED THREAT: gas hazard together with worker health/impact hazard');up(3)}
  const d=deb.get(p.board_id)||{n:0};if(sev>=2){if(++d.n<3){R.unshift(`Confirming reading (${d.n}/3)`);sev=1}}else d.n=0;deb.set(p.board_id,d);
  let risk=Math.min(100,Math.round(Math.max(mq4/2200,mq135/2000)*50+Math.min(accel/24.5,1.5)*35+miss*5));if(sev===3)risk=100;if(sev===0&&risk>40)risk=38;
  if(!R.length)R.push('Gases and worker dynamics within safe limits');
  return{status:LEVELS[sev],risk_score:risk,reasons:R,evaluated_at:Date.now()}}
// ---- fan-out, alerts, notifications ----
function bc(type,payload,id){const m=JSON.stringify({type,...payload});wss.clients.forEach(c=>{if(c.readyState===1&&c.role&&(c.role==='admin'||(id&&c.esp32_id===id)))c.send(m)})}
wss.on('connection',(ws,q)=>{const u=verify(new URL(q.url,'http://x').searchParams.get('token'));if(!u)return ws.close(4401);ws.role=u.role;ws.esp32_id=u.esp32_id});
async function notify(a,esc){const text=`SKIMMS ALERT${esc?' [ESCALATED]':''}\nWorker: ${a.worker_name} (${a.helmet_number}) ${a.area||''}\nStatus: ${a.status} (risk ${a.risk_score}%)\n- ${a.reasons.join('\n- ')}`;
  const T=process.env.TELEGRAM_BOT_TOKEN,C=process.env.TELEGRAM_CHAT_ID,W=process.env.WEBHOOK_URL,p=(u,b)=>fetch(u,{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(b)}).catch(e=>console.error('notify failed:',e.message));
  if(T&&C)await p(`https://api.telegram.org/bot${T}/sendMessage`,{chat_id:C,text});if(W)await p(W,{event:esc?'ALERT_ESCALATED':'ALERT_TRIGGERED',alert:a,text})}
function raise(w,status,risk,reasons,gps){const a={id:'ALT_'+Date.now()+'_'+crypto.randomBytes(2).toString('hex'),esp32_id:w.esp32_id,helmet_number:w.helmet_number,worker_name:w.worker_name,area:w.area||'',status,risk_score:risk,reasons,timestamp:Date.now(),acknowledged:false,escalated:false,gps:gps||{}};
  db.alerts.unshift(a);if(db.alerts.length>500)db.alerts.length=500;save();bc('ALERT_TRIGGERED',{alert:a},a.esp32_id);notify(a,false);return a}
const pubW=w=>({esp32_id:w.esp32_id,helmet_number:w.helmet_number,worker_name:w.worker_name,area:w.area||''});
// ---- auth routes ----
app.post('/api/admin/login',(q,r)=>{const{username,password}=q.body||{},k='a:'+q.ip,l=locked(k);if(l)return r.status(429).json({error:`Too many attempts. Wait ${l}s.`});
  if(safeEq(username||'',ADMIN_USER)&&safeEq(password||'',ADMIN_PASS)){rl.delete(k);return r.json({token:sign({role:'admin',username}),role:'admin'})}fail(k);r.status(401).json({error:'Invalid admin username or password'})});
app.post('/api/worker/login',(q,r)=>{const{esp32_id,pin}=q.body||{};if(!esp32_id||!pin)return r.status(400).json({error:'ESP32 ID and 4-digit PIN required'});
  const k='w:'+q.ip+':'+esp32_id,l=locked(k);if(l)return r.status(429).json({error:`Too many attempts. Wait ${l}s.`});
  const w=db.workers[esp32_id];if(!w||!verifyPin(pin,w.pin_salt,w.pin_hash)){fail(k);return r.status(401).json({error:'Wrong ESP32 ID or PIN'})}
  rl.delete(k);r.json({token:sign({role:'worker',esp32_id}),role:'worker',worker:pubW(w)})});
app.get('/api/worker/status',auth('worker'),(q,r)=>{const w=db.workers[q.user.esp32_id];if(!w)return r.status(404).json({error:'Worker not found'});r.json({worker:pubW(w),telemetry:live[w.esp32_id]||null})});
app.post('/api/worker/sos',auth('worker'),(q,r)=>{const w=db.workers[q.user.esp32_id];if(!w)return r.status(404).json({error:'Worker not found'});
  r.json({success:true,alert:raise(w,'CRITICAL',100,['EMERGENCY SOS pressed by worker'],(live[w.esp32_id]||{}).gps)})});
// ---- helmet ingest ----
app.post('/api/telemetry',(q,r)=>{const p=q.body,id=p&&p.board_id;if(!id||!p.sensors||!p.status)return r.status(400).json({error:'Invalid packet'});
  const w=db.workers[id];if(!w)return r.status(403).json({error:'Forbidden: unregistered ESP32 node'});if(!safeEq(q.headers['x-device-key']||'',w.device_key))return r.status(401).json({error:'Unauthorized: bad x-device-key'});
  const s=p.sensors,g=p.gps||{},rec={board_id:id,sensors:{mq4:+s.mq4||0,mq135:+s.mq135||0,accel:+s.accel||0,ir:+s.ir||0},status:{health_hazard:!!p.status.health_hazard,env_hazard:!!p.status.env_hazard,missing:+p.status.missing||0},gps:{valid:!!g.valid,lat:+g.lat||0,lng:+g.lng||0},battery:p.battery==null?null:+p.battery};
  const h=hist[id]||(hist[id]=[]);h.push({ts:Date.now(),mq4:rec.sensors.mq4,accel:rec.sensors.accel||9.8});if(h.length>120)h.shift();
  const ai=evaluate(rec,h);live[id]={...rec,ai_evaluation:ai,last_seen:Date.now(),helmet_number:w.helmet_number,worker_name:w.worker_name,area:w.area||''};
  if(ai.status==='DANGER'||ai.status==='CRITICAL'){const dup=db.alerts.find(a=>a.esp32_id===id&&!a.acknowledged&&a.status===ai.status&&Date.now()-a.timestamp<30000);if(!dup)raise(w,ai.status,ai.risk_score,ai.reasons,rec.gps)}
  bc('TELEMETRY_UPDATE',{esp32_id:id,telemetry:live[id]},id);r.json({status:'OK',ai_status:ai.status,risk:ai.risk_score})});
// ---- admin ----
app.post('/api/admin/workers',auth('admin'),(q,r)=>{const{esp32_id,helmet_number,worker_name,worker_pin,area}=q.body||{};
  if(!esp32_id||!helmet_number||!worker_name||!worker_pin)return r.status(400).json({error:'ESP32 ID, helmet number, name and PIN are required'});
  if(!/^[A-Za-z0-9_-]{3,40}$/.test(esp32_id))return r.status(400).json({error:'ESP32 ID: 3-40 letters, digits, - or _'});
  if(!/^\d{4}$/.test(String(worker_pin)))return r.status(400).json({error:'PIN must be exactly 4 digits'});
  if(db.workers[esp32_id])return r.status(409).json({error:`ESP32 ID ${esp32_id} already registered`});
  if(Object.values(db.workers).some(x=>x.helmet_number===helmet_number))return r.status(409).json({error:`Helmet ${helmet_number} already assigned`});
  const{salt,hash}=hashPin(worker_pin),key='hex_'+crypto.randomBytes(16).toString('hex');
  db.workers[esp32_id]={esp32_id,helmet_number:String(helmet_number).slice(0,20),worker_name:String(worker_name).slice(0,60),area:String(area||'').slice(0,60),pin_salt:salt,pin_hash:hash,device_key:key,created_at:Date.now()};save();
  bc('WORKER_REGISTERED',{worker:pubW(db.workers[esp32_id])});r.status(201).json({message:'Worker registered',worker:{...pubW(db.workers[esp32_id]),device_key:key}})});
app.post('/api/admin/workers/:id/rotate-key',auth('admin'),(q,r)=>{const w=db.workers[q.params.id];if(!w)return r.status(404).json({error:'Worker not found'});w.device_key='hex_'+crypto.randomBytes(16).toString('hex');save();r.json({new_device_key:w.device_key})});
app.delete('/api/admin/workers/:id',auth('admin'),(q,r)=>{const id=q.params.id;if(!db.workers[id])return r.status(404).json({error:'Worker not found'});delete db.workers[id];delete live[id];delete hist[id];deb.delete(id);save();bc('WORKER_DELETED',{esp32_id:id});r.json({message:'Removed'})});
app.get('/api/admin/fleet',auth('admin'),(q,r)=>r.json(Object.values(db.workers).map(w=>({...pubW(w),telemetry:live[w.esp32_id]||null}))));
app.get('/api/admin/export',auth('admin'),(q,r)=>r.json(db.workers));   // backup for WORKERS_JSON (contains PIN hashes + device keys: keep private)
app.get('/api/alerts',auth(),(q,r)=>r.json(q.user.role==='admin'?db.alerts:db.alerts.filter(a=>a.esp32_id===q.user.esp32_id)));
app.post('/api/alerts/:id/ack',auth('admin'),(q,r)=>{const a=db.alerts.find(x=>x.id===q.params.id);if(!a)return r.status(404).json({error:'Alert not found'});a.acknowledged=true;a.acknowledged_at=Date.now();a.acknowledged_by=q.user.username;save();bc('ALERT_ACKNOWLEDGED',{alert:a},a.esp32_id);r.json({success:true,alert:a})});
app.get('/api/alerts/export-csv',auth('admin'),(q,r)=>{const H=['Alert ID','Time','Helmet','ESP32 ID','Worker','Area','Severity','Risk','Reasons','Acknowledged','Escalated'];
  const rows=db.alerts.map(a=>[a.id,new Date(a.timestamp).toISOString(),a.helmet_number,a.esp32_id,a.worker_name,a.area,a.status,a.risk_score,(a.reasons||[]).join('; '),a.acknowledged?'YES':'NO',a.escalated?'YES':'NO'].map(csvCell).join(','));
  r.setHeader('Content-Type','text/csv; charset=utf-8');r.setHeader('Content-Disposition',`attachment; filename="skimms_alerts_${Date.now()}.csv"`);r.send([H.join(','),...rows].join('\n'))});
// ---- watchdog (signal loss) + auto-escalation ----
setInterval(()=>{const now=Date.now();
  for(const w of Object.values(db.workers)){const t=live[w.esp32_id];if(t&&!t.lost&&now-t.last_seen>15000){t.lost=true;t.ai_evaluation={status:'DANGER',risk_score:85,reasons:['SIGNAL LOST: no telemetry for over 15 s (signal loss or worker trapped)'],evaluated_at:now};
    raise(w,'DANGER',85,t.ai_evaluation.reasons,t.gps);bc('TELEMETRY_UPDATE',{esp32_id:w.esp32_id,telemetry:t},w.esp32_id)}}
  for(const a of db.alerts)if(!a.acknowledged&&!a.escalated&&(a.status==='DANGER'||a.status==='CRITICAL')&&now-a.timestamp>=ESC_MS){a.escalated=true;a.escalated_at=now;save();bc('ALERT_ESCALATED',{alert:a},a.esp32_id);notify(a,true)}},3000).unref();
load();if(require.main===module)server.listen(PORT,'0.0.0.0',()=>console.log(`SKIMMS server on :${PORT}`));
module.exports={app,server,evaluate,csvCell};
