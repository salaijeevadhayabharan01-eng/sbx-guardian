'use strict';
const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const path = require('path');
const rateLimit = require('express-rate-limit');

const { getDB, query, run, get, computeHash, saveDB } = require('./db');
const { detectAnomalies, getRiskScore, getFleetRiskSummary } = require('./anomaly');
const { sendAlert, getAlerts, resolveAlert } = require('./alerts');
const { analyzeAnomaly, generateEvidenceReport, fleetChatAnalysis, predictFailureRisk } = require('./ai');
const { generateLinkedInPost, generateTwitterThread, generatePitchDeck, generateOutreachEmail, TARGETS } = require('./marketing');
const { getMaintenanceScore, getFleetIntelligence, buildIncidentTimeline, getComplianceGapAnalysis } = require('./intelligence');
const { startScheduler } = require('./scheduler');
const { REPORT_TEMPLATES, buildReportContext, buildPromptForTemplate } = require('./reports');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'sbx-guardian-2026';

app.use(express.json({ limit: '10mb' }));
app.use(express.static(__dirname));
app.use('/api/', rateLimit({ windowMs: 15*60*1000, max: 1000 }));
app.use('/api/auth/', rateLimit({ windowMs: 15*60*1000, max: 30 }));

// Security headers
app.use((req, res, next) => {
  res.setHeader('X-Powered-By', 'SBX-Guardian');
  res.setHeader('X-SBX-Version', '5.0.0');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  next();
});

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}

function adminOnly(req, res, next) {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'Admin only' });
  next();
}

// ── HEALTH ────────────────────────────────────────────────────
const startTime = Date.now();
app.get('/health', (req, res) => {
  try {
    get('SELECT COUNT(*) as c FROM users');
    res.json({ status: 'healthy', version: '5.0.0', uptime: Math.round((Date.now()-startTime)/1000), timestamp: new Date().toISOString() });
  } catch(e) { res.status(500).json({ status: 'unhealthy', error: e.message }); }
});
app.get('/ping', (req, res) => res.json({ pong: true, ts: Date.now() }));
app.get('/metrics', auth, (req, res) => {
  res.json({
    version: '5.0.0',
    uptime: Math.round((Date.now()-startTime)/1000),
    organizations: get('SELECT COUNT(*) as c FROM organizations')?.c || 0,
    systems: get('SELECT COUNT(*) as c FROM systems')?.c || 0,
    events: get('SELECT COUNT(*) as c FROM events')?.c || 0,
    waitlist: get('SELECT COUNT(*) as c FROM waitlist')?.c || 0
  });
});

// ── AUTH ──────────────────────────────────────────────────────
app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name, org_name, industry, country } = req.body;
    if (!email||!password||!name) return res.status(400).json({ error: 'Missing fields' });
    if (get('SELECT id FROM users WHERE email=?',[email])) return res.status(400).json({ error: 'Email exists' });
    const orgId = uuidv4(), userId = uuidv4();
    const webhookSecret = crypto.randomBytes(32).toString('hex');
    run('INSERT INTO organizations (id,name,industry,webhook_secret,alert_email,country) VALUES (?,?,?,?,?,?)',
      [orgId, org_name||name+"'s Org", industry||'manufacturing', webhookSecret, email, country||'US']);
    seedComplianceForOrg(orgId);
    seedFirewallForOrg(orgId);
    run('INSERT INTO users (id,email,password,name,role,org_id) VALUES (?,?,?,?,?,?)',
      [userId, email, await bcrypt.hash(password,10), name, 'admin', orgId]);
    const token = jwt.sign({ id:userId, email, role:'admin', name, org_id:orgId }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user: { id:userId, email, name, role:'admin', org_id:orgId } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = get('SELECT * FROM users WHERE email=?',[email]);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
    run('UPDATE users SET last_login=? WHERE id=?',[Date.now(), user.id]);
    const token = jwt.sign({ id:user.id, email:user.email, role:user.role, name:user.name, org_id:user.org_id }, JWT_SECRET, { expiresIn:'7d' });
    res.json({ token, user: { id:user.id, email:user.email, name:user.name, role:user.role, org_id:user.org_id } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── WAITLIST ──────────────────────────────────────────────────
app.post('/api/waitlist', (req, res) => {
  try {
    const { email, company, role, systems_count, message } = req.body;
    if (!email) return res.status(400).json({ error: 'Email required' });
    if (get('SELECT id FROM waitlist WHERE email=?',[email])) return res.json({ success: true });
    run('INSERT INTO waitlist (id,email,company,role,systems_count,message) VALUES (?,?,?,?,?,?)',
      [uuidv4(), email, company||'', role||'', systems_count||'', message||'']);
    res.json({ success: true });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.get('/api/waitlist', auth, adminOnly, (req, res) => {
  res.json(query('SELECT * FROM waitlist ORDER BY created_at DESC'));
});

// ── WEBHOOK ───────────────────────────────────────────────────
app.post('/api/webhook/:secret', async (req, res) => {
  try {
    const org = get('SELECT * FROM organizations WHERE webhook_secret=?',[req.params.secret]);
    if (!org) return res.status(401).json({ error: 'Invalid token' });
    const { system_id, type, severity, message, health, load, data } = req.body;
    const id = uuidv4(), ts = Date.now();
    const last = get('SELECT hash FROM events WHERE org_id=? ORDER BY timestamp DESC LIMIT 1',[org.id]);
    const prevHash = last?.hash || '0'.repeat(64);
    const hash = computeHash({ id, system_id:system_id||'webhook', type:type||'telemetry', message:message||'Webhook', timestamp:ts }, prevHash);
    run('INSERT INTO events (id,org_id,system_id,type,severity,message,data,prev_hash,hash,source,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [id,org.id,system_id||null,type||'telemetry',severity||'info',message||'Webhook',JSON.stringify(data||{}),prevHash,hash,'webhook',ts]);
    if (system_id) {
      if (health !== undefined) run('UPDATE systems SET health=?,last_seen=? WHERE id=? AND org_id=?',[health,ts,system_id,org.id]);
      if (load !== undefined) {
        run('UPDATE circuit_breakers SET current_load=? WHERE system_id=?',[load,system_id]);
        const anomalies = detectAnomalies(system_id, org.id, parseFloat(load), health||100);
        if (anomalies?.length) anomalies.forEach(a => sendAlert(org.id,'Anomaly',`${a.metric} deviation: ${a.deviation}`,a.severity,system_id));
      }
    }
    if (severity==='critical') sendAlert(org.id, type||'Critical', message||'Critical event', 'critical', system_id);
    if (app.locals.broadcast) app.locals.broadcast(org.id, { type:'NEW_EVENT', data:{ id,type,severity,message,timestamp:ts } });
    res.json({ success:true, event_id:id, hash });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// ── DASHBOARD ─────────────────────────────────────────────────
app.get('/api/dashboard', auth, (req, res) => {
  const o = req.user.org_id;
  const systems = query('SELECT status,health FROM systems WHERE org_id=?',[o]);
  const ev24 = get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND timestamp>?',[o,Date.now()-86400000]);
  const crit24 = get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND severity=? AND timestamp>?',[o,'critical',Date.now()-86400000]);
  const comp = query('SELECT status FROM compliance_items WHERE org_id=?',[o]);
  const passing = comp.filter(c=>c.status==='pass').length;
  const activeAlerts = get('SELECT COUNT(*) as c FROM alerts WHERE org_id=? AND resolved=0',[o]);
  const anomalyCount = get('SELECT COUNT(*) as c FROM anomalies WHERE org_id=? AND resolved=0',[o]);
  const recentEvents = query('SELECT e.*,s.name as system_name FROM events e LEFT JOIN systems s ON s.id=e.system_id WHERE e.org_id=? ORDER BY e.timestamp DESC LIMIT 15',[o]);
  const waitlistCount = get('SELECT COUNT(*) as c FROM waitlist');
  res.json({
    systems: { total:systems.length, online:systems.filter(s=>s.status==='online').length, warnings:systems.filter(s=>s.status==='warning').length, offline:systems.filter(s=>s.status==='offline').length, avg_health:systems.length?Math.round(systems.reduce((a,b)=>a+(b.health||0),0)/systems.length):0 },
    events: { last24h:ev24?.c||0, critical:crit24?.c||0 },
    compliance: { score:comp.length?Math.round(passing/comp.length*100):0, passing, total:comp.length },
    alerts: { active:activeAlerts?.c||0 },
    anomalies: { active:anomalyCount?.c||0 },
    fleet_risk: getFleetRiskSummary(o),
    eu_ai_act_days: Math.ceil((new Date('2026-08-02').getTime()-Date.now())/86400000),
    recent_events: recentEvents,
    waitlist_signups: waitlistCount?.c||0,
    intelligence: getFleetIntelligence(o)
  });
});

// ── SYSTEMS ───────────────────────────────────────────────────
app.get('/api/systems', auth, (req, res) => {
  const systems = query('SELECT s.*,cb.status as cb_status,cb.current_load,cb.threshold,cb.trip_count FROM systems s LEFT JOIN circuit_breakers cb ON cb.system_id=s.id WHERE s.org_id=? ORDER BY s.name',[req.user.org_id]);
  res.json(systems.map(s => ({ ...s, risk_score:getRiskScore(s.id,req.user.org_id), maintenance:getMaintenanceScore(s.id) })));
});

app.post('/api/systems', auth, (req, res) => {
  const { name,type,location,firmware,ip,manufacturer,model,serial_number } = req.body;
  const id = uuidv4(), wt = crypto.randomBytes(16).toString('hex');
  run('INSERT INTO systems (id,org_id,name,type,location,firmware,ip,manufacturer,model,serial_number,webhook_token,last_seen) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
    [id,req.user.org_id,name,type||'robot',location||'Unknown',firmware||'1.0.0',ip||'0.0.0.0',manufacturer||'',model||'',serial_number||'',wt,Date.now()]);
  run('INSERT INTO circuit_breakers (id,org_id,system_id,threshold) VALUES (?,?,?,?)',[uuidv4(),req.user.org_id,id,80]);
  const org = get('SELECT webhook_secret FROM organizations WHERE id=?',[req.user.org_id]);
  res.json({ id, name, webhook_url:`${process.env.APP_URL||''}/api/webhook/${org?.webhook_secret}` });
});

app.put('/api/systems/:id', auth, (req, res) => {
  const { name,type,location,status,health,firmware,ip,manufacturer,model } = req.body;
  run('UPDATE systems SET name=COALESCE(?,name),type=COALESCE(?,type),location=COALESCE(?,location),status=COALESCE(?,status),health=COALESCE(?,health),firmware=COALESCE(?,firmware),ip=COALESCE(?,ip),manufacturer=COALESCE(?,manufacturer),model=COALESCE(?,model),last_seen=? WHERE id=? AND org_id=?',
    [name,type,location,status,health,firmware,ip,manufacturer,model,Date.now(),req.params.id,req.user.org_id]);
  res.json({ success:true });
});

app.delete('/api/systems/:id', auth, (req, res) => {
  run('DELETE FROM systems WHERE id=? AND org_id=?',[req.params.id,req.user.org_id]);
  res.json({ success:true });
});

// ── EVENTS ────────────────────────────────────────────────────
app.get('/api/events', auth, (req, res) => {
  const { system_id,severity,type,limit=100,offset=0,from,to } = req.query;
  let sql = 'SELECT e.*,s.name as system_name FROM events e LEFT JOIN systems s ON s.id=e.system_id WHERE e.org_id=?';
  const params = [req.user.org_id];
  if (system_id){sql+=' AND e.system_id=?';params.push(system_id);}
  if (severity){sql+=' AND e.severity=?';params.push(severity);}
  if (type){sql+=' AND e.type=?';params.push(type);}
  if (from){sql+=' AND e.timestamp>=?';params.push(parseInt(from));}
  if (to){sql+=' AND e.timestamp<=?';params.push(parseInt(to));}
  sql+=' ORDER BY e.timestamp DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit),parseInt(offset));
  res.json({ events:query(sql,params), total:get('SELECT COUNT(*) as c FROM events WHERE org_id=?',[req.user.org_id])?.c||0 });
});

app.post('/api/events', auth, (req, res) => {
  const { system_id,type,severity,message,data } = req.body;
  const id=uuidv4(), ts=Date.now();
  const last = get('SELECT hash FROM events WHERE org_id=? ORDER BY timestamp DESC LIMIT 1',[req.user.org_id]);
  const prevHash = last?.hash||'0'.repeat(64);
  const hash = computeHash({id,system_id:system_id||'manual',type:type||'manual',message:message||'Event',timestamp:ts},prevHash);
  run('INSERT INTO events (id,org_id,system_id,type,severity,message,data,prev_hash,hash,source,operator_id,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?,?)',
    [id,req.user.org_id,system_id||null,type||'info',severity||'info',message||'Event',JSON.stringify(data||{}),prevHash,hash,'manual',req.user.id,ts]);
  const ev = get('SELECT e.*,s.name as system_name FROM events e LEFT JOIN systems s ON s.id=e.system_id WHERE e.id=?',[id]);
  if (severity==='critical') sendAlert(req.user.org_id,type||'Critical',message,'critical',system_id);
  if (app.locals.broadcast) app.locals.broadcast(req.user.org_id,{type:'NEW_EVENT',data:ev});
  res.json(ev);
});

app.get('/api/events/verify', auth, (req, res) => {
  const events = query('SELECT * FROM events WHERE org_id=? ORDER BY timestamp ASC',[req.user.org_id]);
  let valid=true, broken_at=null;
  for(let i=1;i<events.length;i++) if(events[i].prev_hash!==events[i-1].hash){valid=false;broken_at=events[i].id;break;}
  res.json({ valid, total:events.length, broken_at, verified_at:new Date().toISOString() });
});

// ── ANOMALIES ─────────────────────────────────────────────────
app.get('/api/anomalies', auth, (req, res) => res.json(query('SELECT a.*,s.name as system_name FROM anomalies a LEFT JOIN systems s ON s.id=a.system_id WHERE a.org_id=? ORDER BY a.detected_at DESC LIMIT 100',[req.user.org_id])));
app.put('/api/anomalies/:id/resolve', auth, (req, res) => { run('UPDATE anomalies SET resolved=1 WHERE id=? AND org_id=?',[req.params.id,req.user.org_id]); res.json({success:true}); });

// ── ALERTS ────────────────────────────────────────────────────
app.get('/api/alerts', auth, (req, res) => res.json(getAlerts(req.user.org_id)));
app.put('/api/alerts/:id/resolve', auth, (req, res) => { resolveAlert(req.params.id); res.json({success:true}); });

// ── FIREWALL ──────────────────────────────────────────────────
app.get('/api/safety/rules', auth, (req, res) => res.json(query('SELECT * FROM firewall_rules WHERE org_id=? ORDER BY mandatory DESC,created_at ASC',[req.user.org_id])));
app.post('/api/safety/rules', auth, (req, res) => {
  const { name,description,action,enabled } = req.body;
  const id=uuidv4();
  run('INSERT INTO firewall_rules (id,org_id,name,description,action,enabled) VALUES (?,?,?,?,?,?)',[id,req.user.org_id,name,description||'',action||'block',enabled?1:0]);
  res.json({id});
});
app.put('/api/safety/rules/:id', auth, (req, res) => {
  const rule = get('SELECT mandatory FROM firewall_rules WHERE id=?',[req.params.id]);
  if (rule?.mandatory && req.body.enabled===false) return res.status(403).json({error:'Cannot disable mandatory rule'});
  run('UPDATE firewall_rules SET name=COALESCE(?,name),description=COALESCE(?,description),action=COALESCE(?,action),enabled=COALESCE(?,enabled) WHERE id=? AND org_id=?',
    [req.body.name,req.body.description,req.body.action,req.body.enabled!==undefined?(req.body.enabled?1:0):null,req.params.id,req.user.org_id]);
  res.json({success:true});
});
app.delete('/api/safety/rules/:id', auth, (req, res) => {
  if (get('SELECT mandatory FROM firewall_rules WHERE id=?',[req.params.id])?.mandatory) return res.status(403).json({error:'Cannot delete mandatory rule'});
  run('DELETE FROM firewall_rules WHERE id=? AND org_id=?',[req.params.id,req.user.org_id]); res.json({success:true});
});

// ── CIRCUIT BREAKERS ──────────────────────────────────────────
app.get('/api/safety/breakers', auth, (req, res) => res.json(query('SELECT cb.*,s.name as system_name,s.type as system_type,s.location FROM circuit_breakers cb JOIN systems s ON s.id=cb.system_id WHERE cb.org_id=? ORDER BY s.name',[req.user.org_id])));
app.put('/api/safety/breakers/:id', auth, (req, res) => {
  run('UPDATE circuit_breakers SET status=COALESCE(?,status),threshold=COALESCE(?,threshold),last_tripped=COALESCE(?,last_tripped) WHERE id=? AND org_id=?',
    [req.body.status,req.body.threshold,req.body.status==='open'?Date.now():null,req.params.id,req.user.org_id]);
  if (app.locals.broadcast) app.locals.broadcast(req.user.org_id,{type:'BREAKER_UPDATE',data:{id:req.params.id,status:req.body.status}});
  res.json({success:true});
});

// ── COMPLIANCE ────────────────────────────────────────────────
app.get('/api/safety/compliance', auth, (req, res) => res.json(query('SELECT * FROM compliance_items WHERE org_id=? ORDER BY framework,article',[req.user.org_id])));
app.put('/api/safety/compliance/:id', auth, (req, res) => {
  run('UPDATE compliance_items SET status=COALESCE(?,status),evidence=COALESCE(?,evidence),updated_at=? WHERE id=? AND org_id=?',
    [req.body.status,req.body.evidence,Date.now(),req.params.id,req.user.org_id]);
  res.json({success:true});
});

// ── REPORTS ───────────────────────────────────────────────────
app.get('/api/safety/reports', auth, (req, res) => res.json(query('SELECT id,title,type,framework,generated_by,created_at FROM reports WHERE org_id=? ORDER BY created_at DESC',[req.user.org_id])));
app.get('/api/safety/reports/:id', auth, (req, res) => {
  const r = get('SELECT * FROM reports WHERE id=? AND org_id=?',[req.params.id,req.user.org_id]);
  if (!r) return res.status(404).json({error:'Not found'});
  res.json(r);
});
app.post('/api/safety/reports', auth, (req, res) => {
  const id=uuidv4();
  run('INSERT INTO reports (id,org_id,title,type,content,framework,generated_by) VALUES (?,?,?,?,?,?,?)',
    [id,req.user.org_id,req.body.title,req.body.type||'incident',req.body.content,req.body.framework||'general',req.user.name]);
  res.json({id});
});
app.post('/api/safety/reports/:id/share', auth, (req, res) => {
  const token = crypto.randomBytes(16).toString('hex');
  const expires = Date.now() + 7*86400000;
  run('UPDATE reports SET shared_token=?,shared_expires=? WHERE id=? AND org_id=?',[token,expires,req.params.id,req.user.org_id]);
  res.json({ share_url:`${process.env.APP_URL||''}/shared/${token}` });
});
app.get('/shared/:token', (req, res) => {
  const r = get('SELECT * FROM reports WHERE shared_token=? AND shared_expires>?',[req.params.token,Date.now()]);
  if (!r) return res.status(404).send('Report not found or expired');
  res.send(`<!DOCTYPE html><html><head><title>${r.title}</title><style>body{font-family:monospace;background:#05070a;color:#e6edf3;padding:40px;max-width:800px;margin:0 auto}h1{color:#00ff88}pre{white-space:pre-wrap}</style></head><body><h1>${r.title}</h1><p style="color:#8b949e">Generated: ${new Date(r.created_at).toISOString()}</p><pre>${r.content}</pre></body></html>`);
});

// ── AUDIT EXPORT ──────────────────────────────────────────────
app.get('/api/audit/export', auth, (req, res) => {
  const fromTs = req.query.from ? parseInt(req.query.from) : Date.now()-30*86400000;
  const toTs = req.query.to ? parseInt(req.query.to) : Date.now();
  const events = query('SELECT * FROM events WHERE org_id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC',[req.user.org_id,fromTs,toTs]);
  let chainValid=true;
  for(let i=1;i<events.length;i++) if(events[i].prev_hash!==events[i-1].hash){chainValid=false;break;}
  const certId = 'AUDIT-'+uuidv4().slice(0,8).toUpperCase();
  const org = get('SELECT name FROM organizations WHERE id=?',[req.user.org_id]);
  const compliance = query('SELECT * FROM compliance_items WHERE org_id=?',[req.user.org_id]);
  const systems = query('SELECT * FROM systems WHERE org_id=?',[req.user.org_id]);
  res.json({
    certification:certId, organization:org?.name,
    generated_at:new Date().toISOString(), generated_by:req.user.name,
    chain_integrity:{ valid:chainValid, events_audited:events.length },
    fleet_summary:{ total:systems.length, online:systems.filter(s=>s.status==='online').length },
    compliance_score:compliance.length?Math.round(compliance.filter(c=>c.status==='pass').length/compliance.length*100):0,
    events, compliance_items:compliance
  });
});

// ── ORG ───────────────────────────────────────────────────────
app.get('/api/org', auth, (req, res) => {
  const org = get('SELECT * FROM organizations WHERE id=?',[req.user.org_id]);
  if (!org) return res.status(404).json({error:'Not found'});
  res.json({...org, webhook_url:`${process.env.APP_URL||req.protocol+'://'+req.get('host')}/api/webhook/${org.webhook_secret}`});
});
app.put('/api/org', auth, adminOnly, (req, res) => {
  run('UPDATE organizations SET name=COALESCE(?,name),alert_email=COALESCE(?,alert_email),slack_webhook=COALESCE(?,slack_webhook),industry=COALESCE(?,industry) WHERE id=?',
    [req.body.name,req.body.alert_email,req.body.slack_webhook,req.body.industry,req.user.org_id]);
  res.json({success:true});
});
app.get('/api/org/users', auth, (req, res) => res.json(query('SELECT id,email,name,role,last_login,created_at FROM users WHERE org_id=?',[req.user.org_id])));
app.post('/api/org/invite', auth, adminOnly, async (req, res) => {
  try {
    const { email, name, role } = req.body;
    if (get('SELECT id FROM users WHERE email=?',[email])) return res.status(400).json({error:'Email exists'});
    const tempPass = crypto.randomBytes(8).toString('hex');
    const id = uuidv4();
    run('INSERT INTO users (id,email,password,name,role,org_id) VALUES (?,?,?,?,?,?)',[id,email,await bcrypt.hash(tempPass,10),name||email,role||'operator',req.user.org_id]);
    res.json({ id, temp_password:tempPass });
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── RISK & INTELLIGENCE ───────────────────────────────────────
app.get('/api/risk', auth, (req, res) => {
  const systems = query('SELECT s.*,cb.status as cb_status,cb.current_load FROM systems s LEFT JOIN circuit_breakers cb ON cb.system_id=s.id WHERE s.org_id=?',[req.user.org_id]);
  res.json({ systems:systems.map(s=>({...s,risk_score:getRiskScore(s.id,req.user.org_id),anomalies:query('SELECT * FROM anomalies WHERE system_id=? AND resolved=0 ORDER BY detected_at DESC LIMIT 3',[s.id])})), summary:getFleetRiskSummary(req.user.org_id) });
});
app.get('/api/intelligence/fleet', auth, (req, res) => res.json(getFleetIntelligence(req.user.org_id)));
app.get('/api/intelligence/maintenance', auth, (req, res) => {
  const systems = query('SELECT id FROM systems WHERE org_id=?',[req.user.org_id]);
  res.json(systems.map(s=>getMaintenanceScore(s.id)).filter(Boolean).sort((a,b)=>a.maintenance_score-b.maintenance_score));
});
app.get('/api/intelligence/compliance-gaps', auth, (req, res) => res.json(getComplianceGapAnalysis(req.user.org_id)));
app.get('/api/intelligence/timeline/:system_id', auth, (req, res) => res.json(buildIncidentTimeline(req.params.system_id, req.user.org_id, req.query.from?parseInt(req.query.from):null, req.query.to?parseInt(req.query.to):null)));

// ── INTEGRATIONS ──────────────────────────────────────────────
app.get('/api/integrations', auth, (req, res) => res.json(query('SELECT id,type,enabled,last_sync,created_at FROM integrations WHERE org_id=?',[req.user.org_id])));
app.post('/api/integrations', auth, (req, res) => {
  const id=uuidv4();
  run('INSERT INTO integrations (id,org_id,type,config,enabled) VALUES (?,?,?,?,?)',[id,req.user.org_id,req.body.type,JSON.stringify(req.body.config||{}),req.body.enabled!==false?1:0]);
  res.json({id});
});
app.put('/api/integrations/:id', auth, (req, res) => {
  run('UPDATE integrations SET enabled=COALESCE(?,enabled),last_sync=? WHERE id=? AND org_id=?',[req.body.enabled!==undefined?(req.body.enabled?1:0):null,Date.now(),req.params.id,req.user.org_id]);
  res.json({success:true});
});
app.delete('/api/integrations/:id', auth, (req, res) => {
  run('DELETE FROM integrations WHERE id=? AND org_id=?',[req.params.id,req.user.org_id]); res.json({success:true});
});

// ── SLA ───────────────────────────────────────────────────────
app.get('/api/sla', auth, (req, res) => {
  const systems = query('SELECT * FROM systems WHERE org_id=?',[req.user.org_id]);
  res.json(systems.map(s => {
    const uptimePct = s.status==='offline'?0:s.status==='warning'?95.0:99.5;
    const incidents = get('SELECT COUNT(*) as c FROM events WHERE system_id=? AND severity=? AND timestamp>?',[s.id,'critical',Date.now()-30*86400000]);
    return { ...s, avg_uptime:uptimePct, incident_count_30d:incidents?.c||0, sla_met:uptimePct>=(s.sla_uptime_target||99) };
  }));
});

// ── REGULATORY ────────────────────────────────────────────────
app.get('/api/regulatory', auth, (req, res) => res.json(query('SELECT * FROM regulatory_updates ORDER BY created_at DESC')));

// ── ADVANCED REPORTS ──────────────────────────────────────────
app.get('/api/report-templates', auth, (req, res) => res.json(Object.entries(REPORT_TEMPLATES).map(([k,v])=>({key:k,...v}))));
app.post('/api/ai/advanced-report', auth, async (req, res) => {
  try {
    const context = buildReportContext(req.user.org_id);
    const prompt = buildPromptForTemplate(req.body.template||'eu_ai_act_conformity', context, req.body.description);
    if (!prompt) return res.status(400).json({error:'Invalid template'});
    const { smartAI } = require('./ai');
    const result = await smartAI('evidence_report', { prompt });
    res.json(result);
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── AI ROUTES ─────────────────────────────────────────────────
app.post('/api/ai/chat', auth, async (req, res) => {
  try {
    const { messages } = req.body, o = req.user.org_id;
    const systems = query('SELECT * FROM systems WHERE org_id=?',[o]);
    const comp = query('SELECT status FROM compliance_items WHERE org_id=?',[o]);
    const passing = comp.filter(c=>c.status==='pass').length;
    const anomalies = get('SELECT COUNT(*) as c FROM anomalies WHERE org_id=? AND resolved=0',[o]);
    const crit = get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND severity=? AND timestamp>?',[o,'critical',Date.now()-86400000]);
    const result = await fleetChatAnalysis(messages, {
      total_systems:systems.length, online:systems.filter(s=>s.status==='online').length,
      offline:systems.filter(s=>s.status==='offline').length, warnings:systems.filter(s=>s.status==='warning').length,
      avg_health:systems.length?Math.round(systems.reduce((a,b)=>a+(b.health||0),0)/systems.length):0,
      avg_risk:getFleetRiskSummary(o).avg_risk, critical_systems:getFleetRiskSummary(o).critical_systems,
      active_anomalies:anomalies?.c||0, compliance_score:comp.length?Math.round(passing/comp.length*100):0,
      failing:comp.filter(c=>c.status==='fail').length,
      eu_days:Math.ceil((new Date('2026-08-02').getTime()-Date.now())/86400000), recent_critical:'Check dashboard'
    });
    res.json(result);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/ai/report', auth, async (req, res) => {
  try {
    const { type,framework,description } = req.body, o = req.user.org_id;
    const org = get('SELECT name FROM organizations WHERE id=?',[o]);
    const systems = query('SELECT * FROM systems WHERE org_id=?',[o]);
    const comp = query('SELECT * FROM compliance_items WHERE org_id=?',[o]);
    const passing = comp.filter(c=>c.status==='pass').length;
    const result = await generateEvidenceReport({
      type,framework,description, org_name:org?.name||'Org',
      total_systems:systems.length, online:systems.filter(s=>s.status==='online').length,
      compliance_score:comp.length?Math.round(passing/comp.length*100):0,
      critical_events:get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND severity=? AND timestamp>?',[o,'critical',Date.now()-86400000])?.c||0,
      anomalies:get('SELECT COUNT(*) as c FROM anomalies WHERE org_id=? AND resolved=0',[o])?.c||0,
      failing_items:comp.filter(c=>c.status==='fail').map(c=>c.title).join(', '), chain_valid:true
    });
    res.json(result);
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/ai/anomaly-explain', auth, async (req, res) => {
  try {
    const a = get('SELECT a.*,s.name as system_name FROM anomalies a LEFT JOIN systems s ON s.id=a.system_id WHERE a.id=?',[req.body.anomaly_id]);
    if (!a) return res.status(404).json({error:'Not found'});
    res.json(await analyzeAnomaly(a, a.system_name));
  } catch(e) { res.status(500).json({error:e.message}); }
});

app.post('/api/ai/predict-failure', auth, async (req, res) => {
  try {
    const s = get('SELECT s.*,cb.status as cb_status,cb.current_load FROM systems s LEFT JOIN circuit_breakers cb ON cb.system_id=s.id WHERE s.id=? AND s.org_id=?',[req.body.system_id,req.user.org_id]);
    if (!s) return res.status(404).json({error:'Not found'});
    res.json(await predictFailureRisk(s, query('SELECT * FROM events WHERE system_id=? ORDER BY timestamp DESC LIMIT 50',[req.body.system_id]), query('SELECT * FROM anomalies WHERE system_id=? AND resolved=0',[req.body.system_id])));
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── MARKETING ─────────────────────────────────────────────────
app.post('/api/marketing/linkedin', auth, async (req, res) => { try { res.json(await generateLinkedInPost(req.body.topic||'EU AI Act')); } catch(e) { res.status(500).json({error:e.message}); }});
app.post('/api/marketing/twitter', auth, async (req, res) => { try { res.json(await generateTwitterThread(req.body.topic||'robot safety')); } catch(e) { res.status(500).json({error:e.message}); }});
app.post('/api/marketing/pitch', auth, async (req, res) => { try { res.json(await generatePitchDeck(req.body.slide||'problem')); } catch(e) { res.status(500).json({error:e.message}); }});
app.post('/api/marketing/email', auth, async (req, res) => { try { res.json({...await generateOutreachEmail(req.body.target_index||0), target:TARGETS[req.body.target_index||0]}); } catch(e) { res.status(500).json({error:e.message}); }});
app.get('/api/marketing/targets', auth, (req, res) => res.json(TARGETS));

// ── PUBLIC API v1 ─────────────────────────────────────────────
function apiKeyAuth(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (!key) return res.status(401).json({ error: 'API key required' });
  const org = get('SELECT * FROM organizations WHERE webhook_secret=?',[key]);
  if (!org) return res.status(401).json({ error: 'Invalid API key' });
  req.org = org;
  next();
}

app.get('/api/v1/status', (req, res) => res.json({ status:'operational', version:'5.0.0', eu_days:Math.ceil((new Date('2026-08-02')-Date.now())/86400000) }));
app.get('/api/v1/fleet', apiKeyAuth, (req, res) => res.json({ systems:query('SELECT * FROM systems WHERE org_id=?',[req.org.id]), intelligence:getFleetIntelligence(req.org.id) }));
app.get('/api/v1/events', apiKeyAuth, (req, res) => res.json(query('SELECT * FROM events WHERE org_id=? ORDER BY timestamp DESC LIMIT 100',[req.org.id])));
app.post('/api/v1/events', apiKeyAuth, (req, res) => {
  const { system_id,type,severity,message } = req.body;
  const id=uuidv4(), ts=Date.now();
  const last = get('SELECT hash FROM events WHERE org_id=? ORDER BY timestamp DESC LIMIT 1',[req.org.id]);
  const prevHash = last?.hash||'0'.repeat(64);
  const hash = computeHash({id,system_id:system_id||'api',type:type||'api',message:message||'API event',timestamp:ts},prevHash);
  run('INSERT INTO events (id,org_id,system_id,type,severity,message,data,prev_hash,hash,source,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [id,req.org.id,system_id||null,type||'info',severity||'info',message||'Event','{}',prevHash,hash,'api_v1',ts]);
  res.json({ success:true, event_id:id, hash });
});
app.get('/api/v1/chain/verify', apiKeyAuth, (req, res) => {
  const events = query('SELECT hash,prev_hash FROM events WHERE org_id=? ORDER BY timestamp ASC',[req.org.id]);
  let valid=true;
  for(let i=1;i<events.length;i++) if(events[i].prev_hash!==events[i-1].hash){valid=false;break;}
  res.json({ valid, total:events.length, verified_at:new Date().toISOString() });
});
app.get('/api/v1/compliance', apiKeyAuth, (req, res) => res.json(getComplianceGapAnalysis(req.org.id)));
app.get('/api/v1/docs', (req, res) => res.json({ name:'SBX Guardian API v1', version:'5.0.0', auth:'X-API-Key header (your webhook secret)', endpoints:{ 'GET /api/v1/status':'Health check', 'GET /api/v1/fleet':'Fleet data', 'GET /api/v1/events':'Event log', 'POST /api/v1/events':'Log event', 'GET /api/v1/chain/verify':'Verify hash chain', 'GET /api/v1/compliance':'Compliance gaps' } }));

// ── SERVE FRONTEND ────────────────────────────────────────────
app.get('/', (req, res) => {
  const fs = require('fs');
  const landingPath = path.join(__dirname, 'landing.html');
  if (fs.existsSync(landingPath)) return res.sendFile(landingPath);
  res.sendFile(path.join(__dirname, 'index.html'));
});
app.get('/app', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));
app.get('*', (req, res) => {
  if (req.path.startsWith('/api/')) return res.status(404).json({error:'Not found'});
  res.sendFile(path.join(__dirname, 'index.html'));
});

// ── WEBSOCKET ─────────────────────────────────────────────────
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Map();

wss.on('connection', (ws, req) => {
  try {
    const token = new URL(req.url, 'http://x').searchParams.get('token');
    const user = jwt.verify(token, JWT_SECRET);
    if (!clients.has(user.org_id)) clients.set(user.org_id, new Set());
    clients.get(user.org_id).add(ws);
    ws.on('close', () => clients.get(user.org_id)?.delete(ws));
    ws.send(JSON.stringify({type:'CONNECTED',data:{user:user.name}}));
  } catch { ws.close(); }
});

app.locals.broadcast = (orgId, data) => {
  const msg = JSON.stringify(data);
  clients.get(orgId)?.forEach(ws => { if(ws.readyState===WebSocket.OPEN) ws.send(msg); });
};

// ── LIVE TELEMETRY ────────────────────────────────────────────
setInterval(() => {
  try {
    query('SELECT id FROM organizations').forEach(org => {
      const systems = query('SELECT id FROM systems WHERE org_id=? AND status != "offline"',[org.id]);
      systems.forEach(s => {
        const load = (20+Math.random()*65).toFixed(1);
        run('UPDATE circuit_breakers SET current_load=? WHERE system_id=?',[load,s.id]);
        if (Math.random()<0.1) {
          const anomalies = detectAnomalies(s.id,org.id,parseFloat(load),85+Math.random()*15);
          if (anomalies?.length) app.locals.broadcast(org.id,{type:'ANOMALY',data:anomalies[0]});
        }
      });
      if (Math.random()<0.15 && systems.length) {
        const s=systems[Math.floor(Math.random()*systems.length)];
        const types=['heartbeat','health_check','sensor_read','command'];
        const type=types[Math.floor(Math.random()*types.length)];
        const id=uuidv4(),ts=Date.now(),message=`Automated ${type}`;
        const last=get('SELECT hash FROM events WHERE org_id=? ORDER BY timestamp DESC LIMIT 1',[org.id]);
        const prevHash=last?.hash||'0'.repeat(64);
        const hash=computeHash({id,system_id:s.id,type,message,timestamp:ts},prevHash);
        run('INSERT INTO events (id,org_id,system_id,type,severity,message,data,prev_hash,hash,source,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)',[id,org.id,s.id,type,'info',message,'{}',prevHash,hash,'auto',ts]);
        app.locals.broadcast(org.id,{type:'TELEMETRY',data:{timestamp:ts}});
      }
    });
  } catch(e) { console.log('Telemetry error:',e.message); }
}, 5000);

// ── HELPERS ───────────────────────────────────────────────────
function seedComplianceForOrg(orgId) {
  const items = [
    {fw:'EU AI Act',art:'Art. 9',title:'Risk Management System',desc:'Establish and maintain risk management throughout lifecycle',status:'pass'},
    {fw:'EU AI Act',art:'Art. 10',title:'Data Governance',desc:'Training, validation and testing data must meet quality criteria',status:'pass'},
    {fw:'EU AI Act',art:'Art. 11',title:'Technical Documentation',desc:'Complete technical documentation before market placement',status:'partial'},
    {fw:'EU AI Act',art:'Art. 12',title:'Record-keeping & Logging',desc:'Automatic logging of events throughout operation',status:'pass'},
    {fw:'EU AI Act',art:'Art. 13',title:'Transparency & Info',desc:'Systems must be transparent; users must be informed',status:'partial'},
    {fw:'EU AI Act',art:'Art. 14',title:'Human Oversight',desc:'Enable effective oversight by natural persons',status:'pass'},
    {fw:'EU AI Act',art:'Art. 15',title:'Accuracy & Cybersecurity',desc:'Achieve appropriate levels of accuracy and cybersecurity',status:'fail'},
    {fw:'EU AI Act',art:'Art. 16',title:'Provider Obligations',desc:'Register in EU database; affix CE marking',status:'fail'},
    {fw:'ISO 10218',art:'5.4',title:'Safety Functions',desc:'Safety-rated monitored stop, speed and force limiting',status:'pass'},
    {fw:'ISO 10218',art:'5.5',title:'Operating Modes',desc:'Manual, automatic, collaborative modes defined',status:'pass'},
    {fw:'ISO 10218',art:'5.6',title:'Emergency Stop',desc:'Emergency stop function per IEC 60204-1',status:'pass'},
    {fw:'ISO 10218',art:'5.7',title:'Enabling Device',desc:'Three-position enabling device for manual operation',status:'partial'},
    {fw:'IEC 61508',art:'SIL-2',title:'Safety Integrity Level',desc:'Target failure measures for SIL 2',status:'partial'},
    {fw:'IEC 61508',art:'FMEA',title:'Failure Mode Analysis',desc:'Complete FMEA documentation for all safety functions',status:'fail'},
    {fw:'ISO 27001',art:'A.12',title:'Operations Security',desc:'Logging, monitoring and audit trail management',status:'partial'},
    {fw:'ISO 27001',art:'A.16',title:'Incident Management',desc:'Information security incident management process',status:'fail'},
  ];
  items.forEach(c => run('INSERT INTO compliance_items (id,org_id,framework,article,title,description,status) VALUES (?,?,?,?,?,?,?)',[uuidv4(),orgId,c.fw,c.art,c.title,c.desc,c.status]));
}

function seedFirewallForOrg(orgId) {
  [
    {name:'EU AI Act Human Oversight Gate',desc:'All autonomous decisions above Risk Level 3 require human confirmation',action:'require_approval',mandatory:1,enabled:1},
    {name:'Emergency Stop Propagation',desc:'E-Stop must propagate to all systems within 50ms',action:'propagate',mandatory:1,enabled:1},
    {name:'Block Unsigned Firmware',desc:'Reject firmware without valid cryptographic signature',action:'block',mandatory:0,enabled:1},
    {name:'Rate-limit Remote Commands',desc:'Max 100 commands per minute per system',action:'rate_limit',mandatory:0,enabled:1},
    {name:'Block External IP Range',desc:'Block commands from non-whitelisted IPs',action:'block',mandatory:0,enabled:1},
    {name:'Log All Safety Zone Entries',desc:'Every safety zone entry must be logged and hashed',action:'log',mandatory:0,enabled:1},
    {name:'Quarantine on Anomaly',desc:'Isolate system exceeding 3 anomaly detections in 60s',action:'isolate',mandatory:0,enabled:0},
  ].forEach(r => run('INSERT INTO firewall_rules (id,org_id,name,description,action,mandatory,enabled,hits) VALUES (?,?,?,?,?,?,?,?)',[uuidv4(),orgId,r.name,r.desc,r.action,r.mandatory,r.enabled,Math.floor(Math.random()*200)]));
}

module.exports = { seedComplianceForOrg, seedFirewallForOrg };

// ── START ─────────────────────────────────────────────────────
getDB().then(() => {
  setTimeout(() => startScheduler(app.locals.broadcast), 3000);
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log(`\n✅ SBX Guardian v5 → http://localhost:${PORT}\n`));
}).catch(console.error);
