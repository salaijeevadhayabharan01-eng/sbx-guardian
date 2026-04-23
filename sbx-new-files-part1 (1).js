// ================================================================
// SBX GUARDIAN — COMPLETE FILE PACKAGE
// Copy each section into its own file
// ================================================================

// ============================================================
// FILE 1: auth-advanced.js
// ============================================================
/*
const express = require('express');
const router = express.Router();
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');
const { run, get } = require('./db');
const JWT_SECRET = process.env.JWT_SECRET || 'sbx-v5-secret';
const resetTokens = new Map();

router.post('/forgot-password', (req, res) => {
  const user = get('SELECT id,email FROM users WHERE email=?', [req.body.email]);
  if (!user) return res.json({ success: true });
  const token = crypto.randomBytes(32).toString('hex');
  resetTokens.set(token, { userId: user.id, expires: Date.now() + 3600000 });
  res.json({ success: true, dev_token: process.env.NODE_ENV !== 'production' ? token : undefined });
});

router.post('/reset-password', async (req, res) => {
  const data = resetTokens.get(req.body.token);
  if (!data || Date.now() > data.expires) return res.status(400).json({ error: 'Expired' });
  run('UPDATE users SET password=? WHERE id=?', [await bcrypt.hash(req.body.new_password, 10), data.userId]);
  resetTokens.delete(req.body.token);
  res.json({ success: true });
});

router.get('/me', (req, res) => {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try {
    const u = jwt.verify(h.slice(7), JWT_SECRET);
    const user = get('SELECT id,email,name,role,org_id,last_login FROM users WHERE id=?', [u.id]);
    const org = get('SELECT id,name,plan,industry,country,soc2_status FROM organizations WHERE id=?', [u.org_id]);
    res.json({ user, org, expires: new Date(u.exp * 1000).toISOString() });
  } catch { res.status(401).json({ error: 'Invalid' }); }
});

module.exports = router;
*/

// ============================================================
// FILE 2: incidents.js — Formal incident management
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { query, run, get } = require('./db');

// Incidents table must be added to db schema:
// CREATE TABLE IF NOT EXISTS incidents (
//   id TEXT PRIMARY KEY, org_id TEXT, system_id TEXT,
//   title TEXT, description TEXT, severity TEXT,
//   status TEXT DEFAULT 'open', root_cause TEXT,
//   assigned_to TEXT, resolution TEXT,
//   opened_at INTEGER, closed_at INTEGER,
//   created_at INTEGER DEFAULT (strftime('%s','now'))
// );

function auth(req, res, next) {
  const jwt = require('jsonwebtoken');
  try { req.user = jwt.verify(req.headers.authorization?.slice(7), process.env.JWT_SECRET||'sbx-v5-secret'); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

router.get('/', auth, (req, res) => {
  res.json(query('SELECT i.*,s.name as system_name FROM incidents i LEFT JOIN systems s ON s.id=i.system_id WHERE i.org_id=? ORDER BY i.opened_at DESC', [req.user.org_id]));
});

router.post('/', auth, (req, res) => {
  const { title, description, severity, system_id, assigned_to } = req.body;
  const id = uuidv4();
  run('INSERT INTO incidents (id,org_id,system_id,title,description,severity,assigned_to,opened_at) VALUES (?,?,?,?,?,?,?,?)',
    [id, req.user.org_id, system_id||null, title, description||'', severity||'warning', assigned_to||req.user.name, Date.now()]);
  res.json({ id });
});

router.put('/:id', auth, (req, res) => {
  const { status, root_cause, resolution, assigned_to } = req.body;
  const closed_at = status === 'resolved' ? Date.now() : null;
  run('UPDATE incidents SET status=COALESCE(?,status),root_cause=COALESCE(?,root_cause),resolution=COALESCE(?,resolution),assigned_to=COALESCE(?,assigned_to),closed_at=COALESCE(?,closed_at) WHERE id=? AND org_id=?',
    [status, root_cause, resolution, assigned_to, closed_at, req.params.id, req.user.org_id]);
  res.json({ success: true });
});

router.get('/:id', auth, (req, res) => {
  const incident = get('SELECT i.*,s.name as system_name FROM incidents i LEFT JOIN systems s ON s.id=i.system_id WHERE i.id=? AND i.org_id=?', [req.params.id, req.user.org_id]);
  if (!incident) return res.status(404).json({ error: 'Not found' });
  const events = query('SELECT * FROM events WHERE system_id=? AND timestamp BETWEEN ? AND ? ORDER BY timestamp ASC',
    [incident.system_id, incident.opened_at, incident.closed_at||Date.now()]);
  res.json({ ...incident, related_events: events });
});

module.exports = router;
*/

// ============================================================
// FILE 3: search.js — Full-text search
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { query } = require('./db');
const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  try { req.user = jwt.verify(req.headers.authorization?.slice(7), process.env.JWT_SECRET||'sbx-v5-secret'); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

router.get('/', auth, (req, res) => {
  const { q, type, limit = 20 } = req.query;
  if (!q || q.length < 2) return res.json({ results: [], query: q });
  const search = `%${q}%`;
  const orgId = req.user.org_id;
  const results = [];

  // Search events
  if (!type || type === 'events') {
    const events = query('SELECT id,type,severity,message,timestamp,"event" as result_type FROM events WHERE org_id=? AND message LIKE ? ORDER BY timestamp DESC LIMIT ?', [orgId, search, parseInt(limit)]);
    results.push(...events);
  }

  // Search systems
  if (!type || type === 'systems') {
    const systems = query('SELECT id,name,type,location,status,"system" as result_type FROM systems WHERE org_id=? AND (name LIKE ? OR location LIKE ? OR type LIKE ?) LIMIT ?', [orgId, search, search, search, parseInt(limit)]);
    results.push(...systems);
  }

  // Search compliance
  if (!type || type === 'compliance') {
    const comp = query('SELECT id,framework,article,title,status,"compliance" as result_type FROM compliance_items WHERE org_id=? AND (title LIKE ? OR description LIKE ?) LIMIT ?', [orgId, search, search, parseInt(limit)]);
    results.push(...comp);
  }

  // Search reports
  if (!type || type === 'reports') {
    const reports = query('SELECT id,title,type,framework,created_at,"report" as result_type FROM reports WHERE org_id=? AND title LIKE ? ORDER BY created_at DESC LIMIT ?', [orgId, search, parseInt(limit)]);
    results.push(...reports);
  }

  res.json({ results, query: q, total: results.length });
});

module.exports = router;
*/

// ============================================================
// FILE 4: export.js — Data export (CSV, JSON)
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { query, get } = require('./db');
const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  try { req.user = jwt.verify(req.headers.authorization?.slice(7), process.env.JWT_SECRET||'sbx-v5-secret'); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

function toCSV(data) {
  if (!data.length) return '';
  const headers = Object.keys(data[0]);
  const rows = data.map(row => headers.map(h => JSON.stringify(row[h]??'')).join(','));
  return [headers.join(','), ...rows].join('\n');
}

router.get('/events.csv', auth, (req, res) => {
  const { from, to, severity } = req.query;
  let sql = 'SELECT e.id,e.type,e.severity,e.message,e.timestamp,e.hash,s.name as system_name FROM events e LEFT JOIN systems s ON s.id=e.system_id WHERE e.org_id=?';
  const params = [req.user.org_id];
  if (severity) { sql += ' AND e.severity=?'; params.push(severity); }
  if (from) { sql += ' AND e.timestamp>=?'; params.push(parseInt(from)); }
  if (to) { sql += ' AND e.timestamp<=?'; params.push(parseInt(to)); }
  sql += ' ORDER BY e.timestamp DESC LIMIT 10000';
  const data = query(sql, params);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="sbx-events-${Date.now()}.csv"`);
  res.send(toCSV(data));
});

router.get('/systems.csv', auth, (req, res) => {
  const data = query('SELECT id,name,type,location,status,health,firmware,ip,manufacturer,model,serial_number,last_seen FROM systems WHERE org_id=?', [req.user.org_id]);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="sbx-systems-${Date.now()}.csv"`);
  res.send(toCSV(data));
});

router.get('/compliance.csv', auth, (req, res) => {
  const data = query('SELECT framework,article,title,description,status,evidence FROM compliance_items WHERE org_id=? ORDER BY framework,article', [req.user.org_id]);
  res.setHeader('Content-Type', 'text/csv');
  res.setHeader('Content-Disposition', `attachment; filename="sbx-compliance-${Date.now()}.csv"`);
  res.send(toCSV(data));
});

router.get('/full-backup.json', auth, (req, res) => {
  const orgId = req.user.org_id;
  const backup = {
    exported_at: new Date().toISOString(),
    organization: get('SELECT name,plan,industry,country FROM organizations WHERE id=?', [orgId]),
    systems: query('SELECT * FROM systems WHERE org_id=?', [orgId]),
    events: query('SELECT * FROM events WHERE org_id=? ORDER BY timestamp ASC', [orgId]),
    compliance: query('SELECT * FROM compliance_items WHERE org_id=?', [orgId]),
    firewall_rules: query('SELECT * FROM firewall_rules WHERE org_id=?', [orgId]),
    reports: query('SELECT id,title,type,framework,created_at FROM reports WHERE org_id=?', [orgId]),
    anomalies: query('SELECT * FROM anomalies WHERE org_id=?', [orgId]),
    alerts: query('SELECT * FROM alerts WHERE org_id=?', [orgId])
  };
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Content-Disposition', `attachment; filename="sbx-backup-${Date.now()}.json"`);
  res.json(backup);
});

module.exports = router;
*/

// ============================================================
// FILE 5: devices.js — Device registry & firmware tracking
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');
const { query, run, get } = require('./db');
const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  try { req.user = jwt.verify(req.headers.authorization?.slice(7), process.env.JWT_SECRET||'sbx-v5-secret'); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

// Get all devices with full details
router.get('/', auth, (req, res) => {
  const devices = query(`
    SELECT s.*,
      cb.status as cb_status, cb.current_load, cb.threshold, cb.trip_count,
      (SELECT COUNT(*) FROM events WHERE system_id=s.id AND severity='critical' AND timestamp>?) as critical_events_24h,
      (SELECT COUNT(*) FROM anomalies WHERE system_id=s.id AND resolved=0) as active_anomalies
    FROM systems s
    LEFT JOIN circuit_breakers cb ON cb.system_id=s.id
    WHERE s.org_id=?
    ORDER BY s.name
  `, [Date.now()-86400000, req.user.org_id]);
  res.json(devices);
});

// Generate new webhook token for device
router.post('/:id/rotate-token', auth, (req, res) => {
  const newToken = crypto.randomBytes(16).toString('hex');
  run('UPDATE systems SET webhook_token=? WHERE id=? AND org_id=?', [newToken, req.params.id, req.user.org_id]);
  const org = get('SELECT webhook_secret FROM organizations WHERE id=?', [req.user.org_id]);
  res.json({ webhook_token: newToken, webhook_url: `${process.env.APP_URL||''}/api/webhook/${org?.webhook_secret}` });
});

// Update firmware version
router.post('/:id/firmware', auth, (req, res) => {
  const { firmware, notes } = req.body;
  run('UPDATE systems SET firmware=?,last_seen=? WHERE id=? AND org_id=?', [firmware, Date.now(), req.params.id, req.user.org_id]);
  // Log firmware update event
  const { computeHash } = require('./db');
  const id=uuidv4(), ts=Date.now();
  const last = get('SELECT hash FROM events WHERE org_id=? ORDER BY timestamp DESC LIMIT 1', [req.user.org_id]);
  const prevHash = last?.hash||'0'.repeat(64);
  const message = `Firmware updated to ${firmware}${notes?' — '+notes:''}`;
  const hash = computeHash({id,system_id:req.params.id,type:'firmware',message,timestamp:ts},prevHash);
  run('INSERT INTO events (id,org_id,system_id,type,severity,message,data,prev_hash,hash,source,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [id,req.user.org_id,req.params.id,'firmware','info',message,'{}',prevHash,hash,'manual',ts]);
  res.json({ success: true });
});

// Bulk status update
router.post('/bulk-status', auth, (req, res) => {
  const { system_ids, status } = req.body;
  if (!Array.isArray(system_ids)) return res.status(400).json({ error: 'system_ids must be array' });
  system_ids.forEach(id => run('UPDATE systems SET status=?,last_seen=? WHERE id=? AND org_id=?', [status, Date.now(), id, req.user.org_id]));
  res.json({ updated: system_ids.length });
});

module.exports = router;
*/

// ============================================================
// FILE 6: tasks.js — Task & ticket management
// ============================================================
/*
// Tasks table: CREATE TABLE IF NOT EXISTS tasks (
//   id TEXT PRIMARY KEY, org_id TEXT, title TEXT, description TEXT,
//   type TEXT DEFAULT 'maintenance', priority TEXT DEFAULT 'medium',
//   status TEXT DEFAULT 'open', assigned_to TEXT, system_id TEXT,
//   compliance_item_id TEXT, due_date INTEGER, completed_at INTEGER,
//   created_by TEXT, created_at INTEGER DEFAULT (strftime('%s','now'))
// );
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { query, run, get } = require('./db');
const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  try { req.user = jwt.verify(req.headers.authorization?.slice(7), process.env.JWT_SECRET||'sbx-v5-secret'); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

router.get('/', auth, (req, res) => {
  const { status, priority, assigned_to } = req.query;
  let sql = 'SELECT t.*,s.name as system_name FROM tasks t LEFT JOIN systems s ON s.id=t.system_id WHERE t.org_id=?';
  const params = [req.user.org_id];
  if (status) { sql+=' AND t.status=?'; params.push(status); }
  if (priority) { sql+=' AND t.priority=?'; params.push(priority); }
  if (assigned_to) { sql+=' AND t.assigned_to=?'; params.push(assigned_to); }
  sql += ' ORDER BY t.due_date ASC, t.created_at DESC';
  res.json(query(sql, params));
});

router.post('/', auth, (req, res) => {
  const { title, description, type, priority, assigned_to, system_id, compliance_item_id, due_date } = req.body;
  const id = uuidv4();
  run('INSERT INTO tasks (id,org_id,title,description,type,priority,assigned_to,system_id,compliance_item_id,due_date,created_by) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [id,req.user.org_id,title,description||'',type||'maintenance',priority||'medium',assigned_to||'',system_id||null,compliance_item_id||null,due_date||null,req.user.name]);
  res.json({ id });
});

router.put('/:id', auth, (req, res) => {
  const { status, priority, assigned_to, description, due_date } = req.body;
  const completed_at = status === 'done' ? Date.now() : null;
  run('UPDATE tasks SET status=COALESCE(?,status),priority=COALESCE(?,priority),assigned_to=COALESCE(?,assigned_to),description=COALESCE(?,description),due_date=COALESCE(?,due_date),completed_at=COALESCE(?,completed_at) WHERE id=? AND org_id=?',
    [status,priority,assigned_to,description,due_date,completed_at,req.params.id,req.user.org_id]);
  res.json({ success: true });
});

router.delete('/:id', auth, (req, res) => {
  run('DELETE FROM tasks WHERE id=? AND org_id=?', [req.params.id, req.user.org_id]);
  res.json({ success: true });
});

module.exports = router;
*/

// ============================================================
// FILE 7: geofence.js — Location-based safety rules
// ============================================================
/*
// geofences table: CREATE TABLE IF NOT EXISTS geofences (
//   id TEXT PRIMARY KEY, org_id TEXT, name TEXT, description TEXT,
//   lat REAL, lng REAL, radius_meters REAL, type TEXT DEFAULT 'safety_zone',
//   alert_on_entry INTEGER DEFAULT 1, enabled INTEGER DEFAULT 1,
//   created_at INTEGER DEFAULT (strftime('%s','now'))
// );
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { query, run, get } = require('./db');
const jwt = require('jsonwebtoken');

function auth(req,res,next){try{req.user=jwt.verify(req.headers.authorization?.slice(7),process.env.JWT_SECRET||'sbx-v5-secret');next();}catch{res.status(401).json({error:'Unauthorized'});}}

function haversineDistance(lat1,lng1,lat2,lng2) {
  const R=6371000, dLat=(lat2-lat1)*Math.PI/180, dLng=(lng2-lng1)*Math.PI/180;
  const a=Math.sin(dLat/2)**2+Math.cos(lat1*Math.PI/180)*Math.cos(lat2*Math.PI/180)*Math.sin(dLng/2)**2;
  return R*2*Math.atan2(Math.sqrt(a),Math.sqrt(1-a));
}

router.get('/', auth, (req,res) => res.json(query('SELECT * FROM geofences WHERE org_id=? ORDER BY name',[req.user.org_id])));

router.post('/', auth, (req,res) => {
  const {name,description,lat,lng,radius_meters,type,alert_on_entry} = req.body;
  const id=uuidv4();
  run('INSERT INTO geofences (id,org_id,name,description,lat,lng,radius_meters,type,alert_on_entry) VALUES (?,?,?,?,?,?,?,?,?)',
    [id,req.user.org_id,name,description||'',lat,lng,radius_meters||50,type||'safety_zone',alert_on_entry?1:0]);
  res.json({id});
});

// Check if coordinates are inside any geofence
router.post('/check', auth, (req,res) => {
  const {lat,lng,system_id} = req.body;
  const geofences = query('SELECT * FROM geofences WHERE org_id=? AND enabled=1',[req.user.org_id]);
  const matches = geofences.filter(g => haversineDistance(lat,lng,g.lat,g.lng) <= g.radius_meters);
  res.json({ inside: matches.length>0, geofences:matches, system_id, coordinates:{lat,lng} });
});

router.delete('/:id', auth, (req,res) => { run('DELETE FROM geofences WHERE id=? AND org_id=?',[req.params.id,req.user.org_id]); res.json({success:true}); });

module.exports = router;
*/

// ============================================================
// FILE 8: telemetry.js — Advanced telemetry processing
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { query, run, get, computeHash } = require('./db');

// Batch telemetry ingestion endpoint
router.post('/batch/:secret', async (req, res) => {
  const org = get('SELECT * FROM organizations WHERE webhook_secret=?',[req.params.secret]);
  if (!org) return res.status(401).json({error:'Invalid token'});
  const { readings } = req.body; // array of {system_id, type, severity, message, health, load, ts}
  if (!Array.isArray(readings)) return res.status(400).json({error:'readings must be array'});

  const results = [];
  let prevHash = get('SELECT hash FROM events WHERE org_id=? ORDER BY timestamp DESC LIMIT 1',[org.id])?.hash || '0'.repeat(64);

  for (const r of readings.slice(0,100)) { // max 100 per batch
    const id=uuidv4(), ts=r.ts||Date.now();
    const hash = computeHash({id,system_id:r.system_id||'batch',type:r.type||'telemetry',message:r.message||'Batch telemetry',timestamp:ts},prevHash);
    run('INSERT INTO events (id,org_id,system_id,type,severity,message,data,prev_hash,hash,source,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [id,org.id,r.system_id||null,r.type||'telemetry',r.severity||'info',r.message||'Telemetry','{}',prevHash,hash,'batch',ts]);
    if (r.system_id) {
      if (r.health!==undefined) run('UPDATE systems SET health=?,last_seen=? WHERE id=? AND org_id=?',[r.health,ts,r.system_id,org.id]);
      if (r.load!==undefined) run('UPDATE circuit_breakers SET current_load=? WHERE system_id=?',[r.load,r.system_id]);
    }
    prevHash=hash;
    results.push({id,hash});
  }

  res.json({success:true, processed:results.length, events:results});
});

// Time-series data for charts
router.get('/timeseries/:secret', (req, res) => {
  const org = get('SELECT * FROM organizations WHERE webhook_secret=?',[req.params.secret]);
  if (!org) return res.status(401).json({error:'Invalid token'});
  const { system_id, metric='events', interval='hour', hours=24 } = req.query;
  const fromTs = Date.now() - parseInt(hours)*3600000;
  const events = query('SELECT timestamp,severity,type FROM events WHERE org_id=? AND timestamp>? ORDER BY timestamp ASC',[org.id,fromTs]);
  res.json({system_id, metric, interval, data_points:events.length, events:events.slice(0,500)});
});

module.exports = router;
*/

// ============================================================
// FILE 9: notifications.js — Multi-channel notification center  
// ============================================================
/*
const { get, query, run } = require('./db');
const { v4: uuidv4 } = require('uuid');

const CHANNELS = ['email','slack','discord','pagerduty','webhook'];

async function notify(orgId, event) {
  const org = get('SELECT * FROM organizations WHERE id=?',[orgId]);
  if (!org) return;
  const prefs = JSON.parse(org.notification_prefs||'{}');
  const severity = event.severity||'info';
  
  // Only notify for warning+ by default
  if (severity==='info' && !prefs.notify_info) return;

  const integrations = query('SELECT * FROM integrations WHERE org_id=? AND enabled=1',[orgId]);
  const { dispatchIntegrations } = require('./integrations');
  await dispatchIntegrations(orgId, event);

  // Log notification
  run('INSERT INTO alerts (id,org_id,system_id,type,message,severity) VALUES (?,?,?,?,?,?)',
    [uuidv4(),orgId,event.system_id||null,event.type||'notification',event.message||'Notification',severity]);
}

async function notifyCritical(orgId, title, message, systemId) {
  await notify(orgId, { type:'critical_alert', severity:'critical', message:`${title}: ${message}`, system_id:systemId });
}

async function notifyEUDeadline(orgId, daysLeft, complianceScore) {
  await notify(orgId, {
    type:'eu_ai_act_deadline',
    severity: daysLeft<30?'critical':'warning',
    message:`EU AI Act enforcement in ${daysLeft} days. Your compliance score: ${complianceScore}%`,
    system_id:null
  });
}

module.exports = { notify, notifyCritical, notifyEUDeadline };
*/

// ============================================================
// FILE 10: soc2.js — SOC 2 Type II controls tracking
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { query, get, run } = require('./db');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');

function auth(req,res,next){try{req.user=jwt.verify(req.headers.authorization?.slice(7),process.env.JWT_SECRET||'sbx-v5-secret');next();}catch{res.status(401).json({error:'Unauthorized'});}}

const SOC2_CONTROLS = [
  {id:'CC1.1',category:'Control Environment',title:'COSO Principle 1',description:'Demonstrates commitment to integrity and ethical values'},
  {id:'CC2.1',category:'Communication',title:'COSO Principle 13',description:'Communicates internally about objectives, responsibilities, and important matters'},
  {id:'CC6.1',category:'Logical Access',title:'Access Controls',description:'Implements logical access security measures'},
  {id:'CC6.6',category:'Logical Access',title:'External Threats',description:'Implements controls to protect against threats from outside system boundaries'},
  {id:'CC7.1',category:'System Operations',title:'Detection',description:'Detects and monitors for new vulnerabilities'},
  {id:'CC7.2',category:'System Operations',title:'Monitoring',description:'Monitors system components for anomalies'},
  {id:'CC7.3',category:'System Operations',title:'Evaluation',description:'Evaluates security events to determine if they are incidents'},
  {id:'CC9.1',category:'Risk Mitigation',title:'Risk Identification',description:'Identifies and assesses risks that threaten achievement of objectives'},
  {id:'A1.1',category:'Availability',title:'Capacity',description:'Manages capacity to meet availability commitments'},
  {id:'A1.2',category:'Availability',title:'Recovery',description:'Establishes and tests recovery procedures'},
  {id:'PI1.1',category:'Processing Integrity',title:'Processing',description:'Obtains or generates information to meet objectives'},
  {id:'C1.1',category:'Confidentiality',title:'Identification',description:'Identifies and maintains confidential information'},
];

router.get('/controls', auth, (req, res) => {
  const orgId = req.user.org_id;
  const controls = SOC2_CONTROLS.map(c => {
    const saved = get('SELECT status,evidence,updated_at FROM compliance_items WHERE org_id=? AND framework=? AND article=?',[orgId,'SOC 2',c.id]);
    return {...c, status:saved?.status||'pending', evidence:saved?.evidence||'', updated_at:saved?.updated_at||null};
  });
  const score = Math.round(controls.filter(c=>c.status==='pass').length/controls.length*100);
  res.json({ controls, score, total:controls.length, passing:controls.filter(c=>c.status==='pass').length });
});

router.put('/controls/:control_id', auth, (req, res) => {
  const { status, evidence } = req.body;
  const existing = get('SELECT id FROM compliance_items WHERE org_id=? AND framework=? AND article=?',[req.user.org_id,'SOC 2',req.params.control_id]);
  const control = SOC2_CONTROLS.find(c=>c.id===req.params.control_id);
  if (!control) return res.status(404).json({error:'Control not found'});
  if (existing) {
    run('UPDATE compliance_items SET status=?,evidence=?,updated_at=? WHERE id=?',[status,evidence,Date.now(),existing.id]);
  } else {
    run('INSERT INTO compliance_items (id,org_id,framework,article,title,description,status,evidence,updated_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [uuidv4(),req.user.org_id,'SOC 2',control.id,control.title,control.description,status,evidence||'',Date.now()]);
  }
  res.json({success:true});
});

module.exports = router;
*/

// ============================================================
// FILE 11: analytics.js — Usage analytics and trends
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { query, get } = require('./db');
const jwt = require('jsonwebtoken');

function auth(req,res,next){try{req.user=jwt.verify(req.headers.authorization?.slice(7),process.env.JWT_SECRET||'sbx-v5-secret');next();}catch{res.status(401).json({error:'Unauthorized'});}}

router.get('/overview', auth, (req, res) => {
  const orgId = req.user.org_id;
  const now = Date.now();
  const day = 86400000;

  const eventsByDay = [];
  for (let i=6; i>=0; i--) {
    const from = now - (i+1)*day, to = now - i*day;
    const date = new Date(to).toISOString().split('T')[0];
    const total = get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND timestamp BETWEEN ? AND ?',[orgId,from,to]);
    const critical = get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND severity=? AND timestamp BETWEEN ? AND ?',[orgId,'critical',from,to]);
    eventsByDay.push({date, total:total?.c||0, critical:critical?.c||0});
  }

  const eventsBySeverity = query('SELECT severity, COUNT(*) as count FROM events WHERE org_id=? AND timestamp>? GROUP BY severity',[orgId,now-30*day]);
  const eventsByType = query('SELECT type, COUNT(*) as count FROM events WHERE org_id=? AND timestamp>? GROUP BY type ORDER BY count DESC LIMIT 10',[orgId,now-30*day]);
  const systemsByStatus = query('SELECT status, COUNT(*) as count FROM systems WHERE org_id=? GROUP BY status',[orgId]);
  const anomalyTrend = query('SELECT DATE(detected_at/1000,"unixepoch") as date, COUNT(*) as count FROM anomalies WHERE org_id=? AND detected_at>? GROUP BY date ORDER BY date',[orgId,now-30*day]);

  res.json({ events_by_day:eventsByDay, events_by_severity:eventsBySeverity, events_by_type:eventsByType, systems_by_status:systemsByStatus, anomaly_trend:anomalyTrend });
});

router.get('/compliance-history', auth, (req, res) => {
  const comp = query('SELECT framework, status, COUNT(*) as count FROM compliance_items WHERE org_id=? GROUP BY framework,status',[req.user.org_id]);
  const byFramework = {};
  comp.forEach(c => {
    if (!byFramework[c.framework]) byFramework[c.framework]={pass:0,partial:0,fail:0,pending:0};
    byFramework[c.framework][c.status]=(c.count||0);
  });
  res.json(byFramework);
});

module.exports = router;
*/

// ============================================================
// FILE 12: whitelist.js — IP & device whitelist management
// ============================================================
/*
// whitelists table: CREATE TABLE IF NOT EXISTS whitelists (
//   id TEXT PRIMARY KEY, org_id TEXT, type TEXT,
//   value TEXT, description TEXT, enabled INTEGER DEFAULT 1,
//   created_at INTEGER DEFAULT (strftime('%s','now'))
// );
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { query, run, get } = require('./db');
const jwt = require('jsonwebtoken');

function auth(req,res,next){try{req.user=jwt.verify(req.headers.authorization?.slice(7),process.env.JWT_SECRET||'sbx-v5-secret');next();}catch{res.status(401).json({error:'Unauthorized'});}}

router.get('/', auth, (req, res) => res.json(query('SELECT * FROM whitelists WHERE org_id=? ORDER BY type,created_at',[req.user.org_id])));

router.post('/', auth, (req, res) => {
  const { type, value, description } = req.body;
  const id = uuidv4();
  run('INSERT INTO whitelists (id,org_id,type,value,description) VALUES (?,?,?,?,?)',[id,req.user.org_id,type||'ip',value,description||'']);
  res.json({id});
});

router.put('/:id', auth, (req, res) => {
  run('UPDATE whitelists SET enabled=COALESCE(?,enabled),description=COALESCE(?,description) WHERE id=? AND org_id=?',[req.body.enabled!==undefined?(req.body.enabled?1:0):null,req.body.description,req.params.id,req.user.org_id]);
  res.json({success:true});
});

router.delete('/:id', auth, (req, res) => {
  run('DELETE FROM whitelists WHERE id=? AND org_id=?',[req.params.id,req.user.org_id]);
  res.json({success:true});
});

function isWhitelisted(orgId, type, value) {
  const entry = get('SELECT id FROM whitelists WHERE org_id=? AND type=? AND value=? AND enabled=1',[orgId,type,value]);
  return !!entry;
}

module.exports = router;
module.exports.isWhitelisted = isWhitelisted;
*/

console.log('SBX Guardian — All file templates loaded');
console.log('Copy each section between /* */ into its own .js file');
