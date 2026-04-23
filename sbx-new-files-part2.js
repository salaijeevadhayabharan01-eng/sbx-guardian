// ================================================================
// SBX GUARDIAN — NEW FILES PART 2 (files 13-21)
// ================================================================

// ============================================================
// FILE 13: predictions.js — Time-series failure prediction
// ============================================================
/*
const { query, get } = require('./db');

function predictNextFailure(systemId) {
  const health_history = query('SELECT health,last_seen FROM systems WHERE id=?',[systemId]);
  const events = query('SELECT severity,timestamp FROM events WHERE system_id=? ORDER BY timestamp DESC LIMIT 100',[systemId]);
  const anomalies = query('SELECT severity,detected_at FROM anomalies WHERE system_id=? ORDER BY detected_at DESC LIMIT 20',[systemId]);
  const sys = get('SELECT * FROM systems WHERE id=?',[systemId]);
  if (!sys) return null;

  // Simple linear degradation model
  const health = sys.health||100;
  const criticalCount = events.filter(e=>e.severity==='critical').length;
  const activeAnomalies = anomalies.filter(a=>!a.resolved).length;
  const degradationRate = (criticalCount * 2 + activeAnomalies * 3) / 100;
  const daysToFailure = degradationRate > 0 ? Math.round((health - 20) / degradationRate) : 999;
  const probability7d = Math.min(95, Math.max(5, Math.round(criticalCount * 8 + activeAnomalies * 12 + (100-health) * 0.3)));

  return {
    system_id: systemId, system_name: sys.name,
    current_health: health,
    failure_probability_7d: probability7d,
    estimated_days_to_failure: Math.max(0, daysToFailure),
    confidence: criticalCount + activeAnomalies > 5 ? 'high' : criticalCount + activeAnomalies > 2 ? 'medium' : 'low',
    factors: { critical_events_recent: criticalCount, active_anomalies: activeAnomalies, health_score: health },
    recommendation: probability7d > 70 ? 'IMMEDIATE maintenance required' : probability7d > 40 ? 'Schedule maintenance within 48 hours' : 'Continue monitoring'
  };
}

function getFleetPredictions(orgId) {
  const systems = query('SELECT id FROM systems WHERE org_id=?',[orgId]);
  return systems.map(s=>predictNextFailure(s.id)).filter(Boolean).sort((a,b)=>b.failure_probability_7d-a.failure_probability_7d);
}

module.exports = { predictNextFailure, getFleetPredictions };
*/

// ============================================================
// FILE 14: cache.js — In-memory caching layer
// ============================================================
/*
class Cache {
  constructor(ttlMs = 30000) {
    this.store = new Map();
    this.ttl = ttlMs;
    setInterval(() => this.cleanup(), ttlMs * 2);
  }

  set(key, value, ttl) {
    this.store.set(key, { value, expires: Date.now() + (ttl||this.ttl) });
    return value;
  }

  get(key) {
    const item = this.store.get(key);
    if (!item) return null;
    if (Date.now() > item.expires) { this.store.delete(key); return null; }
    return item.value;
  }

  invalidate(prefix) {
    for (const key of this.store.keys()) {
      if (key.startsWith(prefix)) this.store.delete(key);
    }
  }

  cleanup() {
    const now = Date.now();
    for (const [key, item] of this.store.entries()) {
      if (now > item.expires) this.store.delete(key);
    }
  }

  async getOrSet(key, fn, ttl) {
    const cached = this.get(key);
    if (cached !== null) return cached;
    const value = await fn();
    return this.set(key, value, ttl);
  }

  stats() {
    return { size: this.store.size, keys: [...this.store.keys()] };
  }
}

// Singleton instances
const dashboardCache = new Cache(15000);  // 15s for dashboard
const complianceCache = new Cache(60000); // 1min for compliance
const riskCache = new Cache(30000);       // 30s for risk scores

module.exports = { Cache, dashboardCache, complianceCache, riskCache };
*/

// ============================================================
// FILE 15: validator.js — Input validation & sanitization
// ============================================================
/*
function validateEmail(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

function validatePassword(password) {
  if (!password || password.length < 8) return { valid: false, error: 'Password must be at least 8 characters' };
  return { valid: true };
}

function sanitizeString(str, maxLen = 500) {
  if (!str) return '';
  return String(str).slice(0, maxLen).replace(/[<>]/g, '');
}

function validateSystem(data) {
  const errors = [];
  if (!data.name) errors.push('Name is required');
  if (data.name && data.name.length > 200) errors.push('Name too long');
  if (data.ip && !/^(\d{1,3}\.){3}\d{1,3}$/.test(data.ip)) errors.push('Invalid IP address');
  if (data.health !== undefined && (data.health < 0 || data.health > 100)) errors.push('Health must be 0-100');
  return { valid: errors.length === 0, errors };
}

function validateEvent(data) {
  const errors = [];
  if (!data.message) errors.push('Message is required');
  const validSeverities = ['info', 'warning', 'critical'];
  if (data.severity && !validSeverities.includes(data.severity)) errors.push('Invalid severity');
  return { valid: errors.length === 0, errors };
}

function validationMiddleware(schema) {
  return (req, res, next) => {
    const result = schema(req.body);
    if (!result.valid) return res.status(400).json({ error: 'Validation failed', details: result.errors });
    next();
  };
}

module.exports = { validateEmail, validatePassword, sanitizeString, validateSystem, validateEvent, validationMiddleware };
*/

// ============================================================
// FILE 16: rbac.js — Role-based access control
// ============================================================
/*
const PERMISSIONS = {
  admin: ['*'],
  operator: ['systems:read','systems:write','events:read','events:write','alerts:read','alerts:resolve','compliance:read','reports:read'],
  viewer: ['systems:read','events:read','alerts:read','compliance:read','reports:read'],
  auditor: ['events:read','events:verify','compliance:read','reports:read','audit:export']
};

function hasPermission(role, permission) {
  const perms = PERMISSIONS[role] || [];
  if (perms.includes('*')) return true;
  if (perms.includes(permission)) return true;
  const [resource, action] = permission.split(':');
  return perms.includes(`${resource}:*`);
}

function requirePermission(permission) {
  return (req, res, next) => {
    if (!req.user) return res.status(401).json({ error: 'Unauthorized' });
    if (!hasPermission(req.user.role, permission)) return res.status(403).json({ error: `Permission denied: ${permission}` });
    next();
  };
}

function getRoleCapabilities(role) {
  return { role, permissions: PERMISSIONS[role] || [], is_admin: role === 'admin' };
}

module.exports = { hasPermission, requirePermission, getRoleCapabilities, PERMISSIONS };
*/

// ============================================================
// FILE 17: backup.js — Database backup and restore
// ============================================================
/*
const fs = require('fs');
const path = require('path');
const { saveDB } = require('./db');

const BACKUP_DIR = path.join(__dirname, 'backups');

function createBackup() {
  if (!fs.existsSync(BACKUP_DIR)) fs.mkdirSync(BACKUP_DIR, { recursive: true });
  const source = path.join(__dirname, 'sbx.db.json');
  if (!fs.existsSync(source)) return null;
  const filename = `sbx-backup-${new Date().toISOString().replace(/[:.]/g,'-')}.json`;
  const dest = path.join(BACKUP_DIR, filename);
  fs.copyFileSync(source, dest);
  console.log(`[BACKUP] Created: ${filename}`);
  return { filename, path: dest, size: fs.statSync(dest).size, created_at: new Date().toISOString() };
}

function listBackups() {
  if (!fs.existsSync(BACKUP_DIR)) return [];
  return fs.readdirSync(BACKUP_DIR)
    .filter(f => f.endsWith('.json'))
    .map(f => ({ filename: f, size: fs.statSync(path.join(BACKUP_DIR, f)).size, created_at: f.replace('sbx-backup-','').replace('.json','') }))
    .sort((a, b) => b.created_at.localeCompare(a.created_at));
}

function cleanOldBackups(keepCount = 10) {
  const backups = listBackups();
  if (backups.length > keepCount) {
    backups.slice(keepCount).forEach(b => {
      fs.unlinkSync(path.join(BACKUP_DIR, b.filename));
      console.log(`[BACKUP] Deleted old backup: ${b.filename}`);
    });
  }
}

// Auto-backup every 6 hours
function startAutoBackup() {
  setInterval(() => { createBackup(); cleanOldBackups(); }, 6 * 3600000);
  console.log('[BACKUP] Auto-backup started (every 6h)');
}

module.exports = { createBackup, listBackups, cleanOldBackups, startAutoBackup };
*/

// ============================================================
// FILE 18: fleet-map.js — Fleet visualization & mapping data
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { query, get } = require('./db');
const jwt = require('jsonwebtoken');
const { getRiskScore } = require('./anomaly');

function auth(req,res,next){try{req.user=jwt.verify(req.headers.authorization?.slice(7),process.env.JWT_SECRET||'sbx-v5-secret');next();}catch{res.status(401).json({error:'Unauthorized'});}}

router.get('/map-data', auth, (req, res) => {
  const systems = query('SELECT s.*,cb.status as cb_status,cb.current_load FROM systems s LEFT JOIN circuit_breakers cb ON cb.system_id=s.id WHERE s.org_id=?',[req.user.org_id]);
  const mapData = systems.map(s => ({
    id: s.id, name: s.name, type: s.type, location: s.location,
    status: s.status, health: s.health, risk_score: getRiskScore(s.id, req.user.org_id),
    cb_status: s.cb_status, load: parseFloat(s.current_load||0),
    last_seen: s.last_seen,
    color: s.status==='offline'?'#484f58': s.health<50?'#ff4d4d': s.health<80?'#ff8c00':'#00ff88'
  }));

  // Group by location
  const byLocation = {};
  mapData.forEach(s => {
    const loc = s.location||'Unknown';
    if (!byLocation[loc]) byLocation[loc] = { location:loc, systems:[], online:0, warnings:0, offline:0 };
    byLocation[loc].systems.push(s);
    if (s.status==='online') byLocation[loc].online++;
    else if (s.status==='warning') byLocation[loc].warnings++;
    else byLocation[loc].offline++;
  });

  res.json({ systems:mapData, locations:Object.values(byLocation), total:mapData.length });
});

router.get('/heatmap', auth, (req, res) => {
  const events = query('SELECT system_id, severity, COUNT(*) as count FROM events WHERE org_id=? AND timestamp>? GROUP BY system_id,severity',[req.user.org_id,Date.now()-7*86400000]);
  const systems = query('SELECT id,name,location FROM systems WHERE org_id=?',[req.user.org_id]);
  const heatmap = systems.map(s => {
    const sEvents = events.filter(e=>e.system_id===s.id);
    const critical = sEvents.find(e=>e.severity==='critical')?.count||0;
    const warning = sEvents.find(e=>e.severity==='warning')?.count||0;
    return { ...s, critical_events_7d:critical, warning_events_7d:warning, heat_score:critical*3+warning };
  }).sort((a,b)=>b.heat_score-a.heat_score);
  res.json(heatmap);
});

module.exports = router;
*/

// ============================================================
// FILE 19: compliance-engine.js — Deep compliance automation
// ============================================================
/*
const { query, get, run } = require('./db');
const { v4: uuidv4 } = require('uuid');

// Auto-assess compliance based on actual system data
function autoAssessCompliance(orgId) {
  const systems = query('SELECT * FROM systems WHERE org_id=?',[orgId]);
  const events = query('SELECT * FROM events WHERE org_id=? AND timestamp>? ORDER BY timestamp DESC',[orgId,Date.now()-30*86400000]);
  const chainCheck = query('SELECT hash,prev_hash FROM events WHERE org_id=? ORDER BY timestamp ASC LIMIT 500',[orgId]);

  let chainValid = true;
  for(let i=1;i<chainCheck.length;i++) if(chainCheck[i].prev_hash!==chainCheck[i-1].hash){chainValid=false;break;}

  const hasLogging = chainCheck.length > 0;
  const hasHumanOversight = query('SELECT id FROM firewall_rules WHERE org_id=? AND action=? AND enabled=1',[orgId,'require_approval']).length > 0;
  const hasRiskManagement = systems.length > 0;
  const criticalEventsHandled = events.filter(e=>e.severity==='critical').length < systems.length * 3;
  const updates = [];

  const assessments = [
    {article:'Art. 9', status: hasRiskManagement ? 'pass' : 'fail'},
    {article:'Art. 12', status: hasLogging && chainValid ? 'pass' : hasLogging ? 'partial' : 'fail'},
    {article:'Art. 14', status: hasHumanOversight ? 'pass' : 'fail'},
    {article:'Art. 15', status: criticalEventsHandled ? 'partial' : 'fail'},
  ];

  assessments.forEach(a => {
    const item = get('SELECT id FROM compliance_items WHERE org_id=? AND article=?',[orgId,a.article]);
    if (item) {
      run('UPDATE compliance_items SET status=?,updated_at=? WHERE id=?',[a.status,Date.now(),item.id]);
      updates.push({article:a.article, status:a.status});
    }
  });

  return { auto_assessed: updates.length, updates, chain_valid: chainValid, assessed_at: new Date().toISOString() };
}

module.exports = { autoAssessCompliance };
*/

// ============================================================
// FILE 20: onboarding.js — New org setup wizard API
// ============================================================
/*
const express = require('express');
const router = express.Router();
const { run, get, query } = require('./db');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

function auth(req,res,next){try{req.user=jwt.verify(req.headers.authorization?.slice(7),process.env.JWT_SECRET||'sbx-v5-secret');next();}catch{res.status(401).json({error:'Unauthorized'});}}

const ONBOARDING_STEPS = [
  {id:'profile',title:'Set up your organization profile',required:true},
  {id:'first_system',title:'Add your first robot/AI system',required:true},
  {id:'webhook',title:'Connect your first device via webhook',required:false},
  {id:'compliance',title:'Review your compliance checklist',required:true},
  {id:'alerts',title:'Configure alert notifications',required:false},
  {id:'invite',title:'Invite your team members',required:false},
];

router.get('/status', auth, (req, res) => {
  const orgId = req.user.org_id;
  const org = get('SELECT * FROM organizations WHERE id=?',[orgId]);
  const systems = get('SELECT COUNT(*) as c FROM systems WHERE org_id=?',[orgId]);
  const users = get('SELECT COUNT(*) as c FROM users WHERE org_id=?',[orgId]);
  const events = get('SELECT COUNT(*) as c FROM events WHERE org_id=?',[orgId]);

  const completedSteps = {
    profile: !!(org?.name && org?.industry),
    first_system: (systems?.c||0) > 0,
    webhook: (events?.c||0) > 0,
    compliance: true, // always show as available
    alerts: !!(org?.alert_email || org?.slack_webhook),
    invite: (users?.c||0) > 1
  };

  const steps = ONBOARDING_STEPS.map(s => ({...s, completed: completedSteps[s.id]||false}));
  const requiredDone = steps.filter(s=>s.required).every(s=>s.completed);
  const totalDone = steps.filter(s=>s.completed).length;

  res.json({ steps, progress: Math.round(totalDone/steps.length*100), required_complete: requiredDone, total_steps: steps.length, completed_steps: totalDone });
});

module.exports = router;
*/

// ============================================================
// FILE 21: rate-limiter.js — Advanced rate limiting
// ============================================================
/*
const rateLimit = require('express-rate-limit');

// Tiered rate limits by plan
const PLAN_LIMITS = {
  starter: { requests_per_hour: 1000, webhook_per_hour: 10000 },
  professional: { requests_per_hour: 10000, webhook_per_hour: 100000 },
  enterprise: { requests_per_hour: 100000, webhook_per_hour: 1000000 }
};

const apiLimiter = rateLimit({ windowMs:15*60*1000, max:1000, message:{ error:'Rate limit exceeded', retry_after:'15 minutes' }, standardHeaders:true, legacyHeaders:false });
const authLimiter = rateLimit({ windowMs:15*60*1000, max:20, message:{ error:'Too many auth attempts' } });
const webhookLimiter = rateLimit({ windowMs:60*1000, max:500, message:{ error:'Webhook rate limit exceeded' } });
const reportLimiter = rateLimit({ windowMs:60*1000, max:10, message:{ error:'Report generation rate limit' } });

module.exports = { apiLimiter, authLimiter, webhookLimiter, reportLimiter, PLAN_LIMITS };
*/

// ============================================================
// HOW TO USE THESE FILES
// ============================================================
// 1. Each file is between /* and */
// 2. Copy the content between /* and */ into its own .js file
// 3. Add to server.js:
//    const authAdv = require('./auth-advanced');
//    const incidents = require('./incidents');
//    const searchRouter = require('./search');
//    const exportRouter = require('./export');
//    const devices = require('./devices');
//    const tasks = require('./tasks');
//    const geofence = require('./geofence');
//    const telemetry = require('./telemetry');
//    const notifications = require('./notifications');
//    const soc2 = require('./soc2');
//    const analytics = require('./analytics');
//    const whitelist = require('./whitelist');
//    const { getFleetPredictions } = require('./predictions');
//    const { dashboardCache } = require('./cache');
//    const { validateSystem } = require('./validator');
//    const { requirePermission } = require('./rbac');
//    const { createBackup, startAutoBackup } = require('./backup');
//    const fleetMap = require('./fleet-map');
//    const { autoAssessCompliance } = require('./compliance-engine');
//    const onboarding = require('./onboarding');
//    const { apiLimiter, webhookLimiter } = require('./rate-limiter');
//
//    app.use('/api/auth', authAdv);
//    app.use('/api/incidents', incidents);
//    app.use('/api/search', searchRouter);
//    app.use('/api/export', exportRouter);
//    app.use('/api/devices', devices);
//    app.use('/api/tasks', tasks);
//    app.use('/api/geofence', geofence);
//    app.use('/api/telemetry', telemetry);
//    app.use('/api/soc2', soc2);
//    app.use('/api/analytics', analytics);
//    app.use('/api/map', fleetMap);
//    app.use('/api/onboarding', onboarding);
//    startAutoBackup();
