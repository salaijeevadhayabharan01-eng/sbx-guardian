// ═══════════════════════════════════════════════════════════════
// SBX GUARDIAN — PUBLIC API LAYER
// Versioned REST API v1 for enterprise integrations
// Separate from internal routes — can be exposed to clients
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const router = express.Router();
const { query, run, get, computeHash } = require('./db');
const { v4: uuidv4 } = require('uuid');
const { getMaintenanceScore, getFleetIntelligence, getComplianceGapAnalysis } = require('./intelligence');
const { dispatchIntegrations } = require('./integrations');
const { REPORT_TEMPLATES, buildReportContext, buildPromptForTemplate } = require('./reports');
const { smartAI } = require('./ai');

function apiAuth(req, res, next) {
  const key = req.headers['x-api-key'] || req.query.api_key;
  if (!key) return res.status(401).json({ error:'API key required', docs:'Pass X-API-Key header' });
  const org = get('SELECT * FROM organizations WHERE webhook_secret=?',[key]);
  if (!org) return res.status(401).json({ error:'Invalid API key' });
  req.org = org;
  next();
}

// ── v1/status ──────────────────────────────────────────────────
router.get('/v1/status', (req, res) => {
  res.json({ status:'operational', version:'5.0.0', timestamp:new Date().toISOString(), days_to_eu_enforcement:Math.ceil((new Date('2026-08-02')-Date.now())/86400000) });
});

// ── v1/fleet ───────────────────────────────────────────────────
router.get('/v1/fleet', apiAuth, (req, res) => {
  const systems = query('SELECT s.*,cb.status as cb_status,cb.current_load FROM systems s LEFT JOIN circuit_breakers cb ON cb.system_id=s.id WHERE s.org_id=?',[req.org.id]);
  const intel = getFleetIntelligence(req.org.id);
  res.json({ fleet:systems.map(s=>({...s, maintenance_score:getMaintenanceScore(s.id)?.maintenance_score})), intelligence:intel });
});

// ── v1/events ──────────────────────────────────────────────────
router.get('/v1/events', apiAuth, (req, res) => {
  const { limit=50, offset=0, severity, from, to } = req.query;
  let sql = 'SELECT * FROM events WHERE org_id=?';
  const params = [req.org.id];
  if (severity){sql+=' AND severity=?';params.push(severity);}
  if (from){sql+=' AND timestamp>=?';params.push(parseInt(from));}
  if (to){sql+=' AND timestamp<=?';params.push(parseInt(to));}
  sql+=' ORDER BY timestamp DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit),parseInt(offset));
  res.json({ events:query(sql,params), total:get('SELECT COUNT(*) as c FROM events WHERE org_id=?',[req.org.id])?.c||0 });
});

router.post('/v1/events', apiAuth, (req, res) => {
  const { system_id,type,severity,message,data } = req.body;
  const id=uuidv4(), ts=Date.now();
  const last = get('SELECT hash FROM events WHERE org_id=? ORDER BY timestamp DESC LIMIT 1',[req.org.id]);
  const prevHash = last?.hash||'0'.repeat(64);
  const hash = computeHash({id,system_id:system_id||'api',type:type||'api',message:message||'API event',timestamp:ts},prevHash);
  run('INSERT INTO events (id,org_id,system_id,type,severity,message,data,prev_hash,hash,source,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
    [id,req.org.id,system_id||null,type||'info',severity||'info',message||'Event',JSON.stringify(data||{}),prevHash,hash,'api',ts]);
  if (severity==='critical') dispatchIntegrations(req.org.id,{type,severity,message,system_name:system_id});
  res.json({ success:true, event_id:id, hash, timestamp:ts });
});

// ── v1/chain/verify ────────────────────────────────────────────
router.get('/v1/chain/verify', apiAuth, (req, res) => {
  const events = query('SELECT id,hash,prev_hash,timestamp FROM events WHERE org_id=? ORDER BY timestamp ASC',[req.org.id]);
  let valid=true, broken_at=null, checked=0;
  for(let i=1;i<events.length;i++){
    checked++;
    if(events[i].prev_hash!==events[i-1].hash){valid=false;broken_at={event_id:events[i].id,timestamp:events[i].timestamp};break;}
  }
  res.json({ valid, total_events:events.length, events_checked:checked, broken_at, verified_at:new Date().toISOString(), certification:`VERIFY-${Date.now()}` });
});

// ── v1/compliance ──────────────────────────────────────────────
router.get('/v1/compliance', apiAuth, (req, res) => {
  const gaps = getComplianceGapAnalysis(req.org.id);
  res.json(gaps);
});

// ── v1/maintenance ─────────────────────────────────────────────
router.get('/v1/maintenance', apiAuth, (req, res) => {
  const systems = query('SELECT id FROM systems WHERE org_id=?',[req.org.id]);
  res.json(systems.map(s=>getMaintenanceScore(s.id)).filter(Boolean).sort((a,b)=>a.maintenance_score-b.maintenance_score));
});

// ── v1/report ──────────────────────────────────────────────────
router.post('/v1/report', apiAuth, async (req, res) => {
  try {
    const { template='eu_ai_act_conformity', description } = req.body;
    const context = buildReportContext(req.org.id);
    const prompt = buildPromptForTemplate(template, context, description);
    if (!prompt) return res.status(400).json({ error:'Invalid template', valid_templates:Object.keys(REPORT_TEMPLATES) });
    const result = await smartAI('evidence_report', { prompt, framework:REPORT_TEMPLATES[template]?.framework });
    res.json({ report:result.text, model:result.model, template, generated_at:new Date().toISOString(), context_snapshot:{ compliance_score:context.compliance.overall_score, fleet_health:context.fleet.avg_health, chain_valid:context.events.chain_valid } });
  } catch(e) { res.status(500).json({error:e.message}); }
});

// ── v1/integrations ────────────────────────────────────────────
router.get('/v1/integrations', apiAuth, (req, res) => {
  res.json(query('SELECT id,type,enabled,last_sync FROM integrations WHERE org_id=?',[req.org.id]));
});

router.post('/v1/integrations', apiAuth, (req, res) => {
  const { type, config, enabled } = req.body;
  const id = uuidv4();
  run('INSERT INTO integrations (id,org_id,type,config,enabled) VALUES (?,?,?,?,?)',[id,req.org.id,type,JSON.stringify(config||{}),enabled!==false?1:0]);
  res.json({ id, type, message:'Integration created' });
});

// ── v1/docs ────────────────────────────────────────────────────
router.get('/v1/docs', (req, res) => {
  res.json({
    name:'SBX Guardian API v1',
    version:'5.0.0',
    auth:'Pass your webhook secret as X-API-Key header',
    base_url:'/api/v1',
    endpoints:{
      'GET /v1/status':'API health check (no auth)',
      'GET /v1/fleet':'Fleet status + intelligence',
      'GET /v1/events':'Event log (filterable)',
      'POST /v1/events':'Log new event',
      'GET /v1/chain/verify':'Verify hash chain integrity',
      'GET /v1/compliance':'Compliance gap analysis',
      'GET /v1/maintenance':'Maintenance scores per system',
      'POST /v1/report':'Generate AI compliance report',
      'GET /v1/integrations':'List integrations',
      'POST /v1/integrations':'Add integration (slack/discord/pagerduty/webhook)'
    },
    report_templates: Object.entries(REPORT_TEMPLATES).map(([k,v])=>({key:k,name:v.name,framework:v.framework}))
  });
});

module.exports = router;
