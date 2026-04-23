// ═══════════════════════════════════════════════════════════════
// SBX GUARDIAN — INTELLIGENCE ENGINE
// Predictive maintenance, fleet scoring, behavioral AI
// ═══════════════════════════════════════════════════════════════
const { query, run, get } = require('./db');
const { v4: uuidv4 } = require('uuid');

// ── PREDICTIVE MAINTENANCE SCORING ────────────────────────────
function getMaintenanceScore(systemId) {
  const sys = get('SELECT * FROM systems WHERE id=?', [systemId]);
  if (!sys) return null;
  const cb = get('SELECT * FROM circuit_breakers WHERE system_id=?', [systemId]);
  const events7d = query('SELECT severity,type FROM events WHERE system_id=? AND timestamp>?', [systemId, Date.now()-7*86400000]);
  const anomalies = query('SELECT severity FROM anomalies WHERE system_id=? AND resolved=0', [systemId]);
  const lastMaint = sys.maintenance_due || 0;
  const overdueHours = lastMaint > 0 ? Math.max(0, (Date.now()-lastMaint)/3600000) : 0;

  let score = 100;
  score -= (100 - (sys.health||100)) * 0.4;
  score -= events7d.filter(e=>e.severity==='critical').length * 6;
  score -= events7d.filter(e=>e.severity==='warning').length * 2;
  score -= anomalies.filter(a=>a.severity==='critical').length * 10;
  score -= anomalies.filter(a=>a.severity==='warning').length * 4;
  score -= Math.min(30, overdueHours / 10);
  score -= cb?.status==='open' ? 15 : 0;
  score -= parseFloat(cb?.current_load||0) > 90 ? 10 : 0;

  const level = score > 75 ? 'good' : score > 50 ? 'fair' : score > 25 ? 'poor' : 'critical';
  const daysToMaintenance = Math.max(0, Math.round(score / 4));

  return {
    system_id: systemId,
    system_name: sys.name,
    maintenance_score: Math.max(0, Math.round(score)),
    level,
    days_to_maintenance: daysToMaintenance,
    overdue_hours: Math.round(overdueHours),
    factors: {
      health: sys.health,
      critical_events_7d: events7d.filter(e=>e.severity==='critical').length,
      warning_events_7d: events7d.filter(e=>e.severity==='warning').length,
      active_anomalies: anomalies.length,
      circuit_breaker: cb?.status||'unknown',
      current_load: parseFloat(cb?.current_load||0)
    }
  };
}

// ── FLEET INTELLIGENCE REPORT ─────────────────────────────────
function getFleetIntelligence(orgId) {
  const systems = query('SELECT id,name,status,health,type FROM systems WHERE org_id=?', [orgId]);
  const scores = systems.map(s => getMaintenanceScore(s.id)).filter(Boolean);
  const critical = scores.filter(s=>s.level==='critical');
  const poor = scores.filter(s=>s.level==='poor');
  const avgScore = scores.length ? Math.round(scores.reduce((a,b)=>a+b.maintenance_score,0)/scores.length) : 0;
  const totalEvents24h = get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND timestamp>?', [orgId, Date.now()-86400000]);
  const totalAnomalies = get('SELECT COUNT(*) as c FROM anomalies WHERE org_id=? AND resolved=0', [orgId]);

  return {
    fleet_health_score: avgScore,
    critical_systems: critical.length,
    poor_systems: poor.length,
    systems_needing_attention: [...critical, ...poor].map(s=>s.system_name),
    events_24h: totalEvents24h?.c||0,
    active_anomalies: totalAnomalies?.c||0,
    top_risks: scores.sort((a,b)=>a.maintenance_score-b.maintenance_score).slice(0,3),
    recommendation: critical.length > 0
      ? `URGENT: ${critical.length} system(s) require immediate maintenance`
      : poor.length > 0
      ? `${poor.length} system(s) should be scheduled for maintenance within 48 hours`
      : 'Fleet operating within normal parameters'
  };
}

// ── BEHAVIORAL BASELINE LEARNING ──────────────────────────────
function updateBaseline(systemId, orgId) {
  const loads = query('SELECT current_load FROM circuit_breakers WHERE system_id=?', [systemId]);
  const events = query('SELECT type,severity FROM events WHERE system_id=? AND timestamp>? ORDER BY timestamp DESC LIMIT 200', [systemId, Date.now()-7*86400000]);
  if (!loads.length) return;
  const avgLoad = loads.reduce((a,b)=>a+parseFloat(b.current_load||0),0)/loads.length;
  const eventFreq = events.length / 7;
  const criticalRate = events.filter(e=>e.severity==='critical').length / Math.max(events.length,1);
  const baseline = { avg_load: avgLoad.toFixed(2), event_freq_per_day: eventFreq.toFixed(2), critical_rate: criticalRate.toFixed(4), updated_at: Date.now() };
  run('UPDATE systems SET baseline_data=? WHERE id=? AND org_id=?', [JSON.stringify(baseline), systemId, orgId]);
  return baseline;
}

// ── INCIDENT TIMELINE BUILDER ──────────────────────────────────
function buildIncidentTimeline(systemId, orgId, fromTs, toTs) {
  const events = query('SELECT e.*,u.name as operator_name FROM events e LEFT JOIN users u ON u.id=e.operator_id WHERE e.system_id=? AND e.org_id=? AND e.timestamp BETWEEN ? AND ? ORDER BY e.timestamp ASC',
    [systemId, orgId, fromTs||Date.now()-86400000, toTs||Date.now()]);
  const anomalies = query('SELECT * FROM anomalies WHERE system_id=? AND org_id=? AND detected_at BETWEEN ? AND ? ORDER BY detected_at ASC',
    [systemId, orgId, fromTs||Date.now()-86400000, toTs||Date.now()]);
  const timeline = [
    ...events.map(e=>({...e, timeline_type:'event', time:e.timestamp})),
    ...anomalies.map(a=>({...a, timeline_type:'anomaly', time:a.detected_at}))
  ].sort((a,b)=>a.time-b.time);
  return { system_id:systemId, event_count:events.length, anomaly_count:anomalies.length, timeline, duration_hours: Math.round(((toTs||Date.now())-(fromTs||Date.now()-86400000))/3600000) };
}

// ── COMPLIANCE GAP ANALYSIS ────────────────────────────────────
function getComplianceGapAnalysis(orgId) {
  const items = query('SELECT * FROM compliance_items WHERE org_id=?', [orgId]);
  const byFramework = {};
  items.forEach(item => {
    if (!byFramework[item.framework]) byFramework[item.framework] = { pass:[], partial:[], fail:[], pending:[] };
    byFramework[item.framework][item.status]?.push(item);
  });
  const gaps = [];
  Object.entries(byFramework).forEach(([fw, data]) => {
    data.fail.forEach(item => gaps.push({ framework:fw, article:item.article, title:item.title, priority:'critical', action:`Immediately address ${item.title} to meet ${fw} ${item.article}` }));
    data.partial.forEach(item => gaps.push({ framework:fw, article:item.article, title:item.title, priority:'medium', action:`Complete implementation of ${item.title} for full ${fw} compliance` }));
  });
  const overallScore = items.length ? Math.round(items.filter(i=>i.status==='pass').length/items.length*100) : 0;
  const euAiActScore = byFramework['EU AI Act'] ? Math.round(byFramework['EU AI Act'].pass.length/Math.max(Object.values(byFramework['EU AI Act']).flat().length,1)*100) : 0;
  return { overall_score:overallScore, eu_ai_act_score:euAiActScore, gaps, by_framework:byFramework, days_to_enforcement:Math.ceil((new Date('2026-08-02')-Date.now())/86400000), enforcement_ready: euAiActScore >= 80 };
}

module.exports = { getMaintenanceScore, getFleetIntelligence, updateBaseline, buildIncidentTimeline, getComplianceGapAnalysis };
