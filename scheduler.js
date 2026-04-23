// ═══════════════════════════════════════════════════════════════
// SBX GUARDIAN — BACKGROUND SCHEDULER
// Automated tasks: health checks, SLA calc, baseline updates,
// compliance reminders, regulatory polling
// ═══════════════════════════════════════════════════════════════
const { query, run, get, saveDB } = require('./db');
const { v4: uuidv4 } = require('uuid');
const { updateBaseline, getMaintenanceScore } = require('./intelligence');
const { sendAlert } = require('./alerts');

let schedulerStarted = false;

function startScheduler(broadcast) {
  if (schedulerStarted) return;
  schedulerStarted = true;
  console.log('⏱  Scheduler started');

  // ── Every 5 min: Update SLA records ──────────────────────────
  setInterval(() => {
    try {
      const orgs = query('SELECT id FROM organizations');
      orgs.forEach(org => {
        const systems = query('SELECT * FROM systems WHERE org_id=?',[org.id]);
        const today = new Date().toISOString().split('T')[0];
        systems.forEach(s => {
          const existing = get('SELECT id FROM sla_records WHERE system_id=? AND date=?',[s.id,today]);
          const uptimePct = s.status==='offline' ? 0 : s.status==='warning' ? 95.0 : 99.5;
          const incidents = get('SELECT COUNT(*) as c FROM events WHERE system_id=? AND severity=? AND timestamp>?',[s.id,'critical',Date.now()-86400000]);
          if (existing) {
            run('UPDATE sla_records SET uptime_pct=?,incidents=? WHERE system_id=? AND date=?',[uptimePct,incidents?.c||0,s.id,today]);
          } else {
            run('INSERT INTO sla_records (id,org_id,system_id,date,uptime_pct,incidents) VALUES (?,?,?,?,?,?)',[uuidv4(),org.id,s.id,today,uptimePct,incidents?.c||0]);
          }
        });
      });
    } catch(e) { console.log('SLA scheduler error:', e.message); }
  }, 5*60*1000);

  // ── Every 15 min: Update behavioral baselines ─────────────────
  setInterval(() => {
    try {
      const systems = query('SELECT id,org_id FROM systems WHERE status != "offline"');
      systems.forEach(s => updateBaseline(s.id, s.org_id));
    } catch(e) { console.log('Baseline scheduler error:', e.message); }
  }, 15*60*1000);

  // ── Every 30 min: Maintenance alerts ─────────────────────────
  setInterval(() => {
    try {
      const systems = query('SELECT id,org_id,name FROM systems');
      systems.forEach(s => {
        const score = getMaintenanceScore(s.id);
        if (score?.level==='critical') {
          sendAlert(s.org_id, 'Maintenance Required', `${s.name} maintenance score is critical (${score.maintenance_score}/100). Immediate attention required.`, 'critical', s.id);
          if (broadcast) broadcast(s.org_id, { type:'MAINTENANCE_ALERT', data:score });
        }
      });
    } catch(e) { console.log('Maintenance scheduler error:', e.message); }
  }, 30*60*1000);

  // ── Every hour: EU AI Act deadline reminder (if <30 days) ─────
  setInterval(() => {
    try {
      const daysLeft = Math.ceil((new Date('2026-08-02')-Date.now())/86400000);
      if (daysLeft <= 30 && daysLeft > 0) {
        const orgs = query('SELECT id FROM organizations');
        orgs.forEach(org => {
          const comp = query('SELECT status FROM compliance_items WHERE org_id=? AND framework=?',[org.id,'EU AI Act']);
          const passing = comp.filter(c=>c.status==='pass').length;
          const score = comp.length ? Math.round(passing/comp.length*100) : 0;
          if (score < 80) {
            sendAlert(org.id, 'EU AI Act Deadline', `${daysLeft} days until enforcement. Your EU AI Act compliance score is ${score}%. Immediate action required.`, 'critical', null);
          }
        });
      }
    } catch(e) { console.log('EU deadline scheduler error:', e.message); }
  }, 60*60*1000);

  // ── Every 6 hours: Auto-reset circuit breakers with auto_reset=1 ─
  setInterval(() => {
    try {
      const breakers = query('SELECT cb.*,s.org_id FROM circuit_breakers cb JOIN systems s ON s.id=cb.system_id WHERE cb.status="open" AND cb.auto_reset=1');
      breakers.forEach(b => {
        const tripTime = b.last_tripped||0;
        const resetDelay = (b.reset_delay_seconds||300)*1000;
        if (Date.now()-tripTime > resetDelay) {
          run('UPDATE circuit_breakers SET status="closed" WHERE id=?',[b.id]);
          if (broadcast) broadcast(b.org_id,{type:'BREAKER_RESET',data:{id:b.id,system_id:b.system_id}});
        }
      });
    } catch(e) { console.log('Auto-reset scheduler error:', e.message); }
  }, 6*60*60*1000);

  // ── Every 24 hours: Generate daily fleet digest ───────────────
  setInterval(() => {
    try {
      const orgs = query('SELECT id FROM organizations');
      orgs.forEach(org => {
        const systems = query('SELECT status FROM systems WHERE org_id=?',[org.id]);
        const events24h = get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND timestamp>?',[org.id,Date.now()-86400000]);
        const critical = get('SELECT COUNT(*) as c FROM events WHERE org_id=? AND severity=? AND timestamp>?',[org.id,'critical',Date.now()-86400000]);
        const digest = { date:new Date().toISOString().split('T')[0], systems_online:systems.filter(s=>s.status==='online').length, total_systems:systems.length, events_24h:events24h?.c||0, critical_events:critical?.c||0 };
        if (broadcast) broadcast(org.id,{type:'DAILY_DIGEST',data:digest});
      });
    } catch(e) { console.log('Digest scheduler error:', e.message); }
  }, 24*60*60*1000);
}

module.exports = { startScheduler };
