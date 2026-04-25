// SBX GUARDIAN — BUILT-IN CRM
// Track every prospect from first touch to signed contract
const express = require('express');
const router = express.Router();
const { v4: uuidv4 } = require('uuid');
const { query, run, get } = require('./db');
const jwt = require('jsonwebtoken');

function auth(req, res, next) {
  try { req.user = jwt.verify(req.headers.authorization?.slice(7), process.env.JWT_SECRET||'sbx-guardian-2026'); next(); }
  catch { res.status(401).json({ error: 'Unauthorized' }); }
}

// CRM tables added via migration
function initCRMTables() {
  try {
    const { db, saveDB } = require('./db');
    // These are added via the main db schema
  } catch {}
}

// PROSPECTS
router.get('/prospects', auth, (req, res) => {
  const prospects = query(`
    SELECT p.*, 
      (SELECT COUNT(*) FROM crm_activities WHERE prospect_id = p.id) as activity_count,
      (SELECT MAX(created_at) FROM crm_activities WHERE prospect_id = p.id) as last_activity
    FROM crm_prospects p
    WHERE p.org_id = ?
    ORDER BY p.score DESC, p.created_at DESC
  `, [req.user.org_id]);
  res.json(prospects);
});

router.post('/prospects', auth, (req, res) => {
  const { company, contact_name, email, phone, title, industry, country, systems_count, source, notes } = req.body;
  const id = uuidv4();
  // Score based on data completeness and fit
  let score = 0;
  if (email) score += 20;
  if (phone) score += 10;
  if (company) score += 15;
  if (country && ['Germany','France','Netherlands','Denmark','Belgium','Austria','Sweden'].includes(country)) score += 25;
  if (systems_count && parseInt(systems_count) > 10) score += 20;
  if (industry && ['manufacturing','automotive','robotics','logistics'].includes(industry?.toLowerCase())) score += 10;

  run('INSERT INTO crm_prospects (id,org_id,company,contact_name,email,phone,title,industry,country,systems_count,source,notes,score,stage) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    [id, req.user.org_id, company||'', contact_name||'', email||'', phone||'', title||'', industry||'', country||'', systems_count||'', source||'manual', notes||'', score, 'lead']);

  // Log activity
  run('INSERT INTO crm_activities (id,prospect_id,org_id,type,description,created_by) VALUES (?,?,?,?,?,?)',
    [uuidv4(), id, req.user.org_id, 'created', `Prospect added from ${source||'manual entry'}`, req.user.name]);

  res.json({ id, score });
});

router.put('/prospects/:id', auth, (req, res) => {
  const { company, contact_name, email, phone, title, stage, notes, score, deal_value } = req.body;
  run('UPDATE crm_prospects SET company=COALESCE(?,company),contact_name=COALESCE(?,contact_name),email=COALESCE(?,email),phone=COALESCE(?,phone),title=COALESCE(?,title),stage=COALESCE(?,stage),notes=COALESCE(?,notes),score=COALESCE(?,score),deal_value=COALESCE(?,deal_value),updated_at=? WHERE id=? AND org_id=?',
    [company,contact_name,email,phone,title,stage,notes,score,deal_value,Date.now(),req.params.id,req.user.org_id]);

  if (req.body.stage) {
    run('INSERT INTO crm_activities (id,prospect_id,org_id,type,description,created_by) VALUES (?,?,?,?,?,?)',
      [uuidv4(), req.params.id, req.user.org_id, 'stage_change', `Stage changed to ${req.body.stage}`, req.user.name]);
  }
  res.json({ success: true });
});

router.delete('/prospects/:id', auth, (req, res) => {
  run('DELETE FROM crm_prospects WHERE id=? AND org_id=?', [req.params.id, req.user.org_id]);
  res.json({ success: true });
});

// ACTIVITIES (calls, emails, meetings)
router.get('/prospects/:id/activities', auth, (req, res) => {
  res.json(query('SELECT * FROM crm_activities WHERE prospect_id=? AND org_id=? ORDER BY created_at DESC', [req.params.id, req.user.org_id]));
});

router.post('/prospects/:id/activities', auth, (req, res) => {
  const { type, description, outcome, next_action, next_action_date } = req.body;
  const id = uuidv4();
  run('INSERT INTO crm_activities (id,prospect_id,org_id,type,description,outcome,next_action,next_action_date,created_by) VALUES (?,?,?,?,?,?,?,?,?)',
    [id, req.params.id, req.user.org_id, type||'note', description||'', outcome||'', next_action||'', next_action_date||null, req.user.name]);

  // Update prospect last_contacted
  run('UPDATE crm_prospects SET last_contacted=? WHERE id=? AND org_id=?', [Date.now(), req.params.id, req.user.org_id]);
  res.json({ id });
});

// PIPELINE STATS
router.get('/pipeline', auth, (req, res) => {
  const stages = ['lead', 'contacted', 'demo_booked', 'proposal_sent', 'negotiating', 'closed_won', 'closed_lost'];
  const pipeline = stages.map(stage => {
    const prospects = query('SELECT COUNT(*) as count, SUM(COALESCE(deal_value,0)) as value FROM crm_prospects WHERE org_id=? AND stage=?', [req.user.org_id, stage]);
    return { stage, count: prospects[0]?.count||0, value: prospects[0]?.value||0 };
  });

  const totalPipeline = pipeline.reduce((a,b) => a + (b.value||0), 0);
  const wonDeals = pipeline.find(p=>p.stage==='closed_won');
  const hotProspects = query('SELECT * FROM crm_prospects WHERE org_id=? AND score>=70 AND stage NOT IN (?,?) ORDER BY score DESC LIMIT 5', [req.user.org_id, 'closed_won', 'closed_lost']);

  res.json({ stages: pipeline, total_pipeline: totalPipeline, won_deals: wonDeals?.count||0, won_value: wonDeals?.value||0, hot_prospects: hotProspects });
});

// IMPORT FROM WAITLIST
router.post('/import-waitlist', auth, (req, res) => {
  const waitlist = query('SELECT * FROM waitlist WHERE org_id IS NULL OR org_id = ?', [req.user.org_id]);
  let imported = 0;
  waitlist.forEach(w => {
    const exists = get('SELECT id FROM crm_prospects WHERE email=? AND org_id=?', [w.email, req.user.org_id]);
    if (!exists && w.email) {
      run('INSERT INTO crm_prospects (id,org_id,company,contact_name,email,source,stage,score,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
        [uuidv4(), req.user.org_id, w.company||'', '', w.email, 'waitlist', 'lead', 50, w.created_at]);
      imported++;
    }
  });
  res.json({ imported, total_waitlist: waitlist.length });
});

module.exports = router;
