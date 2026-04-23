// ═══════════════════════════════════════════════════════════════
// SBX GUARDIAN — HEALTH & METRICS ENDPOINTS
// Uptime, performance, database health, API metrics
// Used by monitoring services and uptime checkers
// ═══════════════════════════════════════════════════════════════
const express = require('express');
const router = express.Router();
const { get, query } = require('./db');

const startTime = Date.now();
let requestCount = 0;
let errorCount = 0;

function incrementRequests() { requestCount++; }
function incrementErrors() { errorCount++; }

router.get('/health', (req, res) => {
  try {
    const dbCheck = get('SELECT COUNT(*) as c FROM users');
    const uptime = Math.round((Date.now()-startTime)/1000);
    res.json({
      status: 'healthy',
      version: '5.0.0',
      uptime_seconds: uptime,
      uptime_human: formatUptime(uptime),
      database: dbCheck!==null ? 'connected' : 'error',
      timestamp: new Date().toISOString(),
      eu_ai_act_days: Math.ceil((new Date('2026-08-02')-Date.now())/86400000)
    });
  } catch(e) {
    res.status(500).json({ status:'unhealthy', error:e.message });
  }
});

router.get('/metrics', (req, res) => {
  try {
    const totalUsers = get('SELECT COUNT(*) as c FROM users');
    const totalOrgs = get('SELECT COUNT(*) as c FROM organizations');
    const totalSystems = get('SELECT COUNT(*) as c FROM systems');
    const totalEvents = get('SELECT COUNT(*) as c FROM events');
    const activeAnomalies = get('SELECT COUNT(*) as c FROM anomalies WHERE resolved=0');
    const waitlistCount = get('SELECT COUNT(*) as c FROM waitlist');
    res.json({
      platform: { version:'5.0.0', uptime_seconds:Math.round((Date.now()-startTime)/1000) },
      usage: { total_organizations:totalOrgs?.c||0, total_users:totalUsers?.c||0, total_systems:totalSystems?.c||0, total_events:totalEvents?.c||0 },
      health: { active_anomalies:activeAnomalies?.c||0 },
      growth: { waitlist_signups:waitlistCount?.c||0 },
      timestamp: new Date().toISOString()
    });
  } catch(e) { res.status(500).json({error:e.message}); }
});

router.get('/ping', (req, res) => res.json({ pong:true, ts:Date.now() }));

function formatUptime(seconds) {
  const d=Math.floor(seconds/86400), h=Math.floor((seconds%86400)/3600), m=Math.floor((seconds%3600)/60), s=seconds%60;
  return `${d}d ${h}h ${m}m ${s}s`;
}

module.exports = { router, incrementRequests, incrementErrors };
