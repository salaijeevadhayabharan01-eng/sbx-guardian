const initSqlJs = require('sql.js');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');

const DB_PATH = path.join(__dirname, 'sbx.db.json');
let db = null;

async function getDB() {
  if (db) return db;
  const SQL = await initSqlJs();
  if (fs.existsSync(DB_PATH)) {
    const saved = JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
    db = new SQL.Database(Buffer.from(saved.data, 'base64'));
  } else {
    db = new SQL.Database();
    initSchema();
  }
  return db;
}

function saveDB() {
  if (!db) return;
  fs.writeFileSync(DB_PATH, JSON.stringify({ data: Buffer.from(db.export()).toString('base64') }));
}

function initSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (
      id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL,
      name TEXT, role TEXT DEFAULT 'operator', org_id TEXT,
      two_fa_secret TEXT, last_login INTEGER,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS organizations (
      id TEXT PRIMARY KEY, name TEXT NOT NULL, industry TEXT,
      plan TEXT DEFAULT 'starter', max_systems INTEGER DEFAULT 10,
      webhook_secret TEXT, alert_email TEXT, slack_webhook TEXT,
      country TEXT, vat_number TEXT, soc2_status TEXT DEFAULT 'not_started',
      white_label INTEGER DEFAULT 0, custom_domain TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS systems (
      id TEXT PRIMARY KEY, org_id TEXT, name TEXT NOT NULL, type TEXT,
      location TEXT, status TEXT DEFAULT 'online', health INTEGER DEFAULT 100,
      firmware TEXT, ip TEXT, mac_address TEXT, webhook_token TEXT,
      manufacturer TEXT, model TEXT, serial_number TEXT,
      last_seen INTEGER, baseline_data TEXT, anomaly_score REAL DEFAULT 0,
      sla_uptime_target REAL DEFAULT 99.0, maintenance_due INTEGER,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS events (
      id TEXT PRIMARY KEY, org_id TEXT, system_id TEXT, type TEXT,
      severity TEXT DEFAULT 'info', message TEXT, data TEXT,
      prev_hash TEXT, hash TEXT, anomaly_flag INTEGER DEFAULT 0,
      source TEXT DEFAULT 'manual', geo_lat REAL, geo_lng REAL,
      operator_id TEXT, timestamp INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS firewall_rules (
      id TEXT PRIMARY KEY, org_id TEXT, name TEXT, description TEXT,
      action TEXT DEFAULT 'block', enabled INTEGER DEFAULT 1,
      mandatory INTEGER DEFAULT 0, hits INTEGER DEFAULT 0,
      priority INTEGER DEFAULT 50, conditions TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS circuit_breakers (
      id TEXT PRIMARY KEY, org_id TEXT, system_id TEXT,
      status TEXT DEFAULT 'closed', threshold REAL DEFAULT 80.0,
      current_load REAL DEFAULT 0.0, trip_count INTEGER DEFAULT 0,
      auto_reset INTEGER DEFAULT 0, reset_delay_seconds INTEGER DEFAULT 300,
      last_tripped INTEGER
    );
    CREATE TABLE IF NOT EXISTS compliance_items (
      id TEXT PRIMARY KEY, org_id TEXT, framework TEXT, article TEXT,
      title TEXT, description TEXT, status TEXT DEFAULT 'pending',
      evidence TEXT, assignee TEXT, due_date INTEGER,
      updated_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS reports (
      id TEXT PRIMARY KEY, org_id TEXT, title TEXT, type TEXT,
      content TEXT, framework TEXT, generated_by TEXT, ai_model TEXT,
      shared_token TEXT, shared_expires INTEGER,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS alerts (
      id TEXT PRIMARY KEY, org_id TEXT, system_id TEXT, type TEXT,
      message TEXT, severity TEXT, resolved INTEGER DEFAULT 0,
      resolved_by TEXT, resolved_at INTEGER, escalated INTEGER DEFAULT 0,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS anomalies (
      id TEXT PRIMARY KEY, org_id TEXT, system_id TEXT,
      metric TEXT, expected REAL, actual REAL, deviation REAL,
      severity TEXT, resolved INTEGER DEFAULT 0, root_cause TEXT,
      detected_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS audit_exports (
      id TEXT PRIMARY KEY, org_id TEXT, generated_by TEXT,
      from_ts INTEGER, to_ts INTEGER, event_count INTEGER,
      chain_valid INTEGER, certification TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS sla_records (
      id TEXT PRIMARY KEY, org_id TEXT, system_id TEXT,
      date TEXT, uptime_pct REAL, incidents INTEGER, mttr_minutes REAL,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS regulatory_updates (
      id TEXT PRIMARY KEY, framework TEXT, title TEXT, summary TEXT,
      impact TEXT, effective_date TEXT, source_url TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS integrations (
      id TEXT PRIMARY KEY, org_id TEXT, type TEXT, config TEXT,
      enabled INTEGER DEFAULT 1, last_sync INTEGER,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
    CREATE TABLE IF NOT EXISTS waitlist (
      id TEXT PRIMARY KEY, email TEXT UNIQUE, company TEXT,
      role TEXT, systems_count TEXT, message TEXT,
      created_at INTEGER DEFAULT (strftime('%s','now'))
    );
  `);
  saveDB();
}

function computeHash(event, prevHash) {
  const payload = `${event.id}|${event.system_id}|${event.type}|${event.message}|${event.timestamp}|${prevHash}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function query(sql, params = []) {
  try {
    const stmt = db.prepare(sql);
    stmt.bind(params);
    const rows = [];
    while (stmt.step()) rows.push(stmt.getAsObject());
    stmt.free();
    return rows;
  } catch(e) { console.error('DB query error:', e.message, sql); return []; }
}

function run(sql, params = []) {
  try { db.run(sql, params); saveDB(); }
  catch(e) { console.error('DB run error:', e.message); }
}

function get(sql, params = []) { return query(sql, params)[0] || null; }

module.exports = { getDB, saveDB, query, run, get, computeHash };
