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
    const buf = Buffer.from(saved.data, 'base64');
    db = new SQL.Database(buf);
  } else {
    db = new SQL.Database();
    initSchema();
  }
  return db;
}

function saveDB() {
  if (!db) return;
  const data = db.export();
  fs.writeFileSync(DB_PATH, JSON.stringify({ data: Buffer.from(data).toString('base64') }));
}

function initSchema() {
  db.run(`
    CREATE TABLE IF NOT EXISTS users (id TEXT PRIMARY KEY, email TEXT UNIQUE NOT NULL, password TEXT NOT NULL, name TEXT, role TEXT DEFAULT 'operator', created_at INTEGER DEFAULT (strftime('%s','now')));
    CREATE TABLE IF NOT EXISTS systems (id TEXT PRIMARY KEY, name TEXT NOT NULL, type TEXT, location TEXT, status TEXT DEFAULT 'online', health INTEGER DEFAULT 100, firmware TEXT, ip TEXT, last_seen INTEGER, created_at INTEGER DEFAULT (strftime('%s','now')));
    CREATE TABLE IF NOT EXISTS events (id TEXT PRIMARY KEY, system_id TEXT, type TEXT, severity TEXT DEFAULT 'info', message TEXT, data TEXT, prev_hash TEXT, hash TEXT, timestamp INTEGER DEFAULT (strftime('%s','now')));
    CREATE TABLE IF NOT EXISTS firewall_rules (id TEXT PRIMARY KEY, name TEXT, description TEXT, action TEXT DEFAULT 'block', enabled INTEGER DEFAULT 1, mandatory INTEGER DEFAULT 0, hits INTEGER DEFAULT 0, created_at INTEGER DEFAULT (strftime('%s','now')));
    CREATE TABLE IF NOT EXISTS circuit_breakers (id TEXT PRIMARY KEY, system_id TEXT, status TEXT DEFAULT 'closed', threshold REAL DEFAULT 80.0, current_load REAL DEFAULT 0.0, trip_count INTEGER DEFAULT 0, last_tripped INTEGER);
    CREATE TABLE IF NOT EXISTS compliance_items (id TEXT PRIMARY KEY, framework TEXT, article TEXT, title TEXT, description TEXT, status TEXT DEFAULT 'pending', evidence TEXT, updated_at INTEGER DEFAULT (strftime('%s','now')));
    CREATE TABLE IF NOT EXISTS reports (id TEXT PRIMARY KEY, title TEXT, type TEXT, content TEXT, framework TEXT, generated_by TEXT, created_at INTEGER DEFAULT (strftime('%s','now')));
  `);
  saveDB();
}

function computeHash(event, prevHash) {
  const payload = `${event.id}|${event.system_id}|${event.type}|${event.message}|${event.timestamp}|${prevHash}`;
  return crypto.createHash('sha256').update(payload).digest('hex');
}

function query(sql, params = []) {
  const stmt = db.prepare(sql);
  stmt.bind(params);
  const rows = [];
  while (stmt.step()) rows.push(stmt.getAsObject());
  stmt.free();
  return rows;
}

function run(sql, params = []) { db.run(sql, params); saveDB(); }

function get(sql, params = []) { return query(sql, params)[0] || null; }

module.exports = { getDB, saveDB, query, run, get, computeHash };
