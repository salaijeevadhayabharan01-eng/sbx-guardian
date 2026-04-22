const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const { getDB, query, run, get, computeHash, saveDB } = require('./db');

const app = express();
const JWT_SECRET = process.env.JWT_SECRET || 'sbx-guardian-secret-2026';
app.use(express.json());
app.use(express.static(__dirname));

function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h || !h.startsWith('Bearer ')) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { return res.status(401).json({ error: 'Invalid token' }); }
}

// AUTH
app.post('/api/auth/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    const user = get('SELECT * FROM users WHERE email = ?', [email]);
    if (!user || !(await bcrypt.compare(password, user.password))) return res.status(401).json({ error: 'Invalid credentials' });
    const token = jwt.sign({ id: user.id, email: user.email, role: user.role, name: user.name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id: user.id, email: user.email, name: user.name, role: user.role } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

app.post('/api/auth/register', async (req, res) => {
  try {
    const { email, password, name } = req.body;
    if (get('SELECT id FROM users WHERE email = ?', [email])) return res.status(400).json({ error: 'Email exists' });
    const id = uuidv4();
    run('INSERT INTO users (id,email,password,name) VALUES (?,?,?,?)', [id, email, await bcrypt.hash(password, 10), name]);
    const token = jwt.sign({ id, email, role: 'operator', name }, JWT_SECRET, { expiresIn: '24h' });
    res.json({ token, user: { id, email, name, role: 'operator' } });
  } catch(e) { res.status(500).json({ error: e.message }); }
});

// DASHBOARD
app.get('/api/dashboard', auth, (req, res) => {
  const systems = query('SELECT status FROM systems');
  const events24h = get('SELECT COUNT(*) as c FROM events WHERE timestamp > ?', [Date.now() - 86400000]);
  const critical = get('SELECT COUNT(*) as c FROM events WHERE severity = ? AND timestamp > ?', ['critical', Date.now() - 86400000]);
  const compliance = query('SELECT status FROM compliance_items');
  const passing = compliance.filter(c => c.status === 'pass').length;
  const recentEvents = query('SELECT e.*, s.name as system_name FROM events e LEFT JOIN systems s ON s.id = e.system_id ORDER BY e.timestamp DESC LIMIT 10');
  const daysUntilEU = Math.ceil((new Date('2026-08-02').getTime() - Date.now()) / 86400000);
  res.json({
    systems: { total: systems.length, online: systems.filter(s=>s.status==='online').length, warnings: systems.filter(s=>s.status==='warning').length, offline: systems.filter(s=>s.status==='offline').length },
    events: { last24h: events24h?.c || 0, critical: critical?.c || 0 },
    compliance: { score: compliance.length ? Math.round(passing/compliance.length*100) : 0, passing, total: compliance.length },
    eu_ai_act_days: daysUntilEU,
    recent_events: recentEvents
  });
});

// SYSTEMS
app.get('/api/systems', auth, (req, res) => res.json(query('SELECT s.*, cb.status as cb_status, cb.current_load, cb.threshold, cb.trip_count FROM systems s LEFT JOIN circuit_breakers cb ON cb.system_id = s.id ORDER BY s.name')));
app.post('/api/systems', auth, (req, res) => {
  const { name, type, location, firmware, ip } = req.body;
  const id = uuidv4();
  run('INSERT INTO systems (id,name,type,location,firmware,ip,last_seen) VALUES (?,?,?,?,?,?,?)', [id, name, type||'robot', location||'Unknown', firmware||'1.0.0', ip||'0.0.0.0', Date.now()]);
  run('INSERT INTO circuit_breakers (id,system_id,threshold) VALUES (?,?,?)', [uuidv4(), id, 80]);
  res.json({ id, name, status: 'online', health: 100 });
});
app.put('/api/systems/:id', auth, (req, res) => {
  const { name, type, location, status, health, firmware, ip } = req.body;
  run('UPDATE systems SET name=COALESCE(?,name),type=COALESCE(?,type),location=COALESCE(?,location),status=COALESCE(?,status),health=COALESCE(?,health),firmware=COALESCE(?,firmware),ip=COALESCE(?,ip),last_seen=? WHERE id=?', [name,type,location,status,health,firmware,ip,Date.now(),req.params.id]);
  res.json({ success: true });
});
app.delete('/api/systems/:id', auth, (req, res) => { run('DELETE FROM systems WHERE id=?', [req.params.id]); res.json({ success: true }); });

// EVENTS
app.get('/api/events', auth, (req, res) => {
  const { system_id, severity, limit=100, offset=0 } = req.query;
  let sql = 'SELECT e.*, s.name as system_name FROM events e LEFT JOIN systems s ON s.id = e.system_id WHERE 1=1';
  const params = [];
  if (system_id) { sql += ' AND e.system_id=?'; params.push(system_id); }
  if (severity) { sql += ' AND e.severity=?'; params.push(severity); }
  sql += ' ORDER BY e.timestamp DESC LIMIT ? OFFSET ?';
  params.push(parseInt(limit), parseInt(offset));
  res.json({ events: query(sql, params), total: get('SELECT COUNT(*) as c FROM events')?.c || 0 });
});
app.post('/api/events', auth, (req, res) => {
  const { system_id, type, severity, message, data } = req.body;
  const id = uuidv4(), ts = Date.now();
  const last = get('SELECT hash FROM events ORDER BY timestamp DESC LIMIT 1');
  const prevHash = last?.hash || '0'.repeat(64);
  const hash = computeHash({ id, system_id: system_id||'system', type, message, timestamp: ts }, prevHash);
  run('INSERT INTO events (id,system_id,type,severity,message,data,prev_hash,hash,timestamp) VALUES (?,?,?,?,?,?,?,?,?)', [id, system_id||null, type||'info', severity||'info', message, JSON.stringify(data||{}), prevHash, hash, ts]);
  const ev = get('SELECT e.*, s.name as system_name FROM events e LEFT JOIN systems s ON s.id=e.system_id WHERE e.id=?', [id]);
  if (app.locals.broadcast) app.locals.broadcast({ type: 'NEW_EVENT', data: ev });
  res.json(ev);
});
app.get('/api/events/verify', auth, (req, res) => {
  const events = query('SELECT * FROM events ORDER BY timestamp ASC');
  let valid = true, broken_at = null;
  for (let i = 1; i < events.length; i++) {
    if (events[i].prev_hash !== events[i-1].hash) { valid = false; broken_at = events[i].id; break; }
  }
  res.json({ valid, total: events.length, broken_at });
});

// FIREWALL
app.get('/api/safety/rules', auth, (req, res) => res.json(query('SELECT * FROM firewall_rules ORDER BY mandatory DESC, created_at ASC')));
app.post('/api/safety/rules', auth, (req, res) => {
  const { name, description, action, enabled, mandatory } = req.body;
  const id = uuidv4();
  run('INSERT INTO firewall_rules (id,name,description,action,enabled,mandatory) VALUES (?,?,?,?,?,?)', [id, name, description||'', action||'block', enabled?1:0, mandatory?1:0]);
  res.json({ id });
});
app.put('/api/safety/rules/:id', auth, (req, res) => {
  const rule = get('SELECT * FROM firewall_rules WHERE id=?', [req.params.id]);
  if (!rule) return res.status(404).json({ error: 'Not found' });
  if (rule.mandatory && req.body.enabled === false) return res.status(403).json({ error: 'Cannot disable mandatory rule' });
  const { name, description, action, enabled } = req.body;
  run('UPDATE firewall_rules SET name=COALESCE(?,name),description=COALESCE(?,description),action=COALESCE(?,action),enabled=COALESCE(?,enabled) WHERE id=?', [name,description,action,enabled!==undefined?(enabled?1:0):null,req.params.id]);
  res.json({ success: true });
});
app.delete('/api/safety/rules/:id', auth, (req, res) => {
  if (get('SELECT mandatory FROM firewall_rules WHERE id=?', [req.params.id])?.mandatory) return res.status(403).json({ error: 'Cannot delete mandatory rule' });
  run('DELETE FROM firewall_rules WHERE id=?', [req.params.id]); res.json({ success: true });
});

// CIRCUIT BREAKERS
app.get('/api/safety/breakers', auth, (req, res) => res.json(query('SELECT cb.*, s.name as system_name, s.type as system_type, s.location FROM circuit_breakers cb JOIN systems s ON s.id=cb.system_id ORDER BY s.name')));
app.put('/api/safety/breakers/:id', auth, (req, res) => {
  const { status, threshold } = req.body;
  run('UPDATE circuit_breakers SET status=COALESCE(?,status),threshold=COALESCE(?,threshold),last_tripped=COALESCE(?,last_tripped) WHERE id=?', [status,threshold,status==='open'?Date.now():null,req.params.id]);
  if (app.locals.broadcast) app.locals.broadcast({ type:'BREAKER_UPDATE', data:{ id:req.params.id, status } });
  res.json({ success: true });
});

// COMPLIANCE
app.get('/api/safety/compliance', auth, (req, res) => res.json(query('SELECT * FROM compliance_items ORDER BY framework, article')));
app.put('/api/safety/compliance/:id', auth, (req, res) => {
  run('UPDATE compliance_items SET status=COALESCE(?,status),evidence=COALESCE(?,evidence),updated_at=? WHERE id=?', [req.body.status,req.body.evidence,Date.now(),req.params.id]);
  res.json({ success: true });
});

// REPORTS
app.get('/api/safety/reports', auth, (req, res) => res.json(query('SELECT id,title,type,framework,generated_by,created_at FROM reports ORDER BY created_at DESC')));
app.get('/api/safety/reports/:id', auth, (req, res) => {
  const r = get('SELECT * FROM reports WHERE id=?', [req.params.id]);
  if (!r) return res.status(404).json({ error: 'Not found' });
  res.json(r);
});
app.post('/api/safety/reports', auth, (req, res) => {
  const { title, type, content, framework } = req.body;
  const id = uuidv4();
  run('INSERT INTO reports (id,title,type,content,framework,generated_by) VALUES (?,?,?,?,?,?)', [id, title, type||'incident', content, framework||'general', req.user.name||req.user.email]);
  res.json({ id });
});

// SERVE FRONTEND
app.get('*', (req, res) => res.sendFile(path.join(__dirname, 'index.html')));

// WEBSOCKET + SERVER
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });
const clients = new Set();
wss.on('connection', ws => { clients.add(ws); ws.on('close', () => clients.delete(ws)); });
app.locals.broadcast = data => { const msg = JSON.stringify(data); clients.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(msg); }); };

// LIVE TELEMETRY
setInterval(() => {
  const systems = query('SELECT id FROM systems WHERE status != "offline"');
  if (!systems.length) return;
  systems.forEach(s => run('UPDATE circuit_breakers SET current_load=? WHERE system_id=?', [(20+Math.random()*60).toFixed(1), s.id]));
  if (Math.random() < 0.3) {
    const s = systems[Math.floor(Math.random()*systems.length)];
    const types = ['heartbeat','health_check','command','sensor_read'];
    const id = uuidv4(), ts = Date.now();
    const last = get('SELECT hash FROM events ORDER BY timestamp DESC LIMIT 1');
    const prevHash = last?.hash || '0'.repeat(64);
    const type = types[Math.floor(Math.random()*types.length)];
    const message = `Automated ${type}`;
    const hash = computeHash({ id, system_id: s.id, type, message, timestamp: ts }, prevHash);
    run('INSERT INTO events (id,system_id,type,severity,message,data,prev_hash,hash,timestamp) VALUES (?,?,?,?,?,?,?,?,?)', [id, s.id, type, 'info', message, '{}', prevHash, hash, ts]);
  }
  app.locals.broadcast({ type: 'TELEMETRY', data: { timestamp: Date.now() } });
}, 5000);

getDB().then(() => {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log(`\n✅ SBX Guardian running at http://localhost:${PORT}\n`));
}).catch(console.error);
