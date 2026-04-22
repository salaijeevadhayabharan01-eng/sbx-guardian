const express = require('express');
const http = require('http');
const WebSocket = require('ws');
const path = require('path');
const { getDB } = require('./db');

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, '../public')));

// Routes
app.use('/api/auth', require('./routes/auth'));
app.use('/api/systems', require('./routes/systems'));
app.use('/api/events', require('./routes/events'));
app.use('/api/safety', require('./routes/safety'));

// Dashboard stats
app.get('/api/dashboard', require('./middleware/auth').authMiddleware, (req, res) => {
  const { query, get } = require('./db');
  const systems = query('SELECT status FROM systems');
  const online = systems.filter(s => s.status === 'online').length;
  const warnings = systems.filter(s => s.status === 'warning').length;
  const offline = systems.filter(s => s.status === 'offline').length;
  const events24h = get(`SELECT COUNT(*) as c FROM events WHERE timestamp > ?`, [Date.now() - 86400000]);
  const critical = get(`SELECT COUNT(*) as c FROM events WHERE severity = 'critical' AND timestamp > ?`, [Date.now() - 86400000]);
  const incidents = get(`SELECT COUNT(*) as c FROM events WHERE type = 'incident'`);
  const compliance = query('SELECT status FROM compliance_items');
  const passing = compliance.filter(c => c.status === 'pass').length;
  const complianceScore = compliance.length ? Math.round((passing / compliance.length) * 100) : 0;
  
  // Recent events
  const recentEvents = query(`
    SELECT e.*, s.name as system_name FROM events e
    LEFT JOIN systems s ON s.id = e.system_id
    ORDER BY e.timestamp DESC LIMIT 10
  `);
  
  const daysUntilEU = Math.ceil((new Date('2026-08-02').getTime() - Date.now()) / 86400000);
  
  res.json({
    systems: { total: systems.length, online, warnings, offline },
    events: { last24h: events24h?.c || 0, critical: critical?.c || 0, total_incidents: incidents?.c || 0 },
    compliance: { score: complianceScore, passing, total: compliance.length },
    eu_ai_act_days: daysUntilEU,
    recent_events: recentEvents
  });
});

// Serve frontend
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../public/index.html'));
});

// HTTP + WebSocket server
const server = http.createServer(app);
const wss = new WebSocket.Server({ server });

const clients = new Set();
wss.on('connection', (ws) => {
  clients.add(ws);
  ws.on('close', () => clients.delete(ws));
});

app.locals.broadcast = (data) => {
  const msg = JSON.stringify(data);
  clients.forEach(ws => { if (ws.readyState === WebSocket.OPEN) ws.send(msg); });
};

// Simulate live telemetry
setInterval(() => {
  const { query, run, get, computeHash } = require('./db');
  const { v4: uuidv4 } = require('uuid');
  const systems = query('SELECT id FROM systems WHERE status != "offline"');
  if (!systems.length) return;
  
  // Random load update
  systems.forEach(s => {
    const load = 20 + Math.random() * 60;
    run('UPDATE circuit_breakers SET current_load = ? WHERE system_id = ?', [load.toFixed(1), s.id]);
  });

  // Occasional random event
  if (Math.random() < 0.3) {
    const s = systems[Math.floor(Math.random() * systems.length)];
    const types = ['heartbeat', 'health_check', 'command', 'sensor_read'];
    const type = types[Math.floor(Math.random() * types.length)];
    const id = uuidv4();
    const ts = Date.now();
    const last = get('SELECT hash FROM events ORDER BY timestamp DESC LIMIT 1');
    const prevHash = last ? last.hash : '0'.repeat(64);
    const event = { id, system_id: s.id, type, message: `Automated ${type}`, timestamp: ts };
    const hash = computeHash(event, prevHash);
    run('INSERT INTO events (id, system_id, type, severity, message, data, prev_hash, hash, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, s.id, type, 'info', `Automated ${type}`, '{}', prevHash, hash, ts]);
  }
  
  app.locals.broadcast({ type: 'TELEMETRY', data: { timestamp: Date.now() } });
}, 5000);

// Start
getDB().then(() => {
  const PORT = process.env.PORT || 3000;
  server.listen(PORT, () => console.log(`\n✅ SBX Guardian running at http://localhost:${PORT}\n`));
}).catch(console.error);
