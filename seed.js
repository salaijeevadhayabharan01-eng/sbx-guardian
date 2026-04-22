const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');

async function seed() {
  const { getDB, query, run, get, computeHash, saveDB } = require('../src/db');
  await getDB();

  // Only seed if empty
  const existing = get('SELECT COUNT(*) as c FROM users');
  if (existing && existing.c > 0) {
    console.log('✅ Database already seeded, skipping...');
    return;
  }

  console.log('🌱 Seeding database...');

  const adminPass = await bcrypt.hash('sbx2026', 10);
  const opPass = await bcrypt.hash('operator123', 10);
  const adminId = uuidv4();
  const opId = uuidv4();
  run('INSERT INTO users (id, email, password, name, role) VALUES (?, ?, ?, ?, ?)', [adminId, 'admin@sbxguardian.com', adminPass, 'Sarah Chen', 'admin']);
  run('INSERT INTO users (id, email, password, name, role) VALUES (?, ?, ?, ?, ?)', [opId, 'operator@sbxguardian.com', opPass, 'Marcus Webb', 'operator']);

  const systemDefs = [
    { name: 'KUKA KR 1000 Titan', type: 'industrial_robot', location: 'Assembly Bay A', status: 'online', health: 94, firmware: '4.1.2', ip: '192.168.1.101' },
    { name: 'ABB IRB 6700', type: 'industrial_robot', location: 'Welding Station B', status: 'online', health: 87, firmware: '3.8.1', ip: '192.168.1.102' },
    { name: 'Boston Dynamics Spot #1', type: 'mobile_robot', location: 'Warehouse Floor', status: 'online', health: 99, firmware: '2.1.0', ip: '192.168.1.103' },
    { name: 'DJI Matrice 300 RTK', type: 'drone', location: 'Outdoor Inspection', status: 'warning', health: 71, firmware: '06.01.06', ip: '192.168.1.104' },
    { name: 'FANUC R-2000iC', type: 'industrial_robot', location: 'Paint Booth C', status: 'online', health: 91, firmware: '9.10.0', ip: '192.168.1.105' },
    { name: 'Universal Robots UR16e', type: 'collaborative_robot', location: 'Packing Line 1', status: 'online', health: 96, firmware: '5.13.0', ip: '192.168.1.106' },
    { name: 'Yaskawa HC20XP', type: 'collaborative_robot', location: 'Packing Line 2', status: 'online', health: 88, firmware: '4.2.1', ip: '192.168.1.107' },
    { name: 'Autonomous Forklift #3', type: 'agv', location: 'Logistics Hub', status: 'warning', health: 62, firmware: '1.9.4', ip: '192.168.1.108' },
    { name: 'MiR 600 AMR', type: 'agv', location: 'Corridor B2', status: 'online', health: 97, firmware: '3.2.1', ip: '192.168.1.109' },
    { name: 'Siemens PLC Gateway', type: 'plc', location: 'Control Room', status: 'online', health: 100, firmware: '17.0', ip: '192.168.1.110' },
    { name: 'Inspection Drone Beta', type: 'drone', location: 'Hangar', status: 'offline', health: 0, firmware: '1.2.0', ip: '192.168.1.111' },
    { name: 'KUKA KR 210 R2700', type: 'industrial_robot', location: 'Assembly Bay B', status: 'online', health: 82, firmware: '4.0.1', ip: '192.168.1.112' },
  ];

  const systemIds = [];
  systemDefs.forEach(s => {
    const id = uuidv4();
    systemIds.push(id);
    run('INSERT INTO systems (id, name, type, location, status, health, firmware, ip, last_seen) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, s.name, s.type, s.location, s.status, s.health, s.firmware, s.ip, Date.now()]);
    const load = s.status === 'offline' ? 0 : (20 + Math.random() * 70).toFixed(1);
    const cbStatus = s.health < 70 ? 'open' : 'closed';
    run('INSERT INTO circuit_breakers (id, system_id, status, threshold, current_load, trip_count) VALUES (?, ?, ?, ?, ?, ?)',
      [uuidv4(), id, cbStatus, 85, load, Math.floor(Math.random() * 5)]);
  });

  const eventTemplates = [
    { type: 'startup', severity: 'info', message: 'System initialized and passed self-diagnostics' },
    { type: 'heartbeat', severity: 'info', message: 'Scheduled heartbeat — all parameters nominal' },
    { type: 'command', severity: 'info', message: 'Operator command received: RESUME_OPERATION' },
    { type: 'health_check', severity: 'info', message: 'Health check passed: servos, sensors, comms OK' },
    { type: 'warning', severity: 'warning', message: 'Joint temperature approaching upper threshold (78C / 85C limit)' },
    { type: 'warning', severity: 'warning', message: 'Battery level below 25% — docking recommended' },
    { type: 'alert', severity: 'critical', message: 'Emergency stop triggered — obstacle detected in safety zone' },
    { type: 'incident', severity: 'critical', message: 'Unexpected collision detected — logging full sensor stack' },
    { type: 'maintenance', severity: 'warning', message: 'Scheduled maintenance overdue by 47 operating hours' },
    { type: 'firmware', severity: 'info', message: 'Firmware update applied successfully' },
    { type: 'sensor_read', severity: 'info', message: 'Lidar scan complete: environment map updated' },
    { type: 'command', severity: 'info', message: 'Remote override accepted — switching to manual mode' },
  ];

  let prevHash = '0'.repeat(64);
  const now = Date.now();
  for (let i = 0; i < 60; i++) {
    const tmpl = eventTemplates[Math.floor(Math.random() * eventTemplates.length)];
    const sysId = systemIds[Math.floor(Math.random() * systemIds.length)];
    const id = uuidv4();
    const ts = now - (60 - i) * 1800000 + Math.floor(Math.random() * 900000);
    const event = { id, system_id: sysId, type: tmpl.type, message: tmpl.message, timestamp: ts };
    const crypto = require('crypto');
    const payload = `${event.id}|${event.system_id}|${event.type}|${event.message}|${event.timestamp}|${prevHash}`;
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    run('INSERT INTO events (id, system_id, type, severity, message, data, prev_hash, hash, timestamp) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
      [id, sysId, tmpl.type, tmpl.severity, tmpl.message, '{}', prevHash, hash, ts]);
    prevHash = hash;
  }

  const rules = [
    { name: 'EU AI Act — Human Oversight Gate', description: 'Mandatory: all autonomous decisions above Risk Level 3 require human confirmation', action: 'require_approval', mandatory: 1, enabled: 1 },
    { name: 'Emergency Stop Propagation', description: 'Any E-Stop signal must propagate to all connected systems within 50ms', action: 'propagate', mandatory: 1, enabled: 1 },
    { name: 'Block Unsigned Firmware', description: 'Reject firmware updates without valid cryptographic signature', action: 'block', mandatory: 0, enabled: 1 },
    { name: 'Rate-limit Remote Commands', description: 'Max 100 remote commands per minute per system', action: 'rate_limit', mandatory: 0, enabled: 1 },
    { name: 'Block External IP Range', description: 'Block all commands from non-whitelisted IP ranges', action: 'block', mandatory: 0, enabled: 1 },
    { name: 'Log All Safety Zone Entries', description: 'Every entry into a defined safety zone must be logged and hashed', action: 'log', mandatory: 0, enabled: 1 },
    { name: 'Quarantine on Anomaly', description: 'Isolate any system that exceeds 3 anomaly detections in 60 seconds', action: 'isolate', mandatory: 0, enabled: 0 },
  ];
  rules.forEach(r => run('INSERT INTO firewall_rules (id, name, description, action, mandatory, enabled, hits) VALUES (?, ?, ?, ?, ?, ?, ?)',
    [uuidv4(), r.name, r.description, r.action, r.mandatory, r.enabled, Math.floor(Math.random() * 200)]));

  const compItems = [
    { framework: 'EU AI Act', article: 'Art. 9', title: 'Risk Management System', description: 'Establish and maintain risk management throughout lifecycle', status: 'pass' },
    { framework: 'EU AI Act', article: 'Art. 10', title: 'Data Governance', description: 'Training, validation and testing data must meet quality criteria', status: 'pass' },
    { framework: 'EU AI Act', article: 'Art. 11', title: 'Technical Documentation', description: 'Complete technical documentation before market placement', status: 'partial' },
    { framework: 'EU AI Act', article: 'Art. 12', title: 'Record-keeping & Logging', description: 'Automatic logging of events throughout system operation', status: 'pass' },
    { framework: 'EU AI Act', article: 'Art. 13', title: 'Transparency & Info', description: 'Systems must be transparent; users must be informed', status: 'partial' },
    { framework: 'EU AI Act', article: 'Art. 14', title: 'Human Oversight', description: 'Enable effective oversight by natural persons during operation', status: 'pass' },
    { framework: 'EU AI Act', article: 'Art. 15', title: 'Accuracy, Robustness & Cybersecurity', description: 'Achieve appropriate levels of accuracy and cybersecurity', status: 'fail' },
    { framework: 'EU AI Act', article: 'Art. 16', title: 'Provider Obligations', description: 'Register system in EU database; affix CE marking', status: 'fail' },
    { framework: 'ISO 10218', article: '5.4', title: 'Safety Functions', description: 'Safety-rated monitored stop, speed & force limiting', status: 'pass' },
    { framework: 'ISO 10218', article: '5.5', title: 'Operating Modes', description: 'Manual, automatic, and collaborative modes defined and controlled', status: 'pass' },
    { framework: 'ISO 10218', article: '5.6', title: 'Emergency Stop', description: 'Emergency stop function per IEC 60204-1', status: 'pass' },
    { framework: 'ISO 10218', article: '5.7', title: 'Enabling Device', description: 'Three-position enabling device for manual operation', status: 'partial' },
    { framework: 'IEC 61508', article: 'SIL-2', title: 'Safety Integrity Level', description: 'Target failure measures for SIL 2 compliance', status: 'partial' },
    { framework: 'IEC 61508', article: 'FMEA', title: 'Failure Mode Analysis', description: 'Complete FMEA documentation for all safety functions', status: 'fail' },
  ];
  compItems.forEach(c => run('INSERT INTO compliance_items (id, framework, article, title, description, status) VALUES (?, ?, ?, ?, ?, ?)',
    [uuidv4(), c.framework, c.article, c.title, c.description, c.status]));

  saveDB();
  console.log('✅ Database seeded successfully');
  console.log('   Admin: admin@sbxguardian.com / sbx2026');
}

seed().catch(err => { console.error(err); process.exit(1); });
