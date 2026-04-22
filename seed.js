const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

async function seed() {
  const { getDB, run, get, saveDB } = require('./db');
  await getDB();

  const existing = get('SELECT COUNT(*) as c FROM users');
  if (existing && existing.c > 0) { console.log('✅ Already seeded, skipping.'); return; }

  console.log('🌱 Seeding...');
  run('INSERT INTO users (id,email,password,name,role) VALUES (?,?,?,?,?)', [uuidv4(), 'admin@sbxguardian.com', await bcrypt.hash('sbx2026',10), 'Sarah Chen', 'admin']);
  run('INSERT INTO users (id,email,password,name,role) VALUES (?,?,?,?,?)', [uuidv4(), 'operator@sbxguardian.com', await bcrypt.hash('operator123',10), 'Marcus Webb', 'operator']);

  const systemDefs = [
    { name:'KUKA KR 1000 Titan', type:'industrial_robot', location:'Assembly Bay A', status:'online', health:94, firmware:'4.1.2', ip:'192.168.1.101' },
    { name:'ABB IRB 6700', type:'industrial_robot', location:'Welding Station B', status:'online', health:87, firmware:'3.8.1', ip:'192.168.1.102' },
    { name:'Boston Dynamics Spot #1', type:'mobile_robot', location:'Warehouse Floor', status:'online', health:99, firmware:'2.1.0', ip:'192.168.1.103' },
    { name:'DJI Matrice 300 RTK', type:'drone', location:'Outdoor Inspection', status:'warning', health:71, firmware:'06.01.06', ip:'192.168.1.104' },
    { name:'FANUC R-2000iC', type:'industrial_robot', location:'Paint Booth C', status:'online', health:91, firmware:'9.10.0', ip:'192.168.1.105' },
    { name:'Universal Robots UR16e', type:'collaborative_robot', location:'Packing Line 1', status:'online', health:96, firmware:'5.13.0', ip:'192.168.1.106' },
    { name:'Yaskawa HC20XP', type:'collaborative_robot', location:'Packing Line 2', status:'online', health:88, firmware:'4.2.1', ip:'192.168.1.107' },
    { name:'Autonomous Forklift #3', type:'agv', location:'Logistics Hub', status:'warning', health:62, firmware:'1.9.4', ip:'192.168.1.108' },
    { name:'MiR 600 AMR', type:'agv', location:'Corridor B2', status:'online', health:97, firmware:'3.2.1', ip:'192.168.1.109' },
    { name:'Siemens PLC Gateway', type:'plc', location:'Control Room', status:'online', health:100, firmware:'17.0', ip:'192.168.1.110' },
    { name:'Inspection Drone Beta', type:'drone', location:'Hangar', status:'offline', health:0, firmware:'1.2.0', ip:'192.168.1.111' },
    { name:'KUKA KR 210 R2700', type:'industrial_robot', location:'Assembly Bay B', status:'online', health:82, firmware:'4.0.1', ip:'192.168.1.112' },
  ];

  const systemIds = [];
  systemDefs.forEach(s => {
    const id = uuidv4(); systemIds.push(id);
    run('INSERT INTO systems (id,name,type,location,status,health,firmware,ip,last_seen) VALUES (?,?,?,?,?,?,?,?,?)', [id,s.name,s.type,s.location,s.status,s.health,s.firmware,s.ip,Date.now()]);
    run('INSERT INTO circuit_breakers (id,system_id,status,threshold,current_load,trip_count) VALUES (?,?,?,?,?,?)', [uuidv4(),id,s.health<70?'open':'closed',85,(20+Math.random()*70).toFixed(1),Math.floor(Math.random()*5)]);
  });

  const templates = [
    {type:'startup',sev:'info',msg:'System initialized and passed self-diagnostics'},
    {type:'heartbeat',sev:'info',msg:'Scheduled heartbeat — all parameters nominal'},
    {type:'command',sev:'info',msg:'Operator command received: RESUME_OPERATION'},
    {type:'health_check',sev:'info',msg:'Health check passed: servos, sensors, comms OK'},
    {type:'warning',sev:'warning',msg:'Joint temperature approaching upper threshold (78C)'},
    {type:'warning',sev:'warning',msg:'Battery level below 25% — docking recommended'},
    {type:'alert',sev:'critical',msg:'Emergency stop triggered — obstacle detected in safety zone'},
    {type:'incident',sev:'critical',msg:'Unexpected collision detected — logging full sensor stack'},
    {type:'maintenance',sev:'warning',msg:'Scheduled maintenance overdue by 47 operating hours'},
    {type:'sensor_read',sev:'info',msg:'Lidar scan complete: environment map updated'},
  ];

  let prevHash = '0'.repeat(64);
  for (let i = 0; i < 60; i++) {
    const t = templates[Math.floor(Math.random()*templates.length)];
    const sysId = systemIds[Math.floor(Math.random()*systemIds.length)];
    const id = uuidv4(), ts = Date.now() - (60-i)*1800000 + Math.floor(Math.random()*900000);
    const payload = `${id}|${sysId}|${t.type}|${t.msg}|${ts}|${prevHash}`;
    const hash = crypto.createHash('sha256').update(payload).digest('hex');
    run('INSERT INTO events (id,system_id,type,severity,message,data,prev_hash,hash,timestamp) VALUES (?,?,?,?,?,?,?,?,?)', [id,sysId,t.type,t.sev,t.msg,'{}',prevHash,hash,ts]);
    prevHash = hash;
  }

  [
    {name:'EU AI Act — Human Oversight Gate',desc:'All autonomous decisions above Risk Level 3 require human confirmation',action:'require_approval',mandatory:1,enabled:1},
    {name:'Emergency Stop Propagation',desc:'E-Stop signal must propagate to all systems within 50ms',action:'propagate',mandatory:1,enabled:1},
    {name:'Block Unsigned Firmware',desc:'Reject firmware updates without valid cryptographic signature',action:'block',mandatory:0,enabled:1},
    {name:'Rate-limit Remote Commands',desc:'Max 100 remote commands per minute per system',action:'rate_limit',mandatory:0,enabled:1},
    {name:'Block External IP Range',desc:'Block commands from non-whitelisted IP ranges',action:'block',mandatory:0,enabled:1},
    {name:'Log All Safety Zone Entries',desc:'Every safety zone entry must be logged and hashed',action:'log',mandatory:0,enabled:1},
    {name:'Quarantine on Anomaly',desc:'Isolate system that exceeds 3 anomaly detections in 60 seconds',action:'isolate',mandatory:0,enabled:0},
  ].forEach(r => run('INSERT INTO firewall_rules (id,name,description,action,mandatory,enabled,hits) VALUES (?,?,?,?,?,?,?)', [uuidv4(),r.name,r.desc,r.action,r.mandatory,r.enabled,Math.floor(Math.random()*200)]));

  [
    {fw:'EU AI Act',art:'Art. 9',title:'Risk Management System',desc:'Establish and maintain risk management throughout lifecycle',status:'pass'},
    {fw:'EU AI Act',art:'Art. 10',title:'Data Governance',desc:'Training, validation and testing data must meet quality criteria',status:'pass'},
    {fw:'EU AI Act',art:'Art. 11',title:'Technical Documentation',desc:'Complete technical documentation before market placement',status:'partial'},
    {fw:'EU AI Act',art:'Art. 12',title:'Record-keeping & Logging',desc:'Automatic logging of events throughout system operation',status:'pass'},
    {fw:'EU AI Act',art:'Art. 13',title:'Transparency & Info',desc:'Systems must be transparent; users must be informed',status:'partial'},
    {fw:'EU AI Act',art:'Art. 14',title:'Human Oversight',desc:'Enable effective oversight by natural persons during operation',status:'pass'},
    {fw:'EU AI Act',art:'Art. 15',title:'Accuracy & Cybersecurity',desc:'Achieve appropriate levels of accuracy and cybersecurity',status:'fail'},
    {fw:'EU AI Act',art:'Art. 16',title:'Provider Obligations',desc:'Register system in EU database; affix CE marking',status:'fail'},
    {fw:'ISO 10218',art:'5.4',title:'Safety Functions',desc:'Safety-rated monitored stop, speed & force limiting',status:'pass'},
    {fw:'ISO 10218',art:'5.5',title:'Operating Modes',desc:'Manual, automatic, and collaborative modes defined',status:'pass'},
    {fw:'ISO 10218',art:'5.6',title:'Emergency Stop',desc:'Emergency stop function per IEC 60204-1',status:'pass'},
    {fw:'ISO 10218',art:'5.7',title:'Enabling Device',desc:'Three-position enabling device for manual operation',status:'partial'},
    {fw:'IEC 61508',art:'SIL-2',title:'Safety Integrity Level',desc:'Target failure measures for SIL 2 compliance',status:'partial'},
    {fw:'IEC 61508',art:'FMEA',title:'Failure Mode Analysis',desc:'Complete FMEA documentation for all safety functions',status:'fail'},
  ].forEach(c => run('INSERT INTO compliance_items (id,framework,article,title,description,status) VALUES (?,?,?,?,?,?)', [uuidv4(),c.fw,c.art,c.title,c.desc,c.status]));

  saveDB();
  console.log('✅ Seeded! Login: admin@sbxguardian.com / sbx2026');
}

seed().catch(e => { console.error(e); process.exit(1); });
