const bcrypt = require('bcryptjs');
const { v4: uuidv4 } = require('uuid');
const crypto = require('crypto');

async function seed() {
  const { getDB, run, get, query, saveDB } = require('./db');
  const { seedComplianceForOrg, seedFirewallForOrg } = require('./server');
  await getDB();
  if (get('SELECT COUNT(*) as c FROM users')?.c > 0) { console.log('✅ Already seeded.'); return; }
  console.log('🌱 Seeding SBX Guardian v5...');

  const orgId = uuidv4();
  const ws = crypto.randomBytes(32).toString('hex');
  run('INSERT INTO organizations (id,name,industry,plan,webhook_secret,alert_email,country,soc2_status) VALUES (?,?,?,?,?,?,?,?)',
    [orgId,'Acme Robotics Corp','manufacturing','enterprise',ws,'admin@sbxguardian.com','DE','in_progress']);

  run('INSERT INTO users (id,email,password,name,role,org_id) VALUES (?,?,?,?,?,?)',
    [uuidv4(),'admin@sbxguardian.com',await bcrypt.hash('sbx2026',10),'Sarah Chen','admin',orgId]);
  run('INSERT INTO users (id,email,password,name,role,org_id) VALUES (?,?,?,?,?,?)',
    [uuidv4(),'operator@sbxguardian.com',await bcrypt.hash('operator123',10),'Marcus Webb','operator',orgId]);

  const defs = [
    {name:'KUKA KR 1000 Titan',type:'industrial_robot',location:'Assembly Bay A',status:'online',health:94,fw:'4.1.2',ip:'192.168.1.101',mfr:'KUKA',model:'KR 1000 Titan'},
    {name:'ABB IRB 6700',type:'industrial_robot',location:'Welding Station B',status:'online',health:87,fw:'3.8.1',ip:'192.168.1.102',mfr:'ABB',model:'IRB 6700'},
    {name:'Boston Dynamics Spot',type:'mobile_robot',location:'Warehouse Floor',status:'online',health:99,fw:'2.1.0',ip:'192.168.1.103',mfr:'Boston Dynamics',model:'Spot'},
    {name:'DJI Matrice 300 RTK',type:'drone',location:'Outdoor Inspection',status:'warning',health:71,fw:'06.01.06',ip:'192.168.1.104',mfr:'DJI',model:'Matrice 300'},
    {name:'FANUC R-2000iC',type:'industrial_robot',location:'Paint Booth C',status:'online',health:91,fw:'9.10.0',ip:'192.168.1.105',mfr:'FANUC',model:'R-2000iC'},
    {name:'Universal Robots UR16e',type:'collaborative_robot',location:'Packing Line 1',status:'online',health:96,fw:'5.13.0',ip:'192.168.1.106',mfr:'Universal Robots',model:'UR16e'},
    {name:'Yaskawa HC20XP',type:'collaborative_robot',location:'Packing Line 2',status:'online',health:88,fw:'4.2.1',ip:'192.168.1.107',mfr:'Yaskawa',model:'HC20XP'},
    {name:'Autonomous Forklift #3',type:'agv',location:'Logistics Hub',status:'warning',health:62,fw:'1.9.4',ip:'192.168.1.108',mfr:'Linde',model:'E30'},
    {name:'MiR 600 AMR',type:'agv',location:'Corridor B2',status:'online',health:97,fw:'3.2.1',ip:'192.168.1.109',mfr:'MiR',model:'600'},
    {name:'Siemens PLC Gateway',type:'plc',location:'Control Room',status:'online',health:100,fw:'17.0',ip:'192.168.1.110',mfr:'Siemens',model:'S7-1500'},
    {name:'Inspection Drone Beta',type:'drone',location:'Hangar',status:'offline',health:0,fw:'1.2.0',ip:'192.168.1.111',mfr:'DJI',model:'Matrice 210'},
    {name:'KUKA KR 210 R2700',type:'industrial_robot',location:'Assembly Bay B',status:'online',health:82,fw:'4.0.1',ip:'192.168.1.112',mfr:'KUKA',model:'KR 210'},
  ];

  const sysIds = [];
  defs.forEach(s => {
    const id=uuidv4(); sysIds.push(id);
    run('INSERT INTO systems (id,org_id,name,type,location,status,health,firmware,ip,manufacturer,model,serial_number,webhook_token,last_seen,sla_uptime_target) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
      [id,orgId,s.name,s.type,s.location,s.status,s.health,s.fw,s.ip,s.mfr,s.model,'SN-'+Math.floor(Math.random()*999999),crypto.randomBytes(16).toString('hex'),Date.now(),99.0]);
    run('INSERT INTO circuit_breakers (id,org_id,system_id,status,threshold,current_load,trip_count,auto_reset) VALUES (?,?,?,?,?,?,?,?)',
      [uuidv4(),orgId,id,s.health<70?'open':'closed',85,(20+Math.random()*70).toFixed(1),Math.floor(Math.random()*5),1]);
  });

  // Events with hash chain
  const templates = [
    {type:'startup',sev:'info',msg:'System initialized and passed self-diagnostics'},
    {type:'heartbeat',sev:'info',msg:'Scheduled heartbeat — all parameters nominal'},
    {type:'command',sev:'info',msg:'Operator command received: RESUME_OPERATION'},
    {type:'health_check',sev:'info',msg:'Health check passed: servos, sensors, comms OK'},
    {type:'warning',sev:'warning',msg:'Joint temperature approaching upper threshold (78C)'},
    {type:'alert',sev:'critical',msg:'Emergency stop triggered — obstacle detected in safety zone'},
    {type:'incident',sev:'critical',msg:'Unexpected collision detected — logging full sensor stack'},
    {type:'maintenance',sev:'warning',msg:'Scheduled maintenance overdue by 47 operating hours'},
    {type:'sensor_read',sev:'info',msg:'Lidar scan complete: environment map updated'},
    {type:'firmware',sev:'info',msg:'Firmware update applied successfully'},
    {type:'compliance',sev:'info',msg:'EU AI Act Article 12 logging requirement satisfied'},
    {type:'anomaly',sev:'warning',msg:'Load deviation detected: 23% above baseline'},
  ];

  let prevHash = '0'.repeat(64);
  for(let i=0;i<100;i++) {
    const t=templates[Math.floor(Math.random()*templates.length)];
    const sId=sysIds[Math.floor(Math.random()*sysIds.length)];
    const id=uuidv4(), ts=Date.now()-(100-i)*1800000+Math.floor(Math.random()*900000);
    const payload=`${id}|${sId}|${t.type}|${t.msg}|${ts}|${prevHash}`;
    const hash=crypto.createHash('sha256').update(payload).digest('hex');
    run('INSERT INTO events (id,org_id,system_id,type,severity,message,data,prev_hash,hash,source,timestamp) VALUES (?,?,?,?,?,?,?,?,?,?,?)',
      [id,orgId,sId,t.type,t.sev,t.msg,'{}',prevHash,hash,'auto',ts]);
    prevHash=hash;
  }

  // Anomalies
  for(let i=0;i<10;i++) {
    const sId=sysIds[Math.floor(Math.random()*sysIds.length)];
    run('INSERT INTO anomalies (id,org_id,system_id,metric,expected,actual,deviation,severity,resolved) VALUES (?,?,?,?,?,?,?,?,?)',
      [uuidv4(),orgId,sId,Math.random()>0.5?'load':'health',55+Math.random()*25,82+Math.random()*18,(15+Math.random()*35).toFixed(1),Math.random()>0.4?'critical':'warning',Math.random()>0.5?1:0]);
  }

  // Regulatory updates
  run('INSERT INTO regulatory_updates (id,framework,title,summary,impact,effective_date) VALUES (?,?,?,?,?,?)',
    [uuidv4(),'EU AI Act','Annex III Classification Guidance Updated','New guidance clarifies which robot systems qualify as high-risk under Annex III of the EU AI Act.','All manufacturers of autonomous industrial robots must review their classification.','2026-03-01']);
  run('INSERT INTO regulatory_updates (id,framework,title,summary,impact,effective_date) VALUES (?,?,?,?,?,?)',
    [uuidv4(),'ISO 10218','ISO 10218-1:2025 Revision Published','Updated safety requirements for industrial robots now include AI-specific provisions.','Organizations must update their risk assessments to align with the new standard.','2025-11-01']);

  // Waitlist entries
  ['robotics.cto@example.com','safety@automationcorp.de','compliance@industrialtech.eu'].forEach(email => {
    run('INSERT INTO waitlist (id,email,company,role,systems_count) VALUES (?,?,?,?,?)',
      [uuidv4(),email,email.split('@')[1],'Engineering Lead','50-200']);
  });

  seedComplianceForOrg(orgId);
  seedFirewallForOrg(orgId);
  saveDB();
  console.log('✅ SBX Guardian v5 seeded!');
  console.log('   Admin: admin@sbxguardian.com / sbx2026');
  console.log('   Webhook:', ws.slice(0,16)+'...');
}

seed().catch(e=>{ console.error(e); process.exit(1); });
