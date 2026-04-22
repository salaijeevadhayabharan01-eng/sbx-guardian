// Alert system - sends email alerts for critical events
const nodemailer = require('nodemailer');
const { query, run, get } = require('./db');
const { v4: uuidv4 } = require('uuid');

// Uses Gmail free SMTP or any SMTP
function getTransporter() {
  if (process.env.SMTP_USER && process.env.SMTP_PASS) {
    return nodemailer.createTransport({
      service: 'gmail',
      auth: { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS }
    });
  }
  return null;
}

async function sendAlert(orgId, type, message, severity, systemId) {
  const alertId = uuidv4();
  run('INSERT INTO alerts (id,org_id,system_id,type,message,severity) VALUES (?,?,?,?,?,?)',
    [alertId, orgId, systemId || null, type, message, severity]);

  const org = get('SELECT * FROM organizations WHERE id = ?', [orgId]);
  if (!org?.alert_email) return;

  const transporter = getTransporter();
  if (!transporter) return;

  try {
    await transporter.sendMail({
      from: process.env.SMTP_USER,
      to: org.alert_email,
      subject: `[SBX Guardian] ${severity.toUpperCase()}: ${type}`,
      html: `
        <div style="font-family:monospace;background:#05070a;color:#e6edf3;padding:24px;border-radius:8px">
          <h2 style="color:#ff4d4d">⚠ SBX Guardian Alert</h2>
          <p><strong>Severity:</strong> ${severity.toUpperCase()}</p>
          <p><strong>Type:</strong> ${type}</p>
          <p><strong>Message:</strong> ${message}</p>
          <p><strong>Time:</strong> ${new Date().toISOString()}</p>
          <p style="margin-top:16px"><a href="${process.env.APP_URL || 'https://sbxguardian.com'}" style="color:#00ff88">View Dashboard →</a></p>
        </div>
      `
    });
  } catch(e) { console.log('Email alert failed:', e.message); }
}

function getAlerts(orgId, limit = 20) {
  return query(
    'SELECT a.*, s.name as system_name FROM alerts a LEFT JOIN systems s ON s.id = a.system_id WHERE a.org_id = ? ORDER BY a.created_at DESC LIMIT ?',
    [orgId, limit]
  );
}

function resolveAlert(alertId) {
  run('UPDATE alerts SET resolved = 1 WHERE id = ?', [alertId]);
}

module.exports = { sendAlert, getAlerts, resolveAlert };
