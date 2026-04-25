// SBX GUARDIAN — EMAIL NURTURE SEQUENCE
// Automatically sends 5 emails over 2 weeks after signup
// Converts cold leads into booked demos
const { query, run, get } = require('./db');
const { v4: uuidv4 } = require('uuid');

const DAYS = () => Math.ceil((new Date('2026-08-02') - Date.now()) / 86400000);
const APP_URL = () => process.env.APP_URL || 'https://sbx-guardian.onrender.com';

// The 5-email sequence — each designed to move toward a booked call
const SEQUENCE = [
  {
    day: 0, // Instant
    subject: `You're on the SBX Guardian waitlist — what's next`,
    type: 'welcome',
    getHTML: (name, company) => `
<div style="font-family:-apple-system,sans-serif;max-width:560px;margin:0 auto;background:#030508;color:#f0f2f8;padding:40px 24px">
  <div style="font-size:20px;font-weight:800;letter-spacing:2px;color:#00e87a;margin-bottom:32px">⬢ SBX GUARDIAN</div>
  <h1 style="font-size:24px;margin-bottom:16px">You're on the list${company?', '+company:''}.</h1>
  <p style="color:#8892a4;line-height:1.7;margin-bottom:16px">Thank you. You've just done something 78% of manufacturers haven't — you're preparing for what's coming.</p>
  <div style="background:rgba(255,136,0,0.08);border:1px solid rgba(255,136,0,0.2);border-radius:6px;padding:16px;margin:20px 0">
    <strong style="color:#ff8800">⚠ EU AI Act enforcement: ${DAYS()} days away.</strong><br>
    <span style="color:#8892a4;font-size:14px">Every industrial robot with ML = High-Risk AI. Penalty: up to €30M.</span>
  </div>
  <p style="color:#8892a4;line-height:1.7">Here's what happens next:<br><br>
  <strong style="color:#f0f2f8">Tomorrow:</strong> I'll send you exactly what the EU AI Act requires from your fleet.<br>
  <strong style="color:#f0f2f8">Day 4:</strong> A walkthrough of how SBX Guardian works in 30 minutes.<br>
  <strong style="color:#f0f2f8">Day 7:</strong> A personal demo invitation.</p>
  <a href="${APP_URL()}" style="display:inline-block;background:#00e87a;color:#030508;padding:14px 28px;border-radius:6px;text-decoration:none;font-weight:700;margin:20px 0">Preview the Dashboard →</a>
  <p style="color:#3d4455;font-size:12px;margin-top:32px;border-top:1px solid #1a1d28;padding-top:16px">Reply directly to this email with any questions. — SBX Guardian Team</p>
</div>`
  },
  {
    day: 1,
    subject: `What EU AI Act Article 12 actually requires from your robots`,
    type: 'education',
    getHTML: (name, company) => `
<div style="font-family:-apple-system,sans-serif;max-width:560px;margin:0 auto;background:#030508;color:#f0f2f8;padding:40px 24px">
  <div style="font-size:14px;font-family:monospace;color:#3d4455;margin-bottom:24px">Day 1 of 5 · EU AI Act Education</div>
  <h1 style="font-size:22px;margin-bottom:16px">What does "tamper-proof logging" actually mean?</h1>
  <p style="color:#8892a4;line-height:1.7">EU AI Act Article 12 requires that high-risk AI systems (including your robots) maintain automatic logs that are:</p>
  <ul style="color:#8892a4;line-height:2;padding-left:20px">
    <li>Tamper-evident (no one can modify them undetected)</li>
    <li>Covering the entire operational period</li>
    <li>Accessible to regulators on request</li>
    <li>Retained for at least 6 months after each operation</li>
  </ul>
  <p style="color:#8892a4;line-height:1.7;margin-top:16px">Most manufacturers have logging. But <strong style="color:#f0f2f8">almost none have tamper-evident logging</strong> — which is what the regulation specifically requires.</p>
  <div style="background:rgba(0,232,122,0.06);border:1px solid rgba(0,232,122,0.15);border-radius:6px;padding:16px;margin:20px 0">
    <strong style="color:#00e87a">How SBX Guardian solves this:</strong><br>
    <span style="color:#8892a4;font-size:14px">Every event is cryptographically signed in a SHA-256 hash chain. If anyone tries to modify a single log entry, the entire chain breaks and flags. It's mathematically provable.</span>
  </div>
  <p style="color:#8892a4">Tomorrow I'll show you the compliance dashboard — where you can see your live compliance score across all 9 EU AI Act articles.</p>
  <a href="${APP_URL()}" style="display:inline-block;background:#00e87a;color:#030508;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:700;margin:16px 0;font-size:14px">See the Dashboard →</a>
  <p style="color:#3d4455;font-size:12px;margin-top:32px;border-top:1px solid #1a1d28;padding-top:16px">SBX Guardian · <a href="${APP_URL()}" style="color:#3d4455">${APP_URL()}</a></p>
</div>`
  },
  {
    day: 3,
    subject: `How SBX Guardian connects to your robots in 30 minutes`,
    type: 'product',
    getHTML: (name, company) => `
<div style="font-family:-apple-system,sans-serif;max-width:560px;margin:0 auto;background:#030508;color:#f0f2f8;padding:40px 24px">
  <div style="font-size:14px;font-family:monospace;color:#3d4455;margin-bottom:24px">Day 3 of 5 · Product Walkthrough</div>
  <h1 style="font-size:22px;margin-bottom:16px">30 minutes. Any robot. No hardware needed.</h1>
  <p style="color:#8892a4;line-height:1.7">Here's exactly how it works:</p>
  <div style="margin:20px 0">
    <div style="display:flex;gap:12px;margin-bottom:16px;align-items:flex-start">
      <div style="width:28px;height:28px;background:#00e87a;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#030508;font-weight:800;font-size:12px;flex-shrink:0">1</div>
      <div><strong style="color:#f0f2f8">You sign up</strong><br><span style="color:#8892a4;font-size:14px">Create an account. We generate a unique webhook URL for your organization.</span></div>
    </div>
    <div style="display:flex;gap:12px;margin-bottom:16px;align-items:flex-start">
      <div style="width:28px;height:28px;background:#00e87a;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#030508;font-weight:800;font-size:12px;flex-shrink:0">2</div>
      <div><strong style="color:#f0f2f8">Your IT team adds 3 lines of code</strong><br><span style="color:#8892a4;font-size:14px">Python, Node.js, or Arduino. Any device that can make an HTTP request can connect.</span></div>
    </div>
    <div style="display:flex;gap:12px;margin-bottom:16px;align-items:flex-start">
      <div style="width:28px;height:28px;background:#00e87a;border-radius:50%;display:flex;align-items:center;justify-content:center;color:#030508;font-weight:800;font-size:12px;flex-shrink:0">3</div>
      <div><strong style="color:#f0f2f8">Your robots start logging automatically</strong><br><span style="color:#8892a4;font-size:14px">Every event is hash-chained, compliance is tracked in real-time, alerts fire on anomalies.</span></div>
    </div>
  </div>
  <div style="background:rgba(0,232,122,0.06);border:1px solid rgba(0,232,122,0.15);border-radius:6px;padding:16px;margin:20px 0;font-family:monospace;font-size:13px;color:#8892a4">
    <span style="color:#3d4455"># Python example</span><br>
    import requests<br>
    requests.post(YOUR_WEBHOOK_URL, json={<br>
    &nbsp;&nbsp;"type": "heartbeat",<br>
    &nbsp;&nbsp;"health": 95, "load": 42.1<br>
    })
  </div>
  <p style="color:#8892a4">That's it. Three lines of code and your robot is EU AI Act compliant.</p>
  <a href="${APP_URL()}" style="display:inline-block;background:#00e87a;color:#030508;padding:12px 24px;border-radius:6px;text-decoration:none;font-weight:700;margin:16px 0;font-size:14px">Try the Live Dashboard →</a>
  <p style="color:#3d4455;font-size:12px;margin-top:32px;border-top:1px solid #1a1d28;padding-top:16px">SBX Guardian · Reply with questions</p>
</div>`
  },
  {
    day: 7,
    subject: `Quick question about your robot fleet`,
    type: 'personal',
    getHTML: (name, company) => `
<div style="font-family:-apple-system,sans-serif;max-width:560px;margin:0 auto;background:#030508;color:#f0f2f8;padding:40px 24px">
  <div style="font-size:14px;font-family:monospace;color:#3d4455;margin-bottom:24px">Day 7 of 5 · Personal Outreach</div>
  <p style="color:#f0f2f8;font-size:16px;line-height:1.7">Hi${name?' '+name:''},</p>
  <p style="color:#8892a4;line-height:1.7">I wanted to reach out personally.</p>
  <p style="color:#8892a4;line-height:1.7">The EU AI Act deadline is in <strong style="color:#ff8800">${DAYS()} days</strong>. Based on what I've seen from manufacturers in ${company?company+'\'s industry':'your industry'}, most are still 6-12 months away from being compliant — and they don't know it yet.</p>
  <p style="color:#8892a4;line-height:1.7">I'd love to do a 15-minute call where I:</p>
  <ul style="color:#8892a4;line-height:2;padding-left:20px">
    <li>Show you your likely compliance gaps based on your fleet type</li>
    <li>Walk through how the platform works live</li>
    <li>Give you an honest assessment of your EU AI Act risk</li>
  </ul>
  <p style="color:#8892a4;line-height:1.7">No pitch. Just a genuine assessment.</p>
  <a href="https://calendly.com" style="display:inline-block;background:#00e87a;color:#030508;padding:14px 28px;border-radius:6px;text-decoration:none;font-weight:700;margin:20px 0">Book 15 Minutes →</a>
  <p style="color:#8892a4;font-size:14px">Or just reply to this email — I respond personally.</p>
  <p style="color:#3d4455;font-size:12px;margin-top:32px;border-top:1px solid #1a1d28;padding-top:16px">SBX Guardian Team · ${APP_URL()}</p>
</div>`
  },
  {
    day: 12,
    subject: `Last email — then I'll leave you alone`,
    type: 'breakup',
    getHTML: (name, company) => `
<div style="font-family:-apple-system,sans-serif;max-width:560px;margin:0 auto;background:#030508;color:#f0f2f8;padding:40px 24px">
  <div style="font-size:14px;font-family:monospace;color:#3d4455;margin-bottom:24px">Day 12 · Final Email</div>
  <p style="color:#f0f2f8;font-size:16px;line-height:1.7">Hi${name?' '+name:''},</p>
  <p style="color:#8892a4;line-height:1.7">This is my last email. I don't want to be annoying.</p>
  <p style="color:#8892a4;line-height:1.7">But before I go — the EU AI Act enforcement date is <strong style="color:#ff8800">${DAYS()} days away</strong>. After that date, operating non-compliant high-risk AI systems in the EU exposes your company to fines up to €30M.</p>
  <p style="color:#8892a4;line-height:1.7">If this isn't the right time, I completely understand. I'll remove you from outreach emails.</p>
  <p style="color:#8892a4;line-height:1.7">But if you want to talk — even just to understand your risk — reply with "yes" and I'll send you a calendar link immediately.</p>
  <p style="color:#f0f2f8;margin-top:24px">— SBX Guardian Team</p>
  <div style="margin-top:32px;padding:16px;background:rgba(255,136,0,0.06);border:1px solid rgba(255,136,0,0.15);border-radius:6px">
    <div style="font-size:12px;color:#3d4455;font-family:monospace;margin-bottom:8px">THE MATH</div>
    <div style="color:#8892a4;font-size:14px">€30,000,000 potential fine<br>vs<br><strong style="color:#00e87a">$499/month SBX Guardian</strong><br>= 5,010x ROI</div>
  </div>
  <p style="color:#3d4455;font-size:12px;margin-top:32px;border-top:1px solid #1a1d28;padding-top:16px">${APP_URL()}</p>
</div>`
  }
];

async function sendNurtureEmail(to, name, company, emailIndex) {
  const { sendEmail } = require('./automarketing');
  const seq = SEQUENCE[emailIndex];
  if (!seq) return false;
  return sendEmail(to, seq.subject, seq.getHTML(name, company));
}

async function processNurtureQueue() {
  const { sendEmail } = require('./automarketing');
  if (!process.env.SMTP_USER) return;

  // Get all leads in nurture sequences
  const leads = query('SELECT * FROM nurture_queue WHERE completed = 0 AND next_email_at <= ? ORDER BY next_email_at ASC LIMIT 20', [Date.now()]);

  for (const lead of leads) {
    const seq = SEQUENCE[lead.email_index];
    if (!seq) { run('UPDATE nurture_queue SET completed=1 WHERE id=?', [lead.id]); continue; }

    const sent = await sendEmail(lead.email, seq.subject, seq.getHTML(lead.name, lead.company));
    if (sent) {
      const nextSeq = SEQUENCE[lead.email_index + 1];
      if (nextSeq) {
        run('UPDATE nurture_queue SET email_index=?,last_sent_at=?,next_email_at=?,emails_sent=emails_sent+1 WHERE id=?',
          [lead.email_index + 1, Date.now(), Date.now() + nextSeq.day * 86400000, lead.id]);
      } else {
        run('UPDATE nurture_queue SET completed=1,emails_sent=emails_sent+1 WHERE id=?', [lead.id]);
      }
      console.log(`[NURTURE] Sent email ${lead.email_index + 1}/5 to ${lead.email}`);
    }
  }
}

function enrollInNurture(email, name, company, orgId) {
  // Check if already enrolled
  const existing = get('SELECT id FROM nurture_queue WHERE email=?', [email]);
  if (existing) return false;

  run('INSERT INTO nurture_queue (id,email,name,company,org_id,email_index,next_email_at,enrolled_at) VALUES (?,?,?,?,?,?,?,?)',
    [uuidv4(), email, name||'', company||'', orgId||null, 0, Date.now(), Date.now()]);
  console.log(`[NURTURE] Enrolled ${email} in 5-email sequence`);
  return true;
}

module.exports = { processNurtureQueue, enrollInNurture, sendNurtureEmail, SEQUENCE };
