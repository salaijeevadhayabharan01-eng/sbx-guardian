// ═══════════════════════════════════════════════════════════════
// SBX GUARDIAN — INTEGRATIONS ENGINE
// Slack, PagerDuty, IFTTT, Discord, email, SMS webhooks
// ═══════════════════════════════════════════════════════════════
const { query, run, get } = require('./db');

// ── SLACK ─────────────────────────────────────────────────────
async function sendSlack(webhookUrl, event) {
  if (!webhookUrl) return;
  const color = event.severity==='critical'?'#ff4d4d':event.severity==='warning'?'#ff8c00':'#00ff88';
  try {
    await fetch(webhookUrl, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        text: `*SBX Guardian Alert*`,
        attachments:[{
          color, fallback: event.message,
          fields:[
            {title:'Severity',value:event.severity?.toUpperCase(),short:true},
            {title:'System',value:event.system_name||'Fleet',short:true},
            {title:'Event',value:event.type,short:true},
            {title:'Time',value:new Date().toISOString(),short:true},
            {title:'Message',value:event.message,short:false}
          ]
        }]
      })
    });
  } catch(e) { console.log('Slack error:', e.message); }
}

// ── DISCORD ───────────────────────────────────────────────────
async function sendDiscord(webhookUrl, event) {
  if (!webhookUrl) return;
  const color = event.severity==='critical'?16711680:event.severity==='warning'?16744448:65408;
  try {
    await fetch(webhookUrl, {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        embeds:[{
          title:`⚠ SBX Guardian: ${event.type}`,
          description: event.message,
          color,
          fields:[
            {name:'Severity',value:event.severity?.toUpperCase(),inline:true},
            {name:'System',value:event.system_name||'Fleet',inline:true}
          ],
          timestamp: new Date().toISOString(),
          footer:{text:'SBX Guardian — AI Systems Compliance Platform'}
        }]
      })
    });
  } catch(e) { console.log('Discord error:', e.message); }
}

// ── PAGERDUTY ─────────────────────────────────────────────────
async function sendPagerDuty(integrationKey, event) {
  if (!integrationKey) return;
  try {
    await fetch('https://events.pagerduty.com/v2/enqueue', {
      method:'POST', headers:{'Content-Type':'application/json'},
      body: JSON.stringify({
        routing_key: integrationKey,
        event_action: 'trigger',
        payload:{
          summary: `SBX Guardian: ${event.severity?.toUpperCase()} - ${event.message}`,
          source: event.system_name || 'sbx-guardian',
          severity: event.severity==='critical'?'critical':event.severity==='warning'?'warning':'info',
          timestamp: new Date().toISOString(),
          custom_details: { event_type:event.type, system:event.system_name }
        }
      })
    });
  } catch(e) { console.log('PagerDuty error:', e.message); }
}

// ── GENERIC OUTBOUND WEBHOOK ───────────────────────────────────
async function sendWebhookOut(url, event, secret) {
  if (!url) return;
  try {
    const payload = JSON.stringify({ source:'sbx-guardian', timestamp:Date.now(), event });
    const headers = {'Content-Type':'application/json'};
    if (secret) {
      const crypto = require('crypto');
      headers['X-SBX-Signature'] = crypto.createHmac('sha256',secret).update(payload).digest('hex');
    }
    await fetch(url, { method:'POST', headers, body:payload });
  } catch(e) { console.log('Outbound webhook error:', e.message); }
}

// ── DISPATCH TO ALL CONFIGURED INTEGRATIONS ───────────────────
async function dispatchIntegrations(orgId, event) {
  const org = get('SELECT * FROM organizations WHERE id=?',[orgId]);
  if (!org) return;
  const integrations = query('SELECT * FROM integrations WHERE org_id=? AND enabled=1',[orgId]);
  const promises = [];
  if (org.slack_webhook && (event.severity==='critical'||event.severity==='warning')) {
    promises.push(sendSlack(org.slack_webhook, event));
  }
  integrations.forEach(i => {
    try {
      const config = JSON.parse(i.config||'{}');
      if (i.type==='discord' && config.webhook_url) promises.push(sendDiscord(config.webhook_url, event));
      if (i.type==='pagerduty' && config.integration_key && event.severity==='critical') promises.push(sendPagerDuty(config.integration_key, event));
      if (i.type==='webhook_out' && config.url) promises.push(sendWebhookOut(config.url, event, config.secret));
    } catch(e) {}
  });
  await Promise.allSettled(promises);
}

module.exports = { sendSlack, sendDiscord, sendPagerDuty, sendWebhookOut, dispatchIntegrations };
