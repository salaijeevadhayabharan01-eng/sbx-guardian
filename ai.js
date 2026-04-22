// SBX Guardian — Multi-AI Intelligence Layer
// Groq (fast) + Gemini (deep) + fallback chain
// All free tiers, layered for maximum power

const GROQ_KEY = process.env.GROQ_API_KEY || '';
const GEMINI_KEY = process.env.GEMINI_API_KEY || '';

// ── GROQ (ultra-fast, real-time analysis) ──────────────────────────────────
async function groqChat(messages, systemPrompt, maxTokens = 800) {
  if (!GROQ_KEY) return null;
  try {
    const res = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', 'Authorization': 'Bearer ' + GROQ_KEY },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        max_tokens: maxTokens,
        messages: [
          { role: 'system', content: systemPrompt },
          ...messages
        ]
      })
    });
    const d = await res.json();
    if (d.error) throw new Error(d.error.message);
    return d.choices?.[0]?.message?.content || null;
  } catch(e) { console.log('Groq error:', e.message); return null; }
}

// ── GEMINI (deep analysis, long documents) ─────────────────────────────────
async function geminiChat(prompt, maxTokens = 2000) {
  if (!GEMINI_KEY) return null;
  try {
    const res = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_KEY}`,
      {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          contents: [{ parts: [{ text: prompt }] }],
          generationConfig: { maxOutputTokens: maxTokens, temperature: 0.3 }
        })
      }
    );
    const d = await res.json();
    if (d.error) throw new Error(d.error.message);
    return d.candidates?.[0]?.content?.parts?.[0]?.text || null;
  } catch(e) { console.log('Gemini error:', e.message); return null; }
}

// ── SMART ROUTER — picks best AI for the task ──────────────────────────────
async function smartAI(task, payload, history = []) {
  const { query, run, get } = require('./db');

  // Real-time tasks → Groq (fastest)
  if (task === 'realtime_alert' || task === 'anomaly_explain' || task === 'quick_analysis') {
    const result = await groqChat(
      [{ role: 'user', content: payload.prompt }],
      payload.system || 'You are SBX Guardian AI. Be concise and direct.',
      600
    );
    if (result) return { text: result, model: 'groq/llama-3.3-70b', task };
  }

  // Deep reports → Gemini (handles long context)
  if (task === 'evidence_report' || task === 'compliance_pack' || task === 'full_audit') {
    const result = await geminiChat(payload.prompt, 2000);
    if (result) return { text: result, model: 'gemini-1.5-flash', task };
  }

  // Fleet analysis → try Groq first, fallback Gemini
  if (task === 'fleet_analysis' || task === 'risk_prediction' || task === 'chat') {
    let result = await groqChat(history.length > 0 ? history : [{ role: 'user', content: payload.prompt }],
      payload.system || 'You are SBX Guardian fleet analyst. Be specific and data-driven.', 1000);
    if (result) return { text: result, model: 'groq/llama-3.3-70b', task };
    // Fallback to Gemini
    result = await geminiChat(payload.prompt, 1200);
    if (result) return { text: result, model: 'gemini-1.5-flash', task };
  }

  // Final fallback — built-in rule-based response
  return builtinFallback(task, payload);
}

// ── BUILT-IN FALLBACK (works with zero API keys) ───────────────────────────
function builtinFallback(task, payload) {
  const responses = {
    anomaly_explain: `ANOMALY ANALYSIS\n\nDetected significant deviation in ${payload.metric || 'system metric'}.\nExpected: ${payload.expected || 'N/A'} | Actual: ${payload.actual || 'N/A'}\n\nRECOMMENDED ACTIONS:\n1. Inspect system immediately\n2. Check recent maintenance logs\n3. Review sensor calibration\n4. Consider isolating system if deviation persists\n\nRisk Level: ${payload.severity === 'critical' ? 'HIGH — immediate action required' : 'MEDIUM — monitor closely'}`,
    quick_analysis: `FLEET STATUS ANALYSIS\n\nBased on current telemetry data, your fleet shows ${payload.online || 0} systems online with an average health score of ${payload.health || 'N/A'}%.\n\nKey concerns require immediate attention. Review anomaly detection panel for specific system alerts.`,
    evidence_report: `EVIDENCE REPORT\n\nGenerated: ${new Date().toISOString()}\nFramework: ${payload.framework || 'General'}\n\nThis report documents the current compliance and operational status of your AI systems fleet.\n\nTo unlock AI-generated reports, add your GROQ_API_KEY or GEMINI_API_KEY in Railway environment variables. Both are free.`,
    chat: `I'm your SBX Guardian fleet analyst. I can see your fleet data and compliance status. To enable full AI analysis, add your free Groq or Gemini API key in settings.\n\nYour current query: "${payload.prompt}"\n\nBased on available data: your fleet is operational. Check the Anomalies and Risk pages for detailed insights.`
  };
  return { text: responses[task] || responses.chat, model: 'builtin-fallback', task };
}

// ── SPECIFIC AI FEATURES ───────────────────────────────────────────────────

async function analyzeAnomaly(anomaly, systemName) {
  return smartAI('anomaly_explain', {
    metric: anomaly.metric,
    expected: anomaly.expected,
    actual: anomaly.actual,
    severity: anomaly.severity,
    system: systemName,
    prompt: `Analyze this robot anomaly and give a 3-sentence explanation + 3 specific action items:
System: ${systemName}
Metric: ${anomaly.metric}
Expected value: ${anomaly.expected}
Actual value: ${anomaly.actual}  
Deviation: ${anomaly.deviation}
Severity: ${anomaly.severity}
Be specific, technical, and actionable.`
  });
}

async function generateEvidenceReport(context) {
  const prompt = `Generate a professional ${context.type} for ${context.framework} compliance.

FLEET DATA:
- Organization: ${context.org_name}
- Systems: ${context.total_systems} total (${context.online} online)
- Compliance Score: ${context.compliance_score}%
- Critical Events (24h): ${context.critical_events}
- Active Anomalies: ${context.anomalies}
- Failing Requirements: ${context.failing_items}
- Hash Chain Status: ${context.chain_valid ? 'VERIFIED - TAMPER-EVIDENT' : 'CHAIN BROKEN - INVESTIGATE'}

Context: ${context.description || 'General compliance assessment'}
Date: ${new Date().toLocaleDateString()}

Write a complete, formal document with:
1. Executive Summary
2. System Overview  
3. Compliance Status by Article
4. Evidence References (cite hash chain certification)
5. Risk Assessment
6. Recommendations
7. Certification Statement

This document will be submitted to insurers/regulators. Be precise and formal.`;

  return smartAI('evidence_report', { prompt, framework: context.framework });
}

async function fleetChatAnalysis(messages, fleetContext) {
  const systemPrompt = `You are SBX Guardian's AI fleet analyst with real-time access to this data:

FLEET: ${fleetContext.total_systems} systems | ${fleetContext.online} online | ${fleetContext.offline} offline
HEALTH: Average ${fleetContext.avg_health}% | ${fleetContext.warnings} warnings
RISK: Fleet risk score ${fleetContext.avg_risk}/100 | ${fleetContext.critical_systems} critical systems
ANOMALIES: ${fleetContext.active_anomalies} active unresolved
COMPLIANCE: ${fleetContext.compliance_score}% score | ${fleetContext.failing} requirements failing
EU AI ACT: ${fleetContext.eu_days} days until enforcement
RECENT CRITICAL EVENTS: ${fleetContext.recent_critical}

Be specific, reference actual numbers, give actionable recommendations.
You have deep expertise in robotics, EU AI Act compliance, and industrial safety.`;

  return smartAI('chat', { prompt: messages[messages.length-1]?.content, system: systemPrompt }, messages);
}

async function predictFailureRisk(system, events, anomalies) {
  const prompt = `Predict failure probability for this industrial robot system in the next 7 days:

System: ${system.name} (${system.type})
Location: ${system.location}
Health: ${system.health}%
Status: ${system.status}
Firmware: ${system.firmware}
Recent critical events: ${events.filter(e=>e.severity==='critical').length}
Active anomalies: ${anomalies.length}
Circuit breaker: ${system.cb_status}
Current load: ${system.current_load}%

Give:
1. Failure probability (0-100%)
2. Most likely failure mode
3. Estimated time to failure if current trend continues
4. 3 specific preventive actions
Be direct and specific.`;

  return smartAI('risk_prediction', { prompt });
}

async function generateColdEmail(companyName, companyType, contactName) {
  const prompt = `Write a cold outreach email from SBX Guardian to ${contactName} at ${companyName} (${companyType}).

SBX Guardian is a platform that:
- Gives industrial robots a tamper-proof black box (like aircraft flight recorders)
- Generates EU AI Act compliance reports automatically
- Reduces legal liability with court-ready evidence packs
- Connects via simple webhook in 30 minutes

The EU AI Act enforcement is in ${Math.ceil((new Date('2026-08-02')-Date.now())/86400000)} days.
Their robots legally qualify as high-risk AI. Penalty: up to €30M.

Write a short (150 words max), compelling, non-spammy email.
Subject line + body. Make it urgent but professional.`;

  return smartAI('fleet_analysis', { prompt });
}

module.exports = { smartAI, analyzeAnomaly, generateEvidenceReport, fleetChatAnalysis, predictFailureRisk, generateColdEmail };
