// ═══════════════════════════════════════════════════════════════
// SBX GUARDIAN — ADVANCED REPORT ENGINE
// SOC2, ISO 27001, insurance, regulatory, custom templates
// ═══════════════════════════════════════════════════════════════
const { query, get } = require('./db');
const { getComplianceGapAnalysis, getFleetIntelligence } = require('./intelligence');

const REPORT_TEMPLATES = {
  eu_ai_act_conformity: {
    name: 'EU AI Act Conformity Assessment',
    framework: 'EU AI Act',
    sections: ['executive_summary','system_classification','risk_management','technical_documentation','logging_evidence','human_oversight','conformity_statement']
  },
  insurance_evidence: {
    name: 'Insurance Evidence Pack',
    framework: 'General',
    sections: ['incident_summary','system_state','event_chain','chain_integrity','liability_assessment','recommendations']
  },
  soc2_readiness: {
    name: 'SOC 2 Type II Readiness Report',
    framework: 'SOC 2',
    sections: ['scope','security','availability','processing_integrity','confidentiality','privacy']
  },
  iso_27001: {
    name: 'ISO 27001 Gap Analysis',
    framework: 'ISO 27001',
    sections: ['scope','risk_assessment','controls','gaps','remediation_plan']
  },
  board_report: {
    name: 'Board-Level AI Risk Report',
    framework: 'General',
    sections: ['executive_summary','risk_posture','compliance_status','incidents','financial_exposure','recommendations']
  }
};

function buildReportContext(orgId) {
  const org = get('SELECT * FROM organizations WHERE id=?',[orgId]);
  const systems = query('SELECT * FROM systems WHERE org_id=?',[orgId]);
  const compliance = query('SELECT * FROM compliance_items WHERE org_id=?',[orgId]);
  const events7d = query('SELECT * FROM events WHERE org_id=? AND timestamp>? ORDER BY timestamp DESC',[orgId,Date.now()-7*86400000]);
  const anomalies = query('SELECT a.*,s.name as system_name FROM anomalies a LEFT JOIN systems s ON s.id=a.system_id WHERE a.org_id=?',[orgId]);
  const alerts = query('SELECT * FROM alerts WHERE org_id=? AND resolved=0',[orgId]);
  const chainCheck = query('SELECT hash,prev_hash FROM events WHERE org_id=? ORDER BY timestamp ASC LIMIT 500',[orgId]);

  let chainValid = true;
  for(let i=1;i<chainCheck.length;i++) {
    if(chainCheck[i].prev_hash!==chainCheck[i-1].hash){chainValid=false;break;}
  }

  const passing = compliance.filter(c=>c.status==='pass').length;
  const compScore = compliance.length ? Math.round(passing/compliance.length*100) : 0;
  const euItems = compliance.filter(c=>c.framework==='EU AI Act');
  const euPassing = euItems.filter(c=>c.status==='pass').length;
  const euScore = euItems.length ? Math.round(euPassing/euItems.length*100) : 0;
  const intel = getFleetIntelligence(orgId);
  const gaps = getComplianceGapAnalysis(orgId);

  return {
    org: org?.name||'Organization',
    generated_at: new Date().toISOString(),
    days_to_eu_enforcement: Math.ceil((new Date('2026-08-02')-Date.now())/86400000),
    fleet: {
      total: systems.length,
      online: systems.filter(s=>s.status==='online').length,
      warning: systems.filter(s=>s.status==='warning').length,
      offline: systems.filter(s=>s.status==='offline').length,
      avg_health: systems.length?Math.round(systems.reduce((a,b)=>a+(b.health||0),0)/systems.length):0,
      health_score: intel.fleet_health_score
    },
    compliance: {
      overall_score: compScore,
      eu_ai_act_score: euScore,
      passing, total: compliance.length,
      failing: compliance.filter(c=>c.status==='fail'),
      partial: compliance.filter(c=>c.status==='partial'),
      gaps: gaps.gaps
    },
    events: {
      total_7d: events7d.length,
      critical_7d: events7d.filter(e=>e.severity==='critical').length,
      warning_7d: events7d.filter(e=>e.severity==='warning').length,
      chain_valid: chainValid,
      chain_events: chainCheck.length
    },
    anomalies: {
      total: anomalies.length,
      active: anomalies.filter(a=>!a.resolved).length,
      critical: anomalies.filter(a=>a.severity==='critical'&&!a.resolved).length
    },
    alerts: { active: alerts.length },
    systems_detail: systems.map(s=>({name:s.name,type:s.type,status:s.status,health:s.health,location:s.location,manufacturer:s.manufacturer,firmware:s.firmware}))
  };
}

function buildPromptForTemplate(templateKey, context, customDescription) {
  const template = REPORT_TEMPLATES[templateKey];
  if (!template) return null;

  const baseContext = `
ORGANIZATION: ${context.org}
REPORT DATE: ${context.generated_at}
EU AI ACT ENFORCEMENT: ${context.days_to_eu_enforcement} days remaining

FLEET STATUS:
- ${context.fleet.total} total systems (${context.fleet.online} online, ${context.fleet.warning} warning, ${context.fleet.offline} offline)
- Average health: ${context.fleet.avg_health}%
- Fleet health score: ${context.fleet.health_score}/100

COMPLIANCE:
- Overall score: ${context.compliance.overall_score}%
- EU AI Act score: ${context.compliance.eu_ai_act_score}%
- Failing requirements: ${context.compliance.failing.map(f=>f.title).join(', ')||'None'}
- Partial requirements: ${context.compliance.partial.map(f=>f.title).join(', ')||'None'}

EVENTS (7 days):
- Total: ${context.events.total_7d}
- Critical: ${context.events.critical_7d}
- Hash chain: ${context.events.chain_valid?'VERIFIED INTACT':'INTEGRITY ISSUE DETECTED'}
- Chain covers: ${context.events.chain_events} events

ANOMALIES:
- Active: ${context.anomalies.active}
- Critical: ${context.anomalies.critical}

SYSTEMS:
${context.systems_detail.map(s=>`- ${s.name} (${s.type}): ${s.status}, ${s.health}% health, ${s.location}`).join('\n')}

${customDescription ? 'ADDITIONAL CONTEXT: '+customDescription : ''}`;

  const prompts = {
    eu_ai_act_conformity: `You are a senior EU AI Act compliance consultant. Generate a complete, formal EU AI Act Conformity Assessment Report.

${baseContext}

Write a professional conformity assessment covering:
1. EXECUTIVE SUMMARY - overall compliance posture and urgency
2. SYSTEM CLASSIFICATION - confirm high-risk AI classification under Annex III
3. RISK MANAGEMENT (Art. 9) - assessment of risk management system
4. TECHNICAL DOCUMENTATION (Art. 11) - documentation completeness
5. RECORD-KEEPING (Art. 12) - logging system assessment with hash chain evidence
6. HUMAN OVERSIGHT (Art. 14) - oversight mechanisms
7. ACCURACY & CYBERSECURITY (Art. 15) - technical robustness
8. CONFORMITY STATEMENT - formal declaration
9. GAPS & REMEDIATION - prioritized action plan before ${context.days_to_eu_enforcement} day deadline

Use formal legal language. Include specific article references. This document may be submitted to EU regulators.`,

    insurance_evidence: `You are a forensic AI systems analyst preparing an insurance evidence pack.

${baseContext}

Generate a complete insurance evidence pack covering:
1. EXECUTIVE SUMMARY
2. SYSTEM STATE AT TIME OF INCIDENT
3. COMPLETE EVENT CHAIN with timestamps
4. HASH CHAIN INTEGRITY CERTIFICATE - ${context.events.chain_valid?'CHAIN VERIFIED':'INTEGRITY ISSUE'}
5. LIABILITY ASSESSMENT
6. ROOT CAUSE ANALYSIS
7. RECOMMENDATIONS FOR INSURER

Be precise, factual, and technical. This document will be submitted to insurers.`,

    board_report: `You are a Chief Risk Officer preparing a board-level AI risk briefing.

${baseContext}

Generate a concise board report covering:
1. EXECUTIVE SUMMARY (3 sentences max)
2. CURRENT RISK POSTURE with RAG status
3. EU AI ACT EXPOSURE - ${context.days_to_eu_enforcement} days to enforcement, potential penalty calculation
4. COMPLIANCE STATUS by framework
5. MATERIAL INCIDENTS (last 7 days)
6. FINANCIAL EXPOSURE estimate
7. RECOMMENDED BOARD ACTIONS with owners and deadlines

Write for a non-technical board audience. Use business language. Lead with risk and money.`
  };

  return prompts[templateKey] || `Generate a professional ${template.name} report for ${context.org}.\n\n${baseContext}`;
}

module.exports = { REPORT_TEMPLATES, buildReportContext, buildPromptForTemplate };
