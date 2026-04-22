// Anomaly Detection Engine
// Learns baseline per system, flags deviations

const { query, run, get } = require('./db');
const { v4: uuidv4 } = require('uuid');

function detectAnomalies(systemId, orgId, newLoad, health) {
  const history = query(
    'SELECT current_load, trip_count FROM circuit_breakers WHERE system_id = ?', [systemId]
  );
  if (!history.length) return null;

  const cb = history[0];
  const anomalies = [];

  // Load spike detection
  const expectedLoad = parseFloat(cb.current_load) || 50;
  const deviation = Math.abs(newLoad - expectedLoad);
  if (deviation > 30 && newLoad > 85) {
    anomalies.push({
      id: uuidv4(), org_id: orgId, system_id: systemId,
      metric: 'load', expected: expectedLoad, actual: newLoad,
      deviation: deviation.toFixed(1),
      severity: newLoad > 95 ? 'critical' : 'warning'
    });
  }

  // Health drop detection
  const prevHealth = query('SELECT health FROM systems WHERE id = ?', [systemId])[0]?.health || 100;
  const healthDrop = prevHealth - health;
  if (healthDrop > 15) {
    anomalies.push({
      id: uuidv4(), org_id: orgId, system_id: systemId,
      metric: 'health', expected: prevHealth, actual: health,
      deviation: healthDrop.toFixed(1),
      severity: healthDrop > 30 ? 'critical' : 'warning'
    });
  }

  anomalies.forEach(a => {
    run('INSERT INTO anomalies (id,org_id,system_id,metric,expected,actual,deviation,severity) VALUES (?,?,?,?,?,?,?,?)',
      [a.id, a.org_id, a.system_id, a.metric, a.expected, a.actual, a.deviation, a.severity]);
  });

  return anomalies;
}

function getRiskScore(systemId, orgId) {
  const sys = get('SELECT * FROM systems WHERE id = ?', [systemId]);
  if (!sys) return 0;
  const cb = get('SELECT * FROM circuit_breakers WHERE system_id = ?', [systemId]);
  const recentCritical = get(
    'SELECT COUNT(*) as c FROM events WHERE system_id = ? AND severity = ? AND timestamp > ?',
    [systemId, 'critical', Date.now() - 86400000]
  );
  const recentAnomalies = get(
    'SELECT COUNT(*) as c FROM anomalies WHERE system_id = ? AND resolved = 0',
    [systemId]
  );

  let score = 0;
  score += (100 - (sys.health || 100)) * 0.35;
  score += (recentCritical?.c || 0) * 8;
  score += (recentAnomalies?.c || 0) * 12;
  score += sys.status === 'warning' ? 20 : sys.status === 'offline' ? 45 : 0;
  score += cb?.status === 'open' ? 20 : 0;
  score += parseFloat(cb?.current_load || 0) > (cb?.threshold || 85) ? 15 : 0;

  return Math.min(100, Math.round(score));
}

function getFleetRiskSummary(orgId) {
  const systems = query('SELECT id FROM systems WHERE org_id = ?', [orgId]);
  const scores = systems.map(s => ({ id: s.id, score: getRiskScore(s.id, orgId) }));
  const avg = scores.length ? Math.round(scores.reduce((a, b) => a + b.score, 0) / scores.length) : 0;
  const critical = scores.filter(s => s.score > 70).length;
  return { avg_risk: avg, critical_systems: critical, total: scores.length, scores };
}

module.exports = { detectAnomalies, getRiskScore, getFleetRiskSummary };
