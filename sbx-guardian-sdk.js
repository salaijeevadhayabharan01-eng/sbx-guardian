/**
 * SBX Guardian SDK
 * The official SDK for connecting any system to SBX Guardian
 * 
 * npm install sbx-guardian-sdk
 * 
 * Usage:
 *   const SBXGuardian = require('sbx-guardian-sdk');
 *   const sbx = new SBXGuardian({ webhookUrl: 'YOUR_WEBHOOK_URL' });
 *   await sbx.log('heartbeat', 'System operational');
 */

'use strict';

class SBXGuardian {
  /**
   * @param {Object} config
   * @param {string} config.webhookUrl - Your unique webhook URL from the dashboard
   * @param {string} [config.systemId] - Default system ID for all events
   * @param {boolean} [config.debug] - Enable debug logging
   * @param {number} [config.heartbeatInterval] - Auto-heartbeat interval in ms (0 to disable)
   * @param {number} [config.batchSize] - Max events to batch before sending (default: 1)
   * @param {number} [config.retryAttempts] - Failed request retry attempts (default: 3)
   */
  constructor(config = {}) {
    if (!config.webhookUrl) throw new Error('SBX Guardian: webhookUrl is required');
    this.webhookUrl = config.webhookUrl;
    this.systemId = config.systemId || null;
    this.debug = config.debug || false;
    this.retryAttempts = config.retryAttempts || 3;
    this.batchSize = config.batchSize || 1;
    this._batch = [];
    this._heartbeatTimer = null;
    this._stats = { sent: 0, failed: 0, retried: 0 };
    
    if (config.heartbeatInterval && config.heartbeatInterval > 0) {
      this.startHeartbeat(config.heartbeatInterval);
    }
    
    this._log('SBX Guardian SDK initialized');
  }

  /**
   * Log an event to SBX Guardian
   * @param {string} type - Event type: heartbeat|ai_decision|safety_event|anomaly|error|maintenance|human_handoff
   * @param {string} message - Human-readable description
   * @param {Object} [options] - Additional options
   * @param {string} [options.severity] - info|warning|critical (default: info)
   * @param {string} [options.systemId] - Override default system ID
   * @param {number} [options.health] - System health 0-100
   * @param {number} [options.load] - System load 0-100
   * @param {Object} [options.data] - Additional structured data
   * @returns {Promise<{success: boolean, event_id: string, hash: string}>}
   */
  async log(type, message, options = {}) {
    const payload = {
      system_id: options.systemId || this.systemId,
      type,
      severity: options.severity || 'info',
      message,
      ...(options.health !== undefined && { health: options.health }),
      ...(options.load !== undefined && { load: options.load }),
      ...(options.data && { data: options.data }),
      sdk_version: '1.0.0'
    };
    
    if (this.batchSize > 1) {
      this._batch.push(payload);
      if (this._batch.length >= this.batchSize) return this._flushBatch();
      return { queued: true, batch_size: this._batch.length };
    }
    
    return this._send(payload);
  }

  // ── CONVENIENCE METHODS ───────────────────────────────────────

  /** Log a heartbeat */
  async heartbeat(health, load, data) {
    return this.log('heartbeat', 'System heartbeat', { health, load, data, severity: 'info' });
  }

  /** Log an AI decision */
  async decision(description, confidence, outcome, data = {}) {
    return this.log('ai_decision', description, {
      severity: confidence < 0.7 ? 'warning' : 'info',
      data: { confidence, outcome, ...data }
    });
  }

  /** Log a safety event */
  async safetyEvent(description, severity = 'warning', data = {}) {
    return this.log('safety_event', description, { severity, data });
  }

  /** Log an anomaly */
  async anomaly(description, metric, value, threshold, severity = 'warning') {
    return this.log('anomaly', description, {
      severity,
      data: { metric, value, threshold, deviation: ((value - threshold) / threshold * 100).toFixed(1) + '%' }
    });
  }

  /** Log a human handoff/override */
  async humanHandoff(operatorId, reason, direction = 'manual') {
    return this.log('human_handoff', `Human ${direction === 'manual' ? 'took' : 'returned'} control`, {
      data: { operator_id: operatorId, reason, direction }
    });
  }

  /** Log a critical error */
  async error(description, errorCode, data = {}) {
    return this.log('error', description, {
      severity: 'critical',
      data: { error_code: errorCode, ...data }
    });
  }

  /** Log a maintenance event */
  async maintenance(description, technician, data = {}) {
    return this.log('maintenance', description, {
      severity: 'info',
      data: { technician, ...data }
    });
  }

  /** Log firmware/software update */
  async update(version, previousVersion, changeLog) {
    return this.log('maintenance', `Firmware update: ${previousVersion} → ${version}`, {
      severity: 'info',
      data: { new_version: version, previous_version: previousVersion, change_log: changeLog }
    });
  }

  // ── BATCH OPERATIONS ──────────────────────────────────────────

  /** Flush the event batch immediately */
  async flush() { return this._flushBatch(); }

  async _flushBatch() {
    if (this._batch.length === 0) return { flushed: 0 };
    const batch = [...this._batch];
    this._batch = [];
    const results = await Promise.allSettled(batch.map(p => this._send(p)));
    return { flushed: batch.length, results };
  }

  // ── HEARTBEAT MANAGEMENT ──────────────────────────────────────

  /** Start automatic heartbeat */
  startHeartbeat(intervalMs = 30000, getMetrics = null) {
    this.stopHeartbeat();
    this._heartbeatTimer = setInterval(async () => {
      const metrics = getMetrics ? await getMetrics() : {};
      await this.heartbeat(metrics.health, metrics.load, metrics.data);
    }, intervalMs);
    this._log(`Heartbeat started: every ${intervalMs/1000}s`);
    return this;
  }

  /** Stop automatic heartbeat */
  stopHeartbeat() {
    if (this._heartbeatTimer) { clearInterval(this._heartbeatTimer); this._heartbeatTimer = null; }
    return this;
  }

  // ── CHAIN VERIFICATION ────────────────────────────────────────

  /** Verify the hash chain integrity of all your logs */
  async verifyChain(apiKey) {
    try {
      const url = this.webhookUrl.replace('/api/webhook/', '/api/v1/');
      const baseUrl = url.split('/api/')[0];
      const response = await this._fetch(`${baseUrl}/api/v1/chain/verify`, {
        headers: { 'X-API-Key': apiKey || this.webhookUrl.split('/').pop() }
      });
      const data = await response.json();
      this._log('Chain verification:', data);
      return data;
    } catch(e) {
      this._log('Chain verification failed:', e.message);
      return { valid: null, error: e.message };
    }
  }

  // ── STATS ─────────────────────────────────────────────────────

  /** Get SDK statistics */
  getStats() { return { ...this._stats }; }

  // ── INTERNAL ──────────────────────────────────────────────────

  async _send(payload, attempt = 1) {
    try {
      const response = await this._fetch(this.webhookUrl, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      
      if (!response.ok) {
        const err = await response.text();
        throw new Error(`HTTP ${response.status}: ${err}`);
      }
      
      const data = await response.json();
      this._stats.sent++;
      this._log(`Event sent: ${payload.type} → ${data.event_id}`);
      return data;
    } catch(e) {
      if (attempt < this.retryAttempts) {
        this._stats.retried++;
        await this._sleep(1000 * attempt);
        return this._send(payload, attempt + 1);
      }
      this._stats.failed++;
      this._log(`Event failed after ${attempt} attempts: ${e.message}`);
      throw e;
    }
  }

  async _fetch(url, options = {}) {
    if (typeof fetch !== 'undefined') return fetch(url, options);
    const https = require('https');
    const http = require('http');
    return new Promise((resolve, reject) => {
      const parsed = new URL(url);
      const mod = parsed.protocol === 'https:' ? https : http;
      const req = mod.request({ hostname: parsed.hostname, port: parsed.port, path: parsed.pathname + parsed.search, method: options.method || 'GET', headers: options.headers || {} }, res => {
        let body = '';
        res.on('data', d => body += d);
        res.on('end', () => resolve({ ok: res.statusCode >= 200 && res.statusCode < 300, status: res.statusCode, json: () => Promise.resolve(JSON.parse(body)), text: () => Promise.resolve(body) }));
      });
      req.on('error', reject);
      if (options.body) req.write(options.body);
      req.end();
    });
  }

  _sleep(ms) { return new Promise(r => setTimeout(r, ms)); }
  _log(...args) { if (this.debug) console.log('[SBX Guardian]', ...args); }

  /** Graceful shutdown — flush batch and stop heartbeat */
  async shutdown() {
    this.stopHeartbeat();
    await this.flush();
    this._log('SDK shutdown complete. Stats:', this._stats);
    return this._stats;
  }
}

// ── FRAMEWORK INTEGRATIONS ────────────────────────────────────

/** ROS2 Node integration */
SBXGuardian.ROS2Integration = class {
  constructor(sbx, node) { this.sbx = sbx; this.node = node; }
  logDecision(topic, message) { this.sbx.decision(message, 0.95, 'executed', { topic }); }
  logSafety(event) { this.sbx.safetyEvent(event.description, event.severity); }
};

/** Express.js middleware — auto-logs API calls affecting AI */
SBXGuardian.expressMiddleware = (sbx, systemId) => (req, res, next) => {
  if (req.path.includes('/command') || req.path.includes('/control')) {
    sbx.log('human_handoff', `API command: ${req.method} ${req.path}`, { systemId, data: { path: req.path, method: req.method } });
  }
  next();
};

/** Python-style context manager pattern */
SBXGuardian.prototype.session = async function(callback) {
  try { return await callback(this); }
  finally { await this.shutdown(); }
};

module.exports = SBXGuardian;

// ================================================================
// USAGE EXAMPLES
// ================================================================
/*

// BASIC - log an AI decision
const sbx = new SBXGuardian({ webhookUrl: 'YOUR_WEBHOOK_URL', systemId: 'robot-arm-01' });
await sbx.decision('Obstacle avoided', 0.97, 'rerouted', { obstacle_distance: 0.3 });

// AUTOMATIC HEARTBEAT every 30 seconds
const sbx = new SBXGuardian({
  webhookUrl: 'YOUR_WEBHOOK_URL',
  systemId: 'robot-01',
  heartbeatInterval: 30000
});

// WITH DYNAMIC METRICS
const sbx = new SBXGuardian({ webhookUrl: 'YOUR_WEBHOOK_URL', heartbeatInterval: 30000 });
sbx.startHeartbeat(30000, async () => ({
  health: await getSystemHealth(),
  load: await getCPULoad(),
  data: { temperature: await getTemperature() }
}));

// SAFETY EVENT CHAIN
try {
  const result = await robot.executeMission(mission);
  await sbx.log('mission_complete', `Mission ${mission.id} completed`, { data: { result } });
} catch(err) {
  await sbx.error(`Mission failed: ${err.message}`, 'MISSION_FAILURE', { mission_id: mission.id });
}

// HUMAN HANDOFF
robot.on('estop', async (operatorId) => {
  await sbx.humanHandoff(operatorId, 'Emergency stop activated', 'manual');
});

// VERIFY CHAIN INTEGRITY (for insurers/auditors)
const verification = await sbx.verifyChain();
console.log(verification.valid); // true/false

// BATCH MODE (high-frequency systems)
const sbx = new SBXGuardian({ webhookUrl: 'YOUR_URL', batchSize: 10 });
// Batches 10 events then sends in one request

// GRACEFUL SHUTDOWN
process.on('SIGTERM', async () => {
  const stats = await sbx.shutdown();
  console.log('Sent:', stats.sent, 'Failed:', stats.failed);
  process.exit(0);
});

*/
