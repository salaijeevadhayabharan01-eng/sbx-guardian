// ═══════════════════════════════════════════════════════════════
// SBX GUARDIAN — SECURITY MIDDLEWARE
// Request logging, audit trail, suspicious activity detection
// ═══════════════════════════════════════════════════════════════
const { run } = require('./db');
const { v4: uuidv4 } = require('uuid');

// ── REQUEST LOGGER ────────────────────────────────────────────
function requestLogger(req, res, next) {
  const start = Date.now();
  res.on('finish', () => {
    const duration = Date.now() - start;
    if (req.path.startsWith('/api/') && req.method !== 'GET') {
      console.log(`[${new Date().toISOString()}] ${req.method} ${req.path} ${res.statusCode} ${duration}ms`);
    }
  });
  next();
}

// ── SUSPICIOUS ACTIVITY DETECTOR ─────────────────────────────
const requestCounts = new Map();
function suspiciousActivityDetector(req, res, next) {
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  const key = `${ip}:${req.path}`;
  const now = Date.now();
  const window = 60000;
  if (!requestCounts.has(key)) requestCounts.set(key, []);
  const times = requestCounts.get(key).filter(t => now-t < window);
  times.push(now);
  requestCounts.set(key, times);
  if (times.length > 100) {
    console.warn(`[SECURITY] High request rate from ${ip} on ${req.path}: ${times.length} req/min`);
  }
  next();
}

// ── RESPONSE HEADERS ──────────────────────────────────────────
function securityHeaders(req, res, next) {
  res.setHeader('X-Powered-By', 'SBX-Guardian');
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'SAMEORIGIN');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  next();
}

// ── API VERSION HEADER ────────────────────────────────────────
function apiVersionHeader(req, res, next) {
  if (req.path.startsWith('/api/')) {
    res.setHeader('X-SBX-Version', '5.0.0');
    res.setHeader('X-SBX-EU-Days', Math.ceil((new Date('2026-08-02')-Date.now())/86400000));
  }
  next();
}

module.exports = { requestLogger, suspiciousActivityDetector, securityHeaders, apiVersionHeader };
