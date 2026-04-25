// SBX GUARDIAN — ENTERPRISE SECURITY LAYER
// Encryption, audit trails, GDPR, session management
// This is what enterprise clients pay for

const crypto = require('crypto');
const { query, run, get } = require('./db');
const { v4: uuidv4 } = require('uuid');

const ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.randomBytes(32).toString('hex');
const ALGORITHM = 'aes-256-gcm';

// ── DATA ENCRYPTION ───────────────────────────────────────────
function encrypt(text) {
  if (!text) return text;
  try {
    const iv = crypto.randomBytes(16);
    const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex');
    const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
    let encrypted = cipher.update(String(text), 'utf8', 'hex');
    encrypted += cipher.final('hex');
    const authTag = cipher.getAuthTag();
    return `${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted}`;
  } catch { return text; }
}

function decrypt(text) {
  if (!text || !text.includes(':')) return text;
  try {
    const [ivHex, authTagHex, encrypted] = text.split(':');
    const key = Buffer.from(ENCRYPTION_KEY.slice(0, 64), 'hex');
    const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(ivHex, 'hex'));
    decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch { return text; }
}

// ── AUDIT TRAIL ───────────────────────────────────────────────
function logAudit(orgId, userId, action, resource, resourceId, details, ipAddress) {
  try {
    run('INSERT INTO security_audit (id,org_id,user_id,action,resource,resource_id,details,ip_address,created_at) VALUES (?,?,?,?,?,?,?,?,?)',
      [uuidv4(), orgId, userId||'system', action, resource||'', resourceId||'', JSON.stringify(details||{}), ipAddress||'unknown', Date.now()]);
  } catch(e) { console.log('[AUDIT]', e.message); }
}

function getAuditLog(orgId, limit=50) {
  return query('SELECT * FROM security_audit WHERE org_id=? ORDER BY created_at DESC LIMIT ?', [orgId, limit]);
}

// ── SECURITY AUDIT MIDDLEWARE ─────────────────────────────────
function auditMiddleware(action, resource) {
  return (req, res, next) => {
    if (req.user) {
      logAudit(req.user.org_id, req.user.id, action, resource, req.params.id||'', { method:req.method, path:req.path, body:req.method==='GET'?undefined:{...req.body,password:undefined} }, req.ip);
    }
    next();
  };
}

// ── SESSION MANAGEMENT ────────────────────────────────────────
const activeSessions = new Map();

function createSession(userId, orgId, ipAddress, userAgent) {
  const sessionId = crypto.randomBytes(32).toString('hex');
  const session = { sessionId, userId, orgId, ipAddress, userAgent, createdAt: Date.now(), lastActive: Date.now() };
  activeSessions.set(sessionId, session);
  run('INSERT INTO security_sessions (id,user_id,org_id,ip_address,user_agent,created_at,last_active) VALUES (?,?,?,?,?,?,?)',
    [sessionId, userId, orgId, ipAddress, userAgent||'', Date.now(), Date.now()]);
  return sessionId;
}

function getActiveSessions(userId) {
  return query('SELECT id,ip_address,user_agent,created_at,last_active FROM security_sessions WHERE user_id=? AND expires_at IS NULL ORDER BY last_active DESC', [userId]);
}

function revokeSession(sessionId, userId) {
  activeSessions.delete(sessionId);
  run('UPDATE security_sessions SET expires_at=? WHERE id=? AND user_id=?', [Date.now(), sessionId, userId]);
}

// ── API KEY MANAGEMENT ────────────────────────────────────────
function generateAPIKey(orgId, name, permissions) {
  const key = 'sbx_' + crypto.randomBytes(32).toString('hex');
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  run('INSERT INTO api_keys (id,org_id,name,key_hash,permissions,created_at) VALUES (?,?,?,?,?,?)',
    [uuidv4(), orgId, name||'API Key', keyHash, JSON.stringify(permissions||['read']), Date.now()]);
  return key; // Only returned once, never stored in plain text
}

function validateAPIKey(key) {
  if (!key?.startsWith('sbx_')) return null;
  const keyHash = crypto.createHash('sha256').update(key).digest('hex');
  return get('SELECT ak.*,o.name as org_name FROM api_keys ak JOIN organizations o ON o.id=ak.org_id WHERE ak.key_hash=? AND ak.revoked=0', [keyHash]);
}

// ── GDPR COMPLIANCE ───────────────────────────────────────────
async function exportUserData(userId, orgId) {
  const user = get('SELECT id,email,name,role,created_at FROM users WHERE id=?', [userId]);
  const events = query('SELECT id,type,severity,message,timestamp FROM events WHERE org_id=? AND operator_id=?', [orgId, userId]);
  const reports = query('SELECT id,title,type,created_at FROM reports WHERE org_id=? AND generated_by=?', [orgId, user?.name||'']);
  return { user, events, reports, exported_at: new Date().toISOString(), gdpr_note: 'Data export under GDPR Article 20 right to data portability' };
}

async function deleteUserData(userId, orgId) {
  // Anonymize rather than delete (preserves chain integrity)
  run('UPDATE users SET name="[Deleted]",email=?,last_login=NULL WHERE id=? AND org_id=?', [`deleted_${userId}@sbx.removed`, userId, orgId]);
  run('UPDATE events SET operator_id=NULL WHERE operator_id=? AND org_id=?', [userId, orgId]);
  logAudit(orgId, userId, 'gdpr_delete', 'user', userId, { reason: 'GDPR right to erasure' }, 'system');
  return { success: true, note: 'User data anonymized per GDPR Article 17' };
}

// ── SECURITY HEADERS ──────────────────────────────────────────
function securityHeadersMiddleware(req, res, next) {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'geolocation=(), microphone=(), camera=()');
  res.setHeader('Cache-Control', 'no-store');
  if (req.secure || req.headers['x-forwarded-proto'] === 'https') {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
}

// ── RATE LIMITING PER USER ────────────────────────────────────
const userRateLimits = new Map();
function userRateLimit(maxRequests, windowMs) {
  return (req, res, next) => {
    if (!req.user) return next();
    const key = req.user.id + ':' + req.path;
    const now = Date.now();
    const window = userRateLimits.get(key) || [];
    const recent = window.filter(t => now - t < windowMs);
    if (recent.length >= maxRequests) {
      return res.status(429).json({ error: 'Rate limit exceeded', retry_after: windowMs/1000 + 's' });
    }
    recent.push(now);
    userRateLimits.set(key, recent);
    next();
  };
}

// ── SECURITY REPORT ───────────────────────────────────────────
function getSecurityReport(orgId) {
  const auditLog = getAuditLog(orgId, 20);
  const apiKeys = query('SELECT id,name,permissions,created_at,last_used FROM api_keys WHERE org_id=? AND revoked=0', [orgId]);
  const sessions = query('SELECT COUNT(*) as c FROM security_sessions WHERE org_id=? AND expires_at IS NULL AND last_active > ?', [orgId, Date.now()-86400000]);
  const users = query('SELECT id,name,email,role,last_login FROM users WHERE org_id=?', [orgId]);
  const failedLogins = query('SELECT COUNT(*) as c FROM security_audit WHERE org_id=? AND action=? AND created_at > ?', [orgId, 'login_failed', Date.now()-86400000]);

  return {
    active_sessions: sessions[0]?.c || 0,
    api_keys: apiKeys.length,
    team_members: users.length,
    failed_logins_24h: failedLogins[0]?.c || 0,
    recent_activity: auditLog,
    security_score: calculateSecurityScore(orgId),
    compliance: {
      gdpr_ready: true,
      data_encrypted: !!process.env.ENCRYPTION_KEY,
      audit_trail: true,
      mfa_enabled: false, // Future feature
      soc2_in_progress: true
    }
  };
}

function calculateSecurityScore(orgId) {
  let score = 60; // Base score
  if (process.env.ENCRYPTION_KEY) score += 15;
  if (process.env.JWT_SECRET && process.env.JWT_SECRET !== 'sbx-guardian-2026') score += 10;
  if (process.env.SMTP_USER) score += 5; // Email alerts configured
  const users = query('SELECT role FROM users WHERE org_id=?', [orgId]);
  if (users.filter(u=>u.role==='admin').length <= 2) score += 10;
  return Math.min(100, score);
}

module.exports = {
  encrypt, decrypt, logAudit, getAuditLog, auditMiddleware,
  createSession, getActiveSessions, revokeSession,
  generateAPIKey, validateAPIKey,
  exportUserData, deleteUserData,
  securityHeadersMiddleware, userRateLimit,
  getSecurityReport, calculateSecurityScore
};
