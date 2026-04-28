# ⬢ SBX Guardian
### The compliance operating system for physical AI systems.

**Tamper-proof logging · EU AI Act compliance · Board reporting · Regulatory intelligence · Insurance evidence**

[![Status](https://img.shields.io/badge/status-live-00d97e)](https://sbx-guardian.onrender.com)
[![License](https://img.shields.io/badge/license-Proprietary-c8a84b)](LICENSE)
[![EU AI Act](https://img.shields.io/badge/EU%20AI%20Act-Compliant-00d97e)](https://sbx-guardian.onrender.com/security.html)
[![Node.js](https://img.shields.io/badge/Node.js-v20-339933)](package.json)

---

## The Problem

When an industrial robot causes an incident — a collision, an unexpected stop, an injury — **nobody can prove what actually happened.**

Logs are messy, incomplete, or easily tampered. Insurance claims get denied. Regulatory fines hit. Liability drags through courts for years.

**Starting August 2, 2026**, every industrial robot running ML software in the EU is legally classified as a **High-Risk AI System** under the EU AI Act — with penalties up to **€15M or 3% of global annual revenue** for non-compliance.

- 78% of senior leaders cannot pass an AI governance audit
- Only 14% of companies with AI risk committees are actually deployment-ready
- Zero products on the market solve this specifically for physical robots

---

## The Solution

SBX Guardian is a **full-stack compliance operating system** for industrial AI. Not just logging — the entire lifecycle:

```
Risk Classification → AI Inventory Discovery → Technical Documentation →
Conformity Assessment → Tamper-proof Logging → Incident Response →
Board Reporting → Regulatory Intelligence → Insurance Evidence → M&A Due Diligence
```

---

## Core Features

| Feature | What it does |
|---|---|
| 🔐 **SHA-256 Hash Chain** | Every event cryptographically signed. Tamper-evident, court-admissible |
| ⚖ **EU AI Act Tracker** | All articles (Art. 9–16) with live pass/fail status |
| 📊 **Board Report Generator** | One-click AI-written board governance report in 60 seconds |
| 📰 **Regulatory Intelligence** | 47 regulations across 12 jurisdictions monitored live |
| 🔍 **AI Inventory Scanner** | Discover shadow AI systems across your facilities |
| 🚨 **Incident Response Playbook** | 72-hour legal response guide with interactive checklists |
| 📋 **FRIA Wizard** | Fundamental Rights Impact Assessment generator (Art. 27) |
| 📄 **Technical Documentation** | Annex IV documentation auto-generator |
| 💼 **M&A Due Diligence** | AI liability risk scoring for acquisition targets |
| 🏢 **White-label Partner Portal** | For law firms, Big 4, and management consultancies |
| 🛡 **Insurance Integration** | Certified audit exports for insurer claims teams |
| ⚡ **Anomaly Detection** | Per-robot baseline learning, predictive failure scoring |
| 🤖 **AI Fleet Analyst** | Plain-English fleet analysis via Groq + Gemini |
| 📈 **Built-in CRM** | Prospect tracking, pipeline management, nurture sequences |
| 📧 **Marketing Automation** | Email, Telegram, Discord, Reddit — 24/7 automated |

---

## Enterprise Trust Stack

| Document | Status | URL |
|---|---|---|
| Terms of Service | ✅ Live | `/terms.html` |
| Privacy Policy (GDPR) | ✅ Live | `/privacy.html` |
| Data Processing Agreement (Art. 28) | ✅ Live | `/dpa.html` |
| Security Overview | ✅ Live | `/security.html` |
| Trust Center | ✅ Live | `/trust-center.html` |
| API Documentation | ✅ Live | `/api-docs.html` |
| Status Page | ✅ Live | `/status.html` |
| Security Questionnaire (SIG) | ✅ Live | `/vendor-questionnaire.html` |
| Responsible Disclosure | ✅ Live | `/.well-known/security.txt` |
| SOC 2 Type II | 🔄 Q3 2026 | Under NDA on request |

---

## Security Architecture

- **Encryption at rest**: AES-256-GCM with unique IVs per record
- **Tamper evidence**: SHA-256 cryptographic hash chain (all events)
- **Authentication**: JWT tokens (organization-scoped), webhook secret auth
- **Authorization**: Row-level security — every query filtered by org_id
- **Transport**: TLS 1.2+ enforced on all endpoints
- **Audit trail**: Every action logged with timestamp, user, IP, and resource
- **Rate limiting**: Per-endpoint and per-user rate limiting
- **GDPR**: Data export, deletion, DPA, SCCs — all implemented

---

## Tech Stack

```
Backend:   Node.js + Express + WebSocket
Database:  SQLite (sql.js) with SHA-256 hash chain
Auth:      JWT (jsonwebtoken) + bcryptjs
AI:        Groq LLaMA 3.3 70B + Google Gemini 1.5 Flash (failover)
Frontend:  Vanilla JS SPA — no framework dependencies
Deploy:    Render (primary) · Railway (secondary)
Marketing: Gmail SMTP · Telegram Bot API · Discord Webhooks · Reddit API
```

---

## Quick Start

```bash
# Clone
git clone https://github.com/YOUR_USERNAME/sbx-guardian.git
cd sbx-guardian

# Install
npm install

# Seed demo data (12 robots, compliance items, sample events)
node seed.js

# Start
npm start

# Open http://localhost:3000
# Demo: admin@sbxguardian.com / sbx2026
```

---

## Environment Variables

```env
# Required
PORT=3000
JWT_SECRET=your-secure-random-string

# AI (get free at console.groq.com and aistudio.google.com)
GROQ_API_KEY=gsk_...
GEMINI_API_KEY=AI...

# Email automation (Gmail App Password from myaccount.google.com/apppasswords)
SMTP_USER=your@gmail.com
SMTP_PASS=xxxx-xxxx-xxxx-xxxx

# App URL (your deployment URL)
APP_URL=https://your-app.onrender.com

# Optional — automated marketing channels
TELEGRAM_BOT_TOKEN=...
TELEGRAM_CHANNEL_ID=...
DISCORD_WEBHOOK_URL=...
```

---

## API Reference

```
POST /api/auth/login                JWT token authentication
GET  /api/dashboard                 Live fleet summary + compliance
GET  /api/systems                   All AI systems with risk scores
POST /api/systems                   Add new system (returns webhook URL)
POST /api/events                    Log event (auto hash-chained)
GET  /api/events/verify             Verify entire chain integrity
GET  /api/safety/compliance         EU AI Act article status
POST /api/safety/reports            Generate AI evidence report
GET  /api/audit/export              Certified audit package (regulator-ready)
GET  /api/security/report           Security posture report
POST /api/marketing/trigger-generate  Trigger content generation
GET  /api/launch/hn                 Hacker News launch content
GET  /api/v1/chain/verify           Public chain verification (insurers/auditors)
```

Full docs: `/api-docs.html`

---

## Webhook SDK

Any robot, any language, any platform — 3 lines:

```python
import requests
requests.post("YOUR_WEBHOOK_URL", json={
    "system_id": "robot-arm-01",
    "type": "ai_decision",
    "severity": "info",
    "message": "Obstacle detected — rerouting",
    "health": 95, "load": 42.5,
    "data": {"obstacle_distance": 0.3, "confidence": 0.97}
})
```

Supported: Python · Node.js · ROS/ROS2 · Arduino · any HTTP client

---

## Services & Pages

| Page | Purpose |
|---|---|
| `/` | Landing page |
| `/app` | Main compliance dashboard |
| `/enterprise.html` | Fortune 500 enterprise page |
| `/trust-center.html` | All security documentation |
| `/regulatory-intelligence.html` | Live regulatory feed |
| `/board-report.html` | Board governance report generator |
| `/ma-due-diligence.html` | M&A AI liability assessment |
| `/consulting-partners.html` | White-label partner program |
| `/fria-wizard.html` | FRIA generator (EU AI Act Art. 27) |
| `/roi-calculator.html` | Fine exposure vs compliance cost calculator |
| `/ai-inventory.html` | Shadow AI discovery wizard |
| `/incident-playbook.html` | 72-hour incident response guide |
| `/insurance.html` | For insurers and risk managers |
| `/compare.html` | vs Alias Robotics, Credo AI, IBM |
| `/client-portal.html` | Client onboarding portal |
| `/api-docs.html` | Full API reference |
| `/status.html` | Live system status |

---

## Pricing

| Plan | Price | Systems | Key Features |
|---|---|---|---|
| **Starter** | $499/mo | Up to 10 | Full compliance, logging, reports |
| **Professional** | $1,999/mo | Up to 50 | + FRIA, Annex IV docs, board reports |
| **Enterprise** | Custom | Unlimited | + SSO, custom DPA, dedicated support |
| **Regulatory Intelligence** | $299/mo | Standalone | 47 regulations, 12 jurisdictions |
| **Consulting Partner** | From $999/mo | White-label | For law firms, Big 4, SIs |

---

## Roadmap

- [x] Tamper-evident SHA-256 hash chain logging
- [x] EU AI Act compliance tracker (Art. 9–16)
- [x] AI evidence report generation
- [x] Command firewall + circuit breakers
- [x] Real-time WebSocket fleet dashboard
- [x] Board governance report generator
- [x] Regulatory intelligence feed (47 regulations)
- [x] FRIA wizard (Art. 27)
- [x] M&A due diligence tool
- [x] White-label consulting portal
- [x] Insurance integration layer
- [x] AI systems inventory scanner
- [x] Incident response playbook
- [x] Full enterprise legal documents
- [ ] Supabase migration (persistent database)
- [ ] Stripe billing integration
- [ ] SOC 2 Type II certification (Q3 2026)
- [ ] Mobile app (React Native)
- [ ] Hardware black box device
- [ ] ISO 27001 certification (2027)

---

## Contact

| Purpose | Contact |
|---|---|
| Enterprise sales | enterprise@sbxguardian.com |
| Insurance partnerships | insurance@sbxguardian.com |
| Consulting partners | partners@sbxguardian.com |
| Security | security@sbxguardian.com |
| Legal / DPA | legal@sbxguardian.com |
| Privacy / GDPR | privacy@sbxguardian.com |

**Live demo**: [sbx-guardian.onrender.com](https://sbx-guardian.onrender.com)

---

© 2026 SBX Guardian. Proprietary software. All rights reserved.

*The compliance operating system for the age of Physical AI.*
