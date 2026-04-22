<div align="center">

# ⬢ SBX Guardian
### The Black Box for Industrial AI Systems

**Tamper-proof logging · EU AI Act compliance · One-click insurer evidence**

[![License: Proprietary](https://img.shields.io/badge/License-Proprietary-red.svg)]()
[![Node.js](https://img.shields.io/badge/Node.js-18%2B-green.svg)]()
[![Status](https://img.shields.io/badge/Status-Active%20Development-brightgreen.svg)]()

</div>

---

## The Problem

When an industrial robot causes an incident — a collision, an unexpected stop, an injury — **nobody can prove what actually happened.**

Logs are messy, incomplete, or tampered with. Insurance claims get denied. Regulatory fines hit. Liability drags through courts for years.

And starting **August 2, 2026**, every industrial robot running ML software in the EU is legally classified as a **High-Risk AI System** under the EU AI Act — with penalties up to **€30 million or 6% of global annual revenue** for non-compliance.

**78% of senior leaders currently cannot pass an AI governance audit.**

Zero products on the market solve this specifically for physical robots.

---

## The Solution

SBX Guardian is a plug-in platform that gives every AI system a **tamper-proof black box** — like flight recorders on aircraft, but for robots.

| Feature | What it does |
|---------|-------------|
| 🔐 **Hash Chain Logging** | Every event cryptographically signed in a SHA-256 chain. Tamper-evident, court-admissible. |
| ⚖️ **EU AI Act Compliance** | Tracks all 9 legal requirements (Art. 9–16) with live pass/fail status. |
| 📄 **Evidence Reports** | AI-generated insurer and regulator packs in one click. |
| ⚡ **Circuit Breakers** | Automatic system isolation on overload or anomaly. |
| 🛡️ **Command Firewall** | Rule-based command filtering with mandatory human oversight gates. |
| 📊 **Risk Prediction** | Predictive failure scoring across your entire fleet. |
| 🤖 **AI Analyst** | Ask anything about your fleet in plain English. |

---

## Market

| Metric | Data |
|--------|------|
| EU AI Act enforcement | **August 2, 2026** |
| Non-compliance penalty | Up to **€30M or 6% global revenue** |
| Robotics safety market (2024) | **$7.4 billion** |
| Robotics safety market (2034) | **$17.2 billion** |
| Industrial downtime cost | Up to **$532,000/hour** |
| Leaders who can pass AI audit today | **22%** |
| Products doing this for physical robots | **0** |

---

## Tech Stack

- **Backend:** Node.js + Express + WebSocket
- **Database:** SQL with SHA-256 tamper-evident hash chain
- **Auth:** JWT (JSON Web Tokens)
- **AI:** Claude (Anthropic) for report generation and fleet analysis
- **Frontend:** Vanilla JS single-page app, no framework dependencies
- **Deploy:** Railway / Render / any Node.js host

---

## Quick Start

```bash
# Clone the repo
git clone https://github.com/YOUR_USERNAME/sbx-guardian.git
cd sbx-guardian

# Install dependencies
npm install

# Seed demo database
node scripts/seed.js

# Start the server
node src/server.js

# Open http://localhost:3000
# Login: admin@sbxguardian.com / sbx2026
```

---

## API Overview

```
POST /api/auth/login           Login, receive JWT
GET  /api/systems              List all AI systems
POST /api/events               Log event (auto hash-chained)
GET  /api/events/verify        Verify entire chain integrity
GET  /api/safety/compliance    EU AI Act compliance status
POST /api/safety/reports       Save evidence report
GET  /api/dashboard            Live fleet summary
```

---

## Roadmap

- [x] Tamper-evident event logging with SHA-256 hash chain
- [x] EU AI Act compliance tracker (Art. 9–16)
- [x] AI-generated insurer evidence packs
- [x] Command firewall with mandatory oversight gates
- [x] Circuit breaker / system isolation
- [x] Real-time WebSocket fleet dashboard
- [ ] Physical device SDK (npm package for robots)
- [ ] Custom domain + marketing site
- [ ] Stripe billing integration
- [ ] Mobile app (React Native)
- [ ] Hardware black box unit (tamper-proof physical device)

---

## Contact

**SBX Guardian**
For partnerships, pilots, and investment inquiries: admin@sbxguardian.com

---

<div align="center">
<sub>© 2026 SBX Guardian. All rights reserved. Proprietary software — see LICENSE.</sub>
</div>
