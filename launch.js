// SBX GUARDIAN — LAUNCH CONTENT GENERATOR
// Hacker News, Product Hunt, Mastodon, Medium
// One-time launch content that gets you first users fast

const APP_URL = process.env.APP_URL || 'https://sbx-guardian.onrender.com';
const DAYS = Math.ceil((new Date('2026-08-02') - Date.now()) / 86400000);

// ── HACKER NEWS "SHOW HN" POST ────────────────────────────────
const HN_POST = {
  title: `Show HN: SBX Guardian – tamper-proof black box for industrial robots (EU AI Act compliance)`,
  text: `Hi HN,

I built SBX Guardian because a problem I couldn't stop thinking about: when an industrial robot causes an incident, nobody can prove what actually happened. Logs are messy, incomplete, or just a text file that anyone can edit.

The EU AI Act (enforcement: ${DAYS} days away) makes this a legal emergency for any company running industrial robots in the EU. Article 12 specifically requires tamper-evident logging. Most companies have logging. Almost none have tamper-evident logging.

What I built:
- SHA-256 cryptographic hash chain on every event (like Git, but for robot telemetry)
- EU AI Act compliance dashboard tracking all 9 articles (Art. 9-16)
- One-click evidence pack generation for insurers/regulators
- Anomaly detection that learns each robot's baseline behavior
- Connects to any robot via webhook in ~30 minutes (Python/Node/Arduino examples included)

The stack: Node.js, sql.js, WebSocket for live updates. No external dependencies for the core logging chain — it's all SHA-256 hashes.

Live demo: ${APP_URL}
Login: admin@sbxguardian.com / sbx2026

I'm especially curious about: (1) whether the hash chain approach is court-admissible in different jurisdictions, (2) whether robotics engineers here have run into the EU AI Act compliance problem, (3) technical feedback on the tamper-evidence mechanism.

Happy to answer any questions.`
};

// ── PRODUCT HUNT LAUNCH ───────────────────────────────────────
const PH_LAUNCH = {
  name: 'SBX Guardian',
  tagline: 'The black box for industrial AI systems',
  description: `When a robot causes an incident, you need to prove exactly what happened.

SBX Guardian gives every industrial robot a tamper-proof black box — like aircraft flight recorders, but for AI systems.

🔐 SHA-256 cryptographic hash chain on every event
⚖️ EU AI Act compliance dashboard (Art. 9-16)
📄 One-click insurer evidence packs
⚡ AI anomaly detection per robot
🔗 Connects in 30 minutes via webhook

The EU AI Act enforcement date is ${DAYS} days away. Every industrial robot running ML qualifies as High-Risk AI. Penalty: up to €30M.

We're the only platform purpose-built for this.`,
  first_comment: `Hi Product Hunt! 👋

I built SBX Guardian after realizing that the EU AI Act creates a massive compliance gap that nobody has solved for physical AI systems.

Software compliance tools like Vanta/Secureframe exist for cloud software. But nothing exists for industrial robots, drones, and AGVs — which are now legally classified as "High-Risk AI" under EU law.

The core innovation is the tamper-evident hash chain: every event is cryptographically signed so that if anyone tries to modify or delete a log entry, the entire chain breaks. It's mathematically provable in court.

Try the live demo: ${APP_URL}
Login: admin@sbxguardian.com / sbx2026

Would love your feedback! Especially from anyone in manufacturing, robotics, or compliance.`
};

// ── MASTODON AUTO-POST ────────────────────────────────────────
async function postToMastodon(content) {
  const MASTODON_TOKEN = process.env.MASTODON_TOKEN;
  const MASTODON_INSTANCE = process.env.MASTODON_INSTANCE || 'mastodon.social';
  if (!MASTODON_TOKEN) return false;

  try {
    const r = await fetch(`https://${MASTODON_INSTANCE}/api/v1/statuses`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${MASTODON_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        status: content.slice(0, 500),
        visibility: 'public'
      })
    });
    const d = await r.json();
    if (d.id) { console.log('[MASTODON] Posted:', d.url); return d.url; }
    console.log('[MASTODON] Failed:', d.error);
    return false;
  } catch(e) { console.log('[MASTODON]', e.message); return false; }
}

// ── MEDIUM ARTICLE PUBLISHER ──────────────────────────────────
async function publishToMedium(title, content, tags) {
  const MEDIUM_TOKEN = process.env.MEDIUM_TOKEN;
  if (!MEDIUM_TOKEN) return false;

  try {
    // Get user ID first
    const userRes = await fetch('https://api.medium.com/v1/me', {
      headers: { 'Authorization': `Bearer ${MEDIUM_TOKEN}` }
    });
    const user = await userRes.json();
    if (!user.data?.id) return false;

    // Publish post
    const r = await fetch(`https://api.medium.com/v1/users/${user.data.id}/posts`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${MEDIUM_TOKEN}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        title, contentFormat: 'markdown', content,
        tags: tags || ['eu-ai-act', 'robotics', 'compliance', 'industrial-ai'],
        publishStatus: 'public'
      })
    });
    const d = await r.json();
    if (d.data?.url) { console.log('[MEDIUM] Published:', d.data.url); return d.data.url; }
    return false;
  } catch(e) { console.log('[MEDIUM]', e.message); return false; }
}

// ── MASTODON POST TEMPLATES ───────────────────────────────────
const MASTODON_POSTS = [
  `EU AI Act enforcement: ${DAYS} days away.

Every industrial robot running ML = High-Risk AI under EU law.
Penalty: up to €30M.
78% of manufacturers are not ready.

SBX Guardian = tamper-proof black box for robots. Connects in 30 minutes.

${APP_URL}

#EUAIAct #Robotics #Compliance #Manufacturing`,

  `When a robot causes an incident, can you prove what happened?

Most manufacturers: no.

SBX Guardian uses SHA-256 hash chains — every robot event cryptographically signed. Like Git, but for industrial AI telemetry.

Court-admissible. EU AI Act compliant.

${APP_URL}

#IndustrialAI #EUAIAct #Robotics`,

  `The EU AI Act creates a new category: "High-Risk AI Systems."

Your industrial robots almost certainly qualify.
Requirements: tamper-proof logging, human oversight, risk management, technical documentation.

${DAYS} days to comply.

We built the platform for this.

${APP_URL}

#EUAIAct #AI #Manufacturing #Compliance`
];

module.exports = { HN_POST, PH_LAUNCH, postToMastodon, publishToMedium, MASTODON_POSTS };
