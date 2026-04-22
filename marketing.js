// SBX Guardian — Marketing Agent
// Generates LinkedIn posts, cold emails, Twitter threads, pitch content
// Powered by Groq (free)

const { smartAI, generateColdEmail } = require('./ai');

const TARGETS = [
  { company: 'KUKA AG', type: 'Robot Manufacturer', contact: 'Head of Digital', location: 'Germany' },
  { company: 'ABB Robotics', type: 'Industrial Automation', contact: 'VP Engineering', location: 'Switzerland' },
  { company: 'Fanuc Corporation', type: 'CNC & Robot Manufacturer', contact: 'CTO', location: 'Japan/EU' },
  { company: 'Boston Dynamics', type: 'Mobile Robotics', contact: 'Head of Safety', location: 'USA' },
  { company: 'Universal Robots', type: 'Collaborative Robots', contact: 'Compliance Director', location: 'Denmark' },
  { company: 'Siemens Digital Industries', type: 'Industrial Automation', contact: 'VP AI Strategy', location: 'Germany' },
  { company: 'Bosch Rexroth', type: 'Drive & Control', contact: 'Head of Safety Engineering', location: 'Germany' },
  { company: 'Yaskawa', type: 'Motion Control & Robotics', contact: 'EU Compliance Lead', location: 'Japan/EU' },
];

const LINKEDIN_HOOKS = [
  `In ${Math.ceil((new Date('2026-08-02')-Date.now())/86400000)} days, your industrial robots become legally high-risk AI.`,
  `78% of manufacturers will fail their first EU AI Act audit. Here's what the 22% are doing differently:`,
  `A robot caused a $2M incident last week. The company couldn't prove what happened. Here's why that matters:`,
  `We just built what every robotics company needs but nobody has made yet:`,
  `The EU AI Act isn't coming. It's here in ${Math.ceil((new Date('2026-08-02')-Date.now())/86400000)} days. Are your robots compliant?`,
];

async function generateLinkedInPost(topic) {
  const hook = LINKEDIN_HOOKS[Math.floor(Math.random() * LINKEDIN_HOOKS.length)];
  const prompt = `Write a LinkedIn post for SBX Guardian about: ${topic}

Start with this hook: "${hook}"

SBX Guardian = tamper-proof black box + EU AI Act compliance + insurer evidence packs for industrial robots.

Rules:
- 150-200 words
- Include 1 specific stat (use real ones: €30M penalty, $532K/hr downtime, 78% fail audit)
- End with a question to drive comments
- 3-5 relevant hashtags
- No emojis except 1-2 max
- Sound like a founder, not a marketer
- Mention the August 2, 2026 deadline`;

  return smartAI('fleet_analysis', { prompt });
}

async function generateTwitterThread(topic) {
  const prompt = `Write a 5-tweet Twitter/X thread for SBX Guardian about: ${topic}

Format as:
Tweet 1/5: Hook (max 280 chars)
Tweet 2/5: Problem (max 280 chars)  
Tweet 3/5: Why now (EU AI Act, deadline)
Tweet 4/5: Solution (SBX Guardian)
Tweet 5/5: CTA

Be punchy, direct, use numbers. No hashtag spam — max 2 per tweet.`;

  return smartAI('fleet_analysis', { prompt });
}

async function generatePitchDeck(slide) {
  const slides = {
    problem: `Write the PROBLEM slide content for SBX Guardian investor pitch deck.
Key points: robots cause incidents, no tamper-proof logging, EU AI Act enforcement Aug 2026, €30M penalties, 78% fail audits.
Format: Slide title + 3 bullet points + 1 compelling stat. Max 80 words.`,
    solution: `Write the SOLUTION slide for SBX Guardian pitch deck.
SBX Guardian = plug-in black box for robots. Records everything, proves compliance, generates evidence.
Format: Slide title + what it does (3 bullets) + key differentiator. Max 80 words.`,
    market: `Write the MARKET slide for SBX Guardian.
Numbers: $7.4B now → $17.2B by 2034. 36,766 robots ordered in North America last year. EU AI Act = mandatory compliance.
Format: TAM/SAM/SOM structure. Max 80 words.`,
    traction: `Write the TRACTION slide for SBX Guardian early-stage startup.
We have: working product, GitHub repo, live deployment, EU AI Act deadline creating urgency.
Format: What we've built + why now is the perfect timing. Max 80 words.`,
    ask: `Write the ASK slide for SBX Guardian seed round.
We need: $250K to hire 1 engineer, get first 10 paying clients, build hardware prototype.
Format: Amount + use of funds (3 items) + 12-month milestones. Max 80 words.`
  };
  return smartAI('fleet_analysis', { prompt: slides[slide] || slides.problem });
}

async function generateOutreachEmail(targetIndex) {
  const target = TARGETS[targetIndex % TARGETS.length];
  return generateColdEmail(target.company, target.type, target.contact);
}

module.exports = { generateLinkedInPost, generateTwitterThread, generatePitchDeck, generateOutreachEmail, TARGETS, LINKEDIN_HOOKS };
