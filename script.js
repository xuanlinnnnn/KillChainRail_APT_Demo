/* ============================================================
   Data — pillars and stage definitions
   ============================================================ */

const PILLARS = [
  {
    num: "01",
    name: "Scoping & Rules of Engagement",
    desc: "Written RoE defines target systems, prohibited actions, and emergency stop conditions before any action is taken. Nothing executes outside the agreed scope.",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round">
             <circle cx="12" cy="12" r="9"/><circle cx="12" cy="12" r="4"/>
             <line x1="12" y1="3" x2="12" y2="7"/><line x1="12" y1="17" x2="12" y2="21"/>
             <line x1="3" y1="12" x2="7" y2="12"/><line x1="17" y1="12" x2="21" y2="12"/>
           </svg>`
  },
  {
    num: "02",
    name: "Realism vs. Safety Trade-off",
    desc: "Techniques that create unacceptable risk are documented as design findings, not demonstrated. The gap itself becomes a hardening task — more valuable than a working exploit.",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
             <path d="M12 3v18M5 21h14"/><path d="M5 8l7-5 7 5"/><path d="M3 8l4 8H7M17 8l4 8h-4"/>
           </svg>`
  },
  {
    num: "03",
    name: "Operational Security Discipline",
    desc: "Every simulated attacker action is logged before execution. Lab snapshots allow instant rollback. No movement is permitted beyond the designated test network segment.",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
             <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
           </svg>`
  },
  {
    num: "04",
    name: "Findings Harden Tooling",
    desc: "Every evasion technique the red team cannot safely demonstrate becomes a blue-team backlog item — turning attacker tradecraft into a concrete defensive investment.",
    icon: `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.6" stroke-linecap="round" stroke-linejoin="round">
             <polyline points="22 12 18 12 15 21 9 3 6 12 2 12"/>
           </svg>`
  }
];

// Each stage maps one ATT&CK technique to its red/safe/blue/nation columns.
// activePillars tells the UI which framework pillars to highlight.
// `plain` is a jargon-free, one-sentence summary for newcomers.
const STAGES = [
  {
    id: 1,
    mitre: "T1566.001",
    tactic: "Initial Access",
    name: "Spearphishing Attachment",
    short: "Initial Access",
    evasion: false,
    activePillars: [0, 2],
    apt: "APT28, APT29",
    plain: "A fake email attachment tricks someone into opening it, giving the attacker their very first foothold on a computer.",
    red: `A simulated adversary delivers a lure document crafted to the target's role — an HR policy PDF with an embedded macro. When opened, it spawns a child shell process and establishes the initial foothold without needing a custom executable.`,
    safe: `Executed in an isolated lab VM with no route to production systems. The macro payload is an inert marker script that writes a log entry only. The lure document is never transmitted outside the lab environment.`,
    blue: `<b>Hunting-tool</b> monitors Office processes spawning <code>cmd.exe</code>, <code>wscript.exe</code>, or <code>powershell.exe</code>. Any <code>WINWORD.EXE</code> &rarr; shell chain is treated as a standalone high-priority alert, regardless of payload content.`,
    nation: `APT29 (Cozy Bear) used this exact chain in the 2016 DNC intrusion. Lures were tailored per recipient's role — this is what separates APT spearphishing from commodity campaigns. Average time to first post-open action: under four minutes.`,
    confidence: "high"
  },
  {
    id: 2,
    mitre: "T1053.005",
    tactic: "Persistence",
    name: "Scheduled Task Persistence",
    short: "Sched. Task",
    evasion: false,
    activePillars: [0],
    apt: "APT29, APT41",
    plain: "The attacker sets up a hidden task that quietly runs every time the computer starts, so they never lose access.",
    red: `A scheduled task disguised as a routine helper utility is created under a service-account context, set to run at every user logon. It survives reboots and blends in with legitimate Windows maintenance tasks.`,
    safe: `Task creation is confined to the lab VM. The payload is an inert marker script, never a live loader. A signed rollback script reverts every change, and a VM snapshot allows instant clean-state restore.`,
    blue: `Event ID <code>4698</code> (task created) and <code>4702</code> (task modified) are monitored. The detector flags tasks whose name, author, or command path falls outside the known-good baseline — especially those containing encoded or LotL-style payloads.`,
    nation: `APT29 used scheduled tasks as a secondary persistence layer in the SolarWinds operation (SUNBURST, 2020). Naming tasks after legitimate Windows utilities — e.g. <code>MicrosoftEdgeUpdateTaskMachineUA</code> — is a standard nation-state masquerading pattern.`,
    confidence: "high"
  },
  {
    id: 3,
    mitre: "T1546.003",
    tactic: "Persistence",
    name: "WMI Event Subscription",
    short: "WMI Sub",
    evasion: false,
    activePillars: [0],
    apt: "APT33, APT41",
    plain: "The attacker hides a trigger deep inside Windows itself — no file is ever saved to disk, so it's almost invisible.",
    red: `A WMI event filter-to-consumer binding adds a third, harder-to-find persistence path built for long dwell time. It triggers on an OS event and writes nothing to disk, making it invisible to file-based detection entirely.`,
    safe: `WMI objects are created under a labelled test namespace (<code>ROOT\\CIMv2\\Hunting_Lab</code>) and auto-purged when the exercise closes. Sysmon captures every WMI object lifecycle event in real time throughout.`,
    blue: `Sysmon Event IDs <code>19</code>, <code>20</code>, <code>21</code> capture WMI filter, consumer, and binding creation. In this environment any WMI subscription is anomalous — the detector flags the first occurrence as a manual-review priority rather than waiting for a threshold.`,
    nation: `APT41 relies on WMI subscriptions because most EDR solutions don't baseline WMI object state. An attacker can hold persistence for months without any file indicator. This is the canonical "long dwell" technique — Mandiant reports nation-state median dwell time at 21+ days before detection.`,
    confidence: "high"
  },
  {
    id: 4,
    mitre: "T1059.001",
    tactic: "Execution",
    name: "Living-off-the-Land PowerShell",
    short: "LotL PS",
    evasion: false,
    activePillars: [2],
    apt: "APT28, Lazarus",
    plain: "Instead of custom hacking tools, the attacker uses PowerShell — a tool already built into Windows — so the activity blends in with normal admin work.",
    red: `Execution pivots to PowerShell with stealth flags (<code>-WindowStyle Hidden -NoProfile -ExecutionPolicy Bypass</code>) and a Base64-encoded command, spawned from the document process established in Stage 1 to mimic a real phishing-triggered chain.`,
    safe: `The encoded payload decodes to a benign marker string only. No network connections are opened. Script Block Logging (Event ID <code>4104</code>) captures the full decoded command before execution, giving a complete audit trail.`,
    blue: `The LotL detector flags PowerShell with encoding flags, invisible windows, and anomalous parent processes. An Office process spawning PowerShell is a high-confidence alert on its own — the parent-child chain matters more than the payload content.`,
    nation: `APT28 used encoded PowerShell to exfiltrate data in the 2015 Bundestag hack. The key defender insight: flag <b>process lineage and flag combinations together</b>. Each flag is individually legitimate; combined with an unexpected parent process they are almost always malicious.`,
    confidence: "high"
  },
  {
    id: 5,
    mitre: "T1021.002",
    tactic: "Lateral Movement",
    name: "SMB Admin Share Pivoting",
    short: "Lateral Mvmt",
    evasion: false,
    activePillars: [2],
    apt: "APT1, APT28",
    plain: "Using stolen login details, the attacker hops from the first infected computer to a second one on the same network.",
    red: `Using credentials gathered from the initial host, the adversary pivots to a second system via the Windows admin share (<code>ADMIN$</code>). A remote service is created on the target — the same mechanism leveraged by PsExec, blending in with legitimate admin tooling.`,
    safe: `Movement is confined to two designated lab hosts in an isolated VLAN. Only pre-staged test credentials are used, never real domain accounts. Every SMB connection is captured at the packet level via a span port.`,
    blue: `Event ID <code>5140</code> (share accessed) combined with <code>4624</code> logon type 3 from an unexpected source. Remote service creation (<code>7045</code>) on the destination is a high-fidelity indicator — PsExec-style lateral movement produces this exact event triplet.`,
    nation: `APT1 (Comment Crew) sustained access for an average of <b>356 days</b> by moving slowly — one lateral hop every few days, only toward hosts needed for the objective. The lesson: lateral movement detection must correlate events across time windows, not just individual events in isolation.`,
    confidence: "high"
  },
  {
    id: 6,
    mitre: "T1562 / T1027",
    tactic: "Defense Evasion",
    name: "EDR Blinding & AMSI Evasion",
    short: "EDR Evasion",
    evasion: true,
    activePillars: [1, 3],
    apt: "APT41, Lazarus",
    plain: "The attacker would try to blind the security software watching the computer — this step is deliberately only discussed, never actually performed.",
    red: `Adversary tradecraft at this stage would target the EDR's telemetry pipeline and the AMSI script-scanning interface — blinding the defender's visibility before executing the next phase of the intrusion.`,
    safe: `<b>Scoped as design and detection-readiness only.</b> No working bypass is built or executed. The specific blind spots these techniques would create are documented and passed to the blue team as a hardening requirement instead.`,
    blue: `The finding generates two backlog items: EDR self-health and tamper alerting, and AMSI-bypass signature research. Absence of telemetry during a known-active session is itself a detection signal — <b>silence can be the alert.</b>`,
    nation: `APT41 performs EDR reconnaissance before attempting bypass — mapping which products are running and which evasion paths remain undetected. The mature red team posture: if you can't safely demonstrate a bypass, <b>document the gap.</b> That gap has more defensive value than a working exploit that never gets fixed.`,
    confidence: "med"
  },
  {
    id: 7,
    mitre: "T1070.006",
    tactic: "Defense Evasion",
    name: "Timestomping",
    short: "Timestomp",
    evasion: false,
    activePillars: [3],
    apt: "APT32, APT41",
    plain: "The attacker fakes a file's creation date so it looks like it has always been there, hiding it from investigators.",
    red: `To blend a dropped file in with legitimate system files, its creation and modified timestamps are backdated to match neighbouring OS files — an anti-forensics technique designed to defeat filesystem timeline analysis during incident response.`,
    safe: `Only synthetic test files inside the lab VM are ever timestomped. Production timestamps are never touched. Every change is logged to a separate audit file before execution, and the test file is deleted at exercise close.`,
    blue: `<b>Hunting-tool</b> flags two anomalies: (1) files where <code>$STANDARD_INFORMATION</code> and <code>$FILE_NAME</code> MFT attributes diverge — a reliable timestomp signature — and (2) files sharing an improbable count of identical timestamps with unrelated system files.`,
    nation: `APT32 (OceanLotus) routinely timestomped malware droppers to evade incident response timelines. The countermeasure — comparing MFT <code>$SI</code> vs <code>$FN</code> attributes — is reliable because most timestomping tools only modify <code>$SI</code>, leaving <code>$FN</code> intact as a forensic artefact.`,
    confidence: "high"
  }
];

const BACKLOG = [
  { status: "closed", title: "Spearphishing process-spawn detection",      note: "T1566.001 — Hunting-tool/detectors/initial_access.py" },
  { status: "closed", title: "Scheduled task baseline detection",          note: "T1053.005 — Hunting-tool/detectors/persistence.py"   },
  { status: "closed", title: "WMI subscription alerting",                  note: "T1546.003 — Hunting-tool/detectors/persistence.py"   },
  { status: "closed", title: "LotL PowerShell detection",                  note: "T1059.001 — Hunting-tool/detectors/lotl.py"          },
  { status: "closed", title: "SMB lateral movement detection",             note: "T1021.002 — Hunting-tool/detectors/lateral.py"       },
  { status: "closed", title: "Timestomp anomaly detection",                note: "T1070.006 — Hunting-tool/detectors/timestomp.py"    },
  { status: "open",   title: "EDR tamper-alerting & AMSI bypass research", note: "T1562 / T1027 — open by design: a genuine gap, not a fabricated fix" }
];

// Plain-English glossary. Keys are matched as whole words/phrases inside
// stage text (case-insensitive) and turned into hover/focus tooltips.
const TERMS = {
  "MITRE ATT&CK":  "A public knowledge base that catalogs real-world attacker techniques, giving defenders a shared vocabulary (like a technique ID) to describe exactly what happened.",
  "APT":           "Advanced Persistent Threat — a well-resourced attacker, often nation-state backed, that breaks in and stays hidden for a long time rather than smash-and-grab.",
  "EDR":           "Endpoint Detection & Response — security software on a computer that watches behavior in real time, far more advanced than traditional antivirus.",
  "AMSI":          "Antimalware Scan Interface — a Windows feature that lets security tools inspect scripts right before they run, catching malicious code even if it's disguised.",
  "WMI":           "Windows Management Instrumentation — a built-in Windows feature for automating the OS. Attackers abuse it because it's trusted and rarely monitored.",
  "PowerShell":    "A powerful scripting tool built into every Windows machine. Attackers love it because it's already installed and can do almost anything.",
  "PsExec":        "A legitimate Microsoft admin tool for running commands on remote computers — attackers mimic its behavior to move between machines unnoticed.",
  "Sysmon":        "A free Microsoft tool that logs detailed system activity (process creation, network connections, file changes) — a backbone of most detection engineering.",
  "VLAN":          "Virtual LAN — a way to split one physical network into isolated segments, so lab traffic can never reach production systems.",
  "dwell time":    "How long an attacker stays inside a network undetected before defenders find them. Nation-state actors often measure this in weeks or months.",
  "lateral movement": "Once inside one computer, the attacker moves sideways to other machines on the same network to reach their real target.",
  "spearphishing": "A targeted, personalized phishing email aimed at one specific person or organization — not a mass, generic campaign.",
  "Rules of Engagement": "The written agreement defining exactly what a red team is and isn't allowed to touch before a simulated attack begins.",
  "kill chain":    "The step-by-step sequence an attacker follows, from first breaking in to achieving their final goal.",
  "MFT":           "Master File Table — the index NTFS uses to track every file. It keeps two separate timestamp records, which is what makes timestomping detectable.",
  "SMB":           "Server Message Block — the protocol Windows uses to share files and folders over a network. Attackers reuse it to hop between machines.",
};

const TERM_KEYS = Object.keys(TERMS).sort((a, b) => b.length - a.length);
const TERM_REGEX = new RegExp(
  '\\b(' + TERM_KEYS.map(k => k.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|') + ')\\b',
  'g'
);

// Wraps known glossary terms in hoverable/focusable tooltip spans, without
// touching text that's actually inside an HTML tag (e.g. class names).
function glossify(html) {
  return html.split(/(<[^>]+>)/g).map(token => {
    if (token.startsWith('<')) return token;
    return token.replace(TERM_REGEX, (match) => {
      const key = TERM_KEYS.find(k => k.toLowerCase() === match.toLowerCase());
      const def = TERMS[key].replace(/"/g, '&quot;');
      return `<span class="term" tabindex="0" data-tip="${def}">${match}</span>`;
    });
  }).join('');
}


/* ============================================================
   State
   ============================================================ */

let currentStage = 0;
let autoPlayTimer = null;


/* ============================================================
   DOM references
   ============================================================ */

const pillarsEl    = document.getElementById('pillars');
const railNodesEl  = document.getElementById('rail-nodes');
const railFillEl   = document.getElementById('rail-fill');
const inspectorEl  = document.getElementById('inspector');
const stageCounter = document.getElementById('stage-counter');
const coverFillEl  = document.getElementById('coverage-fill');
const coverPctEl   = document.getElementById('coverage-pct');
const backlogEl    = document.getElementById('backlog');
const outcomesEl   = document.getElementById('section-outcomes');
const btnPlay      = document.getElementById('btn-play');
const btnPrev      = document.getElementById('btn-prev');
const btnNext      = document.getElementById('btn-next');


/* ============================================================
   Build — called once to stamp out the static structure
   ============================================================ */

function buildPillars() {
  pillarsEl.innerHTML = PILLARS.map((p, i) => `
    <div class="pillar" data-idx="${i}" style="--d:${i}">
      <div class="pillar-icon">${p.icon}</div>
      <div class="pillar-num">PILLAR ${p.num}</div>
      <div class="pillar-name">${p.name}</div>
      <div class="pillar-desc">${p.desc}</div>
    </div>
  `).join('');
}

function buildRailNodes() {
  railNodesEl.innerHTML = STAGES.map((s, i) => `
    <button class="node-btn${s.evasion ? ' evasion' : ''}"
            data-idx="${i}"
            aria-label="Stage ${i + 1}: ${s.name}">
      <div class="dot"></div>
      <div class="node-label">
        ${s.short}
        <span class="node-tactic">${s.tactic}</span>
      </div>
    </button>
  `).join('');

  railNodesEl.querySelectorAll('.node-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      stopAutoPlay();
      goTo(parseInt(btn.dataset.idx));
    });
  });
}


/* ============================================================
   Render — updates UI to reflect currentStage
   ============================================================ */

function renderPillars() {
  const stage = STAGES[currentStage];
  document.querySelectorAll('.pillar').forEach(el => {
    const active = stage.activePillars.includes(parseInt(el.dataset.idx));
    el.classList.toggle('active', active);
  });
}

function renderRail() {
  document.querySelectorAll('.node-btn').forEach((btn, i) => {
    btn.classList.toggle('done',   i < currentStage);
    btn.classList.toggle('active', i === currentStage);
  });

  const progress = (currentStage / (STAGES.length - 1)) * 100;
  railFillEl.style.width = progress + '%';

  const coverage = Math.round(((currentStage + 1) / STAGES.length) * 100);
  coverFillEl.style.width = coverage + '%';
  coverPctEl.textContent  = coverage + '%';

  stageCounter.textContent = `Stage ${currentStage + 1} of ${STAGES.length}`;
}

function renderInspector() {
  const s = STAGES[currentStage];

  const evasionChip = s.evasion
    ? `<div class="chip chip-amber">No working bypass built</div>`
    : '';

  const badge = s.confidence === 'high'
    ? `<div class="conf-badge"><span class="cdot"></span>Detection confidence: High</div>`
    : `<div class="conf-badge medium"><span class="cdot"></span>Detection confidence: Medium</div>`;

  inspectorEl.innerHTML = `
    <div class="insp-head">
      <div>
        <div class="insp-stage-tag">
          Stage ${s.id} of ${STAGES.length} &mdash; ${s.tactic}
          ${s.evasion ? ' &mdash; Conceptual only' : ''}
        </div>
        <div class="insp-name">${s.name}</div>
        <div class="insp-plain">${s.plain}</div>
      </div>
      <div class="chip-row">
        <div class="chip chip-green">${s.mitre}</div>
        <div class="chip chip-blue">${s.tactic}</div>
        <div class="chip chip-purple">Seen: ${s.apt}</div>
        ${evasionChip}
      </div>
    </div>

    <div class="insp-cols">
      <div class="col col-red">
        <div class="col-head"><span class="swatch"></span>Red Team Action</div>
        <div class="col-body">${glossify(s.red)}</div>
      </div>
      <div class="col col-safe">
        <div class="col-head"><span class="swatch"></span>Safety Control Applied</div>
        <div class="col-body">${glossify(s.safe)}</div>
      </div>
      <div class="col col-blue">
        <div class="col-head"><span class="swatch"></span>Blue Team Detection</div>
        <div class="col-body">${glossify(s.blue)}${badge}</div>
      </div>
      <div class="col col-nation">
        <div class="col-head"><span class="swatch"></span>Nation-State Context</div>
        <div class="col-body">${glossify(s.nation)}</div>
      </div>
    </div>
  `;

  // force the entrance animation to replay on every stage change
  inspectorEl.classList.remove('enter');
  void inspectorEl.offsetWidth;
  inspectorEl.classList.add('enter');
}

function renderOutcomes() {
  const isLast = currentStage === STAGES.length - 1;
  outcomesEl.classList.toggle('hidden', !isLast);
  if (!isLast) return;

  const checkSvg = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#37E8A0" stroke-width="2"><path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/></svg>`;
  const warnSvg  = `<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#FFB84D" stroke-width="2"><circle cx="12" cy="12" r="9"/><path d="M12 8v4M12 16h.01"/></svg>`;

  const tickets = BACKLOG.map(item => {
    const isOpen = item.status === 'open';
    return `
      <div class="ticket${isOpen ? ' open' : ''}">
        <div class="ticket-icon">${isOpen ? warnSvg : checkSvg}</div>
        <div>
          <span class="ticket-title" style="color:${isOpen ? '#FFB84D' : '#EDF2F7'}">${item.title}</span>
          <span class="ticket-note">${item.note}</span>
        </div>
      </div>
    `;
  }).join('');

  backlogEl.innerHTML = `
    <div class="backlog-title">
      <svg viewBox="0 0 24 24" fill="none" stroke="#37E8A0" stroke-width="2" width="20" height="20">
        <path d="M9 11l3 3L22 4"/><path d="M21 12v7a2 2 0 01-2 2H5a2 2 0 01-2-2V5a2 2 0 012-2h11"/>
      </svg>
      Hardening Backlog &mdash; Generated From This Exercise
    </div>
    <p class="backlog-desc">
      The point of the simulation isn't proving the chain works — it's what the blue team walks
      away able to catch. Every closed finding below is implemented in the companion
      <b style="color:#EDF2F7">Hunting-tool</b> repo. The open item is intentionally left open:
      a genuine hardening gap, not a fabricated fix.
    </p>
    <div class="backlog-grid">${tickets}</div>
  `;
}

function renderNavButtons() {
  btnPrev.disabled = currentStage === 0;
  btnNext.disabled = currentStage === STAGES.length - 1;
}


/* ============================================================
   Navigation
   ============================================================ */

function goTo(index) {
  currentStage = Math.max(0, Math.min(STAGES.length - 1, index));
  renderPillars();
  renderRail();
  renderInspector();
  renderOutcomes();
  renderNavButtons();
}

function stopAutoPlay() {
  if (!autoPlayTimer) return;
  clearInterval(autoPlayTimer);
  autoPlayTimer = null;
  btnPlay.innerHTML = '&#9654; Play';
}

function startAutoPlay() {
  if (currentStage === STAGES.length - 1) goTo(0);

  btnPlay.innerHTML = '&#10074;&#10074; Pause';

  autoPlayTimer = setInterval(() => {
    if (currentStage >= STAGES.length - 1) {
      stopAutoPlay();
      return;
    }
    goTo(currentStage + 1);
  }, 4200);
}


/* ============================================================
   Event listeners — rail
   ============================================================ */

btnPrev.addEventListener('click', () => { stopAutoPlay(); goTo(currentStage - 1); });
btnNext.addEventListener('click', () => { stopAutoPlay(); goTo(currentStage + 1); });

btnPlay.addEventListener('click', () => {
  if (autoPlayTimer) { stopAutoPlay(); } else { startAutoPlay(); }
});

document.addEventListener('keydown', e => {
  if (e.target.tagName === 'BUTTON' || e.target.tagName === 'INPUT') return;
  if (e.key === 'ArrowRight') { stopAutoPlay(); goTo(currentStage + 1); }
  if (e.key === 'ArrowLeft')  { stopAutoPlay(); goTo(currentStage - 1); }
  if (e.key === ' ')          { e.preventDefault(); autoPlayTimer ? stopAutoPlay() : startAutoPlay(); }
});


/* ============================================================
   Entrance animations — scroll reveal + counting stats
   ============================================================ */

function initScrollReveal() {
  const targets = document.querySelectorAll('.reveal');
  if (!('IntersectionObserver' in window) || targets.length === 0) {
    targets.forEach(t => t.classList.add('in-view'));
    return;
  }
  const io = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.classList.add('in-view');
        io.unobserve(entry.target);
      }
    });
  }, { threshold: 0.12, rootMargin: '0px 0px -40px 0px' });
  targets.forEach(t => io.observe(t));
}

function initStatCounters() {
  document.querySelectorAll('.stat-chip .val').forEach((el, i) => {
    const target = parseInt(el.dataset.count, 10) || 0;
    const duration = 900;
    const startDelay = 300 + i * 120;
    setTimeout(() => {
      const start = performance.now();
      function tick(now) {
        const p = Math.min(1, (now - start) / duration);
        const eased = 1 - Math.pow(1 - p, 3);
        el.textContent = Math.round(eased * target);
        if (p < 1) requestAnimationFrame(tick);
      }
      requestAnimationFrame(tick);
    }, startDelay);
  });
}


/* ============================================================
   SOC Assistant — instant, rule-based answers sourced entirely
   from the data already on this page. No network calls, no API
   key, nothing to leak — just a fast lookup over PILLARS/STAGES/
   TERMS plus a small set of FAQ patterns.
   ============================================================ */

const assistantEl      = document.getElementById('assistant');
const fabEl             = document.getElementById('assistant-fab');
const panelEl           = document.getElementById('assistant-panel');
const closeEl            = document.getElementById('assistant-close');
const messagesEl        = document.getElementById('assistant-messages');
const chipsEl            = document.getElementById('assistant-chips');
const formEl             = document.getElementById('assistant-form');
const inputEl            = document.getElementById('assistant-input');

const STARTER_CHIPS = [
  "What is AMSI?",
  "Explain timestomping",
  "Is this actually dangerous?",
  "What is Hunting-tool?"
];

let assistantOpened = false;

function addMessage(role, html) {
  const row = document.createElement('div');
  row.className = `msg msg-${role}`;
  row.innerHTML = `<div class="msg-bubble">${html}</div>`;
  messagesEl.appendChild(row);
  messagesEl.scrollTop = messagesEl.scrollHeight;
  return row;
}

function showTyping() {
  const row = document.createElement('div');
  row.className = 'msg msg-bot msg-typing';
  row.innerHTML = `<div class="msg-bubble typing-dots"><span></span><span></span><span></span></div>`;
  messagesEl.appendChild(row);
  messagesEl.scrollTop = messagesEl.scrollHeight;
  return row;
}

function renderChips(list) {
  chipsEl.innerHTML = list.map(q => `<button type="button" class="chat-chip">${q}</button>`).join('');
  chipsEl.querySelectorAll('.chat-chip').forEach(btn => {
    btn.addEventListener('click', () => {
      inputEl.value = btn.textContent;
      formEl.requestSubmit();
    });
  });
  // chips sit outside the scrollable message list, so their own height
  // change can leave the latest message's tail (e.g. a "Jump" button)
  // just below the fold — re-settle the scroll after layout catches up.
  requestAnimationFrame(() => { messagesEl.scrollTop = messagesEl.scrollHeight; });
}

function findStage(q) {
  return STAGES.find(s =>
    q.includes(s.mitre.toLowerCase()) ||
    q.includes(s.name.toLowerCase()) ||
    q.includes(s.short.toLowerCase()) ||
    s.short.toLowerCase().split(/[\s.]+/).some(w => w.length > 3 && q.includes(w)) ||
    s.name.toLowerCase().split(/[\s.]+/).some(w => w.length > 5 && q.includes(w))
  );
}

function findTerm(q) {
  const key = TERM_KEYS.find(t => q.includes(t.toLowerCase()));
  return key ? { key, def: TERMS[key] } : null;
}

function findPillar(q) {
  return PILLARS.find(p => p.name.toLowerCase().split(/[\s&/-]+/).some(w => w.length > 4 && q.includes(w)));
}

function answerQuery(raw) {
  const q = raw.toLowerCase().trim();
  if (!q) return "Ask me anything about the simulation — try a stage name, a MITRE ID, or a term like “AMSI”.";

  if (/^(hi|hello|hey|yo|sup)\b/.test(q)) {
    return "Hey! I can explain any stage, technique, or term on this page. Try “what is timestomping” or “explain stage 6”.";
  }
  if (/thank/.test(q)) {
    return "Anytime — click through the kill chain above if you want to see it in action.";
  }
  if (/(what is this|what.?s this (page|site|demo)|explain this (page|demo))/.test(q)) {
    return "This is an interactive walkthrough of a simulated APT (nation-state style) intrusion — 7 real attacker techniques, each shown safely and paired with the actual detection built to catch it.";
  }
  if (/(who (made|built|presented|is the presenter))/.test(q)) {
    return "Built and presented by Lau Xuan Lin for LTA Selection Task, Topic 21 — APT Simulation &amp; Detection Evasion.";
  }
  if (/hunting.?tool/.test(q)) {
    return "Hunting-tool is the companion detection-engineering repo — every “closed” ticket in the Outcomes section is a real detector living there. <a href=\"https://xuanlinnnnn.github.io/Hunting-tool/\" target=\"_blank\" rel=\"noopener\">Open it →</a>";
  }
  if (/(real|actually hack|dangerous|live payload|malware|is this safe)/.test(q)) {
    return "No live payloads, ever. Every technique here only ran against an isolated lab VM using inert marker scripts — check the “Safety Control Applied” column on any stage for the specifics.";
  }
  if (/(how (do i|to) use|how does (it|this) work|instructions)/.test(q)) {
    return "Click any dot on the timeline, or use ← → and Space to step through / auto-play. Each stage opens a 4-column breakdown: what the attacker did, how it was made safe, how it's detected, and which real APT group has used it.";
  }
  if (/mitre/.test(q)) {
    return TERMS["MITRE ATT&CK"] + " Every stage here is tagged with its official technique ID (e.g. T1566.001).";
  }
  if (/(pillar|framework)/.test(q) && !findStage(q)) {
    return "The framework rests on 4 pillars: Scoping &amp; Rules of Engagement, the Realism-vs-Safety trade-off, Operational Security Discipline, and turning findings into hardened tooling. See Section 01 above.";
  }

  const stageHit = findStage(q);
  if (stageHit) {
    const idx = stageHit.id - 1;
    return `<b>${stageHit.name}</b> (${stageHit.mitre}, Stage ${stageHit.id} of 7) &mdash; ${stageHit.plain} Real-world groups seen using it: ${stageHit.apt}.<br><button type="button" class="chat-jump" data-stage="${idx}">Jump to this stage →</button>`;
  }

  const termHit = findTerm(q);
  if (termHit) return `<b>${termHit.key}</b>: ${termHit.def}`;

  const pillarHit = findPillar(q);
  if (pillarHit) return `<b>${pillarHit.name}</b>: ${pillarHit.desc}`;

  return "I don't have an exact answer for that. Try a stage name (“WMI”, “timestomping”), a term (“what is EDR”), or one of the quick questions below.";
}

function handleAssistantSubmit(e) {
  e.preventDefault();
  const text = inputEl.value.trim();
  if (!text) return;
  addMessage('user', text.replace(/[<>]/g, m => m === '<' ? '&lt;' : '&gt;'));
  inputEl.value = '';
  chipsEl.innerHTML = '';

  const typingRow = showTyping();
  const delay = 420 + Math.random() * 380;
  setTimeout(() => {
    typingRow.remove();
    addMessage('bot', answerQuery(text));
    renderChips(STARTER_CHIPS);
  }, delay);
}

function openAssistant() {
  panelEl.classList.remove('hidden');
  fabEl.classList.add('is-open');
  fabEl.setAttribute('aria-expanded', 'true');
  if (!assistantOpened) {
    assistantOpened = true;
    addMessage('bot', "Hi, I'm the SOC Assistant — ask me about any stage, MITRE ID, or term on this page (e.g. “what is AMSI”) and I'll answer instantly from the page's own data.");
    renderChips(STARTER_CHIPS);
  }
  setTimeout(() => inputEl.focus(), 250);
}

function closeAssistant() {
  panelEl.classList.add('hidden');
  fabEl.classList.remove('is-open');
  fabEl.setAttribute('aria-expanded', 'false');
}

fabEl.addEventListener('click', () => {
  panelEl.classList.contains('hidden') ? openAssistant() : closeAssistant();
});
closeEl.addEventListener('click', closeAssistant);
formEl.addEventListener('submit', handleAssistantSubmit);

messagesEl.addEventListener('click', (e) => {
  const btn = e.target.closest('.chat-jump');
  if (!btn) return;
  stopAutoPlay();
  goTo(parseInt(btn.dataset.stage, 10));
  document.getElementById('inspector').scrollIntoView({ behavior: 'smooth', block: 'center' });
  closeAssistant();
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !panelEl.classList.contains('hidden')) closeAssistant();
});


/* ============================================================
   Init
   ============================================================ */

buildPillars();
buildRailNodes();
goTo(0);
initScrollReveal();
initStatCounters();
