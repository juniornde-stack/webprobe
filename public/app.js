/* ═══════════════════════════════════════════════════════════
   app.js — WebProbe Frontend
═══════════════════════════════════════════════════════════ */

const API_BASE = "";  // même origine

// ─── Éléments DOM ─────────────────────────────────────────
const urlInput    = document.getElementById("url-input");
const scanBtn     = document.getElementById("scan-btn");
const scanBtnText = document.getElementById("scan-btn-text");
const scanSpinner = document.getElementById("scan-spinner");
const errorMsg    = document.getElementById("error-msg");
const resultsEl   = document.getElementById("results");
const newScanBtn  = document.getElementById("new-scan-btn");

// ─── Spinner animation frames ──────────────────────────────
const SPINNER_FRAMES = ["⠋","⠙","⠹","⠸","⠼","⠴","⠦","⠧","⠇","⠏"];
let spinnerInterval = null;
let spinnerIdx = 0;

function startSpinner() {
  scanBtnText.classList.add("hidden");
  scanSpinner.classList.remove("hidden");
  spinnerIdx = 0;
  spinnerInterval = setInterval(() => {
    scanSpinner.textContent = SPINNER_FRAMES[spinnerIdx++ % SPINNER_FRAMES.length];
  }, 80);
  scanBtn.disabled = true;
}

function stopSpinner() {
  clearInterval(spinnerInterval);
  scanBtnText.classList.remove("hidden");
  scanSpinner.classList.add("hidden");
  scanBtn.disabled = false;
}

// ─── Lancer le scan ───────────────────────────────────────
async function runScan() {
  const raw = urlInput.value.trim();
  if (!raw) { showError("Veuillez entrer une URL."); return; }

  hideError();
  startSpinner();
  resultsEl.classList.add("hidden");

  try {
    const res  = await fetch(`${API_BASE}/analyze`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url: raw }),
    });

    const data = await res.json();

    if (!res.ok) {
      throw new Error(data.detail || "Erreur serveur");
    }

    renderResults(data);
    resultsEl.classList.remove("hidden");
    resultsEl.scrollIntoView({ behavior: "smooth", block: "start" });

  } catch (err) {
    showError(`Erreur : ${err.message}`);
  } finally {
    stopSpinner();
  }
}

// ─── Afficher les résultats ───────────────────────────────
function renderResults(d) {
  // En-tête
  document.getElementById("res-url").textContent = d.url;
  document.getElementById("res-meta").textContent =
    `HTTP ${d.status_code} · Analysé le ${d.timestamp}`;

  // Risque
  const risk = d.risk;
  const scoreEl = document.getElementById("risk-score");
  const levelEl = document.getElementById("risk-level");
  const badgeEl = document.getElementById("risk-badge");
  const barEl   = document.getElementById("risk-bar");
  const barLbl  = document.getElementById("risk-bar-label");

  scoreEl.textContent = risk.score + "/100";
  levelEl.textContent = risk.level;

  const colorMap = { green: "#00ff88", orange: "#ff8800", red: "#ff3355", darkred: "#cc0022" };
  const c = colorMap[risk.color] || "#00ff88";
  scoreEl.style.color = c;
  levelEl.style.color = c;
  badgeEl.style.borderColor = c + "55";
  barEl.style.background = c;
  barEl.style.boxShadow  = `0 0 8px ${c}66`;
  setTimeout(() => { barEl.style.width = risk.score + "%"; }, 100);
  barLbl.textContent = risk.score + "% de risque";

  // Issues
  const issuesBlock = document.getElementById("issues-block");
  const issuesList  = document.getElementById("issues-list");
  const allIssues   = [...(risk.issues || []), ...(risk.details || [])];
  if (allIssues.length > 0) {
    issuesList.innerHTML = allIssues.map(i => `<li>${i}</li>`).join("");
    issuesBlock.classList.remove("hidden");
  } else {
    issuesBlock.classList.add("hidden");
  }

  // SSL
  renderSSL(d.ssl);
  // En-têtes
  renderHeaders(d.headers);
  // Formulaires
  renderForms(d.forms);
  // Contenu
  renderContent(d.content);
  // Technologies
  renderTech(d.content);
  // Liens & scripts
  renderLinks(d.content);
}

// ─── SSL ──────────────────────────────────────────────────
function renderSSL(ssl) {
  const body  = document.getElementById("ssl-body");
  const badge = document.getElementById("ssl-badge");

  if (ssl.valid) {
    badge.textContent = "VALIDE";
    badge.className   = "module__badge badge--ok";
    body.innerHTML = `
      ${row("Statut",    '<span class="ok">✔ Certificat valide</span>')}
      ${row("Émetteur",  ssl.issuer || "Inconnu")}
      ${row("Expiration",ssl.expires || "—")}
      ${ssl.days_left !== undefined ? row("Jours restants",
        `<span class="${ssl.days_left < 30 ? 'warn' : 'ok'}">${ssl.days_left} jours</span>`) : ""}
    `;
  } else {
    badge.textContent = "INVALIDE";
    badge.className   = "module__badge badge--danger";
    body.innerHTML = `
      ${row("Statut", '<span class="danger">✘ Pas de SSL / Invalide</span>')}
      ${ssl.error ? row("Détail", `<span class="warn">${ssl.error}</span>`) : ""}
    `;
  }
}

// ─── En-têtes ─────────────────────────────────────────────
function renderHeaders(h) {
  const body  = document.getElementById("headers-body");
  const badge = document.getElementById("headers-badge");
  const score = h.score;

  badge.textContent = score + "%";
  badge.className   = `module__badge ${score >= 70 ? "badge--ok" : score >= 40 ? "badge--warn" : "badge--danger"}`;

  const allHeaders = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
  ];

  let chips = '<div class="header-chips">';
  allHeaders.forEach(hdr => {
    const present = h.present.includes(hdr);
    chips += `
      <div class="header-chip">
        <span class="chip-dot ${present ? "chip-dot--ok" : "chip-dot--miss"}"></span>
        <span class="chip-name">${hdr}</span>
      </div>`;
  });
  chips += "</div>";

  let extra = "";
  if (h.server) extra += row("Serveur", h.server);
  if (h.x_powered_by) extra += row("X-Powered-By", `<span class="warn">${h.x_powered_by}</span>`);

  body.innerHTML = chips + extra;
}

// ─── Formulaires ──────────────────────────────────────────
function renderForms(f) {
  const body  = document.getElementById("forms-body");
  const badge = document.getElementById("forms-badge");

  if (f.count === 0) {
    badge.textContent = "AUCUN";
    badge.className   = "module__badge badge--ok";
    body.innerHTML    = `<p class="module-empty">Aucun formulaire détecté</p>`;
    return;
  }

  const hasSuspicious = f.suspicious_count > 0;
  badge.textContent = hasSuspicious ? f.suspicious_count + " SUSPECTS" : f.count + " OK";
  badge.className   = `module__badge ${hasSuspicious ? "badge--danger" : "badge--ok"}`;

  let html = row("Total", f.count);
  html += row("Suspects", hasSuspicious
    ? `<span class="danger">${f.suspicious_count}</span>`
    : `<span class="ok">0</span>`);

  if (hasSuspicious) {
    f.suspicious_forms.forEach((frm, i) => {
      html += `<div style="margin-top:.6rem;padding-top:.5rem;border-top:1px solid var(--bg-panel)">`;
      html += row(`Form ${i + 1}`, `${frm.method} → ${frm.action}`);
      frm.suspicious.forEach(s => {
        html += `<div class="info-row"><span class="info-row__val danger" style="text-align:left">⚠ ${s}</span></div>`;
      });
      html += `</div>`;
    });
  }

  body.innerHTML = html;
}

// ─── Contenu ──────────────────────────────────────────────
function renderContent(c) {
  const body  = document.getElementById("content-body");
  const badge = document.getElementById("content-badge");
  const words = c.suspicious_words || [];

  badge.textContent = words.length > 0 ? words.length + " SUSPECTS" : "CLEAN";
  badge.className   = `module__badge ${words.length > 0 ? "badge--warn" : "badge--ok"}`;

  let html = "";
  html += row("Liens totaux", c.link_count);
  html += row("Liens externes", c.external_links?.length || 0);
  html += row("Iframes", c.iframes?.length > 0
    ? `<span class="warn">${c.iframes.length}</span>`
    : `<span class="ok">0</span>`);
  html += row("Scripts externes", c.external_scripts?.length || 0);

  if (words.length > 0) {
    html += row("Mots suspects",
      `<span class="warn">${words.join(", ")}</span>`);
  }

  body.innerHTML = html;
}

// ─── Technologies ─────────────────────────────────────────
function renderTech(c) {
  const body = document.getElementById("tech-body");
  const tech = c.technologies || [];

  if (tech.length === 0) {
    body.innerHTML = `<p class="module-empty">Aucune technologie identifiée</p>`;
    return;
  }

  body.innerHTML = `<div class="tech-tags">${tech.map(t => `<span class="tech-tag">${t}</span>`).join("")}</div>`;
}

// ─── Liens & Scripts ──────────────────────────────────────
function renderLinks(c) {
  const body = document.getElementById("links-body");
  const ext  = c.external_links  || [];
  const scr  = c.external_scripts || [];

  let html = '<div style="display:grid;grid-template-columns:1fr 1fr;gap:1.5rem">';

  html += '<div>';
  html += `<p style="font-size:.68rem;letter-spacing:.1em;color:var(--ink-muted);margin-bottom:.5rem">LIENS EXTERNES (${ext.length})</p>`;
  if (ext.length > 0) {
    html += `<div class="scroll-list">${ext.map(l => `<a href="${l}" target="_blank" rel="noopener">${l}</a>`).join("")}</div>`;
  } else {
    html += `<p class="module-empty">Aucun</p>`;
  }
  html += '</div>';

  html += '<div>';
  html += `<p style="font-size:.68rem;letter-spacing:.1em;color:var(--ink-muted);margin-bottom:.5rem">SCRIPTS EXTERNES (${scr.length})</p>`;
  if (scr.length > 0) {
    html += `<div class="scroll-list">${scr.map(s => `<span>${s}</span>`).join("")}</div>`;
  } else {
    html += `<p class="module-empty">Aucun</p>`;
  }
  html += '</div>';

  html += '</div>';
  body.innerHTML = html;
}

// ─── Helpers ──────────────────────────────────────────────
function row(key, val) {
  return `
    <div class="info-row">
      <span class="info-row__key">${key}</span>
      <span class="info-row__val">${val}</span>
    </div>`;
}

function showError(msg) {
  errorMsg.textContent = `✘ ${msg}`;
  errorMsg.classList.remove("hidden");
}

function hideError() {
  errorMsg.classList.add("hidden");
}

// ─── Événements ───────────────────────────────────────────
scanBtn.addEventListener("click", runScan);

urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") runScan();
});

newScanBtn.addEventListener("click", () => {
  resultsEl.classList.add("hidden");
  urlInput.value = "";
  urlInput.focus();
  window.scrollTo({ top: 0, behavior: "smooth" });
});

// Focus auto
urlInput.focus();
