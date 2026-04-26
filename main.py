"""
WebProbe — Analyseur de sécurité web
INF232 EC2 — Application de collecte de données en ligne
FastAPI + BeautifulSoup + requests + matplotlib + CSV
"""

import ssl
import socket
import csv
import io
import base64
import os
from urllib.parse import urlparse
from datetime import datetime

import requests
import matplotlib
matplotlib.use("Agg")  # rendu en mémoire, pas d'interface graphique
import matplotlib.pyplot as plt
import numpy as np
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="WebProbe API",
    description="Analyseur de sécurité web — INF232 EC2",
    version="2.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Fichier CSV historique ───────────────────────────────────────────────────
CSV_FILE = "historique.csv"
CSV_HEADERS = [
    "timestamp", "url", "titre", "status_code",
    "ssl_valide", "ssl_emetteur", "ssl_jours_restants",
    "headers_score", "headers_manquants",
    "mots_suspects", "technologies",
    "formulaires_total", "formulaires_suspects",
    "iframes", "scripts_externes",
    "risque_score", "risque_niveau",
]

def init_csv():
    """Crée le CSV avec en-têtes s'il n'existe pas encore."""
    if not os.path.exists(CSV_FILE):
        with open(CSV_FILE, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
            writer.writeheader()

def save_to_csv(data: dict):
    """Ajoute une ligne de résultats dans le CSV."""
    init_csv()
    row = {
        "timestamp":            data["timestamp"],
        "url":                  data["url"],
        "titre":                data["title"],
        "status_code":          data["status_code"],
        "ssl_valide":           data["ssl"]["valid"],
        "ssl_emetteur":         data["ssl"].get("issuer", ""),
        "ssl_jours_restants":   data["ssl"].get("days_left", ""),
        "headers_score":        data["headers"]["score"],
        "headers_manquants":    "|".join(data["headers"]["missing"]),
        "mots_suspects":        "|".join(data["content"]["suspicious_words"]),
        "technologies":         "|".join(data["content"]["technologies"]),
        "formulaires_total":    data["forms"]["count"],
        "formulaires_suspects": data["forms"]["suspicious_count"],
        "iframes":              len(data["content"]["iframes"]),
        "scripts_externes":     len(data["content"]["external_scripts"]),
        "risque_score":         data["risk"]["score"],
        "risque_niveau":        data["risk"]["level"],
    }
    with open(CSV_FILE, "a", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_HEADERS)
        writer.writerow(row)

def read_csv() -> list:
    """Lit tout l'historique CSV et retourne une liste de dicts."""
    init_csv()
    rows = []
    with open(CSV_FILE, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(dict(row))
    return list(reversed(rows))  # plus récent en premier

# ─── Modèles Pydantic ─────────────────────────────────────────────────────────
class AnalyzeRequest(BaseModel):
    url: str

class AnalyzeResponse(BaseModel):
    url: str
    timestamp: str
    reachable: bool
    title: str
    status_code: int | None
    ssl: dict
    headers: dict
    content: dict
    forms: dict
    risk: dict
    charts: dict  # images base64 matplotlib

# ─── Constantes ───────────────────────────────────────────────────────────────
SUSPICIOUS_WORDS = [
    "hack", "attack", "malware", "phishing", "exploit", "payload",
    "inject", "bypass", "crack", "trojan", "keylogger", "botnet",
    "ransomware", "spyware", "rootkit", "vulnerability", "zero-day",
]

SECURITY_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]

CMS_SIGNATURES = {
    "WordPress":   ["/wp-content/", "/wp-includes/", "wp-json"],
    "Joomla":      ["/components/com_", "Joomla!", "/media/jui/"],
    "Drupal":      ["Drupal.settings", "/sites/default/files/", "drupal.js"],
    "Wix":         ["wix.com", "wixstatic.com"],
    "Shopify":     ["cdn.shopify.com", "Shopify.theme"],
    "Squarespace": ["squarespace.com", "squarespace-cdn.com"],
    "Django":      ["csrfmiddlewaretoken", "__admin__"],
    "Laravel":     ["laravel_session", "XSRF-TOKEN"],
    "Next.js":     ["__NEXT_DATA__", "_next/static/"],
    "React":       ["react-root", "__reactFiber", "data-reactroot"],
    "Vue.js":      ["__vue__", "data-v-app"],
}

FORM_SUSPICIOUS_TYPES = ["password", "credit-card", "card", "cvv", "pin", "ssn", "social"]

# ─── Helpers ──────────────────────────────────────────────────────────────────
def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url

# ─── Analyse SSL (option 2) ───────────────────────────────────────────────────
def check_ssl(hostname: str) -> dict:
    result = {"valid": False, "issuer": None, "expires": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=5),
            server_hostname=hostname
        ) as s:
            cert = s.getpeercert()
            result["valid"] = True
            issuer_dict = dict(x[0] for x in cert.get("issuer", []))
            result["issuer"] = issuer_dict.get("organizationName", "Inconnu")
            expires_str = cert.get("notAfter", "")
            if expires_str:
                exp = datetime.strptime(expires_str, "%b %d %H:%M:%S %Y %Z")
                result["expires"] = exp.strftime("%d/%m/%Y")
                result["days_left"] = (exp - datetime.utcnow()).days
    except ssl.SSLCertVerificationError as e:
        result["error"] = f"Certificat invalide : {str(e)[:80]}"
    except Exception as e:
        result["error"] = str(e)[:80]
    return result

# ─── Analyse En-têtes HTTP ────────────────────────────────────────────────────
def analyze_headers(headers: dict) -> dict:
    present, missing, details = [], [], {}
    for h in SECURITY_HEADERS:
        val = headers.get(h) or headers.get(h.lower())
        if val:
            present.append(h)
            details[h] = val[:120]
        else:
            missing.append(h)
    score = round((len(present) / len(SECURITY_HEADERS)) * 100)
    return {
        "present":      present,
        "missing":      missing,
        "score":        score,
        "details":      details,
        "server":       headers.get("Server") or headers.get("server", "Non divulgué"),
        "x_powered_by": headers.get("X-Powered-By") or headers.get("x-powered-by"),
    }

# ─── Analyse Contenu + Technologies CMS (option 3) ───────────────────────────
def analyze_content(soup: BeautifulSoup, raw_html: str) -> dict:
    text = soup.get_text().lower()

    found_words = [w for w in SUSPICIOUS_WORDS if w in text]

    # Fingerprinting CMS/frameworks
    detected_cms = []
    for cms, sigs in CMS_SIGNATURES.items():
        if any(sig.lower() in raw_html.lower() for sig in sigs):
            detected_cms.append(cms)

    links = soup.find_all("a", href=True)
    external_links, internal_links = [], []
    for a in links:
        href = a["href"]
        if href.startswith("http"):
            external_links.append(href[:100])
        elif href.startswith("/") or not href.startswith("#"):
            internal_links.append(href[:100])

    scripts     = soup.find_all("script", src=True)
    ext_scripts = [s["src"] for s in scripts if s["src"].startswith("http")]
    iframes     = soup.find_all("iframe")
    iframe_srcs = [i.get("src", "sans src")[:100] for i in iframes]

    metas = {}
    for m in soup.find_all("meta"):
        name    = m.get("name") or m.get("property") or m.get("http-equiv")
        content = m.get("content")
        if name and content:
            metas[name] = content[:100]

    return {
        "suspicious_words":    found_words,
        "technologies":        detected_cms,
        "link_count":          len(links),
        "external_links":      external_links[:10],
        "internal_link_count": len(internal_links),
        "external_scripts":    ext_scripts[:10],
        "iframes":             iframe_srcs,
        "meta":                metas,
    }

# ─── Analyse Formulaires suspects ────────────────────────────────────────────
def analyze_forms(soup: BeautifulSoup, base_url: str) -> dict:
    forms = soup.find_all("form")
    parsed, suspicious_forms = [], []

    for form in forms:
        action      = form.get("action", "")
        method      = form.get("method", "GET").upper()
        inputs      = form.find_all("input")
        input_types = [i.get("type", "text").lower() for i in inputs]
        input_names = [i.get("name", "") for i in inputs]

        has_password    = "password" in input_types
        has_csrf        = any("csrf" in n.lower() or "token" in n.lower() for n in input_names)
        action_external = action.startswith("http") and base_url not in action

        suspicious = []
        if has_password and not has_csrf:
            suspicious.append("Mot de passe sans protection CSRF")
        if action_external:
            suspicious.append(f"Soumission vers domaine externe : {action[:60]}")
        if method == "GET" and has_password:
            suspicious.append("Mot de passe envoyé via GET (dangereux !)")
        for t in input_types:
            if any(s in t for s in FORM_SUSPICIOUS_TYPES) and not has_csrf:
                suspicious.append(f"Champ sensible '{t}' sans token CSRF")

        form_data = {
            "action":      action[:100] if action else "(même page)",
            "method":      method,
            "inputs":      len(inputs),
            "input_types": input_types,
            "has_csrf":    has_csrf,
            "suspicious":  suspicious,
        }
        parsed.append(form_data)
        if suspicious:
            suspicious_forms.append(form_data)

    return {
        "count":            len(forms),
        "forms":            parsed,
        "suspicious_count": len(suspicious_forms),
        "suspicious_forms": suspicious_forms,
    }

# ─── Score de risque global ───────────────────────────────────────────────────
def compute_risk(ssl_data, headers_data, content_data, forms_data) -> dict:
    score, issues, details = 0, [], []

    if not ssl_data["valid"]:
        score += 30
        issues.append("Certificat SSL invalide ou absent")
    else:
        days = ssl_data.get("days_left", 999)
        if days < 30:
            score += 15
            issues.append(f"Certificat SSL expire dans {days} jours")

    missing_critical = [h for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"]
                        if h in headers_data["missing"]]
    if missing_critical:
        score += len(missing_critical) * 8
        issues.append(f"En-têtes manquants : {', '.join(missing_critical)}")
    if headers_data.get("x_powered_by"):
        score += 5
        details.append(f"Technologies exposées via X-Powered-By : {headers_data['x_powered_by']}")

    if content_data["suspicious_words"]:
        score += len(content_data["suspicious_words"]) * 5
        issues.append(f"Contenu suspect : {', '.join(content_data['suspicious_words'])}")

    if content_data["iframes"]:
        score += len(content_data["iframes"]) * 5
        details.append(f"{len(content_data['iframes'])} iframe(s) détectée(s)")

    if forms_data["suspicious_count"] > 0:
        score += forms_data["suspicious_count"] * 12
        issues.append(f"{forms_data['suspicious_count']} formulaire(s) suspect(s)")

    score = min(score, 100)

    if score <= 20:   level, color = "Faible",   "green"
    elif score <= 50: level, color = "Modéré",   "orange"
    elif score <= 75: level, color = "Élevé",    "red"
    else:             level, color = "Critique", "darkred"

    category_scores = {
        "SSL":          0 if ssl_data["valid"] else 100,
        "En-têtes":     100 - headers_data["score"],
        "Contenu":      min(len(content_data["suspicious_words"]) * 20, 100),
        "Formulaires":  min(forms_data["suspicious_count"] * 30, 100),
        "Iframes":      min(len(content_data["iframes"]) * 25, 100),
        "Scripts ext.": min(len(content_data["external_scripts"]) * 5, 100),
    }

    return {
        "score":           score,
        "level":           level,
        "color":           color,
        "issues":          issues,
        "details":         details,
        "category_scores": category_scores,
    }

# ─── Graphiques Matplotlib ────────────────────────────────────────────────────
DARK_BG = "#0b0f1a"
DARK_AX = "#0e1320"
GREEN   = "#00ff88"
CYAN    = "#00d4ff"
RED     = "#ff3355"
ORANGE  = "#ff8800"
MUTED   = "#5a7a9a"

def fig_to_base64(fig) -> str:
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight",
                facecolor=fig.get_facecolor(), dpi=120)
    buf.seek(0)
    encoded = base64.b64encode(buf.read()).decode("utf-8")
    plt.close(fig)
    return encoded

def make_radar_chart(category_scores: dict) -> str:
    """Graphique radar — risque par catégorie."""
    labels = list(category_scores.keys())
    values = list(category_scores.values())
    N      = len(labels)

    angles      = [n / float(N) * 2 * np.pi for n in range(N)]
    angles     += angles[:1]
    values_plot = values + values[:1]

    fig, ax = plt.subplots(figsize=(5, 5), subplot_kw=dict(polar=True))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_AX)

    ax.set_xticks(angles[:-1])
    ax.set_xticklabels(labels, color=MUTED, fontsize=8)
    ax.set_yticks([25, 50, 75, 100])
    ax.set_yticklabels(["25", "50", "75", "100"], color=MUTED, fontsize=6)
    ax.set_ylim(0, 100)
    ax.grid(color="#1a2235", linewidth=0.8)
    ax.spines["polar"].set_color("#1a2235")

    ax.plot(angles, values_plot, color=RED, linewidth=2)
    ax.fill(angles, values_plot, color=RED, alpha=0.25)

    ax.set_title("Risque par catégorie", color=GREEN,
                 fontsize=10, pad=15, fontweight="bold")
    return fig_to_base64(fig)

def make_bar_chart(category_scores: dict, global_score: int) -> str:
    """Graphique barres horizontales — score par module."""
    labels = list(category_scores.keys())
    values = list(category_scores.values())

    def bar_color(v):
        if v <= 20:  return GREEN
        if v <= 50:  return CYAN
        if v <= 75:  return ORANGE
        return RED

    colors = [bar_color(v) for v in values]

    fig, ax = plt.subplots(figsize=(6, 3.5))
    fig.patch.set_facecolor(DARK_BG)
    ax.set_facecolor(DARK_AX)

    bars = ax.barh(labels, values, color=colors, height=0.5, edgecolor="none")

    for bar, val in zip(bars, values):
        ax.text(min(val + 2, 98), bar.get_y() + bar.get_height() / 2,
                f"{val}%", va="center", ha="left", color="white", fontsize=8)

    ax.set_xlim(0, 115)
    ax.set_xlabel("Score de risque (%)", color=MUTED, fontsize=8)
    for spine in ax.spines.values():
        spine.set_color("#1a2235")
    ax.tick_params(axis="x", colors=MUTED, labelsize=8)
    ax.tick_params(axis="y", colors="#c8d8e8", labelsize=8)

    ax.axvline(global_score, color=ORANGE, linestyle="--",
               linewidth=1.2, label=f"Score global : {global_score}%")
    ax.legend(facecolor=DARK_BG, edgecolor="#1a2235",
              labelcolor=ORANGE, fontsize=8)

    ax.set_title("Score de risque par module", color=GREEN,
                 fontsize=10, pad=10, fontweight="bold")
    fig.tight_layout()
    return fig_to_base64(fig)

# ─── Endpoint : analyser une URL ──────────────────────────────────────────────
@app.post("/analyze", response_model=AnalyzeResponse, summary="Analyser une URL")
async def analyze(req: AnalyzeRequest):
    url      = normalize_url(req.url)
    parsed   = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="URL invalide")

    timestamp = datetime.utcnow().strftime("%d/%m/%Y à %H:%M UTC")

    try:
        response = requests.get(
            url, timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (compatible; WebProbe/2.0)"},
            allow_redirects=True,
        )
        raw_html    = response.text
        status_code = response.status_code
        headers     = dict(response.headers)
        soup        = BeautifulSoup(raw_html, "html.parser")
        title       = soup.title.string.strip() if soup.title and soup.title.string else "Aucun titre"
        reachable   = True
    except requests.exceptions.ConnectionError:
        raise HTTPException(status_code=422, detail="Impossible de joindre ce site.")
    except requests.exceptions.Timeout:
        raise HTTPException(status_code=422, detail="Le site n'a pas répondu (timeout).")
    except Exception as e:
        raise HTTPException(status_code=422, detail=f"Erreur : {str(e)[:100]}")

    ssl_data     = check_ssl(hostname)
    headers_data = analyze_headers(headers)
    content_data = analyze_content(soup, raw_html)
    forms_data   = analyze_forms(soup, url)
    risk_data    = compute_risk(ssl_data, headers_data, content_data, forms_data)

    charts = {
        "radar": make_radar_chart(risk_data["category_scores"]),
        "bars":  make_bar_chart(risk_data["category_scores"], risk_data["score"]),
    }

    result = dict(
        url=url, timestamp=timestamp, reachable=reachable, title=title,
        status_code=status_code, ssl=ssl_data, headers=headers_data,
        content=content_data, forms=forms_data, risk=risk_data, charts=charts,
    )
    save_to_csv(result)

    return AnalyzeResponse(**result)

# ─── Endpoint : historique JSON ───────────────────────────────────────────────
@app.get("/history", summary="Historique des analyses")
def get_history():
    rows = read_csv()
    return {"count": len(rows), "history": rows}

# ─── Endpoint : télécharger le CSV ───────────────────────────────────────────
@app.get("/history/export", summary="Exporter l'historique en CSV")
def export_csv():
    init_csv()
    with open(CSV_FILE, "r", encoding="utf-8") as f:
        content = f.read()
    return StreamingResponse(
        io.StringIO(content),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=webprobe_historique.csv"},
    )

# ─── Endpoint : santé ─────────────────────────────────────────────────────────
@app.get("/health", summary="Vérification du serveur")
def health():
    return {"status": "ok", "app": "WebProbe", "version": "2.0.0"}

# ─── Frontend statique ────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="public"), name="static")

@app.get("/", include_in_schema=False)
def root():
    return FileResponse("public/index.html")
