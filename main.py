"""
WebProbe — Analyseur de sécurité web
INF232 EC2 — Application de collecte de données en ligne
FastAPI + BeautifulSoup + requests
"""

import ssl
import socket
import re
from urllib.parse import urlparse, urljoin
from datetime import datetime

import requests
from bs4 import BeautifulSoup
from fastapi import FastAPI, HTTPException
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, HttpUrl

# ─── App ──────────────────────────────────────────────────────────────────────
app = FastAPI(
    title="WebProbe API",
    description="Analyseur de sécurité web — détection de vulnérabilités et de comportements suspects",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

# ─── Modèles ──────────────────────────────────────────────────────────────────
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

# ─── Helpers ──────────────────────────────────────────────────────────────────
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
    "WordPress":  ["/wp-content/", "/wp-includes/", "wp-json"],
    "Joomla":     ["/components/com_", "Joomla!", "/media/jui/"],
    "Drupal":     ["Drupal.settings", "/sites/default/files/", "drupal.js"],
    "Wix":        ["wix.com", "wixstatic.com"],
    "Shopify":    ["cdn.shopify.com", "Shopify.theme"],
    "Squarespace":["squarespace.com", "squarespace-cdn.com"],
    "Django":     ["csrfmiddlewaretoken", "__admin__"],
    "Laravel":    ["laravel_session", "XSRF-TOKEN"],
    "Next.js":    ["__NEXT_DATA__", "_next/static/"],
    "React":      ["react-root", "__reactFiber", "data-reactroot"],
    "Vue.js":     ["__vue__", "data-v-app"],
}

FORM_SUSPICIOUS_TYPES = ["password", "credit-card", "card", "cvv", "pin", "ssn", "social"]


def normalize_url(url: str) -> str:
    url = url.strip()
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url


def check_ssl(hostname: str) -> dict:
    result = {"valid": False, "issuer": None, "expires": None, "error": None}
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((hostname, 443), timeout=5), server_hostname=hostname) as s:
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


def analyze_headers(headers: dict) -> dict:
    present = []
    missing = []
    details = {}

    for h in SECURITY_HEADERS:
        val = headers.get(h) or headers.get(h.lower())
        if val:
            present.append(h)
            details[h] = val[:120]
        else:
            missing.append(h)

    score = round((len(present) / len(SECURITY_HEADERS)) * 100)

    return {
        "present": present,
        "missing": missing,
        "score": score,
        "details": details,
        "server": headers.get("Server") or headers.get("server", "Non divulgué"),
        "x_powered_by": headers.get("X-Powered-By") or headers.get("x-powered-by", None),
    }


def analyze_content(soup: BeautifulSoup, raw_html: str) -> dict:
    text = soup.get_text().lower()

    # Mots suspects
    found_words = [w for w in SUSPICIOUS_WORDS if w in text]

    # Technologies détectées
    detected_cms = []
    for cms, sigs in CMS_SIGNATURES.items():
        if any(sig.lower() in raw_html.lower() for sig in sigs):
            detected_cms.append(cms)

    # Liens
    links = soup.find_all("a", href=True)
    external_links = []
    internal_links = []
    for a in links:
        href = a["href"]
        if href.startswith("http"):
            external_links.append(href[:100])
        elif href.startswith("/") or not href.startswith("#"):
            internal_links.append(href[:100])

    # Scripts externes
    scripts = soup.find_all("script", src=True)
    ext_scripts = [s["src"] for s in scripts if s["src"].startswith("http")]

    # Iframes
    iframes = soup.find_all("iframe")
    iframe_srcs = [i.get("src", "sans src")[:100] for i in iframes]

    # Meta tags
    metas = {}
    for m in soup.find_all("meta"):
        name = m.get("name") or m.get("property") or m.get("http-equiv")
        content = m.get("content")
        if name and content:
            metas[name] = content[:100]

    return {
        "suspicious_words": found_words,
        "technologies": detected_cms,
        "link_count": len(links),
        "external_links": external_links[:10],
        "internal_link_count": len(internal_links),
        "external_scripts": ext_scripts[:10],
        "iframes": iframe_srcs,
        "meta": metas,
    }


def analyze_forms(soup: BeautifulSoup, base_url: str) -> dict:
    forms = soup.find_all("form")
    parsed = []
    suspicious_forms = []

    for form in forms:
        action = form.get("action", "")
        method = form.get("method", "GET").upper()
        inputs = form.find_all("input")

        input_types = [i.get("type", "text").lower() for i in inputs]
        input_names = [i.get("name", "") for i in inputs]

        has_password   = "password" in input_types
        has_csrf       = any("csrf" in n.lower() or "token" in n.lower() for n in input_names)
        action_external = action.startswith("http") and base_url not in action

        suspicious = []
        if has_password and not has_csrf:
            suspicious.append("Formulaire mot de passe sans protection CSRF")
        if action_external:
            suspicious.append(f"Soumission vers domaine externe : {action[:60]}")
        if method == "GET" and has_password:
            suspicious.append("Mot de passe envoyé via GET (dangereux !)")
        for t in input_types:
            if any(s in t for s in FORM_SUSPICIOUS_TYPES):
                if not has_csrf:
                    suspicious.append(f"Champ sensible '{t}' sans token CSRF")

        form_data = {
            "action": action[:100] if action else "(même page)",
            "method": method,
            "inputs": len(inputs),
            "input_types": input_types,
            "has_csrf": has_csrf,
            "suspicious": suspicious,
        }
        parsed.append(form_data)
        if suspicious:
            suspicious_forms.append(form_data)

    return {
        "count": len(forms),
        "forms": parsed,
        "suspicious_count": len(suspicious_forms),
        "suspicious_forms": suspicious_forms,
    }


def compute_risk(ssl_data, headers_data, content_data, forms_data) -> dict:
    score = 0
    issues = []
    details = []

    # SSL
    if not ssl_data["valid"]:
        score += 30
        issues.append("Certificat SSL invalide ou absent")
    else:
        days = ssl_data.get("days_left", 999)
        if days < 30:
            score += 15
            issues.append(f"Certificat SSL expire dans {days} jours")

    # Headers manquants
    missing_critical = [h for h in ["Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options"]
                        if h in headers_data["missing"]]
    if missing_critical:
        score += len(missing_critical) * 8
        issues.append(f"En-têtes de sécurité manquants : {', '.join(missing_critical)}")

    if headers_data.get("x_powered_by"):
        score += 5
        details.append(f"Technologies exposées dans X-Powered-By : {headers_data['x_powered_by']}")

    # Mots suspects
    if content_data["suspicious_words"]:
        score += len(content_data["suspicious_words"]) * 5
        issues.append(f"Contenu suspect : {', '.join(content_data['suspicious_words'])}")

    # Iframes
    if content_data["iframes"]:
        score += len(content_data["iframes"]) * 5
        details.append(f"{len(content_data['iframes'])} iframe(s) détectée(s)")

    # Formulaires suspects
    if forms_data["suspicious_count"] > 0:
        score += forms_data["suspicious_count"] * 12
        issues.append(f"{forms_data['suspicious_count']} formulaire(s) suspect(s) détecté(s)")

    score = min(score, 100)

    if score <= 20:
        level, color = "Faible", "green"
    elif score <= 50:
        level, color = "Modéré", "orange"
    elif score <= 75:
        level, color = "Élevé", "red"
    else:
        level, color = "Critique", "darkred"

    return {
        "score": score,
        "level": level,
        "color": color,
        "issues": issues,
        "details": details,
    }


# ─── Endpoint principal ───────────────────────────────────────────────────────
@app.post("/analyze", response_model=AnalyzeResponse, summary="Analyser une URL")
async def analyze(req: AnalyzeRequest):
    url = normalize_url(req.url)
    parsed = urlparse(url)
    hostname = parsed.hostname

    if not hostname:
        raise HTTPException(status_code=400, detail="URL invalide")

    timestamp = datetime.utcnow().strftime("%d/%m/%Y à %H:%M UTC")

    # ── Requête HTTP ──
    try:
        response = requests.get(
            url,
            timeout=10,
            headers={"User-Agent": "Mozilla/5.0 (compatible; WebProbe/1.0)"},
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

    # ── Analyses ──
    ssl_data     = check_ssl(hostname)
    headers_data = analyze_headers(headers)
    content_data = analyze_content(soup, raw_html)
    forms_data   = analyze_forms(soup, url)
    risk_data    = compute_risk(ssl_data, headers_data, content_data, forms_data)

    return AnalyzeResponse(
        url=url,
        timestamp=timestamp,
        reachable=reachable,
        title=title,
        status_code=status_code,
        ssl=ssl_data,
        headers=headers_data,
        content=content_data,
        forms=forms_data,
        risk=risk_data,
    )


@app.get("/health", summary="Vérification du serveur")
def health():
    return {"status": "ok", "app": "WebProbe", "version": "1.0.0"}


# ─── Frontend statique ────────────────────────────────────────────────────────
app.mount("/static", StaticFiles(directory="public"), name="static")

@app.get("/", include_in_schema=False)
def root():
    return FileResponse("public/index.html")
