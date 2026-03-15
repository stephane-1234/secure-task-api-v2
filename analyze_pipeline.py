#!/usr/bin/env python3
"""
analyze_pipeline.py
Analyse les logs Jenkins avec Ollama (LLM local, 100% gratuit)
et génère des rapports HTML, PDF, JSON et Email.

Prérequis :
  1. Installer Ollama  : https://ollama.com/download  (Windows)
  2. Télécharger le modèle : ollama pull mistral
  3. pip install requests weasyprint

Usage : python analyze_pipeline.py --log jenkins.log --output ./reports
"""

import argparse
import json
import os
import re
import sys
import smtplib
import datetime
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from email.mime.application import MIMEApplication
from pathlib import Path

try:
    import requests
except ImportError:
    print("pip install requests")
    sys.exit(1)

try:
    from weasyprint import HTML as WeasyprintHTML
    WEASYPRINT_OK = True
except Exception:
    WEASYPRINT_OK = False

# ─────────────────────────────────────────────
# 1. PARSING DES LOGS
# ─────────────────────────────────────────────

STAGES = {
    "checkout":     r"\(Checkout\)",
    "lint":         r"\(Lint - Flake8\)",
    "tests":        r"\(Tests - Pytest\)",
    "bandit":       r"\(Security - Bandit\)",
    "pip_audit":    r"\(Security - pip-audit\)",
    "gitleaks":     r"\(Security - Gitleaks\)",
    "docker_build": r"\(Build Docker Image\)",
    "trivy":        r"\(Security - Trivy\)",
    "deploy":       r"\(Deploy Local Container\)",
    "zap":          r"\(DAST - OWASP ZAP\)",
}


def extract_stages(log_text: str) -> dict:
    """Découpe le log brut par stage Jenkins."""
    lines = log_text.splitlines()
    current_stage = "global"
    stages: dict = {k: [] for k in STAGES}
    stages["global"] = []

    for line in lines:
        matched = False
        for name, pattern in STAGES.items():
            if re.search(pattern, line):
                current_stage = name
                matched = True
                break
        stages.setdefault(current_stage, []).append(line)

    return {k: "\n".join(v) for k, v in stages.items() if v}


def quick_summary(stages: dict) -> dict:
    """Extrait des métriques rapides sans appel LLM."""
    summary = {}

    # Pytest
    pytest_text = stages.get("tests", "")
    m = re.search(r"(\d+) passed", pytest_text)
    summary["pytest_passed"] = int(m.group(1)) if m else 0
    m = re.search(r"(\d+) failed", pytest_text)
    summary["pytest_failed"] = int(m.group(1)) if m else 0

    # Flake8 — présence d'erreurs
    lint_text = stages.get("lint", "")
    lint_errors = [l for l in lint_text.splitlines()
                   if re.search(r"\w+\.py:\d+:\d+:", l)]
    summary["lint_errors"] = lint_errors

    # Bandit
    bandit_text = stages.get("bandit", "")
    summary["bandit_high"] = len(re.findall(r"Severity: High", bandit_text))
    summary["bandit_medium"] = len(re.findall(r"Severity: Medium", bandit_text))

    # Trivy
    trivy_text = stages.get("trivy", "")
    m = re.search(r"HIGH:\s*(\d+)", trivy_text)
    summary["trivy_high"] = int(m.group(1)) if m else 0
    m = re.search(r"CRITICAL:\s*(\d+)", trivy_text)
    summary["trivy_critical"] = int(m.group(1)) if m else 0

    # CVEs détectées
    cves = re.findall(r"CVE-\d{4}-\d+", trivy_text)
    summary["cves"] = list(set(cves))

    # Pip-audit
    pip_text = stages.get("pip_audit", "")
    summary["pip_vulns"] = 0 if "No known vulnerabilities" in pip_text else -1

    # Gitleaks
    git_text = stages.get("gitleaks", "")
    summary["secrets_leaked"] = 0 if "no leaks found" in git_text.lower() else 1

    # ZAP
    zap_text = stages.get("zap", "")
    summary["zap_alerts"] = len(re.findall(r"WARN|FAIL|alert", zap_text, re.I))

    # Statut global
    fatal = (
        summary["pytest_failed"] > 0
        or summary["bandit_high"] > 0
        or summary["trivy_critical"] > 0
        or summary["secrets_leaked"] > 0
    )
    warning = (
        summary["trivy_high"] > 0
        or summary["lint_errors"]
        or summary["bandit_medium"] > 0
    )
    summary["global_status"] = "CRITICAL" if fatal else ("WARNING" if warning else "OK")
    return summary


# ─────────────────────────────────────────────
# 2. APPEL OLLAMA (LLM LOCAL — 100% GRATUIT)
# ─────────────────────────────────────────────

# Modèles recommandés selon votre RAM :
#   mistral        → 7B  — 8 GB RAM min  — excellent rapport qualité/vitesse ✅
#   llama3.2       → 3B  — 4 GB RAM min  — plus rapide, légèrement moins précis
#   mixtral        → 47B — 32 GB RAM min — le plus puissant (votre config !)
# Changez OLLAMA_MODEL selon votre préférence.
OLLAMA_MODEL   = "mistral"          # ollama pull mistral
OLLAMA_URL     = "http://localhost:11434/api/generate"
OLLAMA_TIMEOUT = 300                # secondes — mistral prend ~30-90s selon GPU

SYSTEM_PROMPT = """Tu es un expert DevSecOps senior. Tu analyses les logs de pipelines CI/CD Jenkins
et tu produis des rapports d'analyse structurés, précis et actionnables.

Pour chaque stage analysé, tu fournis :
1. Un résumé clair du résultat (OK / Avertissement / Critique)
2. Une explication technique détaillée des problèmes trouvés
3. Des exemples concrets de corrections à apporter (code, commandes)
4. Un niveau de priorité (P1-Critique / P2-Haute / P3-Moyenne / P4-Faible)

IMPORTANT : Réponds UNIQUEMENT avec du JSON brut valide.
Ne mets AUCUN texte avant ou après le JSON.
Ne mets PAS de balises ```json```.
Commence directement par { et termine par }.

Structure JSON obligatoire :
{
  "pipeline_name": "string",
  "build_date": "string",
  "global_status": "OK|WARNING|CRITICAL",
  "global_summary": "string (2-3 phrases)",
  "risk_score": 0,
  "stages": [
    {
      "name": "string",
      "status": "OK|WARNING|CRITICAL|SKIPPED",
      "summary": "string",
      "issues": [
        {
          "title": "string",
          "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
          "priority": "P1|P2|P3|P4",
          "description": "string",
          "location": "string",
          "fix_example": "string",
          "references": []
        }
      ],
      "metrics": {}
    }
  ],
  "recommendations": [
    {
      "title": "string",
      "impact": "string",
      "effort": "Faible|Moyen|Eleve",
      "steps": ["string"]
    }
  ],
  "developer_checklist": ["string"]
}"""


def check_ollama_running() -> bool:
    """Vérifie qu'Ollama tourne bien sur localhost:11434."""
    try:
        r = requests.get("http://localhost:11434/api/tags", timeout=5)
        return r.status_code == 200
    except Exception:
        return False


def call_ollama(stages: dict, summary: dict,
                model: str = OLLAMA_MODEL) -> dict:
    """Appelle Ollama en local pour une analyse complète des logs."""

    # Vérifie que le service Ollama est démarré
    if not check_ollama_running():
        raise RuntimeError(
            "Ollama n'est pas démarré !\n"
            "  → Ouvrez un terminal et lancez : ollama serve\n"
            "  → Puis dans un autre terminal  : ollama pull " + model
        )

    # Prépare le contexte (limité à 2500 chars/stage pour rester dans le contexte)
    context_parts = []
    for stage_name, content in stages.items():
        if content.strip():
            truncated = content[:2500] + ("...[tronqué]" if len(content) > 2500 else "")
            context_parts.append(f"### STAGE: {stage_name.upper()}\n{truncated}")
    context = "\n\n".join(context_parts)

    prompt = f"""{SYSTEM_PROMPT}

---
MÉTRIQUES RAPIDES DÉTECTÉES :
- Tests Pytest : {summary['pytest_passed']} passed, {summary['pytest_failed']} failed
- Erreurs Lint Flake8 : {len(summary['lint_errors'])}
- Bandit : {summary['bandit_high']} HIGH, {summary['bandit_medium']} MEDIUM
- Trivy : {summary['trivy_high']} HIGH, {summary['trivy_critical']} CRITICAL
- CVEs détectées : {', '.join(summary['cves']) if summary['cves'] else 'aucune'}
- Secrets leakés : {'OUI - CRITIQUE' if summary['secrets_leaked'] else 'Non'}
- Pip-audit : {'Aucune vulnérabilité' if summary['pip_vulns'] == 0 else 'Vulnérabilités détectées'}

LOGS DU PIPELINE :
{context}

Génère maintenant le rapport JSON complet avec exemples de fix concrets.
Rappel : commence directement par {{ sans aucun texte avant."""

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False,
        "options": {
            "temperature": 0.1,      # Basse température = réponses JSON plus stables
            "num_predict": 4096,     # Tokens max en sortie
            "num_ctx": 8192,         # Fenêtre de contexte
        }
    }

    print(f"  🤖 Modèle : {model} | URL : {OLLAMA_URL}")
    print(f"  ⏳ Analyse en cours (peut prendre 30-90s selon GPU)...")

    resp = requests.post(OLLAMA_URL, json=payload, timeout=OLLAMA_TIMEOUT)
    resp.raise_for_status()

    raw = resp.json().get("response", "")

    # Nettoyage robuste — Ollama peut quand même ajouter des backticks
    raw = raw.strip()
    raw = re.sub(r"^```json\s*", "", raw)
    raw = re.sub(r"^```\s*",     "", raw)
    raw = re.sub(r"\s*```$",     "", raw)
    raw = raw.strip()

    # Extrait le JSON même s'il y a du texte parasite avant/après
    json_match = re.search(r"\{.*\}", raw, re.DOTALL)
    if json_match:
        raw = json_match.group(0)

    try:
        return json.loads(raw)
    except json.JSONDecodeError as e:
        # Fallback : retourne un rapport minimal si le JSON est invalide
        print(f"  ⚠️  JSON malformé reçu d'Ollama ({e}). Génération rapport de fallback.")
        return _fallback_report(summary, raw)


# ─────────────────────────────────────────────
# 3. GÉNÉRATION DES RAPPORTS
# ─────────────────────────────────────────────

STATUS_COLOR = {
    "OK": "#22c55e",
    "WARNING": "#f59e0b",
    "CRITICAL": "#ef4444",
    "SKIPPED": "#94a3b8",
}
STATUS_ICON = {"OK": "✅", "WARNING": "⚠️", "CRITICAL": "❌", "SKIPPED": "⏭️"}
SEV_COLOR = {
    "CRITICAL": "#ef4444", "HIGH": "#f97316",
    "MEDIUM": "#f59e0b", "LOW": "#3b82f6", "INFO": "#94a3b8",
}
PRIORITY_BADGE = {
    "P1": "#ef4444", "P2": "#f97316", "P3": "#f59e0b", "P4": "#3b82f6",
}


def build_html_report(report: dict, summary: dict) -> str:
    """Génère un rapport HTML complet et visuellement riche."""
    status = report.get("global_status", "OK")
    color = STATUS_COLOR.get(status, "#94a3b8")
    risk = report.get("risk_score", 0)
    now = datetime.datetime.now().strftime("%d/%m/%Y à %H:%M")

    # ── Stages cards ──
    stages_html = ""
    for stage in report.get("stages", []):
        sname = stage.get("name", "")
        sstatus = stage.get("status", "OK")
        sc = STATUS_COLOR.get(sstatus, "#94a3b8")
        si = STATUS_ICON.get(sstatus, "")
        issues_html = ""
        for issue in stage.get("issues", []):
            sev = issue.get("severity", "INFO")
            prio = issue.get("priority", "P4")
            fix = issue.get("fix_example", "").replace("<", "&lt;").replace(">", "&gt;")
            refs = " ".join(
                f'<a href="https://nvd.nist.gov/vuln/detail/{r}" target="_blank" '
                f'style="color:#60a5fa;font-size:11px">{r}</a>'
                for r in issue.get("references", [])
            )
            issues_html += f"""
            <div class="issue" style="border-left:4px solid {SEV_COLOR.get(sev,'#94a3b8')}">
              <div class="issue-header">
                <span class="badge" style="background:{SEV_COLOR.get(sev,'#94a3b8')}">{sev}</span>
                <span class="badge" style="background:{PRIORITY_BADGE.get(prio,'#94a3b8')}">{prio}</span>
                <strong>{issue.get('title','')}</strong>
              </div>
              <p class="issue-desc">{issue.get('description','')}</p>
              {'<p class="location">📍 ' + issue.get('location','') + '</p>' if issue.get('location') else ''}
              {'<pre class="fix-block"><code>' + fix + '</code></pre>' if fix else ''}
              {'<div class="refs">🔗 ' + refs + '</div>' if refs else ''}
            </div>"""

        metrics = stage.get("metrics", {})
        metrics_html = ""
        if metrics:
            metrics_html = '<div class="metrics">' + "".join(
                f'<span class="metric-pill">{k}: <b>{v}</b></span>'
                for k, v in metrics.items()
            ) + "</div>"

        stages_html += f"""
        <div class="stage-card">
          <div class="stage-header" style="border-left:5px solid {sc}">
            <span class="stage-icon">{si}</span>
            <span class="stage-name">{sname}</span>
            <span class="stage-badge" style="background:{sc}">{sstatus}</span>
          </div>
          <p class="stage-summary">{stage.get('summary','')}</p>
          {metrics_html}
          {issues_html}
        </div>"""

    # ── Recommandations ──
    reco_html = ""
    for reco in report.get("recommendations", []):
        effort = reco.get("effort", "Moyen")
        effort_color = {"Faible": "#22c55e", "Moyen": "#f59e0b", "Élevé": "#ef4444"}.get(effort, "#94a3b8")
        steps = "".join(f"<li>{s}</li>" for s in reco.get("steps", []))
        reco_html += f"""
        <div class="reco-card">
          <div class="reco-header">
            <strong>{reco.get('title','')}</strong>
            <span class="badge" style="background:{effort_color}">Effort: {effort}</span>
          </div>
          <p class="reco-impact">💡 {reco.get('impact','')}</p>
          <ol class="reco-steps">{steps}</ol>
        </div>"""

    # ── Checklist ──
    checklist_html = "".join(
        f'<li class="check-item"><input type="checkbox"> {item}</li>'
        for item in report.get("developer_checklist", [])
    )

    # ── Risk gauge ──
    risk_color = "#22c55e" if risk < 30 else "#f59e0b" if risk < 60 else "#ef4444"

    html = f"""<!DOCTYPE html>
<html lang="fr">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Rapport CI/CD — {report.get('pipeline_name','Pipeline')}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;700&family=Sora:wght@300;400;600;800&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg: #0d1117;
    --surface: #161b22;
    --surface2: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --muted: #8b949e;
    --accent: {color};
  }}

  body {{
    font-family: 'Sora', sans-serif;
    background: var(--bg);
    color: var(--text);
    min-height: 100vh;
    padding: 0;
  }}

  /* HERO */
  .hero {{
    background: linear-gradient(135deg, #0d1117 0%, #161b22 50%, {color}18 100%);
    border-bottom: 1px solid var(--border);
    padding: 48px 40px 36px;
    position: relative;
    overflow: hidden;
  }}
  .hero::before {{
    content: '';
    position: absolute; inset: 0;
    background: radial-gradient(ellipse 80% 60% at 70% 50%, {color}12, transparent);
    pointer-events: none;
  }}
  .hero-top {{ display: flex; justify-content: space-between; align-items: flex-start; flex-wrap: wrap; gap: 20px; }}
  .pipeline-name {{
    font-size: 28px; font-weight: 800; letter-spacing: -0.5px;
    color: var(--text);
  }}
  .pipeline-name span {{ color: {color}; }}
  .build-meta {{ font-size: 13px; color: var(--muted); margin-top: 6px; font-family: 'JetBrains Mono', monospace; }}
  .global-badge {{
    padding: 10px 24px; border-radius: 50px;
    background: {color}22; border: 2px solid {color};
    color: {color}; font-weight: 700; font-size: 16px;
    letter-spacing: 1px;
  }}

  /* KPI STRIP */
  .kpi-strip {{
    display: flex; gap: 0; flex-wrap: wrap;
    border-bottom: 1px solid var(--border);
    background: var(--surface);
  }}
  .kpi {{
    flex: 1; min-width: 120px;
    padding: 20px 24px;
    border-right: 1px solid var(--border);
    text-align: center;
  }}
  .kpi:last-child {{ border-right: none; }}
  .kpi-value {{ font-size: 28px; font-weight: 800; font-family: 'JetBrains Mono', monospace; }}
  .kpi-label {{ font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }}

  /* RISK GAUGE */
  .risk-section {{
    padding: 24px 40px;
    background: var(--surface);
    border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 24px;
  }}
  .risk-label {{ font-size: 13px; font-weight: 600; color: var(--muted); text-transform: uppercase; letter-spacing: 1px; white-space: nowrap; }}
  .risk-bar-bg {{ flex: 1; height: 12px; background: var(--surface2); border-radius: 6px; overflow: hidden; }}
  .risk-bar-fill {{ height: 100%; width: {risk}%; background: linear-gradient(90deg, #22c55e, {risk_color}); border-radius: 6px; transition: width 1s; }}
  .risk-score {{ font-size: 22px; font-weight: 800; color: {risk_color}; font-family: 'JetBrains Mono', monospace; white-space: nowrap; }}

  /* CONTENT */
  .content {{ max-width: 1100px; margin: 0 auto; padding: 40px; }}

  h2 {{
    font-size: 18px; font-weight: 700; margin: 40px 0 16px;
    padding-bottom: 8px; border-bottom: 1px solid var(--border);
    color: var(--text);
  }}
  h2::before {{ content: attr(data-icon); margin-right: 8px; }}

  /* SUMMARY BOX */
  .summary-box {{
    background: var(--surface); border: 1px solid var(--border);
    border-left: 4px solid {color};
    border-radius: 8px; padding: 20px 24px;
    font-size: 15px; line-height: 1.7; color: var(--text);
    margin-bottom: 32px;
  }}

  /* STAGE CARDS */
  .stage-card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 10px; margin-bottom: 16px; overflow: hidden;
  }}
  .stage-header {{
    display: flex; align-items: center; gap: 12px;
    padding: 14px 20px; background: var(--surface2);
  }}
  .stage-icon {{ font-size: 18px; }}
  .stage-name {{ font-weight: 700; font-size: 15px; flex: 1; }}
  .stage-badge {{
    padding: 3px 12px; border-radius: 50px;
    font-size: 11px; font-weight: 700; letter-spacing: 1px;
    color: #fff;
  }}
  .stage-summary {{ padding: 14px 20px; color: var(--muted); font-size: 14px; line-height: 1.6; }}

  .metrics {{ padding: 0 20px 12px; display: flex; gap: 8px; flex-wrap: wrap; }}
  .metric-pill {{
    background: var(--surface2); border: 1px solid var(--border);
    border-radius: 50px; padding: 4px 12px;
    font-size: 12px; color: var(--muted);
    font-family: 'JetBrains Mono', monospace;
  }}

  /* ISSUES */
  .issue {{
    margin: 0 20px 12px; padding: 14px 16px;
    background: var(--bg); border-radius: 8px;
    border: 1px solid var(--border);
  }}
  .issue-header {{ display: flex; align-items: center; gap: 8px; margin-bottom: 8px; flex-wrap: wrap; }}
  .badge {{
    padding: 2px 10px; border-radius: 50px;
    font-size: 10px; font-weight: 700; letter-spacing: 1px;
    color: #fff;
  }}
  .issue-desc {{ font-size: 13px; color: var(--muted); line-height: 1.6; margin-bottom: 8px; }}
  .location {{ font-size: 12px; color: #60a5fa; font-family: 'JetBrains Mono', monospace; margin-bottom: 8px; }}
  .fix-block {{
    background: #010409; border: 1px solid var(--border);
    border-radius: 6px; padding: 12px; margin: 8px 0;
    overflow-x: auto;
  }}
  .fix-block code {{ font-family: 'JetBrains Mono', monospace; font-size: 12px; color: #79c0ff; white-space: pre; }}
  .refs {{ font-size: 11px; color: var(--muted); margin-top: 6px; }}

  /* RECOMMENDATIONS */
  .reco-card {{
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 10px; padding: 20px; margin-bottom: 12px;
  }}
  .reco-header {{ display: flex; align-items: center; justify-content: space-between; gap: 12px; margin-bottom: 10px; flex-wrap: wrap; }}
  .reco-impact {{ font-size: 13px; color: var(--muted); margin-bottom: 10px; line-height: 1.5; }}
  .reco-steps {{ padding-left: 20px; font-size: 13px; color: var(--text); line-height: 2; }}

  /* CHECKLIST */
  .checklist {{ list-style: none; }}
  .check-item {{
    padding: 10px 14px; margin-bottom: 6px;
    background: var(--surface); border: 1px solid var(--border);
    border-radius: 6px; font-size: 13px;
    display: flex; align-items: center; gap: 10px;
    cursor: pointer;
  }}
  .check-item input {{ accent-color: {color}; width: 16px; height: 16px; cursor: pointer; }}
  .check-item:has(input:checked) {{ opacity: 0.5; text-decoration: line-through; }}

  /* FOOTER */
  .footer {{
    text-align: center; padding: 32px;
    color: var(--muted); font-size: 12px;
    border-top: 1px solid var(--border);
    font-family: 'JetBrains Mono', monospace;
  }}
  .footer span {{ color: {color}; }}
</style>
</head>
<body>

<div class="hero">
  <div class="hero-top">
    <div>
      <div class="pipeline-name">🔬 <span>{report.get('pipeline_name','Pipeline')}</span> — Rapport CI/CD</div>
      <div class="build-meta">Généré le {now} · Analyse propulsée par Ollama / {OLLAMA_MODEL}</div>
      <div class="build-meta" style="margin-top:4px">{report.get('build_date','')}</div>
    </div>
    <div class="global-badge">{STATUS_ICON.get(status,'')} {status}</div>
  </div>
</div>

<div class="kpi-strip">
  <div class="kpi">
    <div class="kpi-value" style="color:#22c55e">{summary['pytest_passed']}</div>
    <div class="kpi-label">Tests ✅</div>
  </div>
  <div class="kpi">
    <div class="kpi-value" style="color:#ef4444">{summary['pytest_failed']}</div>
    <div class="kpi-label">Tests ❌</div>
  </div>
  <div class="kpi">
    <div class="kpi-value" style="color:#f97316">{len(summary['lint_errors'])}</div>
    <div class="kpi-label">Erreurs Lint</div>
  </div>
  <div class="kpi">
    <div class="kpi-value" style="color:#ef4444">{summary['trivy_high']}</div>
    <div class="kpi-label">HIGH Trivy</div>
  </div>
  <div class="kpi">
    <div class="kpi-value" style="color:#ef4444">{summary['trivy_critical']}</div>
    <div class="kpi-label">CRITICAL Trivy</div>
  </div>
  <div class="kpi">
    <div class="kpi-value" style="color:{'#ef4444' if summary['secrets_leaked'] else '#22c55e'}">{summary['secrets_leaked']}</div>
    <div class="kpi-label">Secrets leakés</div>
  </div>
</div>

<div class="risk-section">
  <span class="risk-label">Score de risque</span>
  <div class="risk-bar-bg"><div class="risk-bar-fill"></div></div>
  <span class="risk-score">{risk}/100</span>
</div>

<div class="content">

  <h2 data-icon="📋">Résumé global</h2>
  <div class="summary-box">{report.get('global_summary','')}</div>

  <h2 data-icon="🔍">Analyse par stage</h2>
  {stages_html}

  <h2 data-icon="🚀">Recommandations prioritaires</h2>
  {reco_html if reco_html else '<p style="color:var(--muted)">Aucune recommandation générée.</p>'}

  <h2 data-icon="✅">Checklist développeur</h2>
  <ul class="checklist">{checklist_html}</ul>

</div>

<div class="footer">
  Rapport généré par <span>analyze_pipeline.py</span> · Analyse IA par <span>Ollama / Mistral (local)</span>
</div>

</body>
</html>"""
    return html


def _fallback_report(summary: dict, raw_text: str = "") -> dict:
    """Rapport de secours si Ollama retourne un JSON invalide."""
    status = summary.get("global_status", "WARNING")
    issues = []
    if summary.get("trivy_high", 0) > 0:
        issues.append({"title": f"Trivy: {summary['trivy_high']} vulnérabilités HIGH",
                       "severity": "HIGH", "priority": "P2",
                       "description": "Des vulnérabilités HIGH ont été détectées dans l'image Docker.",
                       "location": "Image Docker",
                       "fix_example": "Mettez à jour l'image de base : FROM python:3.12-slim",
                       "references": summary.get("cves", [])})
    if summary.get("secrets_leaked", 0):
        issues.append({"title": "Secret potentiellement leaké (Gitleaks)",
                       "severity": "CRITICAL", "priority": "P1",
                       "description": "Gitleaks a détecté un secret dans le code source.",
                       "location": "Repository Git",
                       "fix_example": "Révoquez immédiatement la clé concernée et utilisez des variables d'environnement.",
                       "references": []})
    if summary.get("pytest_failed", 0) > 0:
        issues.append({"title": f"{summary['pytest_failed']} test(s) Pytest échoué(s)",
                       "severity": "HIGH", "priority": "P1",
                       "description": "Des tests unitaires sont en échec.",
                       "location": "test_app.py",
                       "fix_example": "Lancez : pytest -v pour voir les détails des échecs.",
                       "references": []})
    return {
        "pipeline_name": "secure-task-api-v2",
        "build_date": datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
        "global_status": status,
        "global_summary": (
            f"Pipeline analysé avec {len(issues)} problème(s) détecté(s) "
            f"(analyse LLM partielle — modèle Ollama local). "
            f"Score basé sur les métriques extraites automatiquement."
        ),
        "risk_score": min(100, len(issues) * 20 + summary.get("trivy_high", 0) * 10),
        "stages": [{"name": "Analyse globale", "status": status,
                    "summary": "Résumé basé sur les métriques extraites du log.",
                    "issues": issues, "metrics": {
                        "tests_passed": summary.get("pytest_passed", 0),
                        "tests_failed": summary.get("pytest_failed", 0),
                        "trivy_high": summary.get("trivy_high", 0),
                        "trivy_critical": summary.get("trivy_critical", 0),
                    }}],
        "recommendations": [
            {"title": "Résoudre les vulnérabilités Trivy",
             "impact": "Réduction du risque de sécurité de l'image Docker",
             "effort": "Moyen",
             "steps": ["Mettre à jour l'image de base Docker",
                       "Exécuter trivy image --severity CRITICAL,HIGH",
                       "Corriger les dépendances vulnérables"]}
        ],
        "developer_checklist": [
            "Vérifier les vulnérabilités Trivy HIGH/CRITICAL",
            "S'assurer que tous les tests Pytest passent",
            "Valider l'absence de secrets dans le code",
            "Mettre à jour les dépendances Python",
        ]
    }



    """Retourne le rapport JSON enrichi avec les métriques rapides."""
    report["raw_metrics"] = summary
    report["generated_at"] = datetime.datetime.now().isoformat()
    return report


def generate_pdf(html_content: str, output_path: str):
    """Génère le PDF depuis le HTML via WeasyPrint."""
    if not WEASYPRINT_OK:
        print("⚠️  WeasyPrint non disponible. PDF ignoré. "
              "Installez-le avec : pip install weasyprint")
        return
    WeasyprintHTML(string=html_content).write_pdf(output_path)
    print(f"  📄 PDF généré : {output_path}")


def generate_email_body(report: dict, summary: dict) -> str:
    """Génère un corps d'email HTML synthétique."""
    status = report.get("global_status", "OK")
    color = STATUS_COLOR.get(status, "#94a3b8")
    issues_lines = ""
    for stage in report.get("stages", []):
        for issue in stage.get("issues", []):
            sev = issue.get("severity", "INFO")
            issues_lines += (
                f'<tr><td style="padding:6px 10px;border-bottom:1px solid #30363d">'
                f'{stage.get("name","")}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #30363d;color:{SEV_COLOR.get(sev,"#fff")}">'
                f'{sev}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #30363d">'
                f'{issue.get("priority","")}</td>'
                f'<td style="padding:6px 10px;border-bottom:1px solid #30363d">'
                f'{issue.get("title","")}</td></tr>'
            )

    return f"""
<html><body style="font-family:sans-serif;background:#0d1117;color:#e6edf3;padding:32px">
<div style="max-width:700px;margin:0 auto">
  <h1 style="color:{color};font-size:22px">
    {STATUS_ICON.get(status,'')} Pipeline: {report.get('pipeline_name','')} — {status}
  </h1>
  <p style="color:#8b949e;font-size:13px">Analyse du {datetime.datetime.now().strftime('%d/%m/%Y à %H:%M')}</p>

  <div style="background:#161b22;border:1px solid #30363d;border-left:4px solid {color};
              border-radius:8px;padding:16px;margin:20px 0;font-size:14px;line-height:1.7">
    {report.get('global_summary','')}
  </div>

  <h2 style="font-size:16px;border-bottom:1px solid #30363d;padding-bottom:8px">📊 KPIs</h2>
  <table style="width:100%;border-collapse:collapse;font-size:13px;margin-bottom:20px">
    <tr>
      <td style="padding:8px;background:#161b22">✅ Tests OK</td><td style="padding:8px;color:#22c55e;font-weight:bold">{summary['pytest_passed']}</td>
      <td style="padding:8px;background:#161b22">❌ Tests KO</td><td style="padding:8px;color:#ef4444;font-weight:bold">{summary['pytest_failed']}</td>
    </tr>
    <tr>
      <td style="padding:8px;background:#161b22">🔶 HIGH Trivy</td><td style="padding:8px;color:#f97316;font-weight:bold">{summary['trivy_high']}</td>
      <td style="padding:8px;background:#161b22">🔴 CRITICAL</td><td style="padding:8px;color:#ef4444;font-weight:bold">{summary['trivy_critical']}</td>
    </tr>
    <tr>
      <td style="padding:8px;background:#161b22">🔑 Secrets leakés</td><td style="padding:8px;color:{'#ef4444' if summary['secrets_leaked'] else '#22c55e'};font-weight:bold">{'OUI' if summary['secrets_leaked'] else 'NON'}</td>
      <td style="padding:8px;background:#161b22">📊 Score risque</td><td style="padding:8px;color:#f59e0b;font-weight:bold">{report.get('risk_score',0)}/100</td>
    </tr>
  </table>

  <h2 style="font-size:16px;border-bottom:1px solid #30363d;padding-bottom:8px">⚠️ Problèmes détectés</h2>
  <table style="width:100%;border-collapse:collapse;font-size:13px">
    <thead><tr style="background:#21262d">
      <th style="padding:8px 10px;text-align:left">Stage</th>
      <th style="padding:8px 10px;text-align:left">Sévérité</th>
      <th style="padding:8px 10px;text-align:left">Priorité</th>
      <th style="padding:8px 10px;text-align:left">Problème</th>
    </tr></thead>
    <tbody>{issues_lines if issues_lines else '<tr><td colspan="4" style="padding:12px;color:#8b949e;text-align:center">✅ Aucun problème critique détecté</td></tr>'}</tbody>
  </table>

  <p style="color:#8b949e;font-size:11px;margin-top:24px;text-align:center">
    Rapport complet joint en PDF · Généré par analyze_pipeline.py · Ollama (LLM local)
  </p>
</div>
</body></html>"""


def send_email(html_body: str, pdf_path: str | None, cfg: dict):
    """Envoie le rapport par email avec le PDF en pièce jointe."""
    msg = MIMEMultipart("mixed")
    msg["Subject"] = cfg.get("subject", "📊 Rapport CI/CD Pipeline")
    msg["From"] = cfg["from"]
    msg["To"] = ", ".join(cfg["to"]) if isinstance(cfg["to"], list) else cfg["to"]

    alt = MIMEMultipart("alternative")
    alt.attach(MIMEText(html_body, "html", "utf-8"))
    msg.attach(alt)

    if pdf_path and Path(pdf_path).exists():
        with open(pdf_path, "rb") as f:
            part = MIMEApplication(f.read(), _subtype="pdf")
            part.add_header("Content-Disposition", "attachment",
                            filename=Path(pdf_path).name)
            msg.attach(part)

    host = cfg.get("smtp_host", "smtp.gmail.com")
    port = int(cfg.get("smtp_port", 587))
    use_tls = cfg.get("tls", True)

    with smtplib.SMTP(host, port) as server:
        if use_tls:
            server.starttls()
        server.login(cfg["username"], cfg["password"])
        to_list = cfg["to"] if isinstance(cfg["to"], list) else [cfg["to"]]
        server.sendmail(cfg["from"], to_list, msg.as_string())
    print(f"  📧 Email envoyé à {msg['To']}")


# ─────────────────────────────────────────────
# 4. MAIN
# ─────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="Analyse CI/CD avec Ollama (LLM local)")
    parser.add_argument("--log",          required=True, help="Chemin vers le fichier log Jenkins")
    parser.add_argument("--output",       default="./reports", help="Dossier de sortie")
    parser.add_argument("--model",        default=OLLAMA_MODEL,
                        help=f"Modèle Ollama à utiliser (défaut: {OLLAMA_MODEL})")
    parser.add_argument("--ollama-url",   default=OLLAMA_URL,
                        help="URL de l'API Ollama (défaut: http://localhost:11434/api/generate)")
    parser.add_argument("--email-config", default=None,
                        help="Chemin vers email_config.json")
    parser.add_argument("--no-pdf",       action="store_true", help="Désactiver la génération PDF")
    parser.add_argument("--no-email",     action="store_true", help="Désactiver l'envoi email")
    args = parser.parse_args()

    # Lecture du log
    log_path = Path(args.log)
    if not log_path.exists():
        print(f"❌ Fichier log introuvable : {args.log}")
        sys.exit(1)

    log_text = log_path.read_text(encoding="utf-8", errors="replace")
    print(f"✅ Log chargé : {len(log_text):,} caractères")

    # Parsing
    print("⚙️  Parsing des stages...")
    stages = extract_stages(log_text)
    summary = quick_summary(stages)
    print(f"   Statut rapide : {summary['global_status']}")

    # Appel Ollama
    print(f"🤖 Analyse avec Ollama ({args.model}) — 100% local, 0$ ...")
    report = call_ollama(stages, summary, model=args.model)
    print(f"   Score de risque : {report.get('risk_score', '?')}/100")

    # Création du dossier de sortie
    out_dir = Path(args.output)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")

    # HTML
    print("📝 Génération HTML...")
    html_content = build_html_report(report, summary)
    html_path = out_dir / f"report_{ts}.html"
    html_path.write_text(html_content, encoding="utf-8")
    print(f"  🌐 HTML généré : {html_path}")

    # JSON
    print("📦 Génération JSON...")
    json_report = generate_json_report(report, summary)
    json_path = out_dir / f"report_{ts}.json"
    json_path.write_text(json.dumps(json_report, ensure_ascii=False, indent=2),
                         encoding="utf-8")
    print(f"  📦 JSON généré : {json_path}")

    # PDF
    pdf_path = None
    if not args.no_pdf:
        print("📄 Génération PDF...")
        pdf_path = str(out_dir / f"report_{ts}.pdf")
        generate_pdf(html_content, pdf_path)

    # Email
    if not args.no_email and args.email_config:
        print("📧 Envoi email...")
        cfg_path = Path(args.email_config)
        if cfg_path.exists():
            email_cfg = json.loads(cfg_path.read_text())
            email_body = generate_email_body(report, summary)
            send_email(email_body, pdf_path, email_cfg)
        else:
            print(f"  ⚠️  email_config.json introuvable : {args.email_config}")

    print("\n✅ Analyse terminée !")
    print(f"   Statut global  : {report.get('global_status')}")
    print(f"   Score de risque: {report.get('risk_score')}/100")
    print(f"   Rapports dans  : {out_dir.absolute()}")


if __name__ == "__main__":
    main()