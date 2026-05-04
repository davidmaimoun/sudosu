"""
utils/reporter.py
-----------------
Génération du rapport final de SecureScope.
Produit un fichier  reports/report_<timestamp>.json  ET  .html

Concepts cyber :
  - Un rapport de scan est un DOCUMENT LÉGAL en cas d'incident.
    Il doit contenir : qui a lancé le scan, quand, sur quoi, avec quels résultats.
  - Le format JSON est machine-readable → intégrable dans un SIEM ou pipeline CI/CD.
  - Le format HTML est human-readable → pour présenter à un client ou manager.
  - Le hash SHA256 du rapport lui-même prouve qu'il n'a pas été altéré après génération
    (concept de "chain of custody" / chaîne de preuve en forensic).
  - Les niveaux de sévérité (CRITICAL / HIGH / MEDIUM / LOW / CLEAN) viennent du
    standard CVSS (Common Vulnerability Scoring System) utilisé partout en sécu.

Structure du rapport JSON :
  {
    "meta": {
      "tool":      "SecureScope v0.1.0",
      "timestamp": "2026-05-04T09:54:44Z",
      "os":        "linux",
      "target":    "/tmp",
      "mode":      "quick",
      "report_hash": "sha256:abcd1234..."   ← intégrité du rapport lui-même
    },
    "summary": {
      "total":    12,
      "critical": 1,
      "high":     2,
      "medium":   3,
      "low":      6,
      "clean":    0
    },
    "findings": [
      {
        "severity": "CRITICAL",
        "target":   "/tmp/evil.sh",
        "reason":   "hash matches known malware",
        "timestamp": "2026-05-04T09:54:45Z"
      }
    ]
  }
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

REPORTS_DIR = Path("reports")

# Palette couleurs HTML par sévérité
SEVERITY_CSS = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#aaaaff",
    "CLEAN":    "#44ff88",
    "INFO":     "#888888",
}


# ──────────────────────────────────────────────
# Construction du dict rapport
# ──────────────────────────────────────────────
def build_report(
    findings:  list[dict],
    target:    str,
    mode:      str,
    os_name:   str,
    timestamp: str,
    version:   str = "0.1.0",
) -> dict[str, Any]:
    """
    Assemble le dictionnaire complet du rapport.

    Concept :
      Séparer 'construire le rapport' de 'l'écrire sur disque'
      permet de le tester unitairement et de le réutiliser
      (ex : l'envoyer par webhook sans l'écrire).
    """
    summary = _compute_summary(findings)

    return {
        "meta": {
            "tool":      f"SecureScope v{version}",
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "os":        os_name,
            "target":    target,
            "mode":      mode,
            "session":   timestamp,
        },
        "summary":  summary,
        "findings": findings,
    }


def _compute_summary(findings: list[dict]) -> dict[str, int]:
    """
    Compte les findings par sévérité.
    
    Concept CVSS : les rapports de vulnérabilités comptent toujours
    par niveau de criticité pour prioriser la remédiation.
    Un CRITICAL doit être traité avant un LOW.
    """
    counts = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0}
    for f in findings:
        sev = f.get("severity", "LOW").lower()
        if sev in counts:
            counts[sev] += 1
    return counts


# ──────────────────────────────────────────────
# Export JSON
# ──────────────────────────────────────────────
def save_json(report: dict, timestamp: str) -> Path:
    """
    Écrit le rapport en JSON + calcule son hash SHA256.

    Le hash est ajouté AU rapport lui-même dans la clé meta.report_hash.
    → Proof of integrity : si le fichier est modifié après, le hash ne correspondra plus.
    
    Concept forensic (chain of custody) :
      En cas de procédure légale, on peut prouver que le rapport
      n'a pas été altéré entre sa génération et sa présentation.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"report_{timestamp}.json"

    # Premier dump sans hash (pour calculer le hash du contenu)
    raw = json.dumps(report, indent=2, ensure_ascii=False)
    sha = hashlib.sha256(raw.encode()).hexdigest()

    # On injecte le hash dans le rapport
    report["meta"]["report_hash"] = f"sha256:{sha}"

    # Deuxième dump avec hash
    final = json.dumps(report, indent=2, ensure_ascii=False)
    path.write_text(final, encoding="utf-8")

    return path


# ──────────────────────────────────────────────
# Export HTML
# ──────────────────────────────────────────────
def save_html(report: dict, timestamp: str) -> Path:
    """
    Génère un rapport HTML standalone, lisible dans un navigateur.
    Aucune dépendance externe : tout est inline (CSS + JS embarqués).

    Pourquoi HTML ?
      Un recruteur ou client non-technique peut ouvrir ce fichier directement.
      C'est ce que font les outils pro : nessus, burp suite, openvas...
      tous produisent des rapports HTML exportables.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"report_{timestamp}.html"

    meta     = report["meta"]
    summary  = report["summary"]
    findings = report["findings"]

    # ── Lignes du tableau findings ──
    rows_html = ""
    for f in findings:
        sev   = f.get("severity", "LOW").upper()
        color = SEVERITY_CSS.get(sev, "#888")
        rows_html += f"""
        <tr>
          <td><span class="badge" style="background:{color}">{sev}</span></td>
          <td class="mono">{_esc(f.get('target', 'N/A'))}</td>
          <td>{_esc(f.get('reason', ''))}</td>
          <td class="mono muted">{_esc(f.get('timestamp', ''))}</td>
        </tr>"""

    # ── Cartes summary ──
    cards_html = ""
    card_defs = [
        ("CRITICAL", summary.get("critical", 0), "#ff4444"),
        ("HIGH",     summary.get("high",     0), "#ff8800"),
        ("MEDIUM",   summary.get("medium",   0), "#ffcc00"),
        ("LOW",      summary.get("low",      0), "#aaaaff"),
        ("TOTAL",    summary.get("total",    0), "#cccccc"),
    ]
    for label, count, color in card_defs:
        cards_html += f"""
        <div class="card" style="border-top: 4px solid {color}">
          <div class="card-count" style="color:{color}">{count}</div>
          <div class="card-label">{label}</div>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SecureScope Report — {timestamp}</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    font-family: 'Segoe UI', system-ui, sans-serif;
    background: #0d0d0d; color: #e0e0e0;
    padding: 2rem;
  }}
  header {{
    border-bottom: 2px solid #ff4444;
    padding-bottom: 1.5rem; margin-bottom: 2rem;
  }}
  header h1 {{ font-size: 2rem; color: #ff4444; letter-spacing: 0.1em; }}
  header p  {{ color: #888; font-size: 0.85rem; margin-top: 0.4rem; }}
  .meta-grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
    gap: 1rem; margin-bottom: 2rem;
  }}
  .meta-item {{ background: #1a1a1a; border: 1px solid #333; border-radius: 6px; padding: 0.8rem 1rem; }}
  .meta-item .label {{ font-size: 0.7rem; color: #888; text-transform: uppercase; letter-spacing: 0.08em; }}
  .meta-item .value {{ font-size: 0.95rem; color: #e0e0e0; margin-top: 0.3rem; font-family: monospace; }}
  .summary-cards {{ display: flex; gap: 1rem; flex-wrap: wrap; margin-bottom: 2rem; }}
  .card {{
    background: #1a1a1a; border: 1px solid #333; border-radius: 8px;
    padding: 1rem 1.5rem; min-width: 100px; text-align: center;
  }}
  .card-count {{ font-size: 2rem; font-weight: 700; }}
  .card-label {{ font-size: 0.7rem; color: #888; text-transform: uppercase; margin-top: 0.3rem; letter-spacing: 0.08em; }}
  h2 {{ font-size: 1rem; text-transform: uppercase; letter-spacing: 0.1em; color: #888; margin-bottom: 1rem; }}
  table {{ width: 100%; border-collapse: collapse; background: #1a1a1a; border-radius: 8px; overflow: hidden; }}
  th {{ background: #222; color: #888; font-size: 0.75rem; text-transform: uppercase;
        letter-spacing: 0.08em; padding: 0.8rem 1rem; text-align: left; }}
  td {{ padding: 0.7rem 1rem; border-bottom: 1px solid #222; font-size: 0.88rem; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #1f1f1f; }}
  .badge {{
    display: inline-block; padding: 0.2rem 0.6rem; border-radius: 4px;
    font-size: 0.72rem; font-weight: 700; color: #000; letter-spacing: 0.05em;
  }}
  .mono  {{ font-family: monospace; font-size: 0.82rem; }}
  .muted {{ color: #666; }}
  footer {{ margin-top: 2rem; color: #444; font-size: 0.75rem; text-align: center; }}
</style>
</head>
<body>

<header>
  <h1>⬡ SECURESCOPE</h1>
  <p>Security Scan Report · {meta.get('timestamp','')} · Session {timestamp}</p>
</header>

<section class="meta-grid">
  <div class="meta-item"><div class="label">Tool</div><div class="value">{_esc(meta.get('tool',''))}</div></div>
  <div class="meta-item"><div class="label">Target</div><div class="value">{_esc(meta.get('target',''))}</div></div>
  <div class="meta-item"><div class="label">Mode</div><div class="value">{_esc(meta.get('mode',''))}</div></div>
  <div class="meta-item"><div class="label">OS</div><div class="value">{_esc(meta.get('os',''))}</div></div>
  <div class="meta-item"><div class="label">Report Hash</div><div class="value" style="font-size:0.7rem;word-break:break-all">{_esc(meta.get('report_hash','N/A'))}</div></div>
</section>

<h2>Summary</h2>
<div class="summary-cards">{cards_html}</div>

<h2>Findings</h2>
<table>
  <thead>
    <tr>
      <th>Severity</th><th>Target / Path</th><th>Reason</th><th>Timestamp</th>
    </tr>
  </thead>
  <tbody>{rows_html}</tbody>
</table>

<footer>Generated by SecureScope · {meta.get('timestamp','')} · All times UTC</footer>

</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    return path


# ──────────────────────────────────────────────
# Helper
# ──────────────────────────────────────────────
def _esc(s: str) -> str:
    """Échappe les caractères HTML pour éviter les injections dans le rapport."""
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")