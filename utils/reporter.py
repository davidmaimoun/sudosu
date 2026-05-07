"""
utils/reporter.py
-----------------
Génération du rapport final de SudoSu.
Produit reports/sudosu_report_<timestamp>.json  ET  .html

Concepts cyber :
  - Un rapport de scan est un DOCUMENT LÉGAL en cas d'incident.
  - JSON → machine-readable, intégrable dans un SIEM ou pipeline CI/CD.
  - HTML → human-readable, présentable à un client ou manager.
  - Le hash SHA256 du rapport lui-même (chain of custody).
  - Niveaux CRITICAL/HIGH/MEDIUM/LOW → standard CVSS.
"""

import json
import hashlib
from pathlib import Path
from datetime import datetime, timezone
from typing import Any

REPORTS_DIR = Path("reports")

# Palette sévérité — utilisée dans JSON et HTML
SEVERITY_COLORS = {
    "CRITICAL": {"bg": "#fee2e2", "text": "#991b1b", "border": "#f87171", "dot": "#dc2626"},
    "HIGH":     {"bg": "#ffedd5", "text": "#9a3412", "border": "#fb923c", "dot": "#ea580c"},
    "MEDIUM":   {"bg": "#fef9c3", "text": "#854d0e", "border": "#facc15", "dot": "#ca8a04"},
    "LOW":      {"bg": "#eff6ff", "text": "#1e40af", "border": "#93c5fd", "dot": "#3b82f6"},
    "INFO":     {"bg": "#f0fdf4", "text": "#166534", "border": "#86efac", "dot": "#22c55e"},
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
    summary = _compute_summary(findings)
    return {
        "meta": {
            "tool":      f"SudoSu v{version}",
            "tool_full": "Security Unified Defense & Offensive Scanning Utility",
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
    counts = {"total": len(findings), "critical": 0, "high": 0, "medium": 0, "low": 0}
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
    Écrit le rapport JSON + injecte son propre hash SHA256.
    Chain of custody : prouve l'intégrité du rapport après génération.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"sudosu_report_{timestamp}.json"

    raw = json.dumps(report, indent=2, ensure_ascii=False)
    sha = hashlib.sha256(raw.encode()).hexdigest()
    report["meta"]["report_hash"] = f"sha256:{sha}"

    final = json.dumps(report, indent=2, ensure_ascii=False)
    path.write_text(final, encoding="utf-8")
    return path


# ──────────────────────────────────────────────
# Export HTML — thème clair, design pro
# ──────────────────────────────────────────────
def save_html(report: dict, timestamp: str) -> Path:
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    path = REPORTS_DIR / f"sudosu_report_{timestamp}.html"

    meta     = report["meta"]
    summary  = report["summary"]
    findings = report["findings"]
    ts_pretty = meta.get("timestamp", "")[:19].replace("T", " ") + " UTC"

    # ── Calcul du niveau de risque global ──────────────────────────
    if summary.get("critical", 0) > 0:
        risk_label, risk_color, risk_bg = "CRITICAL", "#dc2626", "#fee2e2"
    elif summary.get("high", 0) > 0:
        risk_label, risk_color, risk_bg = "HIGH", "#ea580c", "#ffedd5"
    elif summary.get("medium", 0) > 0:
        risk_label, risk_color, risk_bg = "MEDIUM", "#ca8a04", "#fef9c3"
    else:
        risk_label, risk_color, risk_bg = "LOW", "#3b82f6", "#eff6ff"

    # ── Cartes de résumé ───────────────────────────────────────────
    cards = [
        ("CRITICAL", summary.get("critical", 0), "#dc2626", "#fee2e2"),
        ("HIGH",     summary.get("high",     0), "#ea580c", "#ffedd5"),
        ("MEDIUM",   summary.get("medium",   0), "#ca8a04", "#fef9c3"),
        ("LOW",      summary.get("low",      0), "#3b82f6", "#eff6ff"),
        ("TOTAL",    summary.get("total",    0), "#6b7280", "#f3f4f6"),
    ]
    cards_html = ""
    for label, count, color, bg in cards:
        cards_html += f"""
        <div class="card" style="background:{bg};border-color:{color}20">
          <div class="card-number" style="color:{color}">{count}</div>
          <div class="card-label" style="color:{color}cc">{label}</div>
        </div>"""

    # ── Lignes du tableau findings ─────────────────────────────────
    rows_html = ""
    if not findings:
        rows_html = '<tr><td colspan="4" class="empty">No findings detected — system appears clean.</td></tr>'
    else:
        for i, f in enumerate(findings):
            sev    = f.get("severity", "LOW").upper()
            colors = SEVERITY_COLORS.get(sev, SEVERITY_COLORS["LOW"])
            bg     = "#fafafa" if i % 2 == 0 else "#ffffff"
            mod    = f.get("module", "").replace("_", " ").replace(".", " › ")
            ts_row = f.get("timestamp", "")[:19].replace("T", " ")

            rows_html += f"""
        <tr style="background:{bg}">
          <td>
            <span class="badge"
              style="background:{colors['bg']};color:{colors['text']};border-color:{colors['border']}">
              <span class="dot" style="background:{colors['dot']}"></span>
              {sev}
            </span>
          </td>
          <td class="target-cell">
            <span class="target-path">{_esc(f.get('target', 'N/A'))}</span>
            <span class="module-tag">{_esc(mod)}</span>
          </td>
          <td class="reason-cell">{_esc(f.get('reason', ''))}</td>
          <td class="ts-cell">{_esc(ts_row)}</td>
        </tr>"""

    # ── Meta items ─────────────────────────────────────────────────
    meta_items_html = ""
    for label, key in [("Target", "target"), ("Mode", "mode"), ("OS", "os"), ("Session", "session")]:
        meta_items_html += f"""
        <div class="meta-chip">
          <span class="meta-label">{label}</span>
          <span class="meta-value">{_esc(str(meta.get(key, 'N/A')))}</span>
        </div>"""

    report_hash = meta.get("report_hash", "N/A")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>SudoSu Report — {timestamp}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=DM+Mono:wght@400;500&family=DM+Sans:wght@300;400;500;600;700&display=swap');

  *, *::before, *::after {{ box-sizing: border-box; margin: 0; padding: 0; }}

  :root {{
    --bg:        #f8f9fb;
    --surface:   #ffffff;
    --border:    #e5e7eb;
    --text:      #111827;
    --text-2:    #6b7280;
    --text-3:    #9ca3af;
    --accent:    #0f172a;
    --radius:    10px;
    --shadow:    0 1px 3px rgba(0,0,0,.08), 0 1px 2px rgba(0,0,0,.04);
    --shadow-md: 0 4px 16px rgba(0,0,0,.08), 0 2px 4px rgba(0,0,0,.04);
  }}

  body {{
    font-family: 'DM Sans', system-ui, sans-serif;
    background: var(--bg);
    color: var(--text);
    line-height: 1.6;
    padding: 0;
  }}

  /* ── Header ── */
  .header {{
    background: var(--accent);
    color: #fff;
    padding: 2.5rem 3rem 2rem;
    position: relative;
    overflow: hidden;
  }}
  .header::before {{
    content: '';
    position: absolute;
    inset: 0;
    background: repeating-linear-gradient(
      45deg,
      transparent,
      transparent 40px,
      rgba(255,255,255,.015) 40px,
      rgba(255,255,255,.015) 80px
    );
  }}
  .header-inner {{
    position: relative;
    display: flex;
    align-items: flex-start;
    justify-content: space-between;
    flex-wrap: wrap;
    gap: 1.5rem;
  }}
  .logo-area h1 {{
    font-size: 2rem;
    font-weight: 700;
    letter-spacing: .12em;
    color: #fff;
  }}
  .logo-area h1 span {{ color: #f87171; }}
  .logo-area .tagline {{
    font-size: .78rem;
    color: rgba(255,255,255,.45);
    letter-spacing: .08em;
    text-transform: uppercase;
    margin-top: .25rem;
    font-family: 'DM Mono', monospace;
  }}
  .risk-pill {{
    display: flex;
    flex-direction: column;
    align-items: flex-end;
    gap: .25rem;
  }}
  .risk-pill .risk-label {{
    font-size: .65rem;
    color: rgba(255,255,255,.4);
    text-transform: uppercase;
    letter-spacing: .1em;
  }}
  .risk-pill .risk-badge {{
    padding: .4rem 1.1rem;
    border-radius: 99px;
    font-size: .85rem;
    font-weight: 700;
    letter-spacing: .06em;
    background: {risk_bg};
    color: {risk_color};
    border: 1.5px solid {risk_color}44;
  }}
  .header-meta {{
    position: relative;
    display: flex;
    flex-wrap: wrap;
    gap: .5rem;
    margin-top: 1.5rem;
    padding-top: 1.25rem;
    border-top: 1px solid rgba(255,255,255,.1);
  }}
  .meta-chip {{
    display: flex;
    align-items: center;
    gap: .4rem;
    background: rgba(255,255,255,.07);
    border: 1px solid rgba(255,255,255,.1);
    border-radius: 6px;
    padding: .3rem .7rem;
    font-size: .78rem;
  }}
  .meta-chip .meta-label {{
    color: rgba(255,255,255,.4);
    text-transform: uppercase;
    letter-spacing: .06em;
    font-size: .65rem;
  }}
  .meta-chip .meta-value {{
    color: rgba(255,255,255,.85);
    font-family: 'DM Mono', monospace;
  }}

  /* ── Body ── */
  .body {{
    padding: 2rem 3rem 3rem;
    max-width: 1400px;
    margin: 0 auto;
  }}

  /* ── Summary Cards ── */
  .section-title {{
    font-size: .7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .1em;
    color: var(--text-2);
    margin-bottom: 1rem;
    margin-top: 2rem;
  }}
  .cards-row {{
    display: flex;
    gap: .75rem;
    flex-wrap: wrap;
    margin-bottom: .5rem;
  }}
  .card {{
    flex: 1;
    min-width: 100px;
    border-radius: var(--radius);
    border: 1.5px solid transparent;
    padding: 1.1rem 1.25rem;
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: .2rem;
    box-shadow: var(--shadow);
    transition: transform .15s, box-shadow .15s;
  }}
  .card:hover {{ transform: translateY(-2px); box-shadow: var(--shadow-md); }}
  .card-number {{
    font-size: 2.2rem;
    font-weight: 700;
    line-height: 1;
    font-family: 'DM Mono', monospace;
  }}
  .card-label {{
    font-size: .65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .1em;
  }}

  /* ── Findings Table ── */
  .table-wrapper {{
    border-radius: var(--radius);
    border: 1px solid var(--border);
    overflow: hidden;
    box-shadow: var(--shadow);
    background: var(--surface);
  }}
  table {{
    width: 100%;
    border-collapse: collapse;
    font-size: .875rem;
  }}
  thead tr {{
    background: #f9fafb;
    border-bottom: 1.5px solid var(--border);
  }}
  th {{
    padding: .75rem 1rem;
    text-align: left;
    font-size: .65rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--text-2);
    white-space: nowrap;
  }}
  td {{
    padding: .85rem 1rem;
    border-bottom: 1px solid #f3f4f6;
    vertical-align: top;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover td {{ background: #fafbff !important; }}
  .empty {{
    text-align: center;
    color: var(--text-3);
    padding: 3rem 1rem;
    font-style: italic;
  }}

  /* ── Badge ── */
  .badge {{
    display: inline-flex;
    align-items: center;
    gap: .3rem;
    padding: .25rem .65rem;
    border-radius: 6px;
    font-size: .7rem;
    font-weight: 700;
    letter-spacing: .05em;
    border: 1.5px solid transparent;
    white-space: nowrap;
    font-family: 'DM Mono', monospace;
  }}
  .dot {{
    width: 6px; height: 6px;
    border-radius: 50%;
    flex-shrink: 0;
  }}

  /* ── Table cells ── */
  .target-cell {{
    max-width: 280px;
  }}
  .target-path {{
    display: block;
    font-family: 'DM Mono', monospace;
    font-size: .78rem;
    color: var(--text);
    word-break: break-all;
    line-height: 1.4;
  }}
  .module-tag {{
    display: inline-block;
    margin-top: .3rem;
    font-size: .65rem;
    color: var(--text-3);
    background: #f3f4f6;
    border-radius: 4px;
    padding: .1rem .4rem;
    font-family: 'DM Mono', monospace;
  }}
  .reason-cell {{
    color: #374151;
    line-height: 1.5;
    max-width: 420px;
    font-size: .83rem;
  }}
  .ts-cell {{
    font-family: 'DM Mono', monospace;
    font-size: .72rem;
    color: var(--text-3);
    white-space: nowrap;
  }}

  /* ── Hash block ── */
  .hash-block {{
    margin-top: 2rem;
    background: #f9fafb;
    border: 1px solid var(--border);
    border-radius: var(--radius);
    padding: 1rem 1.25rem;
    display: flex;
    align-items: flex-start;
    gap: 1rem;
    box-shadow: var(--shadow);
  }}
  .hash-icon {{
    font-size: 1.25rem;
    flex-shrink: 0;
    margin-top: .1rem;
  }}
  .hash-content .hash-title {{
    font-size: .7rem;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: .08em;
    color: var(--text-2);
    margin-bottom: .3rem;
  }}
  .hash-value {{
    font-family: 'DM Mono', monospace;
    font-size: .75rem;
    color: #374151;
    word-break: break-all;
    line-height: 1.6;
  }}
  .hash-note {{
    font-size: .7rem;
    color: var(--text-3);
    margin-top: .3rem;
  }}

  /* ── Footer ── */
  .footer {{
    text-align: center;
    padding: 1.5rem 3rem;
    font-size: .72rem;
    color: var(--text-3);
    border-top: 1px solid var(--border);
    background: var(--surface);
    font-family: 'DM Mono', monospace;
  }}
  .footer strong {{ color: var(--text-2); }}

  @media print {{
    body {{ background: #fff; }}
    .header {{ -webkit-print-color-adjust: exact; print-color-adjust: exact; }}
    tr {{ page-break-inside: avoid; }}
  }}
</style>
</head>
<body>

<!-- ── HEADER ── -->
<div class="header">
  <div class="header-inner">
    <div class="logo-area">
      <h1>⬡ SUDO<span>SU</span></h1>
      <div class="tagline">Security Unified Defense &amp; Offensive Scanning Utility</div>
    </div>
    <div class="risk-pill">
      <div class="risk-label">Overall Risk</div>
      <div class="risk-badge">{risk_label}</div>
    </div>
  </div>
  <div class="header-meta">
    <div class="meta-chip">
      <span class="meta-label">Generated</span>
      <span class="meta-value">{_esc(ts_pretty)}</span>
    </div>
    {meta_items_html}
    <div class="meta-chip">
      <span class="meta-label">Version</span>
      <span class="meta-value">{_esc(meta.get('tool', 'SudoSu'))}</span>
    </div>
  </div>
</div>

<!-- ── BODY ── -->
<div class="body">

  <div class="section-title">Summary</div>
  <div class="cards-row">{cards_html}</div>

  <div class="section-title" style="margin-top:2rem">Findings
    <span style="font-size:.65rem;color:var(--text-3);margin-left:.5rem;text-transform:none;letter-spacing:0">
      ({summary.get('total',0)} total)
    </span>
  </div>
  <div class="table-wrapper">
    <table>
      <thead>
        <tr>
          <th style="width:110px">Severity</th>
          <th>Target / Path</th>
          <th>Reason</th>
          <th style="width:135px">Timestamp (UTC)</th>
        </tr>
      </thead>
      <tbody>{rows_html}</tbody>
    </table>
  </div>

  <!-- Chain of custody -->
  <div class="hash-block">
    <div class="hash-icon">🔒</div>
    <div class="hash-content">
      <div class="hash-title">Report Integrity — Chain of Custody</div>
      <div class="hash-value">{_esc(report_hash)}</div>
      <div class="hash-note">
        This SHA256 hash was computed on the report content at generation time.
        Any modification to the JSON report will invalidate this hash.
      </div>
    </div>
  </div>

</div>

<!-- ── FOOTER ── -->
<div class="footer">
  Generated by <strong>SudoSu v{_esc(meta.get('tool','').split('v')[-1])}</strong>
  &nbsp;·&nbsp; {_esc(ts_pretty)}
  &nbsp;·&nbsp; Built for defenders, inspired by attackers.
</div>

</body>
</html>"""

    path.write_text(html, encoding="utf-8")
    return path


def _esc(s: str) -> str:
    return str(s).replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")