"""
main.py
-------
Point d'entrée de SecureScope.

Lance : python main.py --help
        python main.py --target /home --mode full --output json
        python main.py --target /var/log --mode logs --verbose

Concepts cyber couverts ici :
  - Un outil CLI est la norme en sécu (nmap, nikto, hydra, gobuster...).
  - Le mode d'exécution définit la surface d'attaque analysée.
  - --dry-run : tester sans modifier le système (safe pour la prod).
  - L'OS est détecté automatiquement — comportement différent Linux vs Windows.
"""

import argparse
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

# On importe notre moteur visuel — jamais de print() ici
from utils.printer import (
    print_banner,
    print_info,
    print_warning,
    print_critical,
    print_success,
    print_section,
    print_summary_table,
)
from utils.logger   import get_logger, make_session_log_path
from utils.reporter import build_report, save_json, save_html
from core           import file_analyzer, hash_checker, process_watcher, network_monitor, log_auditor

VERSION = "0.1.0"

# ──────────────────────────────────────────────
# Détection OS
# ──────────────────────────────────────────────
def detect_os() -> str:
    """
    Retourne 'linux', 'windows' ou 'unsupported'.
    
    Pourquoi c'est important en cyber ?
    Les chemins critiques diffèrent totalement :
      Linux  → /etc/passwd, /var/log/auth.log, /proc/<pid>/
      Windows → C:\\Windows\\System32, HKLM registry, Event Viewer logs
    Un outil multi-OS doit adapter ses cibles selon le système.
    """
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    else:
        return "unsupported"


# ──────────────────────────────────────────────
# Construction du parser CLI
# ──────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    """
    Construit et retourne le parser argparse.
    
    Chaque argument correspond à un module qu'on ajoutera step by step.
    Avoir tous les args dès le départ = architecture pensée en amont,
    ce qui montre la maturité d'un dev cyber pro.
    """
    parser = argparse.ArgumentParser(
        prog="securescope",
        description=(
            "SecureScope — Linux/Windows Security Scanner\n"
            "Forensic file analysis, threat detection, network monitoring."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Examples:\n"
            "  python main.py --target /home --mode full\n"
            "  python main.py --target /var/log --mode logs --verbose\n"
            "  python main.py --target /tmp --mode files --output json --dry-run\n"
        ),
    )

    # ── Cible ───────────────────────────────
    parser.add_argument(
        "--target", "-t",
        type=str,
        default="/",
        metavar="PATH",
        help="Répertoire cible à analyser (défaut: /).",
    )

    # ── Mode de scan ────────────────────────
    parser.add_argument(
        "--mode", "-m",
        choices=["full", "files", "network", "processes", "logs", "quick"],
        default="quick",
        help=(
            "Mode de scan :\n"
            "  full      → tous les modules (long)\n"
            "  files     → analyse fichiers suspects + hash\n"
            "  network   → ports ouverts + connexions actives\n"
            "  processes → processus anormaux\n"
            "  logs      → audit des logs système\n"
            "  quick     → check rapide (défaut)\n"
        ),
    )

    # ── Format de rapport ───────────────────
    parser.add_argument(
        "--output", "-o",
        choices=["json", "html", "txt"],
        default="json",
        help="Format du rapport généré dans report_<timestamp>.<ext> (défaut: json).",
    )

    # ── Profondeur de récursion ──────────────
    parser.add_argument(
        "--depth", "-d",
        type=int,
        default=5,
        metavar="N",
        help="Profondeur max de récursion dans les dossiers (défaut: 5).",
    )

    # ── Mode verbeux ────────────────────────
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Affiche les détails de chaque fichier analysé.",
    )

    # ── Dry-run ─────────────────────────────
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Analyse sans écrire de rapport ni modifier le système.",
    )

    # ── Forcer un OS ────────────────────────
    parser.add_argument(
        "--os",
        choices=["linux", "windows"],
        default=None,
        help="Forcer le mode OS (détection auto par défaut).",
    )

    return parser


# ──────────────────────────────────────────────
# Validation des arguments
# ──────────────────────────────────────────────
def validate_args(args: argparse.Namespace, os_name: str) -> bool:
    """
    Vérifie la cohérence des arguments avant de lancer le scan.
    Retourne True si tout est OK, False sinon.
    
    Concept cyber : toujours valider les entrées utilisateur.
    Un outil de sécu qui plante sur une mauvaise entrée n'est pas fiable.
    """
    target = Path(args.target)

    if not target.exists():
        print_critical(f"Target path does not exist: {args.target}")
        return False

    if not target.is_dir():
        print_critical(f"Target must be a directory, not a file: {args.target}")
        return False

    if os_name == "unsupported":
        print_warning("Unsupported OS detected. Behavior may be unpredictable.")

    if args.mode in ("logs", "full") and os_name == "linux":
        log_path = Path("/var/log")
        if not log_path.exists():
            print_warning("/var/log not found — log audit will be skipped.")

    return True


# ──────────────────────────────────────────────
# Affichage de la config de session
# ──────────────────────────────────────────────
def print_session_info(args: argparse.Namespace, os_name: str) -> None:
    """
    Affiche un résumé de la session avant le scan.
    
    Concept forensic : avant toute analyse, on documente le contexte
    (qui, quand, quoi, avec quels paramètres). C'est la base d'un rapport d'investigation.
    """
    print_section("Session Configuration")
    print_info(f"OS detected   : {os_name.upper()}")
    print_info(f"Target        : {args.target}")
    print_info(f"Mode          : {args.mode}")
    print_info(f"Output format : {args.output}")
    print_info(f"Max depth     : {args.depth}")
    print_info(f"Verbose       : {args.verbose}")
    print_info(f"Dry-run       : {args.dry_run}")
    print_info(f"Timestamp     : {datetime.now().strftime('%Y%m%d_%H%M%S')}")


# ──────────────────────────────────────────────
# Dispatcher des modes (stub — sera rempli step by step)
# ──────────────────────────────────────────────
def run_scan(args: argparse.Namespace, os_name: str, log_file: Path | None = None) -> list[dict]:
    """
    Orchestre les modules selon le mode choisi.
    Retourne une liste de findings (dicts) pour le rapport.

    Pipeline logique par mode :
      quick     → file_analyzer uniquement (rapide, pas de VT ni réseau)
      files     → file_analyzer → hash_checker (VT si clé dispo)
      processes → process_watcher
      network   → network_monitor
      logs      → log_auditor
      full      → tous les modules dans l'ordre
    """
    findings = []
    print_section("Starting Scan")

    # ── Module 1 : File Analyzer ─────────────────────────────────────
    # Tous les modes sauf 'network', 'processes', 'logs' seuls
    if args.mode in ("files", "full", "quick"):
        print_info("[ File Analyzer  ] Scanning files, permissions, YARA-like patterns...")
        file_findings = file_analyzer.run(
            args.target, os_name, args.depth, args.verbose, log_file
        )
        findings += file_findings
        print_success(f"File Analyzer   → {len(file_findings)} finding(s)")

    # ── Module 2 : Hash Checker ──────────────────────────────────────
    # Chaîné APRÈS file_analyzer — enrichit ses findings avec SHA256 + VT.
    # Pas en mode 'quick' (VT = réseau + rate limit = trop lent pour un check rapide).
    if args.mode in ("files", "full") and findings:
        print_info("[ Hash Checker   ] Computing SHA256 + VirusTotal lookup...")
        findings = hash_checker.run(findings, log_file, args.verbose)
        vt_hits  = sum(1 for f in findings if "VT CONFIRMED" in f.get("reason", ""))
        print_success(f"Hash Checker    → SHA256 computed | {vt_hits} VT confirmed")

    # ── Module 3 : Process Watcher ───────────────────────────────────
    # Indépendant du target — scanne tous les processus actifs via /proc.
    if args.mode in ("processes", "full"):
        print_info("[ Proc Watcher   ] Scanning /proc — PIDs, UIDs, fileless, webshells...")
        proc_findings = process_watcher.run(log_file, args.verbose)
        findings += proc_findings
        print_success(f"Proc Watcher    → {len(proc_findings)} finding(s)")

    # ── Module 4 : Network Monitor ───────────────────────────────────
    # Indépendant du target — lit /proc/net/tcp directement.
    if args.mode in ("network", "full"):
        print_info("[ Net Monitor    ] Scanning /proc/net/tcp — ports, C2, reverse shells...")
        net_findings = network_monitor.run(log_file, args.verbose)
        findings += net_findings
        print_success(f"Net Monitor     → {len(net_findings)} finding(s)")

    # ── Module 5 : Log Auditor ───────────────────────────────────────
    if args.mode in ("logs", "full"):
        print_info("[ Log Auditor    ] Parsing auth.log, syslog, kern.log, cron.log...")
        log_findings = log_auditor.run(log_file, args.verbose)
        findings += log_findings
        print_success(f"Log Auditor     → {len(log_findings)} finding(s)")

    return findings


# ──────────────────────────────────────────────
# Main
# ──────────────────────────────────────────────
def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Timestamp unique pour cette session — partagé par logs + rapports
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    # 1. Banner
    print_banner(VERSION)

    # 2. Détection OS
    os_name = args.os if args.os else detect_os()

    # 3. Validation
    if not validate_args(args, os_name):
        sys.exit(1)

    # 4. Logger de session (écrit dans logs/securescope_<timestamp>.log)
    log_file = None if args.dry_run else make_session_log_path(timestamp)
    log = get_logger("main", log_file, args.verbose)
    log.info(f"Session start | target={args.target} mode={args.mode} os={os_name}")

    # 5. Info de session
    print_session_info(args, os_name)

    # 6. Scan
    findings = run_scan(args, os_name, log_file)
    log.info(f"Scan complete | {len(findings)} finding(s)")

    # 7. Résumé console
    print_section("Scan Complete")
    print_summary_table(findings)
    print_success(f"{len(findings)} finding(s) recorded.")

    # 8. Rapport
    if args.dry_run:
        print_warning("Dry-run mode — no report written.")
        log.info("Dry-run: report skipped")
    else:
        report = build_report(findings, args.target, args.mode, os_name, timestamp, VERSION)

        json_path = save_json(report, timestamp)
        print_success(f"JSON report → {json_path}")
        log.info(f"Report saved | {json_path}")

        if args.output == "html":
            html_path = save_html(report, timestamp)
            print_success(f"HTML report → {html_path}")
            log.info(f"HTML report saved | {html_path}")

    if log_file:
        print_info(f"Session log  → {log_file}")


if __name__ == "__main__":
    main()