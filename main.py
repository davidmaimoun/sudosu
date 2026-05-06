"""
main.py
-------
Entry point of SecureScope.

Run:
    python main.py --help
    python main.py --target /home --mode full --output json
    python main.py --target /var/log --mode logs --verbose

Cybersecurity concepts covered here:
  - A CLI tool is the standard in security (nmap, nikto, hydra, gobuster...).
  - Execution mode defines the attack surface being analyzed.
  - --dry-run: test without modifying the system (safe for production).
  - The OS is automatically detected — different behavior on Linux vs Windows.
"""

import argparse
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path

# Visual engine import — never use print() directly here
from utils.printer import (
    print_banner,
    print_info,
    print_warning,
    print_critical,
    print_success,
    print_section,
    print_summary_table,
)
from utils.logger import get_logger, make_session_log_path
from utils.reporter import build_report, save_json, save_html
from core import (
    file_analyzer,
    hash_checker,
    process_watcher,
    network_monitor,
    log_auditor,
    firewall_advisor,
)

VERSION = "0.1.0"

# ──────────────────────────────────────────────
# OS detection
# ──────────────────────────────────────────────
def detect_os() -> str:
    """
    Returns 'linux', 'windows', or 'unsupported'.

    Why this matters in cybersecurity:
    Critical paths differ completely:
      Linux   → /etc/passwd, /var/log/auth.log, /proc/<pid>/
      Windows → C:\\Windows\\System32, HKLM registry, Event Viewer logs

    A cross-platform tool must adapt its behavior depending on the OS.
    """
    system = platform.system().lower()
    if system == "linux":
        return "linux"
    elif system == "windows":
        return "windows"
    else:
        return "unsupported"


# ──────────────────────────────────────────────
# CLI parser construction
# ──────────────────────────────────────────────
def build_parser() -> argparse.ArgumentParser:
    """
    Builds and returns the argparse parser.

    Each argument corresponds to a module we will add step by step.
    Defining all arguments upfront reflects a well-designed architecture,
    which is a sign of a mature cybersecurity engineer.
    """
    parser = argparse.ArgumentParser(
        prog="sudosu",
        description=(
            "Sudosu — Linux/Windows Security Scanner\n"
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

    # ── Target ───────────────────────────────
    parser.add_argument(
        "--target", "-t",
        type=str,
        default="/",
        metavar="PATH",
        help="Target directory to analyze (default: /).",
    )

    # ── Scan mode ────────────────────────────
    parser.add_argument(
        "--mode", "-m",
        choices=["full", "files", "network", "processes", "logs", "quick"],
        default="quick",
        help=(
            "Scan mode:\n"
            "  full      → all modules (slow)\n"
            "  files     → suspicious files + hash analysis\n"
            "  network   → open ports + active connections\n"
            "  processes → abnormal processes\n"
            "  logs      → system log auditing\n"
            "  quick     → fast check (default)\n"
        ),
    )

    # ── Output format ────────────────────────
    parser.add_argument(
        "--output", "-o",
        choices=["json", "html", "txt"],
        default="json",
        help="Report format (default: json).",
    )

    # ── Recursion depth ──────────────────────
    parser.add_argument(
        "--depth", "-d",
        type=int,
        default=5,
        metavar="N",
        help="Maximum recursion depth for directory scanning (default: 5).",
    )

    # ── Verbose mode ─────────────────────────
    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show detailed output for each analyzed file.",
    )

    # ── Dry run ──────────────────────────────
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Run analysis without writing reports or modifying system.",
    )

    # ── Force OS ─────────────────────────────
    parser.add_argument(
        "--os",
        choices=["linux", "windows"],
        default=None,
        help="Force OS mode (auto-detected by default).",
    )

    return parser


# ──────────────────────────────────────────────
# Argument validation
# ──────────────────────────────────────────────
def validate_args(args: argparse.Namespace, os_name: str) -> bool:
    """
    Validates user arguments before running the scan.
    Returns True if valid, False otherwise.

    Cyber concept: always validate user input.
    A security tool that crashes on bad input is not reliable.
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
# Session info display
# ──────────────────────────────────────────────
def print_session_info(args: argparse.Namespace, os_name: str) -> None:
    """
    Displays a session summary before scanning.

    Forensics concept: before any analysis, we document context
    (who, when, what, with which parameters). This is fundamental.
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
# Scan dispatcher (stub — built step by step)
# ──────────────────────────────────────────────
def run_scan(args: argparse.Namespace, os_name: str, log_file: Path | None = None) -> list[dict]:
    """
    Orchestrates modules based on selected mode.
    Returns a list of findings (dicts) for reporting.

    Logical pipeline by mode:
      quick     → file_analyzer only
      files     → file_analyzer → hash_checker
      processes → process_watcher
      network   → network_monitor
      logs      → log_auditor
      full      → all modules
    """
    findings = []
    print_section("Starting Scan")

    if args.mode in ("files", "full", "quick"):
        print_info("[ File Analyzer  ] Scanning files, permissions, YARA-like patterns...")
        file_findings = file_analyzer.run(
            args.target, os_name, args.depth, args.verbose, log_file
        )
        findings += file_findings
        print_success(f"File Analyzer   → {len(file_findings)} finding(s)")

    if args.mode in ("files", "full") and findings:
        print_info("[ Hash Checker   ] Computing SHA256 + VirusTotal lookup...")
        findings = hash_checker.run(findings, log_file, args.verbose)
        vt_hits = sum(1 for f in findings if "VT CONFIRMED" in f.get("reason", ""))
        print_success(f"Hash Checker    → SHA256 computed | {vt_hits} VT confirmed")

    if args.mode in ("processes", "full"):
        print_info("[ Proc Watcher   ] Scanning /proc — PIDs, UIDs, fileless, webshells...")
        proc_findings = process_watcher.run(log_file, args.verbose)
        findings += proc_findings
        print_success(f"Proc Watcher    → {len(proc_findings)} finding(s)")

    if args.mode in ("network", "full"):
        print_info("[ Net Monitor    ] Scanning /proc/net/tcp — ports, C2, reverse shells...")
        net_findings = network_monitor.run(log_file, args.verbose)
        findings += net_findings
        print_success(f"Net Monitor     → {len(net_findings)} finding(s)")

    if args.mode in ("network", "full"):
        print_info("[ FW Advisor     ] Analyzing firewall config + generating rules...")
        fw_findings = firewall_advisor.run(findings, log_file, args.verbose)
        findings += fw_findings
        print_success(f"FW Advisor      → {len(fw_findings)} recommendation(s)")

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
    args = parser.parse_args()

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")

    print_banner(VERSION)

    os_name = args.os if args.os else detect_os()

    if not validate_args(args, os_name):
        sys.exit(1)

    log_file = None if args.dry_run else make_session_log_path(timestamp)
    log = get_logger("main", log_file, args.verbose)
    log.info(f"Session start | target={args.target} mode={args.mode} os={os_name}")

    print_session_info(args, os_name)

    findings = run_scan(args, os_name, log_file)

    print_section("Scan Complete")
    print_summary_table(findings)
    print_success(f"{len(findings)} finding(s) recorded.")


if __name__ == "__main__":
    main()