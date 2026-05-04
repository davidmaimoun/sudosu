"""
utils/printer.py
----------------
Moteur visuel de SecureScope.
Toute sortie console passe par ici — jamais de print() brut ailleurs.

Concepts cyber :
  - Un outil de sécu PRO a une sortie lisible, structurée, sans ambiguïté.
  - Les couleurs ont une sémantique : rouge = danger, jaune = warning, vert = clean.
  - Le banner affiché au démarrage identifie l'outil et sa version (comme nmap, metasploit...).
"""

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich import box
from datetime import datetime

# Console globale — un seul objet partagé dans tout le projet
console = Console()

# ──────────────────────────────────────────────
# Palette sémantique
# ──────────────────────────────────────────────
COLORS = {
    "critical": "bold red",
    "warning":  "bold yellow",
    "info":     "bold cyan",
    "success":  "bold green",
    "muted":    "dim white",
    "accent":   "bold magenta",
    "neutral":  "white",
}


# ──────────────────────────────────────────────
# Banner de démarrage
# ──────────────────────────────────────────────
def print_banner(version: str = "0.1.0") -> None:
    """
    Affiche le banner ASCII + infos de lancement.
    Pourquoi ? Identifier visuellement l'outil, sa version, l'heure d'exécution.
    En forensic, l'heure de lancement fait partie de la chaîne de preuve.
    """
    ascii_art = (
        "[bold red]"
        "  _____ _   _______ _____ _____ _   _ \n"
        " /  ___| | | |  _  \\  _  /  ___| | | |\n"
        " \\ `--.| | | | | | | | | \\ `--.| | | |\n"
        "  `--. \\ | | | | | | | | |`--. \\ | | |\n"
        " /\\__/ / |_| | |/ /\\ \\_/ /\\__/ / |_| |\n"
        " \\____/ \\___/|___/  \\___/\\____/ \\___/ \n"
        "[/bold red]"
    )

    subtitle = Text.assemble(
        ("  ", ""),
        ("Security Unified Defense & Offensive Scanning Utility", "dim white"),
        ("\n  by ", "dim white"),
        ("SudoSu Labs", "bold magenta"),
        ("  ·  v", "dim white"),
        (version, "bold cyan"),
        ("  ·  ", "dim white"),
        (datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "dim yellow"),
    )

    panel = Panel(
        ascii_art + "\n" + subtitle.markup,
        border_style="red",
        padding=(0, 2),
    )
    console.print(panel)


# ──────────────────────────────────────────────
# Fonctions d'affichage sémantiques
# ──────────────────────────────────────────────
def print_critical(msg: str) -> None:
    """Menace confirmée / erreur grave."""
    console.print(f"  [bold red][ CRITICAL ][/bold red]  {msg}")


def print_warning(msg: str) -> None:
    """Comportement suspect, à investiguer."""
    console.print(f"  [bold yellow][ WARNING  ][/bold yellow]  {msg}")


def print_info(msg: str) -> None:
    """Information neutre, progression."""
    console.print(f"  [bold cyan][ INFO     ][/bold cyan]  {msg}")


def print_success(msg: str) -> None:
    """Scan terminé, fichier sain, règle appliquée."""
    console.print(f"  [bold green][ OK       ][/bold green]  {msg}")


def print_section(title: str) -> None:
    """Séparateur visuel entre les étapes du scan."""
    console.rule(f"[bold magenta]  {title}  ", style="magenta")


# ──────────────────────────────────────────────
# Résumé en tableau
# ──────────────────────────────────────────────
def print_summary_table(results: list[dict]) -> None:
    """
    Affiche un tableau récapitulatif des findings.
    results : liste de dicts avec clés -> file, severity, reason
    
    Concept cyber : un rapport de scan SOC liste toujours :
      - l'artefact trouvé (fichier, IP, processus)
      - la sévérité (Critical / High / Medium / Low)
      - la raison (pourquoi c'est suspect)
    """
    table = Table(
        title="[bold red]Scan Results[/bold red]",
        box=box.DOUBLE_EDGE,
        border_style="red",
        header_style="bold magenta",
        show_lines=True,
    )

    table.add_column("Severity",  style="bold", width=10)
    table.add_column("Path / Target", style="cyan", no_wrap=False)
    table.add_column("Reason", style="white")

    severity_colors = {
        "CRITICAL": "bold red",
        "HIGH":     "red",
        "MEDIUM":   "yellow",
        "LOW":      "dim yellow",
        "CLEAN":    "green",
    }

    for r in results:
        sev   = r.get("severity", "LOW").upper()
        color = severity_colors.get(sev, "white")
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            r.get("target", "N/A"),
            r.get("reason", ""),
        )

    console.print(table)


# ──────────────────────────────────────────────
# Progress bar réutilisable
# ──────────────────────────────────────────────
def get_progress_bar() -> Progress:
    """
    Retourne une barre de progression Rich prête à l'emploi.
    Usage (dans un with) :
        with get_progress_bar() as progress:
            task = progress.add_task("Scanning...", total=100)
            progress.advance(task)
    """
    return Progress(
        SpinnerColumn(style="bold red"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=40, style="red", complete_style="green"),
        TextColumn("[bold white]{task.percentage:>3.0f}%[/bold white]"),
        TimeElapsedColumn(),
        console=console,
    )