"""
utils/logger.py
---------------
Logging structuré de SecureScope.
Chaque action du scan est tracée : dans la console ET dans un fichier .log.

Concepts cyber :
  - En forensic, les logs sont une PREUVE. Ils doivent être :
      · Horodatés (UTC de préférence, non manipulable)
      · Persistants (fichier sur disque, pas juste console)
      · Structurés (niveau, message, contexte)
  - Un attaquant efface souvent les logs système (/var/log/).
    SecureScope crée ses propres logs dans un dossier dédié.
  - Le niveau de log (DEBUG / INFO / WARNING / ERROR / CRITICAL)
    correspond exactement aux niveaux de sévérité d'un SIEM.

Structure du fichier log :
  2026-05-04 09:54:44 UTC | INFO     | session_start | target=/tmp mode=quick
  2026-05-04 09:54:45 UTC | WARNING  | file_analyzer | /tmp/evil.sh → extension suspecte
  2026-05-04 09:54:45 UTC | CRITICAL | hash_checker  | /tmp/evil.sh → hash matches malware DB
"""

import logging
import sys
from pathlib import Path
from datetime import datetime, timezone

# Dossier où sont écrits les logs (créé automatiquement)
LOGS_DIR = Path("logs")


# ──────────────────────────────────────────────
# Formatter personnalisé — format lisible + UTC
# ──────────────────────────────────────────────
class UTCFormatter(logging.Formatter):
    """
    Formate les logs en UTC avec un séparateur pipe lisible.
    UTC est la norme en cyber pour éviter les ambiguïtés de fuseau horaire
    lors d'une investigation multi-pays (ex: incident response international).
    
    Format : 2026-05-04 09:54:44 UTC | WARNING  | file_analyzer | message
    """
    converter = lambda *args: datetime.now(timezone.utc).timetuple()

    def format(self, record: logging.LogRecord) -> str:
        dt  = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        lvl = record.levelname.ljust(8)
        mod = record.name.ljust(16)
        return f"{dt} UTC | {lvl} | {mod} | {record.getMessage()}"


# ──────────────────────────────────────────────
# Factory : crée un logger nommé par module
# ──────────────────────────────────────────────
def get_logger(name: str, log_file: Path | None = None, verbose: bool = False) -> logging.Logger:
    """
    Retourne un logger configuré pour un module donné.

    Params :
      name     → nom du module ('file_analyzer', 'network_monitor', etc.)
      log_file → chemin du fichier .log de la session (partagé entre tous les modules)
      verbose  → si True, affiche aussi DEBUG en console

    Usage :
      from utils.logger import get_logger
      log = get_logger("file_analyzer", session_log_file)
      log.info("Scanning /tmp")
      log.warning("/tmp/evil.sh → extension suspecte")
      log.critical("/tmp/evil.sh → hash matches malware DB")

    Pourquoi un logger PAR MODULE ?
      → Chaque ligne de log indique son origine exacte.
      → En investigation, on peut filtrer : grep 'network_monitor' session.log
    """
    logger = logging.getLogger(name)

    # Évite de doubler les handlers si get_logger est appelé plusieurs fois
    if logger.handlers:
        return logger

    logger.setLevel(logging.DEBUG if verbose else logging.INFO)

    formatter = UTCFormatter()

    # ── Handler console (stderr pour ne pas polluer stdout / pipes) ──
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setLevel(logging.DEBUG if verbose else logging.WARNING)
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # ── Handler fichier ─────────────────────────────────────────────
    if log_file:
        LOGS_DIR.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(log_file, encoding="utf-8")
        file_handler.setLevel(logging.DEBUG)  # Tout dans le fichier
        file_handler.setFormatter(formatter)
        logger.addHandler(file_handler)

    return logger


# ──────────────────────────────────────────────
# Génération du chemin de fichier log de session
# ──────────────────────────────────────────────
def make_session_log_path(timestamp: str) -> Path:
    """
    Retourne le chemin du fichier log pour cette session.
    Ex : logs/securescope_20260504_095444.log

    Concept forensic :
      Chaque exécution produit son propre fichier log.
      On ne surécrit jamais un log précédent.
      → Préserve l'historique des investigations.
    """
    LOGS_DIR.mkdir(parents=True, exist_ok=True)
    return LOGS_DIR / f"securescope_{timestamp}.log"