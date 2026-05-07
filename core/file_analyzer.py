"""
core/file_analyzer.py
---------------------
Module d'analyse statique de fichiers.
Détecte les fichiers suspects par : extension, permissions, contenu (YARA-like),
nom de fichier, emplacement dans un dossier à risque, modification récente.

Concepts cyber couverts :
  - Analyse statique : examiner un fichier SANS l'exécuter.
    (≠ analyse dynamique qui l'exécute dans un sandbox)
    Avantage : sûr, rapide, pas de risque d'infection.
    Limite : un malware obfusqué peut passer entre les mailles.

  - IOC (Indicator of Compromise) : on cherche des indices, pas des certitudes.
    Un fichier .sh dans /tmp n'est pas forcément malveillant —
    mais c'est un IOC qui mérite investigation.

  - SUID bit (Set User ID) : si un exécutable a ce bit et appartient à root,
    n'importe quel user peut l'exécuter AVEC LES DROITS ROOT.
    C'est la technique de privilege escalation #1 sur Linux.
    Commande pour trouver tous les SUID : find / -perm -4000 2>/dev/null

  - World-writable : permission 0o2 (autres peuvent écrire).
    Si un script world-writable est lancé par une cron root → RCE garanti.

  - Parallelisation avec concurrent.futures.ThreadPoolExecutor :
    Analyser des milliers de fichiers séquentiellement = trop lent.
    On distribue l'analyse sur N threads (I/O-bound task → threads > processes).

  - Read des premiers 8Ko seulement : les malwares mettent leur payload
    dès le début. Lire 8Ko sur un fichier de 2Go = performance x1000.

Structure d'un finding retourné :
  {
    "severity":  "HIGH",
    "target":    "/tmp/evil.sh",
    "reason":    "Dangerous extension in high-risk dir + SUID bit set",
    "timestamp": "2026-05-04T10:05:00Z",
    "module":    "file_analyzer",
    "details": {
        "size_bytes":  4096,
        "permissions": "rwsr-xr-x",
        "owner":       "root",
        "modified_ago_hours": 2.3,
        "matched_patterns": ["reverse_shell_bash"]
    }
  }
"""

import os
import stat
import pwd
import grp
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Generator

from config.patterns import (
    DANGEROUS_EXTENSIONS_LINUX,
    DANGEROUS_EXTENSIONS_WINDOWS,
    DOUBLE_EXTENSION_PATTERNS,
    ARCHIVE_EXTENSIONS,
    HIGH_RISK_DIRS_LINUX,
    CRITICAL_SYSTEM_FILES_LINUX,
    CONTENT_PATTERNS,
    SUSPICIOUS_FILENAMES,
    RECENT_MODIFICATION_HOURS,
)
from utils.logger import get_logger

# Taille max lue pour l'analyse de contenu (8 Ko)
MAX_READ_BYTES = 8_192

# Nombre de threads
THREAD_WORKERS = 8

# ──────────────────────────────────────────────────────────────────────────────
# WHITELIST — fichiers et chemins à ne JAMAIS analyser
#
# Ces fichiers génèrent massivement de faux positifs car ils contiennent
# des signatures binaires, des définitions MIME, ou du code stdlib légitime
# qui ressemble superficiellement à des patterns suspects.
#
# Catégories :
#   1. Bases de données MIME/Magic — contiennent des signatures de fichiers
#      (bytes magiques) qui ressemblent à des payloads
#   2. Bibliothèques Python stdlib — contiennent le mot "password" dans
#      urllib, http.client... mais ce sont des noms de paramètres, pas des secrets
#   3. Caches navigateur dans /tmp — Chrome/Chromium crée des caches
#      temporaires légitimes (WebGPU, réseau, certificats...)
#   4. Fichiers de définition GnuPG/Crypto — contiennent des clés exemples
# ──────────────────────────────────────────────────────────────────────────────

# Préfixes de chemins à exclure entièrement de l'analyse de contenu
# (on vérifie quand même les permissions, mais pas le contenu)
SKIP_CONTENT_PATH_PREFIXES = (
    "/usr/share/mime/",          # définitions MIME (faux positifs "private key")
    "/usr/lib/file/",            # magic database
    "/usr/share/file/",          # magic database
    "/usr/lib/python",           # Python stdlib (urllib, http... contiennent "password")
    "/usr/lib/python2",          # Python 2 legacy
    "/usr/lib/python3",          # Python 3
    "/usr/local/lib/python",     # Python local
    "/usr/share/doc/",           # documentation
    "/usr/share/man/",           # man pages
    "/usr/share/locale/",        # traductions
    "/usr/share/gnupg/",         # GnuPG exemples
    "/usr/share/ca-certificates/",# certificats système
)

# Suffixes de fichiers à exclure de l'analyse de contenu
SKIP_CONTENT_EXTENSIONS = {
    ".mgc",   # magic compiled database
    ".xml",   # définitions XML (MIME, GConf...)
    ".po",    # fichiers de traduction
    ".mo",    # traductions compilées
    ".pyc",   # bytecode Python compilé (faux positifs constants)
    ".pyo",   # optimized bytecode
}

# Noms de fichiers Chrome/Chromium dans /tmp — comportement normal du navigateur
# Chrome crée des dossiers temporaires dans /tmp pour son cache, ses composants...
CHROMIUM_TEMP_PATTERNS = (
    ".org.chromium.", ".org.chromium", "chromium",
    "chrome_", "google-chrome",
    "CrashpadMetrics", "crashpad",
    "DawnWebGPU", "GraphiteDawn", "ShaderCache",
    "Network Persistent State", "shared_proto_db",
    "CertificateRevocation", "component_crx_cache",
    "chrome_debug.log",
)


# ──────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────
def run(
    target:   str,
    os_name:  str,
    depth:    int,
    verbose:  bool,
    log_file: Path | None = None,
) -> list[dict]:
    """
    Lance l'analyse complète du répertoire target.
    Retourne une liste de findings.

    Params :
      target  → chemin racine à analyser
      os_name → 'linux' ou 'windows' (adapte les patterns)
      depth   → profondeur max de récursion
      verbose → log détaillé
      log_file → chemin du fichier log de session
    """
    log = get_logger("file_analyzer", log_file, verbose)
    log.info(f"Starting file analysis | target={target} depth={depth}")

    dangerous_ext = (
        DANGEROUS_EXTENSIONS_LINUX if os_name == "linux"
        else DANGEROUS_EXTENSIONS_WINDOWS
    )

    # Collecte des fichiers à analyser (générateur pour économiser la RAM)
    files = list(_walk_files(Path(target), depth))
    log.info(f"Files discovered: {len(files)}")

    findings: list[dict] = []

    # ── Analyse en parallèle ────────────────────────────────────────
    # ThreadPoolExecutor : pool de threads réutilisables.
    # as_completed() retourne les résultats au fur et à mesure (pas dans l'ordre).
    # Concept : I/O-bound tasks (lecture disque) → threads plus efficaces que processes.
    with ThreadPoolExecutor(max_workers=THREAD_WORKERS) as executor:
        future_to_path = {
            executor.submit(_analyze_file, f, dangerous_ext, os_name, log): f
            for f in files
        }

        for future in as_completed(future_to_path):
            result = future.result()
            if result:
                findings.append(result)
                log.warning(
                    f"Finding [{result['severity']}] {result['target']} | {result['reason']}"
                )

    # ── Vérification des fichiers système critiques (Linux) ─────────
    if os_name == "linux":
        for finding in _check_critical_system_files(log):
            findings.append(finding)

    log.info(f"File analysis complete | {len(findings)} finding(s)")
    return findings


# ──────────────────────────────────────────────
# Générateur de fichiers (walk récursif limité)
# ──────────────────────────────────────────────
def _walk_files(root: Path, max_depth: int) -> Generator[Path, None, None]:
    """
    Parcourt récursivement root jusqu'à max_depth et yield les fichiers.

    Pourquoi un générateur (yield) plutôt qu'une liste ?
    → Ne charge pas tous les chemins en RAM d'un coup.
    → Sur un scan de / avec depth=10, on peut avoir 100k+ fichiers.
    → Le générateur les traite un à un → empreinte mémoire constante.

    Pourquoi limiter la profondeur ?
    → Éviter les boucles infinies sur les symlinks (lien symbolique → /proc/self/…)
    → Contrôler la durée du scan
    """
    try:
        for entry in root.iterdir():
            try:
                if entry.is_symlink():
                    # On ne suit pas les symlinks pour éviter les boucles
                    # Un attaquant peut créer un symlink vers / pour faire boucler le scan
                    continue
                if entry.is_file():
                    yield entry
                elif entry.is_dir() and max_depth > 1:
                    yield from _walk_files(entry, max_depth - 1)
            except PermissionError:
                # Dossier root-only — normal, on skip silencieusement
                pass
            except OSError:
                pass
    except PermissionError:
        pass
    except OSError:
        pass


# ──────────────────────────────────────────────
# Analyse d'un fichier individuel
# ──────────────────────────────────────────────
def _analyze_file(
    path: Path,
    dangerous_ext: set[str],
    os_name: str,
    log,
) -> dict | None:
    """
    Analyse un fichier selon plusieurs heuristiques.
    Retourne un finding dict si suspect, None si clean.

    Les heuristiques sont appliquées dans l'ordre du moins cher au plus cher :
      1. Nom de fichier (O(1))
      2. Extension (O(1))
      3. Emplacement (O(1))
      4. Permissions stat (1 syscall)
      5. Modification récente (1 syscall)
      6. Contenu 8Ko (1 read)
    Dès qu'on a CRITICAL, on arrête — pas besoin d'analyser davantage.
    """
    try:
        stat_info   = path.stat()
        size_bytes  = stat_info.st_size
        mode        = stat_info.st_mode
        mtime       = stat_info.st_mtime
    except (PermissionError, OSError):
        return None

    # Skip les fichiers vides et les très gros (>50Mo → trop lent à lire)
    if size_bytes == 0 or size_bytes > 50 * 1024 * 1024:
        return None

    path_str = str(path)
    suffix   = path.suffix.lower()   # défini ici pour les whitelists ci-dessous

    # Skip les caches Chromium dans /tmp — comportement normal du navigateur
    if any(pat in path_str for pat in CHROMIUM_TEMP_PATTERNS):
        return None

    # Flag pour désactiver l'analyse de contenu sur certains chemins/extensions
    # (on garde les checks de permissions, pas le scan de contenu)
    skip_content_scan = (
        path_str.startswith(SKIP_CONTENT_PATH_PREFIXES) or
        suffix in SKIP_CONTENT_EXTENSIONS
    )

    reasons:  list[str] = []
    severity: str = "LOW"
    details:  dict = {"size_bytes": size_bytes}

    # ── 1. Nom suspect ──────────────────────────────────────────────
    for sus_name in SUSPICIOUS_FILENAMES:
        if sus_name.lower() in path.name.lower():
            reasons.append(f"Suspicious filename match: '{sus_name}'")
            severity = _escalate(severity, "HIGH")
            break

    # ── 2. Double extension ─────────────────────────────────────────
    # Technique de camouflage : rapport.pdf.exe affiché comme PDF
    name_lower = path.name.lower()
    for pattern in DOUBLE_EXTENSION_PATTERNS:
        if name_lower.endswith(pattern):
            reasons.append(f"Double extension detected: {pattern}")
            severity = _escalate(severity, "HIGH")

    # ── 3. Extension dangereuse ─────────────────────────────────────
    if suffix in dangerous_ext:
        reasons.append(f"Dangerous extension: {suffix}")
        severity = _escalate(severity, "MEDIUM")

    # ── 4. Emplacement à risque (Linux) ─────────────────────────────
    if os_name == "linux":
        path_str = str(path)
        for risk_dir in HIGH_RISK_DIRS_LINUX:
            if path_str.startswith(risk_dir):
                reasons.append(f"Located in high-risk directory: {risk_dir}")
                severity = _escalate(severity, "MEDIUM")
                break

    # ── 5. Permissions suspectes (Linux) ────────────────────────────
    if os_name == "linux":
        perm_str, perm_issues = _check_permissions(path, mode, stat_info)
        details["permissions"] = perm_str
        for issue, sev in perm_issues:
            reasons.append(issue)
            severity = _escalate(severity, sev)

    # ── 6. Modification récente ─────────────────────────────────────
    now_ts     = datetime.now(timezone.utc).timestamp()
    age_hours  = (now_ts - mtime) / 3600
    details["modified_ago_hours"] = round(age_hours, 1)

    if age_hours <= RECENT_MODIFICATION_HOURS and (suffix in dangerous_ext or reasons):
        reasons.append(f"Recently modified ({age_hours:.1f}h ago)")
        severity = _escalate(severity, "MEDIUM")

    # ── 7. Analyse de contenu (YARA-like) ───────────────────────────
    # Ignorée pour les fichiers système (mime, magic, python stdlib...)
    # qui génèrent des faux positifs massifs.
    if size_bytes > 0 and not skip_content_scan:
        matched = _scan_content(path)
        if matched:
            details["matched_patterns"] = [m[0] for m in matched]
            for rule_name, rule_sev in matched:
                reasons.append(f"Content pattern matched: {rule_name}")
                severity = _escalate(severity, rule_sev)

    # ── Résultat ─────────────────────────────────────────────────────
    if not reasons:
        return None

    # Anti-bruit : exige au moins 2 IOC pour sévérité MEDIUM,
    # ou 1 signal suffisant pour HIGH/CRITICAL.
    # Concept SOC : réduire les faux positifs en exigeant convergence.
    # Un seul fichier .js dans /tmp sans rien d'autre = bruit, pas un IOC.
    if _SEV_RANK.get(severity, 0) < _SEV_RANK["HIGH"] and len(reasons) < 2:
        return None


    # Récupère le propriétaire du fichier
    try:
        details["owner"] = pwd.getpwuid(stat_info.st_uid).pw_name
    except (KeyError, AttributeError):
        details["owner"] = str(stat_info.st_uid)

    return {
        "severity":  severity,
        "target":    str(path),
        "reason":    " | ".join(reasons),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module":    "file_analyzer",
        "details":   details,
    }


# ──────────────────────────────────────────────
# Vérification des permissions Linux
# ──────────────────────────────────────────────
def _check_permissions(path: Path, mode: int, stat_info) -> tuple[str, list[tuple[str, str]]]:
    """
    Retourne (permission_string, list of (issue, severity)).

    SUID bit (4000) : exécution avec les droits du propriétaire.
      Si owner=root et SUID set → n'importe quel user devient root pendant l'exécution.
      C'est la base de la privilege escalation via GTFObins.

    SGID bit (2000) : exécution avec les droits du groupe.
      Moins critique mais peut quand même mener à une escalade.

    Sticky bit (1000) : sur un dossier → seul le propriétaire peut supprimer ses fichiers.
      Sur un fichier (rare) → comportement legacy, souvent une erreur de config.

    World-writable (0o2) : tout le monde peut écrire dans ce fichier.
      Un script world-writable appelé par un cron root = RCE immédiat.
    """
    issues: list[tuple[str, str]] = []

    # Format lisible des permissions (ex: rwsr-xr-x)
    perm_str = stat.filemode(mode)

    # SUID bit
    if mode & stat.S_ISUID:
        try:
            owner = pwd.getpwuid(stat_info.st_uid).pw_name
        except KeyError:
            owner = str(stat_info.st_uid)
        sev = "CRITICAL" if owner == "root" else "HIGH"
        issues.append((f"SUID bit set (owner: {owner}) → potential privilege escalation", sev))

    # SGID bit
    if mode & stat.S_ISGID:
        issues.append(("SGID bit set → group privilege execution", "MEDIUM"))

    # World-writable
    if mode & stat.S_IWOTH:
        issues.append(("World-writable file → anyone can modify content", "HIGH"))

    return perm_str, issues


# ──────────────────────────────────────────────
# Scan de contenu YARA-like
# ──────────────────────────────────────────────
def _scan_content(path: Path) -> list[tuple[str, str]]:
    """
    Lit les premiers MAX_READ_BYTES du fichier et applique tous les patterns.
    Retourne la liste des (rule_name, severity) qui matchent.

    Pourquoi bytes et pas str ?
    → Les malwares peuvent avoir des encodages exotiques (latin-1, utf-16…).
    → Lire en bytes bruts est universel et plus rapide.
    → Les regex sont compilées avec le flag re.IGNORECASE.

    Pourquoi 8Ko ?
    → Un shebang, un header de script, une clé hardcodée :
      tout ça se trouve dans les premières lignes.
    → 8Ko = ~200 lignes de code → largement suffisant pour les patterns.
    → Multiplié par des milliers de fichiers → économie de RAM significative.
    """
    try:
        with open(path, "rb") as f:
            data = f.read(MAX_READ_BYTES)
    except (PermissionError, OSError, IsADirectoryError):
        return []

    matched = []
    for rule_name, pattern, severity in CONTENT_PATTERNS:
        if pattern.search(data):
            matched.append((rule_name, severity))

    return matched


# ──────────────────────────────────────────────
# Vérification des fichiers système critiques
# ──────────────────────────────────────────────
def _check_critical_system_files(log) -> list[dict]:
    """
    Vérifie si les fichiers système critiques ont été modifiés récemment.

    Concept : un attaquant qui a compromis un système va souvent modifier :
      - /etc/passwd  → pour ajouter un compte backdoor
      - /etc/sudoers → pour s'accorder des droits root sans mot de passe
      - /etc/crontab → pour persister via une tâche planifiée
      - /root/.ssh/authorized_keys → pour un accès SSH permanent

    Si ces fichiers ont été touchés dans les dernières 24h sans maintenance
    prévue → IOC fort. C'est ce que vérifie cette fonction.
    """
    findings = []
    now_ts   = datetime.now(timezone.utc).timestamp()

    for filepath in CRITICAL_SYSTEM_FILES_LINUX:
        p = Path(filepath)
        if not p.exists():
            continue
        try:
            st        = p.stat()
            age_hours = (now_ts - st.st_mtime) / 3600
            if age_hours <= RECENT_MODIFICATION_HOURS:
                findings.append({
                    "severity":  "HIGH",
                    "target":    filepath,
                    "reason":    f"Critical system file modified {age_hours:.1f}h ago — possible backdoor",
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "module":    "file_analyzer",
                    "details":   {
                        "modified_ago_hours": round(age_hours, 1),
                        "permissions": stat.filemode(st.st_mode),
                    },
                })
                log.warning(f"Critical system file modified: {filepath} ({age_hours:.1f}h ago)")
        except (PermissionError, OSError):
            pass

    return findings


# ──────────────────────────────────────────────
# Utilitaire : escalade de sévérité
# ──────────────────────────────────────────────
_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def _escalate(current: str, candidate: str) -> str:
    """
    Retourne la sévérité la plus haute entre current et candidate.
    On ne descend jamais la sévérité — un fichier qui a plusieurs
    red flags garde la sévérité maximale.
    """
    return candidate if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0) else current