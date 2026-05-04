"""
config/patterns.py
------------------
Base de signatures utilisée par le File Analyzer.
C'est l'équivalent simplifié d'une base de règles YARA ou Snort.

Concepts cyber :
  - IOC (Indicator of Compromise) : tout artefact observable qui indique
    une compromission potentielle. Peut être un hash, une extension,
    une chaîne de caractères, une IP, un nom de domaine.
  - YARA : outil standard en malware analysis pour écrire des règles
    de détection basées sur des patterns (strings, regex, conditions).
    Ex: rule detect_webshell { strings: $s = "eval(base64_decode" condition: $s }
  - SUID bit : permission Linux qui permet d'exécuter un fichier
    avec les droits du propriétaire (souvent root). Très exploité
    pour la privilege escalation (GTFObins).
  - World-writable : fichier modifiable par n'importe quel utilisateur.
    Si un script world-writable est exécuté par cron en root → RCE.

Ce fichier est la SEULE source de vérité pour les patterns.
Ajouter une nouvelle signature ici suffit — aucun autre fichier à modifier.
"""

# ──────────────────────────────────────────────
# Extensions de fichiers suspects
# ──────────────────────────────────────────────

# Exécutables Linux dangereux dans des dossiers world-writable (/tmp, /dev/shm)
DANGEROUS_EXTENSIONS_LINUX = {
    ".sh", ".bash", ".zsh", ".ksh",   # scripts shell
    ".py", ".pl", ".rb", ".php",       # scripts interprétés
    ".elf",                            # binaire ELF Linux
    ".so",                             # shared object (bibliothèque dynamique)
    ".out",                            # binaire compilé générique
}

# Exécutables Windows suspects
DANGEROUS_EXTENSIONS_WINDOWS = {
    ".exe", ".bat", ".cmd", ".ps1",    # exécutables classiques
    ".vbs", ".js", ".jse", ".wsf",    # scripts Windows Script Host
    ".scr", ".pif", ".com",           # déguisements d'exécutables
    ".hta",                            # HTML Application (exécutable via mshta)
    ".dll",                            # bibliothèque dynamique
}

# Extensions qui CACHENT souvent un exécutable (double extension)
# Ex: rapport_confidentiel.pdf.exe  →  affiché comme PDF, exécuté comme EXE
DOUBLE_EXTENSION_PATTERNS = [
    ".pdf.exe", ".pdf.sh", ".doc.exe", ".jpg.exe",
    ".png.sh",  ".txt.py", ".csv.py",  ".zip.exe",
]

# Fichiers compressés/chiffrés — souvent utilisés pour exfiltration ou staging
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".gz", ".7z", ".rar", ".bz2", ".xz"}

# ──────────────────────────────────────────────
# Dossiers à risque élevé (Linux)
# ──────────────────────────────────────────────
# Ces dossiers sont world-writable : n'importe quel user peut y écrire.
# Un attaquant y dépose souvent ses outils après intrusion.
HIGH_RISK_DIRS_LINUX = {
    "/tmp",
    "/var/tmp",
    "/dev/shm",      # RAM filesystem, volatile, favori des malwares "fileless"
    "/run/shm",
    "/proc/self",
}

# ──────────────────────────────────────────────
# Fichiers système critiques (Linux)
# ──────────────────────────────────────────────
# Si ces fichiers sont modifiés récemment sans raison → compromission probable.
CRITICAL_SYSTEM_FILES_LINUX = [
    "/etc/passwd",           # comptes utilisateurs
    "/etc/shadow",           # hashes de mots de passe
    "/etc/sudoers",          # droits sudo
    "/etc/crontab",          # tâches planifiées système
    "/etc/hosts",            # résolution DNS locale (peut être poisonné)
    "/etc/ld.so.preload",    # LD_PRELOAD global — rootkit classique
    "/root/.bashrc",
    "/root/.bash_history",
    "/root/.ssh/authorized_keys",
]

# ──────────────────────────────────────────────
# Patterns de contenu suspects (YARA-like)
# ──────────────────────────────────────────────
# Chaque entrée : (nom_de_la_règle, regex_pattern, sévérité)
# On cherche ces patterns dans les premiers Ko du fichier (pas lecture complète).
#
# Pourquoi limiter aux premiers Ko ?
#   - Performance : pas de lecture de fichiers de plusieurs Go
#   - Les malwares mettent souvent leur payload au début
#   - Les webshells ont leur code d'activation en en-tête

import re

CONTENT_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    # ── Webshells ─────────────────────────────────────────────────────
    (
        "webshell_eval_base64",
        re.compile(rb"eval\s*\(\s*base64_decode", re.IGNORECASE),
        "CRITICAL",
    ),
    (
        "webshell_passthru",
        re.compile(rb"passthru\s*\(\s*\$_(GET|POST|REQUEST)", re.IGNORECASE),
        "CRITICAL",
    ),
    (
        "webshell_system_cmd",
        re.compile(rb"system\s*\(\s*\$_(GET|POST|REQUEST)", re.IGNORECASE),
        "CRITICAL",
    ),

    # ── Reverse shells ────────────────────────────────────────────────
    (
        "reverse_shell_bash",
        re.compile(rb"bash\s+-i\s+>&\s*/dev/tcp/", re.IGNORECASE),
        "CRITICAL",
    ),
    (
        "reverse_shell_python",
        re.compile(rb"socket\.connect\s*\(\s*\(['\"][\d\.]+['\"],\s*\d+\)", re.IGNORECASE),
        "HIGH",
    ),
    (
        "reverse_shell_nc",
        re.compile(rb"nc\s+(-e|-c)\s+/bin/(sh|bash)", re.IGNORECASE),
        "HIGH",
    ),

    # ── Credentials hardcodés ─────────────────────────────────────────
    (
        "hardcoded_password",
        re.compile(rb"(password|passwd|pwd)\s*=\s*['\"][^'\"]{6,}['\"]", re.IGNORECASE),
        "MEDIUM",
    ),
    (
        "hardcoded_aws_key",
        re.compile(rb"AKIA[0-9A-Z]{16}", re.IGNORECASE),
        "HIGH",
    ),
    (
        "hardcoded_private_key",
        re.compile(rb"-----BEGIN (RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        "HIGH",
    ),

    # ── Obfuscation ───────────────────────────────────────────────────
    (
        "base64_encoded_payload",
        re.compile(rb"(exec|eval|system)\s*\(\s*(base64\.b64decode|__import__)", re.IGNORECASE),
        "HIGH",
    ),
    (
        "python_obfuscated_import",
        re.compile(rb"__import__\s*\(\s*['\"]os['\"]", re.IGNORECASE),
        "MEDIUM",
    ),

    # ── Privilege escalation ──────────────────────────────────────────
    (
        "suid_chmod_script",
        re.compile(rb"chmod\s+(u\+s|4[0-9]{3})\s+/bin/(sh|bash)", re.IGNORECASE),
        "CRITICAL",
    ),
    (
        "sudo_nopasswd_injection",
        re.compile(rb"ALL\s*=\s*\(ALL\)\s*NOPASSWD", re.IGNORECASE),
        "HIGH",
    ),
]

# ──────────────────────────────────────────────
# Noms de fichiers suspects
# ──────────────────────────────────────────────
# Malwares et outils offensifs utilisent souvent ces noms pour se camoufler.
SUSPICIOUS_FILENAMES = {
    # Camouflage système
    "systemd-private", "kworker", "kthreadd",
    # Outils offensifs connus
    "mimikatz", "meterpreter", "empire",
    "cobaltstrike", "beacon", "mettle",
    # Webshells classiques
    "c99.php", "r57.php", "b374k.php", "wso.php",
    "shell.php", "cmd.php", "webshell.php",
    # Noms génériques suspects
    ".hidden", "....",
}

# ──────────────────────────────────────────────
# Seuil de modification récente (en heures)
# ──────────────────────────────────────────────
# Fichier modifié dans les dernières N heures = potentiellement suspect
# (surtout si c'est un binaire système ou un fichier de config critique)
RECENT_MODIFICATION_HOURS = 24