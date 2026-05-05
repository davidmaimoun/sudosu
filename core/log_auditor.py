"""
core/log_auditor.py
-------------------
Analyse des logs système Linux pour détecter des activités malveillantes.

Lit directement les fichiers de log bruts — sans dépendance externe.
Fonctionne sur les logs compressés (.gz) aussi.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ARCHITECTURE DES LOGS LINUX
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Deux systèmes de logging coexistent sur Linux moderne :

  1. Syslog (fichiers texte dans /var/log/)
     ─────────────────────────────────────
     Chaque service écrit dans son propre fichier texte.
     Lisibles directement avec cat/grep.

     Fichiers critiques :
       /var/log/auth.log     → authentifications SSH, sudo, su, PAM
                               (Debian/Ubuntu)
       /var/log/secure       → même chose sur RedHat/CentOS/Fedora
       /var/log/syslog       → messages système généraux
       /var/log/messages     → idem (RedHat)
       /var/log/kern.log     → messages du kernel (chargement modules suspects)
       /var/log/cron.log     → tâches planifiées (persistence d'attaquants)
       /var/log/dpkg.log     → paquets installés (un attaquant installe des outils)
       /var/log/apache2/     → logs web (brute force, LFI, RFI, SQLi...)
       /var/log/nginx/       → idem pour nginx
       /var/log/fail2ban.log → IP déjà bannies (ce qui a échoué, pas tout)

     Rotation des logs :
       Les fichiers sont compressés et numérotés périodiquement :
       auth.log → auth.log.1 → auth.log.2.gz → auth.log.3.gz...
       On doit lire les .gz aussi pour l'historique.

  2. Journald (binaire, via journalctl)
     ────────────────────────────────────
     systemd stocke ses logs en format binaire dans /var/log/journal/.
     Accessible via la commande journalctl.
     Avantage : structuré, indexé, requêtable.
     Inconvénient pour nous : format binaire → on parse via subprocess.
     On le supporte en fallback si auth.log est absent.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONCEPTS CYBER COUVERTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Brute Force SSH
  ───────────────
  Technique d'attaque consistant à essayer massivement des mots de passe
  jusqu'à en trouver un valide.

  Signature dans auth.log :
    Failed password for root from 192.168.1.100 port 54321 ssh2
    Failed password for root from 192.168.1.100 port 54322 ssh2
    Failed password for root from 192.168.1.100 port 54323 ssh2
    ... (des centaines de fois depuis la même IP)

  Seuil de détection : > N échecs depuis la même IP dans une fenêtre de temps.
  Fail2ban utilise typiquement 5 échecs en 10 minutes.
  Nous utilisons un seuil configurable (défaut : 10 échecs).

  Distinction importante :
    - Brute force DISTRIBUÉ : une IP différente par tentative
      → difficile à détecter par IP (nécessite corrélation temporelle)
    - Brute force CLASSIQUE : même IP → facile à détecter
    Notre module détecte le classique. Le distribué = SIEM avec ML.


  Connexion root directe
  ────────────────────────
  "Accepted password for root from X.X.X.X"

  ROOT LOGIN DIRECT EST UNE MAUVAISE PRATIQUE.
  La bonne pratique : se connecter en user, puis sudo.
  Pourquoi ?
    - Audit trail : sudo logge chaque commande → forensic possible
    - Fail safe : une typo en root = dommages immédiats
    - Clé SSH compromise = accès root direct si PermitRootLogin yes

  Un login root réussi depuis une IP externe inconnue
  = compromission probable ou politique de sécurité très laxiste.


  Sudo anormal
  ─────────────
  Chaque commande sudo est loggée :
    user alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash

  Patterns suspects :
    - "COMMAND=/bin/bash" ou "COMMAND=/bin/sh" → shell root ouvert
    - "COMMAND=/bin/su" → double escalade
    - "sudo: pam_unix(sudo:auth): authentication failure" → tentative ratée
    - Heure inhabituelle (3h du matin)
    - User qui n'a jamais utilisé sudo auparavant


  Chargement de module kernel (LKM Rootkit)
  ──────────────────────────────────────────
  Les rootkits kernel (LKM = Loadable Kernel Module) se chargent
  via insmod/modprobe et ont accès total au kernel.

  Signature dans kern.log / syslog :
    kernel: Loading module: evil_rootkit
    kernel: Module evil_rootkit loaded

  Un module légitime chargé après le boot et hors maintenance = suspect.
  Exemples de rootkits LKM connus : Diamorphine, Reptile, Azazel.


  Effacement de logs (Anti-forensic)
  ────────────────────────────────────
  Un attaquant qui efface ses traces modifie /var/log/auth.log.
  Indices d'effacement :
    - Taille du fichier anormalement petite (truncate)
    - Gaps temporels dans les timestamps (lignes supprimées)
    - Fichier vide mais processus actif (cat /dev/null > auth.log)

  Ironie : si auth.log EST effacé, c'est lui-même un IOC.
  C'est pourquoi les systèmes sérieux envoient les logs vers
  un serveur SIEM distant en temps réel (syslog-ng, rsyslog → Splunk/Elastic).
  Un attaquant qui efface le log local ne touche pas le SIEM distant.


  PAM (Pluggable Authentication Modules)
  ────────────────────────────────────────
  Couche d'abstraction de l'authentification Linux.
  Tous les "Failed password", "session opened/closed" passent par PAM.
  PAM logge dans auth.log via le module pam_unix.

  Format typique :
    May  4 02:13:07 server sshd[1234]: Failed password for invalid user admin
                                                               ↑
                                                    "invalid user" = user inexistant
                                                    Signe de scan/brute force
"""

import re
import gzip
import subprocess
from pathlib import Path
from datetime import datetime, timezone
from collections import defaultdict

from utils.logger import get_logger

# ──────────────────────────────────────────────
# Fichiers de logs à analyser (par ordre de priorité)
# ──────────────────────────────────────────────

# Authentification — le fichier le plus critique
AUTH_LOG_CANDIDATES = [
    "/var/log/auth.log",       # Debian / Ubuntu
    "/var/log/secure",         # RedHat / CentOS / Fedora / AlmaLinux
    "/var/log/auth.log.1",     # rotation J-1
]

# Logs système généraux
SYSLOG_CANDIDATES = [
    "/var/log/syslog",
    "/var/log/messages",
    "/var/log/syslog.1",
]

# Logs kernel (modules, erreurs matérielles)
KERN_LOG_CANDIDATES = [
    "/var/log/kern.log",
    "/var/log/kern.log.1",
]

# Logs cron (tâches planifiées — vecteur de persistence)
CRON_LOG_CANDIDATES = [
    "/var/log/cron.log",
    "/var/log/cron",
]

# ──────────────────────────────────────────────
# Seuils de détection
# ──────────────────────────────────────────────

# Nombre d'échecs SSH depuis une même IP pour déclencher une alerte
BRUTE_FORCE_THRESHOLD = 10

# Nombre maximum de lignes à lire par fichier (performance)
# Les logs peuvent être énormes — on lit les N dernières lignes
MAX_LINES_PER_FILE = 50_000

# ──────────────────────────────────────────────
# Patterns regex compilés
# ──────────────────────────────────────────────
# Chaque pattern : (nom, regex compilée, sévérité, description)
#
# Pourquoi des regex compilées ?
#   re.compile() pré-compile le pattern une seule fois.
#   Sur 50 000 lignes × N patterns → gain de performance significatif.

SSH_FAIL_PATTERN = re.compile(
    r"Failed (password|publickey) for (?:invalid user )?(\S+) from ([\d\.]+)"
)
SSH_SUCCESS_PATTERN = re.compile(
    r"Accepted (password|publickey) for (\S+) from ([\d\.]+)"
)
ROOT_LOGIN_PATTERN = re.compile(
    r"Accepted \w+ for root from ([\d\.]+)"
)
SUDO_SHELL_PATTERN = re.compile(
    r"sudo.*COMMAND=(/bin/bash|/bin/sh|/bin/su|/usr/bin/bash)"
)
SUDO_FAIL_PATTERN = re.compile(
    r"sudo.*authentication failure"
)
INVALID_USER_PATTERN = re.compile(
    r"Invalid user (\S+) from ([\d\.]+)"
)
LKM_PATTERN = re.compile(
    r"(insmod|modprobe|Loading module|module.*loaded)",
    re.IGNORECASE,
)
LOG_CLEARED_PATTERN = re.compile(
    r"(log file turned over|BEGIN|wtmp begins)",
    re.IGNORECASE,
)
CRON_ANOMALY_PATTERN = re.compile(
    r"CMD\s+\((.{0,200})\)"  # capture la commande cron exécutée
)


# ──────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────
def run(
    log_file: Path | None = None,
    verbose:  bool = False,
) -> list[dict]:
    """
    Analyse les logs système et retourne les findings suspects.

    Pipeline :
      1. auth.log / secure  → brute force SSH, root login, sudo anormal
      2. syslog / messages  → anomalies système générales
      3. kern.log           → chargement de modules kernel suspects
      4. cron.log           → commandes cron suspectes (persistence)
      5. Journald           → fallback si fichiers texte absents
    """
    log = get_logger("log_auditor", log_file, verbose)
    log.info("Starting log audit")

    findings: list[dict] = []

    # ── 1. Auth log ──────────────────────────────────────────────────
    auth_lines = _read_log_files(AUTH_LOG_CANDIDATES, log)
    if auth_lines:
        log.info(f"Auth log: {len(auth_lines)} lines loaded")
        findings += _audit_auth_log(auth_lines, log)
    else:
        log.info("Auth log not found or empty — trying journald fallback")
        auth_lines = _read_journald("sshd", log)
        if auth_lines:
            findings += _audit_auth_log(auth_lines, log)

    # ── 2. Syslog ────────────────────────────────────────────────────
    sys_lines = _read_log_files(SYSLOG_CANDIDATES, log)
    if sys_lines:
        log.info(f"Syslog: {len(sys_lines)} lines loaded")
        findings += _audit_syslog(sys_lines, log)

    # ── 3. Kern log ──────────────────────────────────────────────────
    kern_lines = _read_log_files(KERN_LOG_CANDIDATES, log)
    if kern_lines:
        log.info(f"Kern log: {len(kern_lines)} lines loaded")
        findings += _audit_kern_log(kern_lines, log)

    # ── 4. Cron log ──────────────────────────────────────────────────
    cron_lines = _read_log_files(CRON_LOG_CANDIDATES, log)
    if cron_lines:
        log.info(f"Cron log: {len(cron_lines)} lines loaded")
        findings += _audit_cron_log(cron_lines, log)

    # ── 5. Vérification intégrité des logs ──────────────────────────
    findings += _check_log_integrity(AUTH_LOG_CANDIDATES + SYSLOG_CANDIDATES, log)

    log.info(f"Log audit complete | {len(findings)} finding(s)")
    return findings


# ──────────────────────────────────────────────
# Analyse auth.log
# ──────────────────────────────────────────────
def _audit_auth_log(lines: list[str], log) -> list[dict]:
    """
    Détecte dans auth.log / secure :
      - Brute force SSH (N échecs depuis même IP)
      - Connexions root réussies
      - Utilisateurs invalides scannés
      - Sudo vers shell root
      - Échecs sudo répétés
    """
    findings = []

    # Compteurs pour agrégation
    # defaultdict évite le KeyError sur première apparition d'une clé
    ssh_fails:    defaultdict[str, int]        = defaultdict(int)   # IP → nb échecs
    ssh_success:  defaultdict[str, list[str]]  = defaultdict(list)  # IP → [users]
    invalid_users: defaultdict[str, set[str]]  = defaultdict(set)   # IP → {users tentés}
    sudo_fails:   defaultdict[str, int]        = defaultdict(int)   # user → nb échecs

    for line in lines:

        # ── Échecs SSH ───────────────────────────────────────────────
        # "Failed password for root from 1.2.3.4 port 54321 ssh2"
        # "Failed password for invalid user admin from 1.2.3.4"
        #
        # "invalid user" est crucial : ça veut dire que le compte
        # n'existe même pas. L'attaquant scanne des usernames communs
        # (admin, administrator, ubuntu, pi, oracle...).
        m = SSH_FAIL_PATTERN.search(line)
        if m:
            auth_method = m.group(1)   # "password" ou "publickey"
            username    = m.group(2)
            ip          = m.group(3)
            ssh_fails[ip] += 1
            if "invalid user" in line:
                invalid_users[ip].add(username)

        # ── Succès SSH ───────────────────────────────────────────────
        m = SSH_SUCCESS_PATTERN.search(line)
        if m:
            username = m.group(2)
            ip       = m.group(3)
            ssh_success[ip].append(username)

            # Login root direct réussi depuis l'extérieur
            # → sévérité HIGH car root login direct = mauvaise pratique absolue
            if username == "root":
                findings.append(_make_finding(
                    severity="HIGH",
                    target=f"SSH login as root from {ip}",
                    reason=(
                        f"Direct root SSH login succeeded from {ip} — "
                        "PermitRootLogin should be disabled. "
                        "Use sudo instead for audit trail."
                    ),
                    module="log_auditor.ssh",
                    details={"ip": ip, "user": "root", "method": m.group(1)},
                ))
                log.warning(f"Root SSH login from {ip}")

        # ── Sudo vers shell root ─────────────────────────────────────
        # "alice : TTY=pts/0 ; COMMAND=/bin/bash"
        #
        # Obtenir un shell root via sudo est la technique de base
        # pour maintenir un accès root interactif après intrusion.
        # Légitime pour un admin → suspect à 2h du matin ou par un
        # user qui n'a jamais utilisé sudo.
        if SUDO_SHELL_PATTERN.search(line):
            # Extrait le user depuis la ligne sudo
            user_match = re.search(r"sudo:\s+(\S+)\s+:", line)
            user = user_match.group(1) if user_match else "unknown"
            cmd_match = re.search(r"COMMAND=(\S+)", line)
            cmd = cmd_match.group(1) if cmd_match else "unknown"
            findings.append(_make_finding(
                severity="HIGH",
                target=f"sudo shell by {user}",
                reason=(
                    f"User '{user}' opened a root shell via sudo ({cmd}) — "
                    "legitimate for admins, critical IOC if unexpected user or time"
                ),
                module="log_auditor.sudo",
                details={"user": user, "command": cmd, "line": line.strip()[:200]},
            ))
            log.warning(f"Sudo shell opened by {user}: {cmd}")

        # ── Échecs sudo ──────────────────────────────────────────────
        if SUDO_FAIL_PATTERN.search(line):
            user_match = re.search(r"user=(\S+)", line)
            user = user_match.group(1) if user_match else "unknown"
            sudo_fails[user] += 1

    # ── Agrégation : brute force SSH ─────────────────────────────────
    # On analyse les compteurs APRÈS avoir lu toutes les lignes.
    # Concept : on ne peut pas détecter un brute force ligne par ligne
    # (chaque ligne prise isolément est "normale").
    # C'est la CORRÉLATION temporelle qui révèle l'attaque.
    # C'est exactement ce que fait un SIEM (Splunk, Elastic SIEM, QRadar).
    for ip, count in ssh_fails.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            # Avait-il réussi après ? Brute force RÉUSSI = pire scénario.
            success_after = bool(ssh_success.get(ip))
            sev = "CRITICAL" if success_after else "HIGH"
            tried_users = invalid_users.get(ip, set())

            findings.append(_make_finding(
                severity=sev,
                target=f"Brute force SSH from {ip}",
                reason=(
                    f"{count} failed SSH attempts from {ip}"
                    f"{' — SUCCESSFUL LOGIN AFTER BRUTE FORCE!' if success_after else ''}"
                    f"{f' — Tried {len(tried_users)} invalid users: {list(tried_users)[:5]}' if tried_users else ''}"
                ),
                module="log_auditor.brute_force",
                details={
                    "ip":             ip,
                    "fail_count":     count,
                    "login_success":  success_after,
                    "invalid_users":  list(tried_users)[:10],
                },
            ))
            log.warning(
                f"Brute force SSH | {ip} | {count} failures | "
                f"{'SUCCESS after brute force!' if success_after else 'no success'}"
            )

    # ── Agrégation : scan d'utilisateurs invalides ───────────────────
    # Une IP qui essaie > 5 usernames différents = credential stuffing
    # ou reconnaissance de comptes (user enumeration).
    for ip, users in invalid_users.items():
        if len(users) >= 5 and ssh_fails[ip] < BRUTE_FORCE_THRESHOLD:
            # Pas assez de tentatives pour le brute force threshold,
            # mais beaucoup d'usernames différents = scan de comptes.
            findings.append(_make_finding(
                severity="MEDIUM",
                target=f"User enumeration from {ip}",
                reason=(
                    f"IP {ip} tried {len(users)} different usernames — "
                    f"credential stuffing or user enumeration attack. "
                    f"Users tried: {list(users)[:8]}"
                ),
                module="log_auditor.enum",
                details={"ip": ip, "users_tried": list(users)[:20]},
            ))

    # ── Agrégation : échecs sudo répétés ─────────────────────────────
    for user, count in sudo_fails.items():
        if count >= 3:
            findings.append(_make_finding(
                severity="MEDIUM",
                target=f"Repeated sudo failures by {user}",
                reason=(
                    f"User '{user}' failed sudo authentication {count} times — "
                    "possible privilege escalation attempt or misconfigured account"
                ),
                module="log_auditor.sudo",
                details={"user": user, "fail_count": count},
            ))

    return findings


# ──────────────────────────────────────────────
# Analyse syslog / messages
# ──────────────────────────────────────────────
def _audit_syslog(lines: list[str], log) -> list[dict]:
    """
    Détecte dans syslog :
      - Erreurs de segfault répétées (exploitation buffer overflow)
      - Services redémarrés anormalement (watchdog d'un malware ?)
      - Modifications de crontab système
    """
    findings = []
    segfault_procs: defaultdict[str, int] = defaultdict(int)

    for line in lines:

        # ── Segfaults répétés ────────────────────────────────────────
        # Un segfault = accès mémoire invalide → crash du programme.
        #
        # Contexte offensif : lors d'un exploit (buffer overflow),
        # l'attaquant tente souvent des dizaines de fois avant de trouver
        # le bon offset. Chaque tentative ratée = segfault.
        # Des centaines de segfaults du même processus = exploitation en cours.
        if "segfault" in line.lower():
            proc_match = re.search(r"(\w+)\[\d+\]: segfault", line)
            if proc_match:
                proc = proc_match.group(1)
                segfault_procs[proc] += 1

        # ── Crontab modifié ──────────────────────────────────────────
        # La modification de crontab est une technique de PERSISTENCE classique.
        # L'attaquant ajoute une tâche planifiée qui relance son malware
        # ou exfiltre des données régulièrement.
        # "* * * * * /tmp/.hidden/beacon.sh"
        if "crontab" in line.lower() and (
            "REPLACE" in line or "BEGIN EDIT" in line or "new crontab" in line.lower()
        ):
            findings.append(_make_finding(
                severity="MEDIUM",
                target="crontab modification detected",
                reason=(
                    "Crontab was modified — common persistence technique. "
                    "Verify cron entries with: crontab -l -u <user>"
                ),
                module="log_auditor.syslog",
                details={"line": line.strip()[:300]},
            ))

    # ── Agrégation segfaults ─────────────────────────────────────────
    for proc, count in segfault_procs.items():
        if count >= 5:
            findings.append(_make_finding(
                severity="MEDIUM",
                target=f"Repeated segfaults in {proc}",
                reason=(
                    f"Process '{proc}' crashed {count} times (segfault) — "
                    "possible exploitation attempt (buffer overflow fuzzing)"
                ),
                module="log_auditor.syslog",
                details={"process": proc, "segfault_count": count},
            ))
            log.warning(f"Segfault storm: {proc} × {count}")

    return findings


# ──────────────────────────────────────────────
# Analyse kern.log
# ──────────────────────────────────────────────
def _audit_kern_log(lines: list[str], log) -> list[dict]:
    """
    Détecte dans kern.log :
      - Chargement de modules kernel non standards (rootkit LKM)
      - Erreurs de module suspectes

    LKM Rootkit = Loadable Kernel Module malveillant.
    Un module kernel a les droits ABSOLUS sur le système :
      - Cacher des fichiers (hooker les syscalls getdents)
      - Cacher des processus (hooker /proc)
      - Cacher des connexions réseau
      - Keylogger au niveau kernel
      - Intercepter toutes les communications

    Exemples connus : Diamorphine, Reptile, Azazel, Necro.
    Commande pour lister les modules chargés : lsmod
    """
    findings = []
    seen_modules: set[str] = set()

    for line in lines:
        if LKM_PATTERN.search(line):
            # Extrait le nom du module si possible
            mod_match = re.search(
                r"(insmod|modprobe)\s+(\S+)|Loading module:\s*(\S+)", line
            )
            mod_name = "unknown"
            if mod_match:
                mod_name = mod_match.group(2) or mod_match.group(3) or "unknown"

            if mod_name not in seen_modules:
                seen_modules.add(mod_name)
                findings.append(_make_finding(
                    severity="HIGH",
                    target=f"Kernel module loaded: {mod_name}",
                    reason=(
                        f"Kernel module '{mod_name}' was loaded — "
                        "LKM rootkits (Diamorphine, Reptile) use this mechanism "
                        "to gain full kernel-level access. "
                        "Verify with: lsmod | grep " + mod_name
                    ),
                    module="log_auditor.kernel",
                    details={"module": mod_name, "line": line.strip()[:300]},
                ))
                log.warning(f"Kernel module loaded: {mod_name}")

    return findings


# ──────────────────────────────────────────────
# Analyse cron.log
# ──────────────────────────────────────────────
def _audit_cron_log(lines: list[str], log) -> list[dict]:
    """
    Détecte dans cron.log les commandes planifiées suspectes.

    La persistence via cron est LA technique la plus utilisée :
      - Simple à mettre en place (crontab -e)
      - Survit aux redémarrages
      - Discret si la fréquence est faible (1x/jour)
      - Peut relancer un reverse shell si coupé

    Patterns suspects dans les commandes cron :
      - Appels vers /tmp, /dev/shm (dossiers world-writable)
      - Scripts encodés en base64
      - Téléchargements (curl, wget) suivis d'exécution
      - Commandes de reverse shell directes
    """
    findings = []

    # Patterns suspects dans les commandes cron
    suspicious_cron_patterns = [
        (r"/tmp/\S+",                    "Cron executing from /tmp",        "HIGH"),
        (r"/dev/shm/\S+",                "Cron executing from /dev/shm",    "HIGH"),
        (r"base64\s+-d",                 "Base64-decoded execution in cron", "HIGH"),
        (r"(curl|wget)\s+.*\|\s*(ba)?sh","Download and execute in cron",    "CRITICAL"),
        (r"/dev/tcp/",                   "Reverse shell in cron task",       "CRITICAL"),
        (r"bash\s+-i\s+>&",              "Interactive shell in cron",        "CRITICAL"),
        (r"nc\s+(-e|-c)",               "Netcat shell in cron",             "CRITICAL"),
        (r"python[23]?\s+-c",            "Python one-liner in cron",        "HIGH"),
        (r"perl\s+-e",                   "Perl one-liner in cron",          "HIGH"),
    ]

    for line in lines:
        m = CRON_ANOMALY_PATTERN.search(line)
        if not m:
            continue

        cmd = m.group(1)  # La commande exécutée par cron

        for pattern, desc, sev in suspicious_cron_patterns:
            if re.search(pattern, cmd, re.IGNORECASE):
                findings.append(_make_finding(
                    severity=sev,
                    target=f"Suspicious cron command: {cmd[:80]}",
                    reason=(
                        f"{desc} — cron is the most common persistence mechanism. "
                        f"Command: {cmd[:150]}"
                    ),
                    module="log_auditor.cron",
                    details={"command": cmd[:500], "pattern": pattern},
                ))
                log.warning(f"Suspicious cron: {desc} | {cmd[:80]}")
                break  # Un seul finding par ligne

    return findings


# ──────────────────────────────────────────────
# Vérification intégrité des logs
# ──────────────────────────────────────────────
def _check_log_integrity(log_paths: list[str], log) -> list[dict]:
    """
    Vérifie que les fichiers de log n'ont pas été effacés ou tronqués.

    Anti-forensic : la première chose qu'un attaquant fait après
    une intrusion est d'effacer ses traces dans les logs.
    Méthodes courantes :
      - cat /dev/null > /var/log/auth.log    → vide le fichier
      - sed -i '/attacker_ip/d' auth.log     → supprime les lignes suspectes
      - rm /var/log/auth.log                 → supprime le fichier

    Détection :
      - Fichier auth.log existant mais vide (taille = 0)
      - Fichier auth.log très petit alors que le système tourne depuis longtemps
      - Permissions anormales sur les fichiers de log

    Limitation : on ne peut pas détecter les suppressions chirurgicales
    (sed -i ligne par ligne) sans avoir une baseline de référence.
    Un SIEM distant (Splunk, Elastic) qui reçoit les logs en temps réel
    est la seule vraie protection contre l'anti-forensic.
    """
    findings = []

    for path_str in log_paths:
        p = Path(path_str)

        if not p.exists():
            continue  # Fichier absent = peut être normal (pas encore créé)

        try:
            stat = p.stat()
            size = stat.st_size

            # Fichier vide = effacement probable
            if size == 0:
                findings.append(_make_finding(
                    severity="HIGH",
                    target=path_str,
                    reason=(
                        f"Log file is empty (0 bytes) — possible anti-forensic: "
                        f"'cat /dev/null > {path_str}'. "
                        "Check: last modification time and check SIEM for prior entries."
                    ),
                    module="log_auditor.integrity",
                    details={"path": path_str, "size": 0},
                ))
                log.warning(f"Empty log file: {path_str}")

            # Fichier anormalement petit (< 1 Ko pour auth.log sur système actif)
            elif size < 512 and "auth" in path_str:
                findings.append(_make_finding(
                    severity="MEDIUM",
                    target=path_str,
                    reason=(
                        f"Auth log suspiciously small ({size} bytes) — "
                        "possible partial deletion. "
                        "A healthy system auth.log is typically several KB."
                    ),
                    module="log_auditor.integrity",
                    details={"path": path_str, "size": size},
                ))

        except (PermissionError, OSError):
            pass

    return findings


# ──────────────────────────────────────────────
# Lecture des fichiers de log
# ──────────────────────────────────────────────
def _read_log_files(candidates: list[str], log) -> list[str]:
    """
    Lit les fichiers de log depuis la liste de candidats.
    Supporte les fichiers .gz (rotation compressée).
    Retourne toutes les lignes concaténées des fichiers trouvés.
    Limite à MAX_LINES_PER_FILE lignes pour éviter l'OOM.

    Pourquoi plusieurs candidats ?
      auth.log existe sur Debian/Ubuntu, mais s'appelle 'secure' sur RedHat.
      Un outil cyber sérieux doit fonctionner sur toutes les distributions.
    """
    all_lines = []

    for path_str in candidates:
        p = Path(path_str)
        if not p.exists():
            continue

        try:
            if path_str.endswith(".gz"):
                # Lecture fichier compressé (rotation de logs)
                with gzip.open(p, "rt", encoding="utf-8", errors="replace") as f:
                    lines = f.readlines()
            else:
                lines = p.read_text(encoding="utf-8", errors="replace").splitlines()

            # On garde les N dernières lignes (les plus récentes = les plus pertinentes)
            all_lines.extend(lines[-MAX_LINES_PER_FILE:])
            log.info(f"Read {len(lines)} lines from {path_str}")

        except (PermissionError, OSError, gzip.BadGzipFile) as e:
            log.warning(f"Cannot read {path_str}: {e}")

    return all_lines


# ──────────────────────────────────────────────
# Fallback : journald
# ──────────────────────────────────────────────
def _read_journald(unit: str, log) -> list[str]:
    """
    Lit les logs via journalctl si les fichiers texte sont absents.
    Fallback pour les systèmes sans syslog classique (systemd only).

    journalctl -u sshd --no-pager -n 5000
    """
    try:
        result = subprocess.run(
            ["journalctl", "-u", unit, "--no-pager", "-n", "5000"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        if result.returncode == 0 and result.stdout:
            log.info(f"Journald fallback: {unit} — {len(result.stdout.splitlines())} lines")
            return result.stdout.splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        pass
    return []


# ──────────────────────────────────────────────
# Helper : construction d'un finding standard
# ──────────────────────────────────────────────
def _make_finding(
    severity: str,
    target:   str,
    reason:   str,
    module:   str,
    details:  dict,
) -> dict:
    """
    Construit un finding au format standard SudoSu.
    Centraliser la construction garantit la cohérence des champs
    pour le rapport JSON/HTML généré par reporter.py.
    """
    return {
        "severity":  severity,
        "target":    target,
        "reason":    reason,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module":    module,
        "details":   details,
    }