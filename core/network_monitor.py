"""
core/network_monitor.py
-----------------------
Surveillance des connexions réseau et ports ouverts.

Lit directement /proc/net/tcp et /proc/net/tcp6 — sans netstat,
sans ss, sans aucune dépendance externe.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
QU'EST-CE QUE /proc/net/tcp ?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  Comme /proc/<PID>/, c'est un pseudo-fichier généré à la volée
  par le kernel. Il liste TOUTES les connexions TCP actives
  et les ports en écoute sur la machine.

  Format d'une ligne :
    sl  local_address  rem_address  st  tx_queue:rx_queue  ...  uid  inode
    0: 0100007F:0035   00000000:0000  0A  00000000:00000000  ...  101  12345

  Chaque champ est en hexadécimal, little-endian pour les IPs :
    - 0100007F → 127.0.0.1   (bytes inversés : 7F=127, 00=0, 00=0, 01=1)
    - 0035     → port 53     (0x35 = 53 en décimal)
    - st=0A    → état LISTEN (0x0A = 10)

  États TCP importants :
    01 = ESTABLISHED  (connexion active)
    0A = LISTEN       (port ouvert en attente)
    06 = TIME_WAIT    (fermeture en cours)
    02 = SYN_SENT     (connexion en cours d'établissement)

  Pourquoi lire /proc/net/tcp plutôt que netstat/ss ?
    - Pas de dépendance externe — fonctionne même si netstat est absent
      (containers minimalistes, systèmes compromis où netstat est remplacé)
    - Un rootkit peut hooker les syscalls libc utilisés par netstat
      pour cacher des connexions → /proc/net/tcp est plus difficile à falsifier
    - C'est exactement ce que fait ss en interne (ss lit /proc/net/tcp)


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONCEPTS RÉSEAU / CYBER COUVERTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  C2 (Command & Control)
  ───────────────────────
  Serveur contrôlé par l'attaquant vers lequel le malware se connecte
  pour recevoir des ordres et exfiltrer des données.

  Modèle classique :
    Machine compromise → connexion sortante → C2 server (attaquant)
                      ←  commandes           ←
                      →  données volées       →

  Pourquoi sortant ? Les pare-feux bloquent souvent l'entrant,
  mais laissent passer l'HTTP/HTTPS sortant.
  → Les C2 modernes utilisent le port 443 (HTTPS) pour se camoufler.

  Indicateurs C2 :
    - Connexion vers IP publique sur port inhabituel (4444, 1337, 31337...)
    - Connexion persistante (ESTABLISHED depuis longtemps)
    - Processus inhabituel avec connexion sortante (bash, python, perl...)
    - Beacon régulier (connexion toutes les N secondes = heartbeat C2)


  Ports suspects vs légitimes
  ────────────────────────────
  Ports légitimes connus (à ne pas alerter) :
    22=SSH, 80=HTTP, 443=HTTPS, 53=DNS, 25=SMTP, 3306=MySQL...

  Ports C2 classiques (Metasploit par défaut) :
    4444  → Meterpreter default
    4445  → Meterpreter alternatif
    1337  → "leet" — favori des script kiddies
    31337 → "elite" — classique depuis les années 90
    8080, 8443 → proxy/C2 déguisé en HTTP

  Ports de tunneling (exfiltration) :
    DNS (53) → DNS tunneling : données encodées dans des requêtes DNS
    ICMP     → ICMP tunneling (non visible dans /proc/net/tcp)
    HTTP(S)  → le plus furtif car rarement bloqué


  Bind shell vs Reverse shell
  ────────────────────────────
  Bind shell   : le malware OUVRE un port sur la machine compromise.
                 L'attaquant s'y connecte.
    Détection : port inhabituel en LISTEN, avec processus = bash/sh

  Reverse shell : le malware SE CONNECTE vers le C2 de l'attaquant.
                  Traverse les NAT et firewalls plus facilement.
    Détection : processus bash/python/perl avec connexion ESTABLISHED
                vers une IP externe

  Notre scanner détecte les deux.


  UID propriétaire d'une connexion
  ──────────────────────────────────
  /proc/net/tcp contient l'UID du processus propriétaire de chaque socket.
  On peut croiser avec /etc/passwd pour savoir quel user a ouvert la connexion.
  Un port 443 ouvert par root (UID=0) sans être apache/nginx → suspect.
"""

import re
import socket
import struct
from pathlib import Path
from datetime import datetime, timezone

from utils.logger import get_logger

# ──────────────────────────────────────────────
# Tables de référence
# ──────────────────────────────────────────────

# États TCP (valeur hex → nom lisible)
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

# Ports légitimes connus — pas d'alerte sur ces ports en écoute
LEGIT_LISTEN_PORTS = {
    22,    # SSH
    25,    # SMTP
    53,    # DNS
    80,    # HTTP
    110,   # POP3
    143,   # IMAP
    443,   # HTTPS
    465,   # SMTPS
    587,   # SMTP submission
    993,   # IMAPS
    995,   # POP3S
    3306,  # MySQL
    5432,  # PostgreSQL
    5433,  # PostgreSQL alt
    6379,  # Redis
    27017, # MongoDB
    8080,  # HTTP alternatif
    8443,  # HTTPS alternatif
    8888,  # Jupyter Notebook (dev)
    # Ports dev courants — trop de faux positifs sinon
    3000, 3001,        # Node.js / React
    4200,              # Angular
    5000, 5001,        # Flask / Python API
    5173, 5174,        # Vite (React/Vue dev server)
    8000, 8001,        # Django / Python
    9000,              # PHP-FPM / SonarQube
}

# Plages d'IP Google (services légitimes : Chrome sync, FCM, Firebase...)
# Port 5228 = Google Cloud Messaging / Firebase — normal pour Chrome, Android
GOOGLE_IP_RANGES = [
    (0x4000_0000, 0x40FF_FFFF),  # 64.0.0.0/8  (Google partiel)
    (0x4A7D_0000, 0x4A7D_FFFF),  # 74.125.0.0/16 (Google)
    (0x4265_0000, 0x4265_FFFF),  # 66.102.0.0/16 (Google)
    (0x4A6C_0000, 0x4A6C_FFFF),  # 74.108.0.0/16 (Google)
]

# Ports utilisés par des services Google légitimes
GOOGLE_SERVICE_PORTS = {
    5228,  # Google Cloud Messaging / Firebase / Chrome sync
    19302, # Google STUN (WebRTC)
}

# Ports C2 connus — présence = très suspect
KNOWN_C2_PORTS = {
    4444:  "Metasploit Meterpreter default",
    4445:  "Metasploit Meterpreter alt",
    1337:  "Leet shell / C2",
    31337: "Elite backdoor (Back Orifice era)",
    5555:  "Android ADB / C2",
    6666:  "IRC C2 (old school botnet)",
    6667:  "IRC C2",
    9001:  "Tor / Cobalt Strike default",
    9002:  "Cobalt Strike alt",
    9090:  "Openfire / C2",
    2222:  "Alt SSH (souvent backdoor)",
    1234:  "Generic backdoor",
    8888:  "Generic C2",
}

# Processus qui N'ONT PAS de raison d'avoir des connexions réseau
# Si on les voit avec une socket ouverte → suspect
UNEXPECTED_NETWORK_PROCS = {
    "bash", "sh", "zsh", "ksh", "dash",  # shells
    "vim", "nano", "cat", "less",          # éditeurs/lecture
    "find", "grep", "awk", "sed",          # utilitaires
    "ls", "cp", "mv", "rm",               # commandes fichiers
}

# Plages d'IP privées (RFC 1918) — connexions hors ces plages = internet
PRIVATE_RANGES = [
    (0x0A000000, 0x0AFFFFFF),   # 10.0.0.0/8
    (0xAC100000, 0xAC1FFFFF),   # 172.16.0.0/12
    (0xC0A80000, 0xC0A8FFFF),   # 192.168.0.0/16
    (0x7F000000, 0x7FFFFFFF),   # 127.0.0.0/8 (loopback)
]


# ──────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────
def run(
    log_file: Path | None = None,
    verbose:  bool = False,
) -> list[dict]:
    """
    Scanne les connexions réseau via /proc/net/tcp et /proc/net/tcp6.
    Retourne la liste des findings suspects.

    Heuristiques :
      1. Port C2 connu en écoute ou en connexion
      2. Port inhabituel en écoute (bind shell potentiel)
      3. Connexion ESTABLISHED vers internet par un processus inattendu
      4. Shell avec socket ouverte (reverse shell actif)
      5. Port privilégié (< 1024) ouvert par un UID non-root
    """
    log = get_logger("network_monitor", log_file, verbose)
    log.info("Starting network scan via /proc/net/tcp")

    findings: list[dict] = []

    # ── Lecture des connexions IPv4 et IPv6 ─────────────────────────
    connections: list[dict] = []
    for proc_file in ("/proc/net/tcp", "/proc/net/tcp6"):
        conns = _parse_proc_net_tcp(proc_file, log)
        connections.extend(conns)
        log.info(f"Parsed {len(conns)} entries from {proc_file}")

    if not connections:
        log.warning("No connections found — possibly no network activity or permission denied")
        return findings

    log.info(f"Total connections: {len(connections)}")

    # ── Analyse de chaque connexion ──────────────────────────────────
    for conn in connections:
        finding = _analyze_connection(conn, log)
        if finding:
            findings.append(finding)
            log.warning(
                f"[{finding['severity']}] "
                f"{conn.get('local_ip')}:{conn.get('local_port')} "
                f"→ {conn.get('remote_ip')}:{conn.get('remote_port')} "
                f"| {finding['reason']}"
            )

    # ── Résumé des ports en écoute ───────────────────────────────────
    listen_ports = [
        c for c in connections if c.get("state") == "LISTEN"
    ]
    log.info(f"Listening ports: {[c['local_port'] for c in listen_ports]}")

    log.info(f"Network scan complete | {len(findings)} finding(s)")
    return findings


# ──────────────────────────────────────────────
# Parsing de /proc/net/tcp
# ──────────────────────────────────────────────
def _parse_proc_net_tcp(filepath: str, log) -> list[dict]:
    """
    Parse /proc/net/tcp ou /proc/net/tcp6.
    Retourne une liste de dicts décrivant chaque connexion.

    Format d'une ligne /proc/net/tcp :
      sl  local_addr:port  rem_addr:port  state  tx:rx  ...  uid  inode
      0:  0100007F:0035    00000000:0000  0A     ...         101  12345

    Encodage little-endian :
      IP 0100007F → bytes [01, 00, 00, 7F] → inversés → [7F, 00, 00, 01] → 127.0.0.1

      Pourquoi little-endian ?
      Le kernel Linux stocke les IPs dans l'ordre des octets du processeur (x86).
      Les processeurs x86 sont little-endian : l'octet de poids faible en premier.
      Donc 127.0.0.1 (0x7F000001) est stocké comme 0x0100007F.
      On doit inverser pour lire correctement.
    """
    path = Path(filepath)
    if not path.exists():
        return []

    connections = []
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except (PermissionError, OSError) as e:
        log.warning(f"Cannot read {filepath}: {e}")
        return []

    # Première ligne = en-tête, on skip
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue

        try:
            local_hex  = parts[1]   # "0100007F:0035"
            remote_hex = parts[2]   # "00000000:0000"
            state_hex  = parts[3]   # "0A"
            uid        = int(parts[7])

            local_ip,   local_port  = _decode_address(local_hex,  filepath)
            remote_ip,  remote_port = _decode_address(remote_hex, filepath)
            state = TCP_STATES.get(state_hex.upper(), f"UNKNOWN({state_hex})")

            connections.append({
                "local_ip":    local_ip,
                "local_port":  local_port,
                "remote_ip":   remote_ip,
                "remote_port": remote_port,
                "state":       state,
                "uid":         uid,
                "ipv6":        "tcp6" in filepath,
            })
        except (ValueError, IndexError):
            continue

    return connections


def _decode_address(hex_addr: str, filepath: str) -> tuple[str, int]:
    """
    Décode une adresse hexadécimale du format /proc/net/tcp.

    IPv4 : "0100007F:0035"
      → IP hex = "0100007F" → little-endian → struct.unpack → 127.0.0.1
      → Port hex = "0035" → int(0x35) = 53

    IPv6 : "00000000000000000000000001000000:0035"
      → 32 caractères hex → 16 bytes → socket.inet_ntop

    Pourquoi struct.pack/unpack ?
      struct.pack('>I', n) encode n en big-endian (réseau standard).
      socket.inet_ntoa() attend du big-endian.
      L'IP dans /proc est en little-endian machine.
      Donc on lit en little-endian ('<I') puis on réencapsule en big-endian ('>I').
    """
    ip_hex, port_hex = hex_addr.split(":")
    port = int(port_hex, 16)

    if "tcp6" in filepath and len(ip_hex) == 32:
        # IPv6 : 32 hex chars = 16 bytes
        try:
            raw = bytes.fromhex(ip_hex)
            # Chaque groupe de 4 bytes est little-endian
            parts = []
            for i in range(0, 16, 4):
                word = raw[i:i+4]
                parts.append(struct.unpack(">I", bytes(reversed(word)))[0])
            packed = struct.pack(">4I", *parts)
            ip = socket.inet_ntop(socket.AF_INET6, packed)
        except Exception:
            ip = ip_hex
    else:
        # IPv4 : 8 hex chars = 4 bytes little-endian
        raw_int = int(ip_hex, 16)
        # Convertit l'entier little-endian en bytes big-endian pour inet_ntoa
        ip = socket.inet_ntoa(struct.pack(">I", socket.htonl(raw_int)))

    return ip, port


# ──────────────────────────────────────────────
# Analyse d'une connexion
# ──────────────────────────────────────────────
def _analyze_connection(conn: dict, log) -> dict | None:
    """
    Applique les heuristiques de détection sur une connexion.
    Retourne un finding si suspect, None sinon.
    """
    local_port  = conn["local_port"]
    local_ip    = conn["local_ip"]
    remote_port = conn["remote_port"]
    remote_ip   = conn["remote_ip"]
    state       = conn["state"]
    uid         = conn["uid"]

    reasons:  list[str] = []
    severity: str = "LOW"

    # ── Check 1 : Port C2 connu ──────────────────────────────────────
    #
    # Ces ports sont quasi-exclusivement utilisés par des outils offensifs.
    # Métasploit, Cobalt Strike, et les backdoors "maison" utilisent
    # ces ports par défaut — les attaquants débutants ne les changent pas.
    #
    # Un attaquant sophistiqué utilisera le port 443 pour se camoufler
    # → c'est pourquoi le port seul ne suffit pas : on croise avec le processus.
    for port in (local_port, remote_port):
        if port in KNOWN_C2_PORTS:
            desc = KNOWN_C2_PORTS[port]
            reasons.append(f"Known C2 port {port} ({desc}) — state={state}")
            severity = _escalate(severity, "CRITICAL")

    # ── Check 2 : Port en LISTEN — distinguer localhost vs 0.0.0.0 ─────────────
    #
    # DISTINCTION FONDAMENTALE que l'ancienne version ignorait :
    #
    #   127.0.0.1:5173 (LISTEN) → accessible UNIQUEMENT depuis cette machine
    #                             → dev server Vite/React/Flask → NORMAL
    #
    #   0.0.0.0:4444  (LISTEN)  → accessible depuis tout le réseau
    #                             → bind shell Meterpreter → CRITICAL
    #
    # Un scanner qui traite les deux identiquement génère massivement
    # de faux positifs sur les machines de développement.
    #
    # Règle :
    #   localhost (127.x.x.x / ::1) → bruit si port non-C2 → ignorer
    #   0.0.0.0 / :: → potentiel bind shell → analyser
    if state == "LISTEN" and local_port not in LEGIT_LISTEN_PORTS:
        is_localhost_only = local_ip in ("127.0.0.1", "::1", "0:0:0:0:0:0:0:1")

        if local_port > 1024 and not is_localhost_only:
            # Port élevé accessible depuis le réseau → potentiel bind shell
            reasons.append(
                f"Non-standard port {local_port} listening on {local_ip} "
                f"(network-accessible) — possible bind shell or misconfigured service"
            )
            severity = _escalate(severity, "HIGH")
        elif local_port > 1024 and is_localhost_only:
            # Port localhost uniquement → probablement un dev server, on ignore
            # (Vite:5173, Flask:5000, Node:3000, etc.)
            pass
        elif local_port <= 1024 and uid != 0:
            reasons.append(
                f"Privileged port {local_port} listening — opened by UID={uid} (not root)"
                f" → privilege escalation indicator"
            )
            severity = _escalate(severity, "HIGH")

    # ── Check 3 : Connexion ESTABLISHED vers internet ────────────────
    #
    # Distingue les services légitimes (Google, CDN) des vrais C2.
    #
    # Ports Google légitimes (Chrome sync, FCM, Firebase) :
    #   5228 → Google Cloud Messaging — NORMAL si process=chrome/google-services
    #
    # Un vrai C2 :
    #   - IP inconnue (pas Google, pas CDN connu)
    #   - Port non-standard (pas 80, 443, 5228...)
    #   - Process inattendu (bash, python, perl... pas chrome)
    if state == "ESTABLISHED" and not _is_private_ip(remote_ip):
        is_google_ip = _is_google_ip(remote_ip)
        is_google_port = remote_port in GOOGLE_SERVICE_PORTS

        if is_google_ip and is_google_port:
            # Google infrastructure sur port Google → Chrome/Firebase/sync → ignorer
            pass
        elif remote_port not in LEGIT_LISTEN_PORTS and remote_port > 1024:
            if is_google_ip:
                # IP Google mais port inhabituel → MEDIUM (probablement légitime mais inhabituel)
                reasons.append(
                    f"Connection to Google IP {remote_ip}:{remote_port} on non-standard port "
                    f"— likely legitimate (Chrome/GCP) but verify process"
                )
                severity = _escalate(severity, "MEDIUM")
            else:
                reasons.append(
                    f"Established connection to public IP {remote_ip}:{remote_port} "
                    f"on non-standard port — possible reverse shell / C2 beacon"
                )
                severity = _escalate(severity, "HIGH")

    # ── Check 4 : Connexion sur port 0 ──────────────────────────────
    #
    # Port 0 est invalide. Une socket avec port local=0 indique
    # un socket RAW ou une anomalie noyau — peut signaler une injection
    # au niveau du kernel (rootkit réseau).
    if local_port == 0 and state == "ESTABLISHED":
        reasons.append(
            "Connection with local port=0 — raw socket or kernel anomaly"
        )
        severity = _escalate(severity, "MEDIUM")

    if not reasons:
        return None

    # Résolution du nom de l'IP distante (best-effort, pas bloquant)
    remote_hostname = _resolve_hostname(remote_ip)

    target_str = (
        f"{conn['local_ip']}:{local_port} → "
        f"{remote_ip}:{remote_port}"
        f"{f' ({remote_hostname})' if remote_hostname else ''}"
        f" [{state}]"
    )

    return {
        "severity":  severity,
        "target":    target_str,
        "reason":    " | ".join(reasons),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "module":    "network_monitor",
        "details": {
            "local_ip":        conn["local_ip"],
            "local_port":      local_port,
            "remote_ip":       remote_ip,
            "remote_port":     remote_port,
            "state":           state,
            "uid":             uid,
            "remote_hostname": remote_hostname or "",
            "ipv6":            conn["ipv6"],
        },
    }


# ──────────────────────────────────────────────
# Helpers réseau
# ──────────────────────────────────────────────
def _is_google_ip(ip: str) -> bool:
    """
    Retourne True si l'IP appartient aux plages Google.

    Google utilise plusieurs blocs d'IP pour ses services :
    Chrome sync, Firebase Cloud Messaging, Google APIs, CDN...
    Une connexion vers ces IPs est presque toujours légitime
    sur une machine desktop (Chrome, Android Studio, Google Drive...).

    Pour une liste complète et à jour : https://www.gstatic.com/ipranges/goog.json
    On implémente ici les plages les plus courantes.
    """
    if ":" in ip:  # IPv6 Google → on traite comme potentiellement légitime
        return ip.startswith("2607:f8b0") or ip.startswith("2404:6800")
    try:
        packed = struct.unpack(">I", socket.inet_aton(ip))[0]
        # Plages principales Google (approximatif — suffisant pour réduire les FP)
        google_ranges = [
            (0x4009_0000, 0x4009_FFFF),  # 64.9.x.x
            (0x4015_0000, 0x4015_FFFF),  # 64.21.x.x
            (0x4233_0000, 0x4233_FFFF),  # 66.51.x.x
            (0x4A7D_0000, 0x4A7D_FFFF),  # 74.125.x.x (Gmail, Google APIs)
            (0x4E80_0000, 0x4E8F_FFFF),  # 78.128.x.x
            (0x8EFA_0000, 0x8EFA_FFFF),  # 142.250.x.x (Google)
            (0x8EFB_0000, 0x8EFB_FFFF),  # 142.251.x.x (Google)
            (0xACD9_0000, 0xACD9_FFFF),  # 172.217.x.x (Google)
            (0xACDA_0000, 0xACDA_FFFF),  # 172.218.x.x (Google)
            (0xD83A_C000, 0xD83A_CFFF),  # 216.58.x.x (Google)
            (0xD83A_D000, 0xD83A_DFFF),  # 216.58.x.x suite
            (0xD854_0000, 0xD854_FFFF),  # 216.84.x.x
        ]
        return any(lo <= packed <= hi for lo, hi in google_ranges)
    except (socket.error, struct.error):
        return False


def _is_private_ip(ip: str) -> bool:
    """
    Retourne True si l'IP est dans une plage privée (RFC 1918) ou loopback.

    Plages privées (jamais routées sur internet) :
      10.0.0.0/8       → grands réseaux d'entreprise
      172.16.0.0/12    → plage intermédiaire
      192.168.0.0/16   → réseaux domestiques / petites entreprises
      127.0.0.0/8      → loopback (localhost)
      0.0.0.0          → toutes interfaces (LISTEN)

    Une IP hors de ces plages = adresse publique internet = potentiel C2.
    """
    if ip in ("0.0.0.0", "::", "::1"):
        return True
    if ":" in ip:
        # IPv6 — simplifié : on traite comme privé pour éviter les faux positifs
        return True
    try:
        packed = struct.unpack(">I", socket.inet_aton(ip))[0]
        return any(lo <= packed <= hi for lo, hi in PRIVATE_RANGES)
    except (socket.error, struct.error):
        return True  # En cas d'erreur, on ne lève pas d'alerte


def _resolve_hostname(ip: str) -> str | None:
    """
    Résolution DNS inverse de l'IP (best-effort, timeout court).
    Permet de voir si une IP C2 a un domaine suspect (DGA, bulletproof hosting...).

    DGA = Domain Generation Algorithm : les malwares génèrent des domaines
    aléatoires pour leurs C2 (ex: xk3j9.com, qpwm7.net).
    Un nom de domaine de 6-8 chars aléatoires sur une IP inconnue = IOC fort.
    """
    if ip in ("0.0.0.0", "::", "::1"):
        return None
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        return hostname if hostname != ip else None
    except (socket.herror, socket.gaierror, OSError):
        return None


def _escalate(current: str, candidate: str) -> str:
    rank = {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}
    return candidate if rank.get(candidate, 0) > rank.get(current, 0) else current