# ⬡ SudoSu
### *Security Unified Defense & Offensive Scanning Utility*

> **Un scanner de sécurité Linux modulaire, écrit en Python pur.**  
> Forensic · Threat Detection · Firewall Advisory · Report Generation

```
  _____ _   _______ _____ _____ _   _
 /  ___| | | |  _  \  _  /  ___| | | |
 \ `--.| | | | | | | | | \ `--.| | | |
  `--. \ | | | | | | | | |`--. \ | | |
 /\__/ / |_| | |/ /\ \_/ /\__/ / |_| |
 \____/ \___/|___/  \___/\____/ \___/

 Security Unified Defense & Offensive Scanning Utility
 by SudoSu Labs  ·  v0.1.0
```

---

## Table des matières

- [Vue d'ensemble](#vue-densemble)
- [Architecture](#architecture)
- [Installation](#installation)
- [Usage](#usage)
- [Modules](#modules)
- [Exemples de sorties](#exemples-de-sorties)
- [Concepts cyber couverts](#concepts-cyber-couverts)
- [Roadmap](#roadmap)

---

## Vue d'ensemble

SudoSu est un outil d'audit de sécurité conçu pour détecter des compromissions sur un système Linux. Il combine plusieurs techniques utilisées par les professionnels de la sécurité offensive et défensive : analyse statique de fichiers, surveillance des processus, monitoring réseau, audit de logs, et génération de règles pare-feu contextuelles.

**Ce que SudoSu fait :**

- Scanne les fichiers à la recherche d'IOC (Indicators of Compromise) : extensions dangereuses, permissions SUID, patterns YARA-like, malwares fileless
- Vérifie les hashes SHA256 contre VirusTotal (70+ moteurs antivirus)
- Surveille les processus via `/proc` pour détecter les privilege escalations, webshells actifs, et reverse shells
- Lit `/proc/net/tcp` directement pour trouver des ports C2 et connexions suspectes
- Parse `auth.log` pour détecter le brute force SSH, les root logins, et les mouvements latéraux
- Génère des règles `iptables`/`ipset` contextuelles basées sur les menaces détectées
- Produit un rapport `report_<timestamp>.json` hashé SHA256 + rapport HTML standalone

**Ce que SudoSu ne fait PAS :**

- Il ne modifie jamais le système (lecture seule, sauf écriture des rapports)
- Il ne supprime aucun fichier
- Il n'applique jamais de règles pare-feu sans confirmation explicite

---

## Architecture

```
sudosu/
├── main.py                   # Point d'entrée CLI (argparse)
├── requirements.txt
│
├── config/
│   └── patterns.py           # Base de signatures IOC (YARA-like)
│
├── core/
│   ├── file_analyzer.py      # Analyse statique fichiers + permissions
│   ├── hash_checker.py       # SHA256 + VirusTotal API + FIM baseline
│   ├── process_watcher.py    # Surveillance /proc — PIDs, UIDs, fileless
│   ├── network_monitor.py    # /proc/net/tcp — ports, C2, reverse shells
│   ├── log_auditor.py        # auth.log, syslog, kern.log, cron.log
│   └── firewall_advisor.py   # Analyse iptables + règles recommandées
│
├── utils/
│   ├── printer.py            # Affichage Rich (couleurs, tableaux, progress)
│   ├── logger.py             # Logging UTC structuré par module
│   └── reporter.py           # Export JSON (hashé SHA256) + HTML standalone
│
├── reports/                  # Rapports générés (report_<timestamp>.json/html)
└── logs/                     # Logs de session (securescope_<timestamp>.log)
```

### Pipeline d'exécution

```
main.py
  │
  ├─► file_analyzer   →  findings[]  ─────────────────────────┐
  │                                                            │
  ├─► hash_checker    →  enrichit findings[] avec SHA256/VT   │
  │                                                            │
  ├─► process_watcher →  findings[]  ─────────────────────────┤
  │                                                            │
  ├─► network_monitor →  findings[]  ─────────────────────────┤
  │                                                            │
  ├─► log_auditor     →  findings[]  ─────────────────────────┤
  │                                                            ▼
  ├─► firewall_advisor ◄── corrèle TOUS les findings  →  recommandations
  │
  └─► reporter  →  report_<timestamp>.json + .html
      logger    →  logs/securescope_<timestamp>.log
```

---

## Installation

```bash
# Cloner le projet
git clone https://github.com/yourhandle/sudosu.git
cd sudosu

# Installer les dépendances (une seule : rich)
pip install -r requirements.txt

# Optionnel : clé API VirusTotal (gratuit sur virustotal.com)
export VT_API_KEY="votre_clé_ici"
```

**Dépendances :**
- Python 3.10+
- `rich` >= 13.7.0 (affichage terminal)
- Accès root recommandé pour lire `/proc/<PID>/exe` et `/var/log/auth.log`

---

## Usage

```bash
# Scan rapide du répertoire home
python main.py --target /home --mode quick

# Analyse complète avec rapport HTML
python main.py --target / --mode full --output html

# Scan des fichiers uniquement (+ VirusTotal si clé dispo)
python main.py --target /tmp --mode files --verbose

# Surveillance réseau + conseils pare-feu
python main.py --target / --mode network --output json

# Audit des logs système
python main.py --target / --mode logs --verbose

# Test sans rien écrire (dry-run)
python main.py --target /var/www --mode full --dry-run

# Forcer le mode Windows (cross-platform)
python main.py --target C:\Users --mode files --os windows
```

### Référence des arguments

| Argument | Valeurs | Description |
|----------|---------|-------------|
| `--target` / `-t` | chemin | Répertoire cible (défaut : `/`) |
| `--mode` / `-m` | `quick` `files` `network` `processes` `logs` `full` | Mode de scan |
| `--output` / `-o` | `json` `html` `txt` | Format du rapport |
| `--depth` / `-d` | entier | Profondeur max de récursion (défaut : 5) |
| `--verbose` / `-v` | flag | Affichage détaillé |
| `--dry-run` | flag | Scan sans écriture de rapport |
| `--os` | `linux` `windows` | Forcer le mode OS |

### Modes expliqués

| Mode | Modules actifs | Durée estimée |
|------|----------------|---------------|
| `quick` | file_analyzer uniquement | ~5-30s |
| `files` | file_analyzer + hash_checker (VT) | ~1-5min |
| `processes` | process_watcher | ~5s |
| `network` | network_monitor + firewall_advisor | ~10s |
| `logs` | log_auditor | ~15s |
| `full` | tous les modules | ~5-15min |

---

## Modules

### 🔍 file_analyzer — Analyse statique de fichiers

Parcourt récursivement le répertoire cible et applique 7 heuristiques en cascade, du moins cher au plus cher :

1. **Nom suspect** — `mimikatz`, `c99.php`, `beacon`, `meterpreter`...
2. **Double extension** — `rapport.pdf.sh`, `facture.doc.exe` (camouflage)
3. **Extension dangereuse** — `.sh`, `.php`, `.py` dans `/tmp`, `/dev/shm`
4. **Emplacement à risque** — `/tmp`, `/dev/shm`, `/var/tmp` (world-writable)
5. **Permissions SUID/world-writable** — privilege escalation et RCE
6. **Modification récente** — fichier système touché dans les dernières 24h
7. **Patterns YARA-like** — regex sur les 8 premiers Ko du fichier

Patterns détectés : reverse shells bash/python/perl/nc, webshells PHP (`eval(base64_decode`), credentials hardcodés, clés AWS/RSA privées, obfuscation base64.

Parallélisé avec `concurrent.futures.ThreadPoolExecutor` (8 threads).  
Filtre anti-bruit : minimum 2 IOC convergents pour sévérité MEDIUM.

---

### #️⃣ hash_checker — Empreinte cryptographique + Threat Intel

**Usage 1 — Identification :**  
Calcule le SHA256 de chaque fichier suspect et l'envoie à l'API VirusTotal. Si le hash est connu de 70+ antivirus → malware confirmé.

**Usage 2 — Intégrité (FIM) :**  
Compare les binaires système (`/bin/ls`, `/sbin/init`...) contre une baseline T0. Si le hash diffère → trojan binary détecté (technique rootkit classique).

- Lecture en streaming par chunks de 4 Mo (compatible fichiers volumineux)
- Déduplication par hash (1 seule requête VT si même malware à plusieurs endroits)
- Rate limiting respecté : 4 req/min sur l'API gratuite VirusTotal
- Hash envoyé, jamais le fichier lui-même (confidentialité)

---

### 👁 process_watcher — Surveillance des processus via /proc

Lit directement `/proc/<PID>/status`, `/proc/<PID>/cmdline`, `/proc/<PID>/exe` pour chaque processus actif.

Détections :
- **Privilege escalation** : `UID > 0` mais `EUID = 0` avec processus hors whitelist
- **Malware fileless** : `/proc/<PID>/exe` contient `(deleted)` — exécutable supprimé du disque mais toujours en RAM
- **Webshell actif** : shell (`bash`, `sh`) enfant d'un serveur web (`apache`, `nginx`, `php`)
- **Outils offensifs** : `mimikatz`, `meterpreter`, `sliver`, `chisel`... dans le nom ou la cmdline
- **Cmdline obfusquée** : `base64 -d`, `eval(__import__`, `bash -i >&`, `/dev/tcp/`
- **Shell orphelin** : `PPID=1` + shell interactif → reverse shell détaché

---

### 🌐 network_monitor — Surveillance réseau sans outil externe

Parse `/proc/net/tcp` et `/proc/net/tcp6` directement. Décode les adresses IP en little-endian (format natif kernel x86).

Détections :
- **Ports C2 connus** : 4444 (Meterpreter), 1337, 31337, 9001 (Cobalt Strike)...
- **Bind shell** : port inhabituel en état `LISTEN` avec processus = shell
- **Reverse shell** : connexion `ESTABLISHED` vers IP publique sur port non-standard
- **Port 0** : socket RAW ou anomalie kernel (possible injection réseau)

Résolution DNS inverse des IPs distantes pour détecter les domaines DGA (Domain Generation Algorithm).

---

### 📋 log_auditor — Forensic des logs système

Lit `auth.log`/`secure`, `syslog`/`messages`, `kern.log`, `cron.log`. Support des fichiers `.gz` (rotation). Fallback `journalctl` si fichiers texte absents.

Détections avec **corrélation temporelle** (agrégation multi-lignes) :
- **Brute force SSH** : > 10 échecs depuis même IP → `CRITICAL` si login réussi après
- **User enumeration** : > 5 usernames invalides tentés depuis même IP
- **Root login direct** : `Accepted password for root from X.X.X.X`
- **Sudo vers shell root** : `COMMAND=/bin/bash` dans les logs sudo
- **LKM Rootkit** : chargement de module kernel non standard (`insmod`, `modprobe`)
- **Persistence cron** : commandes cron avec `/tmp/`, `curl|sh`, `base64 -d`, reverse shells
- **Anti-forensic** : fichier `auth.log` vide ou tronqué

---

### 🛡 firewall_advisor — Analyse pare-feu + Règles contextuelles

Détecte le pare-feu actif (nftables → iptables → ufw → firewalld) et analyse sa configuration.

Analyse statique :
- Absence totale de pare-feu → `CRITICAL`
- Policy `INPUT ACCEPT` (default-allow) → `HIGH`
- Policy `OUTPUT ACCEPT` (pas d'egress filtering) → `MEDIUM`
- Règle `ESTABLISHED,RELATED` absente (stateful manquant) → `HIGH`

**Corrélation intelligente avec les autres modules :**
- IPs attaquantes (log_auditor) → règles `ipset` pour blocage O(1)
- Ports C2 (network_monitor) → `fuser -k <port>/tcp` + règles DROP
- Reverse shell détecté → recommandation egress filtering complet
- Brute force SSH → rate limiting `--recent` + fail2ban

Génère un script bash complet copier-coller avec commentaires.

---

### 📊 reporter — Rapports forensic

**JSON** : rapport structuré avec métadonnées, résumé par sévérité, findings détaillés.  
Le hash SHA256 du rapport lui-même est inclus dans `meta.report_hash` → chain of custody.

**HTML** : rapport standalone (CSS inline, aucune dépendance externe), thème dark, filtrable par sévérité. Ouvrable hors ligne, archivable 5 ans.

---

## Exemples de sorties

### Rapport JSON (extrait)

```json
{
  "meta": {
    "tool": "SudoSu v0.1.0",
    "timestamp": "2026-05-04T09:54:44Z",
    "os": "linux",
    "target": "/tmp",
    "mode": "full",
    "report_hash": "sha256:a3f1c2d8..."
  },
  "summary": {
    "total": 8,
    "critical": 2,
    "high": 4,
    "medium": 1,
    "low": 1
  },
  "findings": [
    {
      "severity": "CRITICAL",
      "target": "/tmp/update.sh",
      "reason": "Dangerous extension: .sh | Located in high-risk dir | Content pattern matched: reverse_shell_bash",
      "module": "file_analyzer",
      "details": {
        "sha256": "24d004a1...",
        "permissions": "-rwxr-xr-x",
        "matched_patterns": ["reverse_shell_bash"],
        "virustotal": {
          "malicious": 58,
          "total": 72,
          "vt_permalink": "https://www.virustotal.com/gui/file/24d004a1..."
        }
      }
    }
  ]
}
```

### Tableau de résultats (terminal)

```
╔══════════╦═══════════════════════════════╦═══════════════════════════════════╗
║ Severity ║ Path / Target                 ║ Reason                            ║
╠══════════╬═══════════════════════════════╬═══════════════════════════════════╣
║ CRITICAL ║ /tmp/update.sh                ║ reverse_shell_bash + high-risk    ║
║ CRITICAL ║ Brute force from 185.220.x.x  ║ 150 fails → SUCCESSFUL LOGIN      ║
║ HIGH     ║ /tmp/rapport.pdf.sh           ║ Double extension .pdf.sh          ║
║ HIGH     ║ PID 1337 (bash)               ║ Shell child of nginx (webshell)   ║
║ HIGH     ║ 0.0.0.0:4444 [LISTEN]         ║ Known C2 port (Meterpreter)       ║
╚══════════╩═══════════════════════════════╩═══════════════════════════════════╝
```

---

## Concepts cyber couverts

| Concept | Module | Description |
|---------|--------|-------------|
| IOC (Indicator of Compromise) | file_analyzer | Artefacts révélateurs d'une compromission |
| YARA rules | file_analyzer | Signatures de détection basées sur patterns |
| SUID bit / Privilege Escalation | file_analyzer, process_watcher | UID réel ≠ UID effectif |
| Malware fileless | process_watcher | Exécutable supprimé, toujours en RAM |
| Webshell detection | process_watcher | Shell enfant d'un serveur web |
| SHA256 / Chain of custody | hash_checker | Intégrité cryptographique |
| File Integrity Monitoring (FIM) | hash_checker | Baseline + comparaison binaires |
| VirusTotal Threat Intel | hash_checker | 70+ AV engines via API |
| /proc filesystem | process_watcher, network_monitor | Interface directe kernel Linux |
| Little-endian decoding | network_monitor | Décodage IPs /proc/net/tcp |
| C2 (Command & Control) | network_monitor | Détection beacons et reverse shells |
| Bind shell vs Reverse shell | network_monitor | Techniques d'accès distant |
| DGA (Domain Generation Algorithm) | network_monitor | Domaines C2 aléatoires |
| Brute force + corrélation temporelle | log_auditor | Agrégation multi-lignes |
| PAM (Pluggable Auth Modules) | log_auditor | Couche d'abstraction auth Linux |
| LKM Rootkit | log_auditor | Modules kernel malveillants |
| Anti-forensic detection | log_auditor | Logs effacés/tronqués |
| Default Deny policy | firewall_advisor | Blocklist vs allowlist |
| Stateful firewall | firewall_advisor | ESTABLISHED,RELATED |
| Egress filtering | firewall_advisor | Filtrage sortant contre reverse shells |
| ipset O(1) vs iptables O(N) | firewall_advisor | Blocage efficace de listes d'IPs |
| SOAR (Security Orchestration) | firewall_advisor | Corrélation multi-sources → réponse |
| UTC logging / Chain of custody | logger, reporter | Traçabilité forensic internationale |
| Report integrity hash | reporter | SHA256 du rapport lui-même |

---

## Roadmap

- [ ] `--baseline` : créer une baseline FIM des binaires système
- [ ] `--compare` : comparer deux rapports (avant/après incident)
- [ ] Module `vuln_scanner` : CVEs connus via NIST NVD API
- [ ] Module `ssh_auditor` : analyse de `/etc/ssh/sshd_config`
- [ ] Export STIX 2.1 (format standard partage de threat intel)
- [ ] Intégration webhook Slack/Discord pour alertes temps réel
- [ ] Mode daemon : surveillance continue avec alertes

---

## Avertissement légal

SudoSu est conçu pour l'audit de **vos propres systèmes** ou dans un cadre autorisé explicitement (pentest avec scope défini, bug bounty).  
L'utilisation sur des systèmes sans autorisation est illégale dans la plupart des juridictions.  
L'auteur décline toute responsabilité pour un usage malveillant.

---

*SudoSu Labs — Built for defenders, inspired by attackers.*
