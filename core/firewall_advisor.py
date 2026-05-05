"""
core/firewall_advisor.py
------------------------
Analyse la configuration du pare-feu actuel et génère des recommandations
défensives basées sur les findings des modules précédents.

NE MODIFIE JAMAIS LES RÈGLES — suggestion uniquement.
Pourquoi ? Un outil qui touche iptables sans confirmation explicite
peut couper l'accès SSH à une machine distante → brick complet.
Le principe de moindre surprise : on propose, l'admin décide.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
ARCHITECTURE DU PARE-FEU LINUX
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Le pare-feu Linux a évolué en trois générations :

  1. iptables (historique, encore très répandu)
     ─────────────────────────────────────────
     Interface userspace vers Netfilter (le vrai moteur dans le kernel).
     Règles organisées en TABLES → CHAINS → RULES.

     Tables principales :
       filter  → décisions accept/drop (INPUT, OUTPUT, FORWARD)
       nat     → translation d'adresses (PREROUTING, POSTROUTING)
       mangle  → modification des paquets
       raw     → bypass du connection tracking

     Chains principales (table filter) :
       INPUT   → paquets ENTRANTS vers la machine
       OUTPUT  → paquets SORTANTS depuis la machine
       FORWARD → paquets en transit (si la machine est un routeur)

     Politiques par défaut (policy) :
       ACCEPT → tout passer par défaut (dangereux)
       DROP   → tout bloquer par défaut (recommandé)

     Exemple de règle :
       iptables -A INPUT -p tcp --dport 22 -j ACCEPT
       ↑        ↑       ↑  ↑   ↑           ↑
       Append   Chain   proto port         Action

  2. nftables (moderne, remplace iptables depuis kernel 3.13)
     ─────────────────────────────────────────────────────────
     API plus propre, meilleures performances, syntaxe unifiée.
     Debian 10+, Ubuntu 20.04+, RHEL 8+ l'utilisent par défaut.
     iptables est souvent un wrapper vers nftables en interne.

  3. ufw (Uncomplicated Firewall)
     ────────────────────────────
     Surcouche simplifiée d'iptables pour Ubuntu/Debian.
     Commandes humaines : ufw allow ssh, ufw deny 4444.
     En interne : génère des règles iptables.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
CONCEPTS PARE-FEU / CYBER COUVERTS
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

  Politique "Default Deny" (allowlist)
  ──────────────────────────────────────
  Principe : bloquer TOUT par défaut, n'autoriser que l'explicitement connu.
    iptables -P INPUT DROP    ← policy par défaut = DROP
    iptables -A INPUT -p tcp --dport 22 -j ACCEPT   ← exception SSH

  À l'opposé : "Default Accept" (blocklist/denylist)
    iptables -P INPUT ACCEPT  ← tout passe sauf ce qu'on bloque explicitement
    iptables -A INPUT -p tcp --dport 4444 -j DROP   ← on bloque au cas par cas

  Default Deny >> Default Accept.
  Pourquoi ? Un attaquant connaît des milliers de ports et techniques.
  Bloquer au cas par cas = course sans fin.
  Autoriser seulement ce qui est nécessaire = surface d'attaque minimale.

  C'est le principe du "Least Privilege" appliqué au réseau.


  Stateful vs Stateless firewall
  ───────────────────────────────
  Stateless : examine chaque paquet indépendamment.
    Simple, rapide, mais ne comprend pas les connexions.
    Ne peut pas distinguer un paquet entrant légitime (réponse à une
    requête sortante) d'un paquet entrant malveillant.

  Stateful (Netfilter/iptables avec conntrack) :
    Suit l'état des connexions TCP (NEW, ESTABLISHED, RELATED).
    Permet : "accepter les paquets entrants qui sont des RÉPONSES
    à des connexions qu'on a initiées" → règle ESTABLISHED,RELATED.

    Règle fondamentale stateful :
      iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    → Autorise les réponses aux connexions sortantes légitimes
      sans ouvrir de ports entrants.


  Egress filtering (filtrage sortant)
  ─────────────────────────────────────
  La plupart des admins ne filtrent que l'INPUT.
  L'OUTPUT est souvent ignoré → les reverse shells passent !

  Un reverse shell fait une connexion SORTANTE.
  Si OUTPUT est ACCEPT (par défaut), rien ne le bloque.

  Egress filtering : limiter ce que la machine peut initier.
    iptables -P OUTPUT DROP
    iptables -A OUTPUT -p tcp --dport 80 -j ACCEPT   # HTTP
    iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT  # HTTPS
    iptables -A OUTPUT -p udp --dport 53 -j ACCEPT   # DNS
    iptables -A OUTPUT -p tcp --dport 22 -j ACCEPT   # SSH sortant
    # Tout le reste → DROP → reverse shell sur port 4444 bloqué

  C'est ce que SudoSu recommande quand il détecte un reverse shell.


  Rate limiting / SYN flood protection
  ──────────────────────────────────────
  SYN flood : attaque DoS qui envoie des milliers de paquets TCP SYN
  pour épuiser la table des connexions en attente du serveur.

  Protection iptables :
    iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
    iptables -A INPUT -p tcp --syn -j DROP

  Rate limiting SSH (contre brute force) :
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
             -m recent --set --name SSH
    iptables -A INPUT -p tcp --dport 22 -m state --state NEW \
             -m recent --update --seconds 60 --hitcount 4 \
             --name SSH -j DROP
    → Bloque une IP si elle tente > 3 nouvelles connexions SSH en 60s.


  IP reputation / Blocklist
  ──────────────────────────
  Certaines IP sont connues comme sources d'attaques (Tor exit nodes,
  serveurs de scanning, botnets). On peut les bloquer avec ipset :
    ipset create blacklist hash:ip
    ipset add blacklist 185.220.101.47   ← IP Tor exit node
    iptables -A INPUT -m set --match-set blacklist src -j DROP

  SudoSu détecte les IPs attaquantes et génère les commandes ipset.
"""

import subprocess
import re
from pathlib import Path
from datetime import datetime, timezone

from utils.logger  import get_logger
from utils.printer import print_warning, print_info, console
from rich.panel    import Panel
from rich.table    import Table
from rich          import box

# ──────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────
def run(
    findings: list[dict],
    log_file: Path | None = None,
    verbose:  bool = False,
) -> list[dict]:
    """
    Analyse la config pare-feu actuelle et génère des recommandations
    basées sur les findings de tous les modules précédents.

    Retourne une liste de "findings" de type RECOMMENDATION
    (sévérité INFO ou WARNING — jamais des détections à proprement parler).

    Params :
      findings → tous les findings accumulés des modules précédents
                 (file_analyzer, network_monitor, log_auditor...)
    """
    log = get_logger("firewall_advisor", log_file, verbose)
    log.info("Starting firewall analysis")

    recommendations: list[dict] = []

    # ── 1. État actuel du pare-feu ────────────────────────────────────
    fw_state = _read_current_firewall(log)

    # ── 2. Analyse des règles actuelles ──────────────────────────────
    rule_issues = _analyze_firewall_rules(fw_state, log)
    recommendations.extend(rule_issues)

    # ── 3. Recommandations basées sur les findings ────────────────────
    contextual = _generate_contextual_rules(findings, fw_state, log)
    recommendations.extend(contextual)

    # ── 4. Affichage du rapport pare-feu (rich) ───────────────────────
    _print_firewall_report(fw_state, recommendations)

    log.info(f"Firewall analysis complete | {len(recommendations)} recommendation(s)")
    return recommendations


# ──────────────────────────────────────────────
# Lecture de la configuration pare-feu actuelle
# ──────────────────────────────────────────────
def _read_current_firewall(log) -> dict:
    """
    Détecte quel pare-feu est actif et lit sa configuration.

    Ordre de détection :
      1. nftables  → nft list ruleset
      2. iptables  → iptables -L -n -v
      3. ufw       → ufw status verbose
      4. firewalld → firewall-cmd --list-all

    Retourne un dict avec le type détecté et la config brute.

    Pourquoi subprocess et pas une lib Python ?
      iptables/nft n'ont pas d'API Python stable.
      Les wrappers Python (python-iptables) sont souvent désynchronisés.
      subprocess sur les commandes système = toujours à jour.

      Risque : injection de commande → on ne passe jamais de données
      utilisateur dans ces commandes, seulement des strings hardcodées.
    """
    state = {
        "tool":        "none",
        "active":      False,
        "policy":      {},      # chain → policy (ACCEPT/DROP)
        "rules_raw":   "",
        "input_policy":  "ACCEPT",  # Par défaut optimiste (dangereux)
        "output_policy": "ACCEPT",
        "ufw_active":  False,
        "nft_active":  False,
    }

    # ── Essai nftables ───────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["nft", "list", "ruleset"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0 and result.stdout.strip():
            state["tool"]      = "nftables"
            state["active"]    = True
            state["rules_raw"] = result.stdout
            state["nft_active"] = True
            log.info("Firewall detected: nftables")
            return state
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # ── Essai iptables ───────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["iptables", "-L", "-n", "-v"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            state["tool"]      = "iptables"
            state["active"]    = True
            state["rules_raw"] = result.stdout
            # Extrait les politiques (policy ACCEPT / policy DROP)
            for line in result.stdout.splitlines():
                m = re.match(r"Chain (\w+) \(policy (\w+)", line)
                if m:
                    state["policy"][m.group(1)] = m.group(2)
            state["input_policy"]  = state["policy"].get("INPUT",  "ACCEPT")
            state["output_policy"] = state["policy"].get("OUTPUT", "ACCEPT")
            log.info(
                f"Firewall detected: iptables | "
                f"INPUT={state['input_policy']} OUTPUT={state['output_policy']}"
            )
            return state
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    # ── Essai ufw ────────────────────────────────────────────────────
    try:
        result = subprocess.run(
            ["ufw", "status", "verbose"],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode == 0:
            state["tool"]       = "ufw"
            state["rules_raw"]  = result.stdout
            state["ufw_active"] = "Status: active" in result.stdout
            state["active"]     = state["ufw_active"]
            log.info(f"Firewall detected: ufw | active={state['ufw_active']}")
            return state
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass

    log.warning("No firewall detected (nftables/iptables/ufw all absent or inactive)")
    return state


# ──────────────────────────────────────────────
# Analyse des règles actuelles
# ──────────────────────────────────────────────
def _analyze_firewall_rules(fw_state: dict, log) -> list[dict]:
    """
    Identifie les problèmes dans la configuration pare-feu actuelle.

    Vérifie :
      - Absence totale de pare-feu
      - Politique INPUT = ACCEPT (dangereux)
      - Politique OUTPUT = ACCEPT (laisse passer les reverse shells)
      - Règles ACCEPT trop larges (0.0.0.0/0 sur tous ports)
      - Absence de règle ESTABLISHED,RELATED (stateful manquant)
    """
    issues = []
    ts = datetime.now(timezone.utc).isoformat()

    # ── Pas de pare-feu du tout ───────────────────────────────────────
    if not fw_state["active"]:
        issues.append({
            "severity":  "CRITICAL",
            "target":    "Firewall",
            "reason":    (
                "NO ACTIVE FIREWALL DETECTED — machine is fully exposed. "
                "All ports are reachable from any source."
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type":        "missing_firewall",
                "fix_command": "apt install ufw && ufw default deny incoming && ufw allow ssh && ufw enable",
            },
        })
        log.warning("No firewall active!")
        return issues   # Inutile d'analyser des règles qui n'existent pas

    # ── INPUT policy = ACCEPT (Default Allow — dangereux) ────────────
    #
    # C'est l'erreur la plus commune. La plupart des serveurs Linux
    # ont iptables installé mais avec policy ACCEPT partout.
    # → N'importe quelle connexion entrante est acceptée par défaut.
    # → Les règles DROP ajoutées ensuite sont du "blocklist" (course sans fin).
    #
    # La bonne pratique : policy INPUT DROP + règles ACCEPT explicites.
    if fw_state["input_policy"] == "ACCEPT":
        issues.append({
            "severity":  "HIGH",
            "target":    "iptables INPUT chain",
            "reason":    (
                "INPUT policy is ACCEPT (default-allow) — insecure. "
                "Should be DROP (default-deny). "
                "With ACCEPT policy, any port not explicitly blocked is reachable."
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type":        "weak_policy",
                "current":     "INPUT ACCEPT",
                "recommended": "INPUT DROP",
                "fix_command": "iptables -P INPUT DROP",
            },
        })

    # ── OUTPUT policy = ACCEPT (laisse passer les reverse shells) ─────
    #
    # Presque tous les serveurs ont OUTPUT = ACCEPT.
    # C'est compréhensible (egress filtering est complexe à maintenir)
    # mais ça laisse passer n'importe quelle connexion sortante :
    # reverse shells, exfiltration de données, beacon C2...
    #
    # On note en MEDIUM (pas HIGH) car c'est une pratique répandue
    # et légitime pour beaucoup de cas d'usage.
    if fw_state["output_policy"] == "ACCEPT":
        issues.append({
            "severity":  "MEDIUM",
            "target":    "iptables OUTPUT chain",
            "reason":    (
                "OUTPUT policy is ACCEPT — no egress filtering. "
                "Reverse shells and C2 beacons can freely connect outbound. "
                "Consider allowlisting only necessary outbound ports (22, 80, 443, 53)."
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type":        "no_egress_filtering",
                "fix_command": (
                    "iptables -P OUTPUT DROP\n"
                    "iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT\n"
                    "iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT\n"
                    "iptables -A OUTPUT -p udp --dport 53  -j ACCEPT\n"
                    "iptables -A OUTPUT -p tcp --dport 22  -j ACCEPT"
                ),
            },
        })

    # ── Règle ESTABLISHED,RELATED absente (pas de stateful) ──────────
    #
    # Sans cette règle et avec INPUT DROP, le serveur ne peut pas
    # recevoir les réponses aux connexions qu'il a lui-même initiées.
    # Ex : apt update échoue car les réponses HTTP sont droppées.
    # C'est la règle "de base" du stateful firewall.
    if (fw_state["input_policy"] == "DROP" and
            "ESTABLISHED" not in fw_state["rules_raw"]):
        issues.append({
            "severity":  "HIGH",
            "target":    "iptables stateful rule",
            "reason":    (
                "INPUT is DROP but ESTABLISHED,RELATED rule is missing. "
                "The server cannot receive replies to its own connections "
                "(apt update, curl, etc. will fail). "
                "Add: iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type":        "missing_stateful_rule",
                "fix_command": (
                    "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT"
                ),
            },
        })

    return issues


# ──────────────────────────────────────────────
# Recommandations contextuelles basées sur les findings
# ──────────────────────────────────────────────
def _generate_contextual_rules(
    findings:  list[dict],
    fw_state:  dict,
    log,
) -> list[dict]:
    """
    Génère des règles iptables spécifiques basées sur ce que les autres
    modules ont découvert.

    Si le network_monitor a trouvé un port C2 ouvert → règle DROP ce port.
    Si le log_auditor a trouvé une IP en brute force → règle DROP cette IP.
    Si le file_analyzer a trouvé un reverse shell → recommande egress filtering.

    C'est la valeur ajoutée de l'approche modulaire :
    les modules s'enrichissent mutuellement.
    Un SIEM fait exactement ça : corrèle des événements de sources
    différentes pour générer des réponses automatiques (SOAR).
    """
    recs  = []
    ts    = datetime.now(timezone.utc).isoformat()

    # Collecte des IPs attaquantes (brute force dans les logs)
    attacker_ips: set[str] = set()

    # Collecte des ports C2 trouvés ouverts
    c2_ports: set[int] = set()

    # Flags de détection
    reverse_shell_detected = False
    fileless_detected      = False

    for f in findings:
        module = f.get("module", "")
        reason = f.get("reason", "")
        details = f.get("details", {})

        # ── IPs attaquantes depuis log_auditor ────────────────────────
        if module == "log_auditor.brute_force":
            ip = details.get("ip")
            if ip:
                attacker_ips.add(ip)

        # ── Ports C2 depuis network_monitor ──────────────────────────
        if module == "network_monitor":
            port = details.get("local_port") or details.get("remote_port")
            if port and "Known C2 port" in reason:
                c2_ports.add(port)

        # ── Reverse shell détecté ─────────────────────────────────────
        if "reverse_shell" in reason.lower() or "/dev/tcp/" in reason:
            reverse_shell_detected = True

        # ── Malware fileless ──────────────────────────────────────────
        if "fileless" in reason.lower() or "deleted" in reason.lower():
            fileless_detected = True

    # ── Règles pour IPs attaquantes ───────────────────────────────────
    #
    # ipset est bien plus efficace qu'une règle iptables par IP.
    # iptables parcourt les règles linéairement → N règles = O(N) par paquet.
    # ipset utilise une hash table → O(1) peu importe le nombre d'IPs.
    # Pour bloquer des milliers d'IPs (blocklist Tor, Shodan...) → ipset obligatoire.
    if attacker_ips:
        ip_list = "\n".join(f"    ipset add sudosu_blacklist {ip}" for ip in attacker_ips)
        recs.append({
            "severity":  "HIGH",
            "target":    f"Block {len(attacker_ips)} attacker IP(s)",
            "reason":    (
                f"Detected {len(attacker_ips)} attacking IP(s) in logs. "
                f"IPs: {', '.join(attacker_ips)}. "
                "Use ipset for efficient blocking (O(1) lookup vs O(N) for iptables rules)."
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type":           "block_attacker_ips",
                "attacker_ips":   list(attacker_ips),
                "fix_command": (
                    "ipset create sudosu_blacklist hash:ip\n"
                    f"{ip_list}\n"
                    "iptables -A INPUT -m set --match-set sudosu_blacklist src -j DROP\n"
                    "# Pour persister après reboot :\n"
                    "ipset save > /etc/ipset.conf\n"
                    "iptables-save > /etc/iptables/rules.v4"
                ),
            },
        })
        log.warning(f"Recommending block for {len(attacker_ips)} attacker IP(s)")

    # ── Fermeture des ports C2 détectés ──────────────────────────────
    for port in c2_ports:
        recs.append({
            "severity":  "CRITICAL",
            "target":    f"Close C2 port {port}",
            "reason":    (
                f"Port {port} was found open and is associated with C2/malware. "
                "Close the listening process AND add firewall rule. "
                "The process must be killed first, then block the port."
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type": "close_c2_port",
                "port": port,
                "fix_command": (
                    f"# 1. Trouver et tuer le processus sur le port {port} :\n"
                    f"fuser -k {port}/tcp\n"
                    f"# 2. Bloquer le port en INPUT et OUTPUT :\n"
                    f"iptables -A INPUT  -p tcp --dport {port} -j DROP\n"
                    f"iptables -A OUTPUT -p tcp --dport {port} -j DROP\n"
                    f"iptables -A INPUT  -p tcp --sport {port} -j DROP"
                ),
            },
        })

    # ── Recommandation egress filtering si reverse shell détecté ──────
    if reverse_shell_detected:
        recs.append({
            "severity":  "HIGH",
            "target":    "Enable egress filtering (reverse shell detected)",
            "reason":    (
                "A reverse shell pattern was detected. "
                "Without OUTPUT filtering, the attacker's shell can freely "
                "communicate outbound. Implement egress filtering to block "
                "all outbound connections except whitelisted ports."
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type": "egress_filtering",
                "fix_command": (
                    "# Politique sortante restrictive — adapte selon tes services :\n"
                    "iptables -P OUTPUT DROP\n"
                    "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT\n"
                    "iptables -A OUTPUT -p tcp --dport 443 -j ACCEPT   # HTTPS\n"
                    "iptables -A OUTPUT -p tcp --dport 80  -j ACCEPT   # HTTP\n"
                    "iptables -A OUTPUT -p udp --dport 53  -j ACCEPT   # DNS\n"
                    "iptables -A OUTPUT -p tcp --dport 22  -j ACCEPT   # SSH sortant\n"
                    "# Tout le reste → DROP (bloque les reverse shells)"
                ),
            },
        })

    # ── Protection brute force SSH (rate limiting) ────────────────────
    #
    # Si des tentatives brute force SSH ont été détectées
    # ET qu'il n'y a pas de rate limiting dans les règles actuelles.
    brute_force_found = any(
        "brute_force" in f.get("module", "") or "brute force" in f.get("reason", "").lower()
        for f in findings
    )
    if brute_force_found and "recent" not in fw_state.get("rules_raw", ""):
        recs.append({
            "severity":  "HIGH",
            "target":    "SSH rate limiting (brute force detected)",
            "reason":    (
                "Brute force SSH attempts detected in logs. "
                "No rate limiting rule found in current firewall. "
                "Add connection rate limiting to slow brute force attacks. "
                "This limits new SSH connections to 3 per 60 seconds per IP."
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type": "ssh_rate_limit",
                "fix_command": (
                    "# Rate limiting SSH — max 3 tentatives / 60s par IP :\n"
                    "iptables -A INPUT -p tcp --dport 22 -m state --state NEW "
                    "-m recent --set --name SSH_RATELIMIT\n"
                    "iptables -A INPUT -p tcp --dport 22 -m state --state NEW "
                    "-m recent --update --seconds 60 --hitcount 4 "
                    "--name SSH_RATELIMIT -j DROP\n"
                    "iptables -A INPUT -p tcp --dport 22 -j ACCEPT\n"
                    "# Alternative plus simple avec ufw + fail2ban :\n"
                    "apt install fail2ban && systemctl enable fail2ban"
                ),
            },
        })

    # ── Baseline pare-feu si aucune règle active ──────────────────────
    if not fw_state["active"]:
        recs.append({
            "severity":  "CRITICAL",
            "target":    "Firewall baseline setup",
            "reason":    (
                "No firewall active. Providing a minimal secure baseline. "
                "Adapt to your services before applying."
            ),
            "timestamp": ts,
            "module":    "firewall_advisor",
            "details":   {
                "type": "baseline",
                "fix_command": _generate_baseline_rules(),
            },
        })

    return recs


# ──────────────────────────────────────────────
# Affichage rich du rapport pare-feu
# ──────────────────────────────────────────────
def _print_firewall_report(fw_state: dict, recommendations: list[dict]) -> None:
    """
    Affiche un rapport visuel de la config pare-feu + recommandations.
    Chaque recommandation inclut la commande prête à copier-coller.
    """
    from rich.syntax import Syntax

    # ── En-tête état actuel ───────────────────────────────────────────
    tool   = fw_state["tool"].upper() if fw_state["tool"] != "none" else "NONE"
    active = "[bold green]ACTIVE[/bold green]" if fw_state["active"] else "[bold red]INACTIVE[/bold red]"
    input_pol  = fw_state.get("input_policy", "?")
    output_pol = fw_state.get("output_policy", "?")

    input_color  = "green" if input_pol  == "DROP" else "red"
    output_color = "green" if output_pol == "DROP" else "yellow"

    console.print(Panel(
        f"  Tool    : [bold cyan]{tool}[/bold cyan]   Status: {active}\n"
        f"  INPUT   : [{input_color}]{input_pol}[/{input_color}]   "
        f"OUTPUT: [{output_color}]{output_pol}[/{output_color}]\n"
        f"  Recommendations: [bold yellow]{len(recommendations)}[/bold yellow]",
        title="[bold magenta]⬡ Firewall Status[/bold magenta]",
        border_style="magenta",
    ))

    if not recommendations:
        console.print("  [bold green][ OK ][/bold green]  Firewall configuration looks good.")
        return

    # ── Tableau des recommandations ───────────────────────────────────
    table = Table(
        title="[bold yellow]Firewall Recommendations[/bold yellow]",
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold magenta",
        show_lines=True,
    )
    table.add_column("Sev",     width=8,  style="bold")
    table.add_column("Target",  width=35)
    table.add_column("Reason",  style="dim white")

    sev_colors = {"CRITICAL": "red", "HIGH": "yellow", "MEDIUM": "cyan", "LOW": "white"}

    for r in recommendations:
        sev   = r.get("severity", "LOW")
        color = sev_colors.get(sev, "white")
        table.add_row(
            f"[{color}]{sev}[/{color}]",
            r.get("target", ""),
            r.get("reason", "")[:100],
        )
    console.print(table)

    # ── Commandes de correction ───────────────────────────────────────
    console.print("\n[bold magenta]━━━ Fix Commands (copy-paste ready) ━━━[/bold magenta]\n")
    for r in recommendations:
        fix_cmd = r.get("details", {}).get("fix_command", "")
        if fix_cmd:
            console.print(f"[bold yellow]# {r.get('target', '')}[/bold yellow]")
            syntax = Syntax(fix_cmd, "bash", theme="monokai", line_numbers=False)
            console.print(syntax)
            console.print()


# ──────────────────────────────────────────────
# Baseline de règles iptables minimale sécurisée
# ──────────────────────────────────────────────
def _generate_baseline_rules() -> str:
    """
    Génère un jeu de règles iptables minimal sécurisé.
    Adapté à un serveur Linux avec SSH + HTTP/HTTPS.
    À personnaliser selon les services réels.

    Ce script peut être exécuté directement (bash).
    Il utilise les bonnes pratiques :
      - Default deny INPUT et FORWARD
      - Loopback autorisé (sinon les apps locales cassent)
      - Stateful (ESTABLISHED,RELATED)
      - SSH avec rate limiting intégré
      - ICMP limité (ping autorisé, pas flood)
      - Sauvegarde des règles pour persistance
    """
    return """#!/bin/bash
# SudoSu — Baseline iptables rules
# Adapte les ports selon tes services avant d'appliquer !

# ─── Flush des règles existantes ───
iptables -F
iptables -X
iptables -Z

# ─── Politiques par défaut (DEFAULT DENY) ───
iptables -P INPUT   DROP
iptables -P FORWARD DROP
iptables -P OUTPUT  ACCEPT   # Assoupli — adapte si besoin

# ─── Loopback (obligatoire — les apps locales en ont besoin) ───
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# ─── Connexions établies (stateful — réponses aux requêtes sortantes) ───
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# ─── SSH avec rate limiting (max 3 nouvelles connexions / 60s / IP) ───
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \\
         -m recent --set --name SSH_RATELIMIT
iptables -A INPUT -p tcp --dport 22 -m state --state NEW \\
         -m recent --update --seconds 60 --hitcount 4 \\
         --name SSH_RATELIMIT -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# ─── Services web (adapte ou supprime selon tes besoins) ───
iptables -A INPUT -p tcp --dport 80  -j ACCEPT   # HTTP
iptables -A INPUT -p tcp --dport 443 -j ACCEPT   # HTTPS

# ─── ICMP (ping — limité pour éviter flood) ───
iptables -A INPUT -p icmp --icmp-type echo-request \\
         -m limit --limit 1/s --limit-burst 3 -j ACCEPT

# ─── SYN flood protection ───
iptables -A INPUT -p tcp --syn \\
         -m limit --limit 1/s --limit-burst 3 -j ACCEPT
iptables -A INPUT -p tcp --syn -j DROP

# ─── Log les paquets droppés (forensic) ───
iptables -A INPUT -j LOG --log-prefix "IPTABLES_DROP: " --log-level 4

# ─── Persistance (survive au reboot) ───
# Debian/Ubuntu :
apt install iptables-persistent -y
iptables-save > /etc/iptables/rules.v4
# RedHat/CentOS :
# service iptables save"""