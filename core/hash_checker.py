"""
core/hash_checker.py
--------------------
Vérification cryptographique des fichiers suspects.

Deux usages distincts du hash — c'est LA nuance à comprendre :

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
USAGE 1 — IDENTIFICATION (Threat Intelligence)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  On calcule le SHA256 d'un fichier suspect et on le compare à
  une base de malwares connus (VirusTotal, NSRL, MISP...).

  Logique : si evil.sh a le même SHA256 qu'un malware connu,
  c'est le même fichier — peu importe son nom ou son emplacement.

  → Le hash EST une identité cryptographique du contenu.
  → Si le hash match → malware CONFIRMÉ, pas juste "suspect".

  Exemple réel : WannaCry a le hash
    SHA256: 24d004a104d4d54034dbcffc2a4b19a11f39008a575aa614ea04703480b1022c
  N'importe où dans le monde, ce fichier = WannaCry.


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
USAGE 2 — INTÉGRITÉ (Forensic / File Integrity Monitoring)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  On hash un fichier à T0 (ex: installation propre), puis à T1.
  Si les deux hashes diffèrent → le fichier a été modifié.

  → Oui, si quelqu'un MODIFIE le fichier, le hash CHANGE.
  → C'est précisément l'intérêt : détecter cette modification.

  Cas d'usage concrets :
    - /bin/ls hashé à T0 = aabbcc...
    - Après intrusion : /bin/ls hashé à T1 = ff1234...  ← ALERTE
    - Un rootkit a remplacé /bin/ls par une version qui cache
      les processus malveillants (technique "trojan binaries").

  Pour le RAPPORT lui-même (reporter.py) :
    - On hash le rapport à sa génération → meta.report_hash
    - Si quelqu'un altère le rapport après coup, le hash stocké
      ne correspondra plus au contenu actuel.
    - En procédure légale = preuve que le rapport est intact.
    - NOTE : si l'attaquant peut modifier LE FICHIER ET recalculer
      le hash, la protection est nulle → en forensic pro, on signe
      avec GPG ou on dépose le hash chez un tiers (horodatage notarié).


━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
POURQUOI SHA256 ET PAS MD5 ?
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
  MD5 est CASSÉ depuis 2004 (Wang et al.) :
    - Deux fichiers DIFFÉRENTS peuvent avoir le MÊME MD5
      → "collision attack"
    - Un attaquant peut créer un malware avec le même MD5
      qu'un fichier légitime → contourner la détection.

  SHA256 résiste aux collisions connues (2^128 de résistance).
  SHA512 est encore plus fort mais trop lent pour scanner
  des milliers de fichiers. SHA256 = meilleur compromis.

  VirusTotal utilise MD5 + SHA1 + SHA256 pour rétrocompatibilité.
"""

import hashlib
import os
import time
import urllib.request
import urllib.error
import json
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed

from utils.logger import get_logger

CHUNK_SIZE          = 4 * 1024 * 1024   # 4 Mo par chunk (lecture streaming)
VT_RATE_LIMIT_DELAY = 15.0              # 4 req/min en gratuit → 15s entre chaque
VT_MAX_FILE_SIZE    = 32 * 1024 * 1024  # 32 Mo max pour l'API gratuite
VT_API_URL          = "https://www.virustotal.com/api/v3/files/{hash}"
VT_DETECTION_THRESHOLD = 3              # N moteurs → CRITICAL


# ──────────────────────────────────────────────
# Point d'entrée principal
# ──────────────────────────────────────────────
def run(
    findings: list[dict],
    log_file: Path | None = None,
    verbose:  bool = False,
) -> list[dict]:
    """
    Prend la liste des findings du file_analyzer et enrichit chacun
    avec son SHA256. Interroge VirusTotal si une clé API est disponible.

    Stratégie :
      1. Calculer SHA256 de chaque fichier suspect
      2. Dédupliquer par hash (même malware = même hash, chemins différents)
      3. Interroger VT pour les hashes uniques
      4. Enrichir les findings avec les résultats
    """
    log = get_logger("hash_checker", log_file, verbose)

    if not findings:
        log.info("No findings to hash-check")
        return findings

    vt_api_key = os.environ.get("VT_API_KEY", "")
    if vt_api_key:
        log.info("VirusTotal API key found — online lookup enabled")
    else:
        log.info("No VT_API_KEY — local hash only (export VT_API_KEY=<key> to enable)")

    log.info(f"Computing SHA256 for {len(findings)} finding(s)...")

    # ── Calcul des hashes en parallèle ──────────────────────────────
    hashes: dict[str, str] = {}  # path → sha256

    with ThreadPoolExecutor(max_workers=8) as executor:
        future_to_path = {
            executor.submit(_compute_sha256, f["target"]): f["target"]
            for f in findings
            if Path(f["target"]).is_file()
        }
        for future in as_completed(future_to_path):
            path = future_to_path[future]
            sha  = future.result()
            if sha:
                hashes[path] = sha
                log.info(f"SHA256 | {Path(path).name} → {sha[:16]}...")

    # ── Enrichissement des findings avec le hash ─────────────────────
    for f in findings:
        target = f["target"]
        if target in hashes:
            f.setdefault("details", {})["sha256"] = hashes[target]

    # ── Déduplication par hash ────────────────────────────────────────
    # Même binaire malveillant déposé à plusieurs endroits → 1 seule requête VT.
    # Concept : les campagnes de malware déploient souvent le même binaire.
    unique_hashes = list(set(hashes.values()))
    log.info(f"Unique hashes: {len(unique_hashes)} (deduped from {len(hashes)})")

    # ── Lookup VirusTotal ─────────────────────────────────────────────
    vt_results: dict[str, dict] = {}

    if vt_api_key and unique_hashes:
        log.info(f"VirusTotal lookup: {len(unique_hashes)} hash(es)...")
        for i, sha256 in enumerate(unique_hashes):
            if i > 0:
                # Rate limiting : 4 req/min gratuit
                # Respecter les rate limits = comportement responsable
                # Un outil qui les ignore peut être banni de l'API.
                time.sleep(VT_RATE_LIMIT_DELAY)

            result = _query_virustotal(sha256, vt_api_key, log)
            if result:
                vt_results[sha256] = result
                log.info(
                    f"VT | {sha256[:16]}... → "
                    f"{result['malicious']}/{result['total']} engines"
                )

    # ── Injection des résultats VT dans les findings ──────────────────
    for f in findings:
        target = f["target"]
        sha    = hashes.get(target)

        if sha and sha in vt_results:
            vt = vt_results[sha]
            f["details"]["virustotal"] = vt

            if vt["malicious"] >= VT_DETECTION_THRESHOLD:
                f["severity"] = "CRITICAL"
                f["reason"]  += (
                    f" | ★ VT CONFIRMED MALWARE: "
                    f"{vt['malicious']}/{vt['total']} engines"
                )
                log.warning(
                    f"MALWARE CONFIRMED | {target} | "
                    f"{vt['malicious']}/{vt['total']} detections"
                )
            elif vt["malicious"] > 0:
                f["reason"] += (
                    f" | VT suspicious: {vt['malicious']}/{vt['total']} engines"
                )

        elif sha and not vt_api_key:
            f["reason"] += f" | SHA256: {sha[:16]}... [no VT key]"

    log.info(f"Hash checker done | {len(vt_results)} VT lookup(s) performed")
    return findings


# ──────────────────────────────────────────────
# Calcul SHA256 (streaming, chunk par chunk)
# ──────────────────────────────────────────────
def _compute_sha256(path_str: str) -> str | None:
    """
    Calcule le SHA256 d'un fichier en streaming.

    Pourquoi en streaming (chunks) ?
      Un fichier de 2 Go chargé d'un coup = Out Of Memory.
      En lisant par chunks de 4 Mo, la RAM utilisée est constante.

    Propriétés de SHA256 :
      - Déterministe : même fichier → même hash, toujours.
      - Effet avalanche : 1 bit changé → hash complètement différent.
      - Sens unique : impossible de retrouver le fichier depuis son hash.
      - 256 bits = 64 caractères hex.
    """
    path = Path(path_str)
    if not path.is_file():
        return None

    try:
        if path.stat().st_size > 50 * 1024 * 1024:
            return None  # Trop gros, on skip
    except OSError:
        return None

    sha256 = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            while chunk := f.read(CHUNK_SIZE):
                sha256.update(chunk)
        return sha256.hexdigest()
    except (PermissionError, OSError, IsADirectoryError):
        return None


# ──────────────────────────────────────────────
# Query VirusTotal API v3
# ──────────────────────────────────────────────
def _query_virustotal(sha256: str, api_key: str, log) -> dict | None:
    """
    Interroge VirusTotal pour un hash SHA256.

    On envoie SEULEMENT le hash — jamais le fichier.
    Pourquoi ? Confidentialité : un fichier peut contenir des données
    sensibles (backup de /etc/shadow, dump de BDD...).
    Le hash identifie sans révéler le contenu.
    """
    url = VT_API_URL.format(hash=sha256)
    req = urllib.request.Request(
        url,
        headers={"x-apikey": api_key, "Accept": "application/json"},
        method="GET",
    )

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode())

        stats = data["data"]["attributes"]["last_analysis_stats"]
        attrs = data["data"]["attributes"]

        return {
            "malicious":    stats.get("malicious",  0),
            "suspicious":   stats.get("suspicious", 0),
            "undetected":   stats.get("undetected", 0),
            "total":        sum(stats.values()),
            "name":         attrs.get("meaningful_name", "unknown"),
            "type":         attrs.get("type_description", "unknown"),
            "vt_permalink": f"https://www.virustotal.com/gui/file/{sha256}",
        }

    except urllib.error.HTTPError as e:
        if e.code == 404:
            # Hash inconnu de VT = fichier pas encore analysé
            # Peut être un malware 0-day ou un fichier légitime custom
            log.info(f"VT: hash not found (new/custom file) | {sha256[:16]}...")
            return None
        elif e.code == 429:
            log.warning("VT rate limit hit — waiting 60s and retrying...")
            time.sleep(60)
            return _query_virustotal(sha256, api_key, log)
        else:
            log.warning(f"VT HTTP error {e.code} | {sha256[:16]}...")
            return None
    except Exception as e:
        log.warning(f"VT query failed | {sha256[:16]}... | {e}")
        return None


# ──────────────────────────────────────────────
# File Integrity Monitoring (FIM)
# ──────────────────────────────────────────────
def compute_baseline(paths: list[str], output_file: Path) -> dict[str, str]:
    """
    Crée une baseline SHA256 des fichiers indiqués (snapshot à T0).

    Concept — File Integrity Monitoring (FIM) :
      T0 (système sain) → on hash tous les binaires critiques
        → baseline.json : { "/bin/ls": "aabbcc...", "/sbin/init": "ff..." }

      T1 (après incident potentiel) → on rehash et on compare.
        Si /bin/ls a un hash différent → ALERTE "binary tampering".

      Outils FIM connus : AIDE, Tripwire, OSSEC, Wazuh.
      SudoSu implémente une version simplifiée du même principe.

    LIMITATION :
      Si l'attaquant a root ET peut modifier baseline.json,
      il peut recalculer les hashes après avoir trafiqué les binaires.
      → Solution pro : stocker la baseline sur un système externe
        en read-only, signer avec GPG, ou utiliser un TPM.
    """
    baseline: dict[str, str] = {}
    for path_str in paths:
        sha = _compute_sha256(path_str)
        if sha:
            baseline[path_str] = sha

    output_file.parent.mkdir(parents=True, exist_ok=True)
    output_file.write_text(json.dumps(baseline, indent=2), encoding="utf-8")
    return baseline


def check_against_baseline(
    baseline_file: Path,
    log_file: Path | None = None,
) -> list[dict]:
    """
    Compare l'état actuel des binaires avec la baseline T0.
    Retourne un finding CRITICAL pour chaque binaire modifié.

    C'est le cœur du FIM : détecter les "trojan binaries" —
    binaires système remplacés par des versions modifiées
    qui cachent les activités malveillantes (rootkit classique).
    """
    log = get_logger("hash_checker.fim", log_file)
    findings = []

    if not baseline_file.exists():
        log.warning(f"Baseline not found: {baseline_file}")
        return findings

    try:
        baseline = json.loads(baseline_file.read_text(encoding="utf-8"))
    except Exception as e:
        log.warning(f"Cannot read baseline: {e}")
        return findings

    for path_str, expected_hash in baseline.items():
        current_hash = _compute_sha256(path_str)

        if current_hash is None:
            findings.append({
                "severity":  "HIGH",
                "target":    path_str,
                "reason":    "Baseline file missing — possible deletion after tampering",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "module":    "hash_checker.fim",
                "details":   {"baseline_hash": expected_hash},
            })
        elif current_hash != expected_hash:
            findings.append({
                "severity":  "CRITICAL",
                "target":    path_str,
                "reason":    "Binary hash mismatch vs baseline — possible rootkit/trojan binary",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "module":    "hash_checker.fim",
                "details":   {
                    "baseline_hash": expected_hash,
                    "current_hash":  current_hash,
                    "diff":          f"{expected_hash[:12]}... → {current_hash[:12]}...",
                },
            })
            log.warning(
                f"HASH MISMATCH | {path_str} | "
                f"expected={expected_hash[:16]}... got={current_hash[:16]}..."
            )

    log.info(f"FIM check done | {len(findings)} mismatch(es)")
    return findings