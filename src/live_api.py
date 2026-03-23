"""
live_api.py
Serveur Flask qui lit TOUS les logs réels depuis le dossier partagé VirtualBox.
Tourne en parallèle de main.py — indépendant.
"""
from flask import Flask, jsonify
import re, os, random
from datetime import datetime
from collections import Counter

app = Flask(__name__)

# ── Chemin Windows vers le dossier partagé VirtualBox ──
LOGS_DIR = r"C:\Users\LENOVO\pfe-linux-supervision\data\logs"

# ── Tous les fichiers logs à lire ──
LOG_FILES = {
    "auth":     "auth.log",       # SSH, sudo, connexions
    "syslog":   "syslog.log",     # système général
    "kernel":   "kern.log",       # erreurs kernel
    "fail2ban": "fail2ban.log",   # IPs bannies
    "dpkg":     "dpkg.log",       # paquets installés
    "cron":     "cron.log",       # tâches planifiées
}


# ──────────────────────────────────────────
# LECTURE DES LOGS RÉELS
# ──────────────────────────────────────────
def lire_log(nom_fichier, n=500):
    """Lit les n dernières lignes d'un fichier log réel."""
    path = os.path.join(LOGS_DIR, nom_fichier)
    if os.path.exists(path):
        try:
            with open(path, "r", errors="ignore") as f:
                lignes = f.readlines()
            if lignes:
                return lignes[-n:]
        except Exception as e:
            print(f"[WARN] Erreur lecture {nom_fichier} : {e}")
    return []


# ──────────────────────────────────────────
# FALLBACK SIMULATION
# Utilisée seulement si les fichiers sont absents
# ──────────────────────────────────────────
def simulation_logs(n=200):
    print("[SIMULATION] Dossier partagé non disponible — données simulées")
    ips = ["192.168.1.10", "192.168.1.45", "10.0.0.23", "172.16.0.5"]
    faux_logs = []
    for _ in range(n):
        ip = random.choice(ips)
        choix = random.choice([
            f"Failed password for root from {ip} port 22 ssh2",
            f"Failed password for admin from {ip} port 22 ssh2",
            f"Accepted password for user from {ip} port 22 ssh2",
            f"error: kernel: Out of memory",
            f"INFO: normal operation on {ip}",
            f"sudo: arouja : TTY=pts/0 ; USER=root ; COMMAND=/bin/ls",
        ])
        faux_logs.append(choix)
    return faux_logs


# ──────────────────────────────────────────
# ROUTE PRINCIPALE
# ──────────────────────────────────────────
@app.route("/live")
def live():
    # Lire tous les fichiers logs disponibles
    auth_lines     = lire_log("auth.log")
    syslog_lines   = lire_log("syslog.log")
    kern_lines     = lire_log("kern.log")
    fail2ban_lines = lire_log("fail2ban.log")
    cron_lines     = lire_log("cron.log")

    # Source réelle ou simulation ?
    source_reelle = os.path.exists(os.path.join(LOGS_DIR, "auth.log"))

    # Fallback simulation si aucun fichier disponible
    if not auth_lines:
        auth_lines = simulation_logs()
        source_reelle = False
    else:
        print(f"[LIVE] auth={len(auth_lines)} syslog={len(syslog_lines)} "
              f"kern={len(kern_lines)} fail2ban={len(fail2ban_lines)} lignes lues")

    # ── Métriques SSH (auth.log) ──
    tentatives_ssh  = sum(1 for l in auth_lines if "Failed password" in l)
    connexions_ok   = sum(1 for l in auth_lines if "Accepted password" in l)
    sudo_cmds       = sum(1 for l in auth_lines if "sudo" in l)
    invalid_user    = sum(1 for l in auth_lines if "Invalid user" in l)
    connexions_root = sum(1 for l in auth_lines if "root" in l and "Failed" in l)

    # ── Métriques système (syslog) ──
    erreurs_sys  = sum(1 for l in syslog_lines if "error" in l.lower())
    warnings_sys = sum(1 for l in syslog_lines if "warning" in l.lower())
    oom_killer   = sum(1 for l in syslog_lines if "Out of memory" in l)

    # ── Métriques kernel (kern.log) ──
    erreurs_kernel = sum(1 for l in kern_lines if "error" in l.lower())
    panics_kernel  = sum(1 for l in kern_lines if "panic" in l.lower())

    # ── Fail2ban — IPs bannies ──
    ips_bannies = list(set(
        re.findall(r"Ban (\d+\.\d+\.\d+\.\d+)", "".join(fail2ban_lines))
    ))

    # ── Top IPs suspectes ──
    toutes_ips = re.findall(r"from (\d+\.\d+\.\d+\.\d+)", "".join(auth_lines))
    top_ips = Counter(toutes_ips).most_common(10)

    # ── Dernières lignes brutes (pour affichage live) ──
    derniers_events = []
    for ligne in (auth_lines + syslog_lines)[-20:]:
        ligne = ligne.strip()
        if ligne:
            derniers_events.append(ligne)

    return jsonify({
        "timestamp":        datetime.now().isoformat(),
        "source":           "reel" if source_reelle else "simulation",

        # SSH
        "tentatives_ssh":   tentatives_ssh,
        "connexions_ok":    connexions_ok,
        "sudo_cmds":        sudo_cmds,
        "invalid_user":     invalid_user,
        "tentatives_root":  connexions_root,

        # Système
        "erreurs_sys":      erreurs_sys,
        "warnings_sys":     warnings_sys,
        "oom_killer":       oom_killer,

        # Kernel
        "erreurs_kernel":   erreurs_kernel,
        "panics_kernel":    panics_kernel,

        # IPs
        "top_ips_suspectes": [{"ip": ip, "count": c} for ip, c in top_ips],
        "ips_bannies":       ips_bannies,
        "nb_ips_uniques":    len(set(toutes_ips)),

        # Stats fichiers lus
        "nb_logs_lus": {
            "auth":     len(auth_lines),
            "syslog":   len(syslog_lines),
            "kernel":   len(kern_lines),
            "fail2ban": len(fail2ban_lines),
            "cron":     len(cron_lines),
        },

        # Derniers événements bruts
        "derniers_events": derniers_events[-10:],
    })


@app.route("/health")
def health():
    """Endpoint de vérification — utile pour debug."""
    fichiers_dispos = {
        nom: os.path.exists(os.path.join(LOGS_DIR, fichier))
        for nom, fichier in LOG_FILES.items()
    }
    return jsonify({
        "status":   "ok",
        "logs_dir": LOGS_DIR,
        "fichiers": fichiers_dispos,
    })


if __name__ == "__main__":
    print(f"[INFO] Lecture des logs depuis : {LOGS_DIR}")
    print(f"[INFO] Vérification dossier : {os.path.exists(LOGS_DIR)}")
    app.run(host="0.0.0.0", port=5001, debug=False)