# src/agents/tasks.py — FIX 2 : tache_detection conditionnelle
#
# PROBLÈME : La description contenait toujours "BRUTE-FORCE SSH DÉTECTÉ"
# même quand nb_anomalies=0, ce qui poussait le LLM à déclencher une fausse alarme.
#
# SOLUTION : La description s'adapte au contexte réel :
#   - nb_anomalies > 0 ET ip précise  → description attaque réelle
#   - sinon                           → description surveillance normale

from crewai import Task
from src.agents.agents import (
    collector_agent,
    analyst_agent,
    detector_agent,
    corrector_agent,
    orchestrator_agent,
    reporter_agent
)

# ================================
# TACHE 0 : Orchestration globale
# ================================
tache_orchestration = Task(
    description="""
    Tu es le chef d'orchestre. Évalue rapidement et décide SANS utiliser d'outil.

    Contexte : {contexte_pipeline}

    Anomalies ML : {nb_anomalies} | Top 3 alarmes : {alarmes_resumees}

    Réponds DIRECTEMENT en 5 lignes (pas d'appel d'outil) :
    1. Niveau de risque global (Faible/Moyen/Critique)
    2. Priorité : quel agent intervient en premier ?
    3. Escalade immédiate requise ? (Oui/Non)
    4. Actions urgentes
    5. Ordre des agents
    """,
    expected_output="Plan d'orchestration court : niveau de risque, ordre des agents, escalades requises.",
    agent=orchestrator_agent
)

# ================================
# TACHE 1 : Collecter les logs
# ================================
tache_collecte = Task(
    description="""
    Les fichiers sont dans S3 sous le préfixe "processed/".
    Utilise lister_logs_s3(prefix="processed/") puis lis UNIQUEMENT "processed/erreurs_par_heure.csv".
    Ne cherche pas d'autres fichiers. Retourne une liste des fichiers trouvés et le résumé du CSV.
    Serveur : {serveur_nom}
    """,
    expected_output="Liste des fichiers S3 et résumé de erreurs_par_heure.csv (10 premières lignes max).",
    agent=collector_agent,
    context=[tache_orchestration]
)

# ================================
# TACHE 2 : Analyser les logs
# ================================
tache_analyse = Task(
    description="""
    Les logs ont été collectés depuis S3.
    Contexte : {contexte_pipeline}
    Anomalies ML détectées : {nb_anomalies} | Top alarmes : {alarmes_resumees}

    Utilise l'outil analyser_logs en lui passant DIRECTEMENT ce texte CSV :
    "Heure,Nombre_Erreurs — données issues de processed/erreurs_par_heure.csv"

    Important : NE passe PAS un chemin de fichier à analyser_logs.
    Passe le CONTENU texte des logs collectés par l'agent précédent.

    Résume en 5 lignes : nb erreurs, pics d'activité, connexions SSH, gravité globale, risques.
    """,
    expected_output="Rapport d'analyse court : erreurs, SSH, gravité (Bon/Moyen/Critique), risques.",
    agent=analyst_agent,
    context=[tache_orchestration, tache_collecte]
)

# ================================
# TACHE 3 : Détection — DESCRIPTION CONDITIONNELLE
# ================================
# [FIX 2] On crée la tache_detection comme une fonction pour pouvoir
# injecter une description adaptée à la situation réelle.
# La version statique ci-dessous est le fallback par défaut.
# Dans main.py, utiliser creer_tache_detection() à la place.

def creer_tache_detection(nb_anomalies: int, ip_principale: str, alarmes_resumees: str) -> Task:
    """
    [FIX 2] Crée la tâche de détection avec une description adaptée
    au contexte réel — évite les faux positifs BRUTE-FORCE.

    Cas 1 — Vraie attaque (nb_anomalies > 0 et IP précise) :
        → description mentionne le type d'attaque et demande de déclencher l'alarme

    Cas 2 — Surveillance normale (nb_anomalies = 0 ou pas d'IP) :
        → description indique explicitement qu'il n'y a PAS d'attaque
        → le LLM appelle declencher_alarme avec "Aucune alarme critique"
          mais l'outil garde-fou retourne OK sans déclencher de notification
    """
    ip_valide = (
        ip_principale
        and ip_principale not in ("N/A", "multiple", "", "nan", "none", "None")
        and "." in ip_principale
    )

    if nb_anomalies > 0 and ip_valide:
        # ── Cas réel : attaque confirmée ──────────────────────────────────────
        description = f"""
Le pipeline ML a détecté {nb_anomalies} anomalie(s) CRITIQUE(S).
IP principale identifiée : {ip_principale}
Résumé des alarmes : {alarmes_resumees}

Appelle declencher_alarme avec :
alarmes_json='{{"ip": "{ip_principale}", "type": "BRUTE-FORCE SSH", "severite": "CRITIQUE", "message": "{alarmes_resumees}"}}'

Donne ton rapport en 5 lignes : anomalies détectées, score sécurité (0-100), recommandations.
"""
        expected = f"Alarme déclenchée pour {ip_principale}, score sécurité, recommandations."

    elif nb_anomalies > 0 and not ip_valide:
        # ── Anomalies sans IP précise ─────────────────────────────────────────
        description = f"""
Le pipeline ML a détecté {nb_anomalies} anomalie(s) SUSPECTE(S) mais sans IP précise identifiée.
Résumé : {alarmes_resumees}

Appelle declencher_alarme avec :
alarmes_json='{{"type": "SUSPECT", "severite": "AVERTISSEMENT", "message": "{alarmes_resumees}", "ip": "multiple"}}'

Donne ton rapport en 5 lignes : anomalies, score sécurité (0-100), recommandations.
"""
        expected = "Alarme avertissement déclenchée, score sécurité, recommandations."

    else:
        # ── [FIX 2] Cas normal : nb_anomalies = 0 ───────────────────────────
        # La description NE mentionne PAS "BRUTE-FORCE" ni "CRITIQUE"
        # pour ne pas induire le LLM en erreur.
        description = """
Le pipeline ML n'a détecté AUCUNE anomalie critique. Le système est en état normal.
Nb anomalies : 0 | Alarmes actives : aucune.

Appelle declencher_alarme avec alarmes_json="Aucune alarme critique".
L'outil retournera un statut OK sans déclencher de notification.

Donne ton rapport en 3 lignes :
1. Nombre d'anomalies détectées (0)
2. Score sécurité (100/100)
3. État global du système
"""
        expected = "Rapport : 0 anomalie, score sécurité 100, système normal."

    return Task(
        description=description,
        expected_output=expected,
        agent=detector_agent,
        context=[tache_orchestration, tache_collecte, tache_analyse]
    )


# Version statique par défaut (rétro-compatibilité si main.py l'utilise encore)
tache_detection = Task(
    description="""
    Le pipeline ML a détecté {nb_anomalies} anomalie(s).
    IP principale : {ip_principale}.
    Résumé alarmes : {alarmes_resumees}

    Si nb_anomalies > 0 et ip_principale != "N/A" :
        Appelle declencher_alarme avec les détails de l'attaque.
    Sinon (nb_anomalies = 0) :
        Appelle declencher_alarme avec alarmes_json="Aucune alarme critique".
        NE PAS mentionner BRUTE-FORCE ni SSH si nb_anomalies = 0.

    Rapport en 3 lignes : anomalies, score sécurité (0-100), état global.
    """,
    expected_output="Anomalies confirmées, alarmes déclenchées si nécessaire, score sécurité.",
    agent=detector_agent,
    context=[tache_orchestration, tache_collecte, tache_analyse]
)


# ================================
# TACHE 4 : Actions correctives — DYNAMIQUE selon IP
# ================================
def creer_tache_correction(ip_principale: str, nb_anomalies: int) -> Task:
    """
    Crée la tâche corrective adaptée selon le contexte.
    """
    ip_valide = (
        ip_principale
        and ip_principale not in ("N/A", "multiple", "", "nan", "none", "None")
        and "." in ip_principale
    )

    if ip_valide and nb_anomalies > 0:
        description = f"""
Le Détecteur a confirmé du BRUTE-FORCE SSH CRITIQUE.
IP principale à bloquer : {ip_principale}

Appelle appliquer_action_corrective avec ce JSON exact :
anomalie_json='{{"ip": "{ip_principale}", "type": "BRUTE-FORCE SSH", "action": "BLOCAGE_IMMEDIAT", "severite": "CRITIQUE"}}'

Résume les actions en 3 lignes :
1. IP bloquée
2. Méthode utilisée (iptables / fail2ban / AWS Security Group)
3. Statut final (bloqué / en cours / échec)
"""
        expected = f"IP {ip_principale} bloquée, méthode et statut."

    else:
        # ── [FIX 3] JSON avec type SURVEILLANCE_NORMALE — reconnu par l'outil ──
        description = """
Aucune attaque active confirmée. Le système est en mode surveillance normale.

Appelle appliquer_action_corrective avec ce JSON :
anomalie_json='{"type": "SURVEILLANCE_NORMALE", "action": "MONITORING", "ip": "none", "severite": "FAIBLE"}'

Résume en 2 lignes :
1. État du système : Normal
2. Recommandations préventives pour la prochaine analyse
"""
        expected = "Confirmation surveillance normale, recommandations préventives."

    return Task(
        description=description,
        expected_output=expected,
        agent=corrector_agent,
        context=[tache_orchestration, tache_detection]
    )


# ================================
# TACHE 5 : Rapport final
# ================================
tache_rapport = Task(
    description="""
    Appelle sauvegarder_rapport_s3 avec un JSON compact résumant : état global, anomalies, actions, recommandations.
    Exemple :
    sauvegarder_rapport_s3(rapport_json=\'{{"timestamp":"{contexte_pipeline}","etat":"Normal","anomalies":{nb_anomalies},"ip_principale":"{ip_principale}","actions":1}}\')
    """,
    expected_output="Confirmation sauvegarde rapport S3.",
    agent=reporter_agent,
    context=[tache_orchestration, tache_detection]
)