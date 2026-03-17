# src/agents/tasks.py
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
# TACHE 3 : Détecter les anomalies + alarmes préventives
# ================================
tache_detection = Task(
    description="""
    Le pipeline ML a détecté {nb_anomalies} anomalies CRITIQUES de type BRUTE-FORCE SSH.
    IP principale : {ip_principale} ({nb_anomalies} tentatives détectées).

    Appelle declencher_alarme avec alarmes_json="{alarmes_resumees}".
    Donne ton rapport en 5 lignes : anomalies détectées, score sécurité (0-100), recommandations.
    """,
    expected_output="Liste courte : anomalies, alarmes déclenchées, score sécurité (0-100).",
    agent=detector_agent,
    context=[tache_orchestration, tache_collecte, tache_analyse]
)

# ================================
# TACHE 4 : Actions correctives automatiques
# ================================
tache_correction = Task(
    description="""
    Le Détecteur a confirmé du BRUTE-FORCE SSH CRITIQUE.
    IP principale à bloquer : {ip_principale}
    Appelle appliquer_action_corrective avec anomalie_json="BLOCAGE IP {ip_principale} brute-force SSH critique".
    Résume les actions en 3 lignes : IPs bloquées, méthode (iptables/fail2ban), statut.
    """,
    expected_output="Liste des actions correctives appliquées (IP, méthode, statut).",
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
    sauvegarder_rapport_s3(rapport_json=\'{{"timestamp":"2026-03-09","etat":"Critique","anomalies":{nb_anomalies},"ip_principale":"{ip_principale}","actions":1}}\')
    """,
    expected_output="Confirmation sauvegarde rapport S3.",
    agent=reporter_agent,
    context=[tache_orchestration, tache_detection, tache_correction]
)