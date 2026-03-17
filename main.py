"""
main.py
Pipeline complet de supervision Linux avec :
- Entraînement continu du modèle ML (plus il apprend → plus il est intelligent)
- Détection d'anomalies + alarmes préventives AVANT les pannes
- Actions correctives automatiques
- Orchestration de 6 agents CrewAI spécialisés
"""

import os
import sys
import json

# ==============================
# VARIABLES D'ENVIRONNEMENT — EN PREMIER
# ==============================
os.environ["OPENAI_API_KEY"]            = "fake-not-needed"
os.environ["CREWAI_EMBEDDING_PROVIDER"] = "ollama"
os.environ["CREWAI_EMBEDDING_MODEL"]    = "nomic-embed-text"
os.environ["OLLAMA_BASE_URL"]           = "http://localhost:11434"
os.environ["CREWAI_DISABLE_TELEMETRY"]  = "true"
os.environ["OLLAMA_TIMEOUT"]            = "120"
os.environ["OLLAMA_REQUEST_TIMEOUT"]    = "120"

from dotenv import load_dotenv
load_dotenv()

# Patch ChromaDB pour utiliser Ollama
try:
    from chromadb.utils.embedding_functions.ollama_embedding_function import OllamaEmbeddingFunction
    import crewai.rag.chromadb.config as _chroma_cfg

    def _ollama_ef():
        return OllamaEmbeddingFunction(
            model_name="nomic-embed-text",
            url="http://localhost:11434/api/embeddings"
        )
    _chroma_cfg.ChromaDBConfig._default_embedding_function = staticmethod(_ollama_ef)
    print("[OK] Patch ChromaDB Ollama appliqué")
except Exception as _e:
    print(f"[WARN] Patch ChromaDB échoué: {_e}")

import boto3
import pandas as pd
import io
import time
from datetime import datetime
from crewai import Crew, Process

sys.path.append(r"C:\Users\LENOVO\pfe-linux-supervision")

from src.metriques          import calculer_metriques
from src.anomaly_detection  import detecter_anomalies, reentralner_avec_nouveaux_logs
from src.forecasting        import prevoir_erreurs
from src.upload_s3          import sauvegarder_localement, uploader_vers_s3
from src.agents.memory      import charger_memoire, sauvegarder_memoire, get_contexte_historique

from src.agents.agents import (
    collector_agent,
    analyst_agent,
    detector_agent,
    corrector_agent,
    orchestrator_agent,
    reporter_agent,
)
from src.agents.tasks import (
    tache_collecte,
    tache_analyse,
    tache_detection,
    tache_correction,
    tache_orchestration,
    tache_rapport,
)


# ══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 1 — CHARGEMENT DES VRAIS LOGS DEPUIS S3
# ══════════════════════════════════════════════════════════════════════════════
print("\n" + "="*60)
print("   PIPELINE SUPERVISION LINUX — DÉMARRAGE")
print("="*60)

# Connexion S3
s3 = boto3.client(
    "s3",
    aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
    aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
    region_name=os.environ.get("AWS_REGION", "us-east-1"),
)
BUCKET = os.environ.get("S3_BUCKET_NAME", "pfe-linux-logs-supervision")

# Lister tous les dataset_*.csv dans processed/
print("[S3] Recherche des datasets dans processed/...")
response = s3.list_objects_v2(Bucket=BUCKET, Prefix="processed/dataset_")
objets = response.get("Contents", [])

if not objets:
    print("[ERREUR] Aucun dataset trouvé dans S3 processed/ — vérifier le bucket")
    sys.exit(1)

# Charger et combiner tous les datasets
print(f"[S3] {len(objets)} dataset(s) trouvé(s) :")
frames = []
for obj in objets:
    key = obj["Key"]
    print(f"   → Chargement : {key} ({obj['Size'] // 1024} Ko)")
    try:
        resp = s3.get_object(Bucket=BUCKET, Key=key)
        df_tmp = pd.read_csv(io.BytesIO(resp["Body"].read()))

        # Extraire le nom du serveur depuis le nom du fichier
        # ex: processed/dataset_2026-03-10_06-32.csv → server_2026-03-10_06-32
        nom_fichier = key.split("/")[-1].replace("dataset_", "").replace(".csv", "")
        df_tmp["Serveur"] = f"server_{nom_fichier}"

        frames.append(df_tmp)
        print(f"      [OK] {len(df_tmp)} lignes chargées")
    except Exception as e:
        print(f"      [WARN] Échec chargement {key} : {e}")

if not frames:
    print("[ERREUR] Impossible de charger les datasets S3")
    sys.exit(1)

# Combiner tous les datasets réels
df_multi_raw = pd.concat(frames, ignore_index=True)
print(f"\n[DATA] {len(df_multi_raw)} lignes réelles chargées depuis {len(frames)} dataset(s)")

# Les datasets S3 sont déjà transformés — normaliser les colonnes directement
df_multi = df_multi_raw.copy()

# ── MAPPING des colonnes S3 → colonnes attendues par le pipeline ──────────────
# Colonnes S3 réelles : timestamp, source_ip, type_event, statut, detail, source_log, severite
# Colonnes attendues  : Date, IP_Source, Etat, Service, Message

# 1. Date
if "Date" not in df_multi.columns:
    if "timestamp" in df_multi.columns:
        df_multi["Date"] = pd.to_datetime(df_multi["timestamp"], errors="coerce")
    elif "DateTime" in df_multi.columns:
        df_multi["Date"] = pd.to_datetime(df_multi["DateTime"], errors="coerce")
    else:
        print("[WARN] Aucune colonne date trouvée — date par défaut")
        df_multi["Date"] = pd.Timestamp.now()
else:
    df_multi["Date"] = pd.to_datetime(df_multi["Date"], errors="coerce")

# 2. IP_Source
if "IP_Source" not in df_multi.columns:
    if "source_ip" in df_multi.columns:
        df_multi["IP_Source"] = df_multi["source_ip"]
    else:
        df_multi["IP_Source"] = None

# 3. Etat (Error / Warning / Info) — mappé depuis statut ou severite
if "Etat" not in df_multi.columns:
    if "statut" in df_multi.columns:
        def mapper_etat(val):
            val = str(val).lower()
            if any(m in val for m in ["error", "failed", "critical", "denied", "refused", "failure"]):
                return "Error"
            elif any(m in val for m in ["warning", "warn", "timeout"]):
                return "Warning"
            return "Info"
        df_multi["Etat"] = df_multi["statut"].apply(mapper_etat)
    elif "severite" in df_multi.columns:
        def mapper_etat_sev(val):
            val = str(val).lower()
            if val in ["critical", "error", "high"]:
                return "Error"
            elif val in ["warning", "medium"]:
                return "Warning"
            return "Info"
        df_multi["Etat"] = df_multi["severite"].apply(mapper_etat_sev)
    else:
        df_multi["Etat"] = "Info"

# 4. Service — mappé depuis source_log ou type_event
if "Service" not in df_multi.columns:
    if "source_log" in df_multi.columns:
        df_multi["Service"] = df_multi["source_log"]
    elif "type_event" in df_multi.columns:
        df_multi["Service"] = df_multi["type_event"]
    else:
        df_multi["Service"] = "unknown"

# 5. Message — mappé depuis detail
if "Message" not in df_multi.columns:
    if "detail" in df_multi.columns:
        df_multi["Message"] = df_multi["detail"]
    else:
        df_multi["Message"] = ""

# Supprimer les lignes sans date valide
avant = len(df_multi)
df_multi = df_multi.dropna(subset=["Date"])
if len(df_multi) < avant:
    print(f"[WARN] {avant - len(df_multi)} lignes supprimées (date invalide)")

print(f"[DATA] Colonnes disponibles : {list(df_multi.columns)}")
print(f"[DATA] Etat distribution : {df_multi['Etat'].value_counts().to_dict()}")

nb_serveurs = df_multi["Serveur"].nunique()
print(f"[DATA] {len(df_multi)} lignes nettoyées | {nb_serveurs} source(s) de logs distincte(s)")

# Métriques
erreurs_par_heure, tentatives_par_ip, events_par_service = calculer_metriques(df_multi)


# ══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 2 — DÉTECTION D'ANOMALIES + ALARMES PRÉVENTIVES
# ══════════════════════════════════════════════════════════════════════════════
print("\n[DÉTECTION] Analyse des anomalies en cours...")
tentatives_par_ip, anomalies, alarmes = detecter_anomalies(tentatives_par_ip)

if alarmes:
    print(f"\n🚨 {len(alarmes)} ALARME(S) PRÉVENTIVE(S) DÉCLENCHÉE(S) :")
    for alarme in alarmes:
        print(f"   → {alarme['message']}")
else:
    print("[OK] Aucune alarme préventive — système normal")


# ══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 3 — RÉENTRAÎNEMENT CONTINU
# ══════════════════════════════════════════════════════════════════════════════
print("\n[APPRENTISSAGE] Réentraînement avec les nouvelles données...")
reentralner_avec_nouveaux_logs(tentatives_par_ip)


# ══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 4 — PRÉVISION + SAUVEGARDE
# ══════════════════════════════════════════════════════════════════════════════
previsions = prevoir_erreurs(erreurs_par_heure)
sauvegarder_localement(df_multi, erreurs_par_heure, tentatives_par_ip, events_par_service)
uploader_vers_s3()
print("\n[OK] Pipeline de données terminé avec succès")


# ══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 5 — CONTEXTE COMPACT POUR LES AGENTS (limite Groq : 6000 tokens)
# ══════════════════════════════════════════════════════════════════════════════

# Garder seulement les 5 alarmes les plus critiques
alarmes_critiques = [a for a in alarmes if a.get("severite") == "CRITIQUE"][:5]
alarmes_resume = [
    {"ip": a["ip"], "type": a["type"], "valeur": a["valeur"], "severite": a["severite"]}
    for a in alarmes_critiques
]

# Top 3 anomalies ML uniquement
top_anomalies = anomalies.head(3)[["IP_Source", "Nombre_Tentatives", "anomalie_score"]].to_string() \
    if len(anomalies) > 0 else "Aucune"

# Liste des sources de logs réelles
sources_logs = df_multi["Serveur"].unique().tolist()
sources_str = ",".join(sources_logs)

contexte_pipeline = (
    f"SUPERVISION {datetime.now().strftime('%Y-%m-%d %H:%M')} | "
    f"Sources: {sources_str} | Logs reels: {len(df_multi)} | "
    f"Anomalies ML: {len(anomalies)} | Alarmes: {len(alarmes)}"
)

# Résumé ultra-court pour les tâches (≈ 80 tokens max)
def _resumer_alarmes(alarmes_list, anomalies_df):
    """Crée un résumé en une ligne des alarmes pour économiser les tokens."""
    if not alarmes_list:
        return "Aucune alarme critique"
    parties = []
    for a in alarmes_list[:3]:   # max 3 IPs
        parties.append(f"{a['ip']}({int(a['valeur'])} tentatives)")
    resume = ", ".join(parties)
    if len(anomalies_df) > 3:
        resume += f" — {len(anomalies_df)} anomalies au total"
    return resume

alarmes_resumees = _resumer_alarmes(alarmes_critiques, anomalies)

# IP principale = l'attaquant le plus actif (première alarme critique)
ip_principale = alarmes_critiques[0]["ip"] if alarmes_critiques else "N/A"

# JSON compact pour les rares cas où le JSON complet est nécessaire
alarmes_json_compact = json.dumps(alarmes_resume, ensure_ascii=False)

print("\n" + "="*60)
print("   DÉMARRAGE DES 6 AGENTS IA CREWAI")
print("="*60)
print(f"[TOKEN GUARD] Contexte : {len(contexte_pipeline)} chars | "
      f"Alarmes envoyées : {len(alarmes_critiques)}/{len(alarmes)}")
print(f"[TOKEN GUARD] Résumé alarmes : {alarmes_resumees}")
print(f"[TOKEN GUARD] IP principale  : {ip_principale}")
print(f"[TOKEN GUARD] Sources logs   : {sources_str}")


# ══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 6 — ORCHESTRATION DES 6 AGENTS
# ══════════════════════════════════════════════════════════════════════════════

# THROTTLE GROQ : 20s entre chaque appel LLM
from src.agents.agents import llm as groq_llm
_last_llm_call_time = [0.0]

def _throttled_call(self, *args, **kwargs):
    elapsed = time.time() - _last_llm_call_time[0]
    wait = 20.0 - elapsed
    if wait > 0:
        print(f"[THROTTLE] Attente {wait:.1f}s avant prochain appel LLM...")
        time.sleep(wait)
    _last_llm_call_time[0] = time.time()
    for tentative in range(3):  # 3 essais max
        try:
            return _original_call(self, *args, **kwargs)
        except Exception as e:
            if "SSL" in str(e) or "ConnectError" in str(e):
                print(f"[RETRY] Erreur réseau ({tentative+1}/3) — attente 15s...")
                time.sleep(15)
            else:
                raise
    raise RuntimeError("Echec après 3 tentatives réseau")

_original_call = groq_llm.__class__.call
groq_llm.__class__.call = _throttled_call

crew = Crew(
    agents=[
        orchestrator_agent,
        collector_agent,
        analyst_agent,
        detector_agent,
        corrector_agent,
        reporter_agent,
    ],
    tasks=[
        tache_orchestration,
        tache_collecte,
        tache_analyse,
        tache_detection,
        tache_correction,
        tache_rapport,
    ],
    process=Process.sequential,
    memory=False,
    verbose=True,
)

resultat = crew.kickoff(
    inputs={
        "serveur_nom":        sources_str,             # ← noms réels des sources
        "date":               datetime.now().strftime("%Y%m%d_%H%M%S"),
        "contexte_pipeline":  contexte_pipeline,
        "alarmes_json":       alarmes_json_compact,
        "alarmes_resumees":   alarmes_resumees,
        "ip_principale":      ip_principale,
        "nb_anomalies":       str(len(anomalies)),
    }
)


# ══════════════════════════════════════════════════════════════════════════════
# ÉTAPE 7 — SAUVEGARDE MÉMOIRE LONG TERME
# ══════════════════════════════════════════════════════════════════════════════
sauvegarder_memoire({
    "ips_suspectes":   tentatives_par_ip.head(5)["IP_Source"].tolist() if len(tentatives_par_ip) > 0 else [],
    "nb_anomalies":    len(anomalies),
    "nb_alarmes":      len(alarmes),
    "alarmes":         alarmes,
    "resultat_agents": str(resultat)[:500]
})

print("\n[MÉMOIRE] Contexte historique mis à jour :")
print(get_contexte_historique())

print("\n" + "="*60)
print("   ANALYSE IA TERMINÉE AVEC SUCCÈS")
print("="*60)
print(resultat)
print("="*60)