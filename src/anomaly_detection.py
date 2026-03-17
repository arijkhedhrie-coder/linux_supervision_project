"""
anomaly_detection.py
Pipeline de détection d'anomalies avec entraînement continu (Isolation Forest)
+ prédiction préventive de pannes avant qu'elles surviennent.
"""

import os
import json
import joblib                          # Remplace pickle — sécurisé + rapide
import numpy as np
import pandas as pd
from datetime import datetime
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler

# ──────────────────────────────────────────
# CHEMINS
# ──────────────────────────────────────────
MODEL_PATH   = "src/models/isolation_forest.joblib"
SCALER_PATH  = "src/models/scaler.joblib"
HISTORY_PATH = "src/models/training_history.json"

# ──────────────────────────────────────────
# FEATURES MULTI-DIMENSIONNELLES
# (plus on a de features → plus le modèle est intelligent)
# ──────────────────────────────────────────
FEATURES = ["Nombre_Tentatives"]   # colonne produite par calculer_metriques()
EXTRA_FEATURES = [
    "Nombre_Erreurs",
    "nb_warnings",
    "cpu_usage",
    "mem_usage",
]

def _get_features(df: pd.DataFrame) -> list[str]:
    """Retourne toutes les features disponibles dans le DataFrame.
    Si aucune feature connue n'est trouvée, utilise toutes les colonnes numériques."""
    known = [f for f in [*FEATURES, *EXTRA_FEATURES] if f in df.columns]
    if known:
        return known
    # Fallback : toutes les colonnes numériques disponibles
    numeric_cols = df.select_dtypes(include=[np.number]).columns.tolist()
    if not numeric_cols:
        raise ValueError(
            f"Aucune feature numérique trouvée dans le DataFrame.\n"
            f"Colonnes disponibles : {df.columns.tolist()}\n"
            f"Features attendues   : {[*FEATURES, *EXTRA_FEATURES]}"
        )
    print(f"[WARN] Features connues absentes — utilisation de : {numeric_cols}")
    return numeric_cols


# ──────────────────────────────────────────
# SEUILS D'ALERTE PRÉVENTIVE
# Avant qu'une panne survienne, une alarme se déclenche
# ──────────────────────────────────────────
SEUILS_ALERTE = {
    "Nombre_Tentatives": 50,    # > 50 tentatives SSH → alerte brute-force imminente
    "Nombre_Erreurs":    200,   # > 200 erreurs/heure → surcharge système imminente
    "cpu_usage":         85.0,  # > 85% CPU → risque de panne imminente
    "mem_usage":         90.0,  # > 90% RAM → saturation imminente
}

TYPE_ALARME = {
    "Nombre_Tentatives": "🔴 BRUTE-FORCE SSH IMMINENT",
    "Nombre_Erreurs":    "🟠 SURCHARGE SYSTÈME IMMINENTE",
    "cpu_usage":         "🟡 SATURATION CPU IMMINENTE",
    "mem_usage":         "🟡 SATURATION MÉMOIRE IMMINENTE",
}


# ──────────────────────────────────────────
# HISTORIQUE D'ENTRAÎNEMENT
# ──────────────────────────────────────────
def _charger_historique() -> dict:
    if os.path.exists(HISTORY_PATH):
        with open(HISTORY_PATH, "r") as f:
            return json.load(f)
    return {"sessions": 0, "total_samples": 0, "last_train": None}


def _sauvegarder_historique(nb_samples: int):
    hist = _charger_historique()
    hist["sessions"]      += 1
    hist["total_samples"] += nb_samples
    hist["last_train"]     = datetime.now().isoformat()
    os.makedirs("src/models", exist_ok=True)
    with open(HISTORY_PATH, "w") as f:
        json.dump(hist, f, indent=2)
    print(f"[HISTORIQUE] Session #{hist['sessions']} — "
          f"{hist['total_samples']} échantillons cumulés")


# ──────────────────────────────────────────
# ENTRAÎNEMENT
# ──────────────────────────────────────────
def entrainer_et_sauvegarder(df: pd.DataFrame):
    """
    Entraîne Isolation Forest sur toutes les features disponibles.
    Plus il y a de données → plus le modèle est intelligent.
    """
    features = _get_features(df)
    X = df[features].values

    # Normalisation
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Contamination adaptative : min 5%, max 20%
    col_principale = features[0]
    seuil_principal = SEUILS_ALERTE.get(col_principale, 50)
    contamination = min(0.20, max(0.05, len(df[df[col_principale] > seuil_principal]) / max(len(df), 1)))

    modele = IsolationForest(
        contamination=contamination,
        random_state=42,
        n_estimators=200,      # Plus d'arbres = plus précis
        max_samples="auto",
        n_jobs=-1              # Utilise tous les CPU disponibles
    )
    modele.fit(X_scaled)

    os.makedirs("src/models", exist_ok=True)
    joblib.dump(modele, MODEL_PATH)
    joblib.dump(scaler, SCALER_PATH)
    _sauvegarder_historique(len(X))

    hist = _charger_historique()
    print(f"[OK] Modèle entraîné — {len(X)} nouveaux échantillons "
          f"({hist['total_samples']} au total) | contamination={contamination:.2%}")
    return modele, scaler


def charger_ou_entrainer(df: pd.DataFrame):
    """Charge le modèle existant ou l'entraîne si premier lancement."""
    if os.path.exists(MODEL_PATH) and os.path.exists(SCALER_PATH):
        modele = joblib.load(MODEL_PATH)
        scaler = joblib.load(SCALER_PATH)
        hist   = _charger_historique()
        print(f"[OK] Modèle chargé — {hist['total_samples']} échantillons appris | "
              f"session #{hist['sessions']}")
    else:
        print("[INFO] Premier lancement — entraînement initial...")
        modele, scaler = entrainer_et_sauvegarder(df)
    return modele, scaler


# ──────────────────────────────────────────
# ALARMES PRÉVENTIVES
# Déclenchées AVANT qu'une panne survienne
# ──────────────────────────────────────────
def verifier_seuils_alarme(df: pd.DataFrame) -> list[dict]:
    """
    Vérifie les seuils critiques et génère des alarmes préventives
    avec un message adapté au type d'anomalie détectée.
    Retourne une liste d'alarmes à transmettre aux agents.
    """
    alarmes = []
    features = _get_features(df)

    for feature in features:
        seuil = SEUILS_ALERTE.get(feature)
        if seuil is None:
            continue
        lignes_critiques = df[df[feature] > seuil]
        if len(lignes_critiques) == 0:
            continue

        for _, row in lignes_critiques.iterrows():
            valeur    = row[feature]
            type_msg  = TYPE_ALARME.get(feature, "⚠️ ANOMALIE DÉTECTÉE")
            ip        = row.get("IP_Source", row.get("ip", row.get("IP", "N/A")))

            # Message d'alarme adapté au type d'anomalie
            if feature == "nb_tentatives":
                message = (
                    f"{type_msg} | IP: {ip} | "
                    f"{int(valeur)} tentatives SSH détectées (seuil={seuil}) | "
                    f"Action recommandée : BLOCAGE IP immédiat via iptables/Fail2Ban"
                )
            elif feature == "nb_erreurs":
                message = (
                    f"{type_msg} | Serveur: {row.get('Serveur', 'N/A')} | "
                    f"{int(valeur)} erreurs/heure (seuil={seuil}) | "
                    f"Action recommandée : Inspection des services + redémarrage si nécessaire"
                )
            elif feature == "cpu_usage":
                message = (
                    f"{type_msg} | CPU: {valeur:.1f}% (seuil={seuil}%) | "
                    f"Action recommandée : Identifier et arrêter les processus gourmands"
                )
            elif feature == "mem_usage":
                message = (
                    f"{type_msg} | RAM: {valeur:.1f}% (seuil={seuil}%) | "
                    f"Action recommandée : Libérer la mémoire ou ajouter de la RAM"
                )
            else:
                message = (
                    f"{type_msg} | {feature}={valeur} > seuil={seuil} | "
                    f"Vérification manuelle requise"
                )

            alarme = {
                "timestamp":  datetime.now().isoformat(),
                "type":       type_msg,
                "feature":    feature,
                "valeur":     float(valeur),
                "seuil":      float(seuil),
                "ip":         str(ip),
                "message":    message,
                "severite":   "CRITIQUE" if valeur > seuil * 1.5 else "AVERTISSEMENT",
            }
            alarmes.append(alarme)
            print(f"🚨 ALARME PRÉVENTIVE : {message}")

    return alarmes


# ──────────────────────────────────────────
# DÉTECTION D'ANOMALIES
# ──────────────────────────────────────────
def detecter_anomalies(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.DataFrame, list[dict]]:
    """
    Détecte les anomalies ML + vérifie les seuils d'alarme préventive.
    Retourne : (df_annoté, df_anomalies, liste_alarmes)
    """
    modele, scaler = charger_ou_entrainer(df)
    features       = _get_features(df)

    X        = df[features].values
    X_scaled = scaler.transform(X)

    # Prédiction ML : -1 = anomalie, 1 = normal
    scores           = modele.predict(X_scaled)
    scores_continus  = modele.score_samples(X_scaled)  # Score de confiance

    df = df.copy()
    df["anomalie"]       = scores
    df["anomalie_score"] = scores_continus  # Plus négatif = plus anormal

    anomalies = df[df["anomalie"] == -1].copy()

    # Alarmes préventives (seuils)
    alarmes = verifier_seuils_alarme(df)

    nb_total    = len(df)
    nb_anomalie = len(anomalies)
    print(f"[DÉTECTION] {nb_anomalie}/{nb_total} anomalies ML détectées | "
          f"{len(alarmes)} alarmes préventives déclenchées")

    return df, anomalies, alarmes


# ──────────────────────────────────────────
# RÉENTRAÎNEMENT CONTINU
# Plus il apprend → plus il est intelligent
# ──────────────────────────────────────────
def reentralner_avec_nouveaux_logs(df: pd.DataFrame):
    """
    Réentraîne le modèle avec les nouvelles données.
    L'accumulation des sessions améliore progressivement la précision.
    """
    print("[APPRENTISSAGE] Réentraînement avec les nouveaux logs...")
    modele, scaler = entrainer_et_sauvegarder(df)

    hist = _charger_historique()
    print(f"[APPRENTISSAGE] ✅ Modèle mis à jour — "
          f"Intelligence cumulée : {hist['total_samples']} échantillons "
          f"sur {hist['sessions']} sessions")
    return modele, scaler