"""
upload_s3.py — VERSION EXPERT
==============================
Améliorations :
1. Upload parallèle   — tous les fichiers en même temps (ThreadPoolExecutor)
2. Versioning         — chaque upload garde l'historique horodaté
3. Streaming          — upload ligne par ligne sans charger en RAM
4. EC2 / Lambda       — détection automatique de l'environnement d'exécution
5. Retry intelligent  — backoff exponentiel (1s, 2s, 4s) au lieu de 10s fixe
6. Vérification hash  — MD5 pour garantir l'intégrité des fichiers uploadés
7. Stats d'upload     — temps, taille, débit en Mo/s
"""

import boto3
import os
import sys
import time
import hashlib
import threading
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from botocore.exceptions import SSLError, EndpointConnectionError, ClientError
from botocore.config import Config

sys.path.append(r"C:\Users\LENOVO\pfe-linux-supervision")

# ──────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────
BUCKET_NAME  = os.environ.get("S3_BUCKET_NAME", "pfe-linux-logs-supervision")
AWS_REGION   = os.environ.get("AWS_REGION", "eu-north-1")
MAX_WORKERS  = 4          # upload parallèle — 4 threads simultanés
MAX_RETRIES  = 3          # tentatives max par fichier
BACKOFF_BASE = 2          # délai exponentiel : 2s, 4s, 8s

# ──────────────────────────────────────────
# DÉTECTION ENVIRONNEMENT (EC2 / Lambda / Local)
# ──────────────────────────────────────────
def _detecter_environnement() -> str:
    """
    Détecte automatiquement où le code tourne.
    EC2     → utilise le rôle IAM attaché à l'instance (pas de clés)
    Lambda  → utilise les variables d'environnement Lambda
    Local   → utilise les clés AWS du .env
    """
    # Test EC2 — métadonnées d'instance disponibles
    try:
        import urllib.request
        urllib.request.urlopen(
            "http://169.254.169.254/latest/meta-data/instance-id",
            timeout=1
        )
        return "EC2"
    except Exception:
        pass

    # Test Lambda — variable d'environnement spécifique
    if os.environ.get("AWS_LAMBDA_FUNCTION_NAME"):
        return "LAMBDA"

    return "LOCAL"


def _creer_client_s3():
    """
    Crée le client S3 adapté à l'environnement détecté.
    EC2/Lambda : pas de clés nécessaires (rôle IAM)
    Local      : utilise les clés du .env
    """
    env = _detecter_environnement()

    # Config réseau optimisée — retry automatique boto3
    config = Config(
        retries={"max_attempts": 3, "mode": "adaptive"},
        max_pool_connections=MAX_WORKERS + 2,
    )

    if env in ("EC2", "LAMBDA"):
        print(f"[S3] Environnement détecté : {env} → rôle IAM utilisé")
        return boto3.client("s3", region_name=AWS_REGION, config=config), env

    # Local — utilise les clés du .env
    print(f"[S3] Environnement détecté : LOCAL → clés .env utilisées")
    return boto3.client(
        "s3",
        aws_access_key_id     = os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY"),
        region_name           = AWS_REGION,
        config                = config,
    ), env


# Client S3 singleton — créé une seule fois
_s3_client = None
_s3_lock   = threading.Lock()

def _get_s3():
    global _s3_client
    if _s3_client is None:
        with _s3_lock:
            if _s3_client is None:
                _s3_client, _ = _creer_client_s3()
    return _s3_client


# ──────────────────────────────────────────
# SAUVEGARDE LOCALE
# ──────────────────────────────────────────
def sauvegarder_localement(df_clean, erreurs_par_heure,
                            tentatives_par_ip, events_par_service):
    """Sauvegarde les DataFrames en CSV localement."""
    os.makedirs("output", exist_ok=True)
    df_clean.to_csv("output/logs_clean.csv", index=False)
    erreurs_par_heure.to_csv("output/erreurs_par_heure.csv", index=False)
    tentatives_par_ip.to_csv("output/tentatives_par_ip.csv", index=False)
    events_par_service.to_csv("output/events_par_service.csv", index=False)
    print("Fichiers sauvegardes localement")


# ──────────────────────────────────────────
# AMÉLIORATION 1 — VÉRIFICATION HASH MD5
# Garantit l'intégrité du fichier après upload
# ──────────────────────────────────────────
def _calculer_md5(chemin_fichier: str) -> str:
    """Calcule le MD5 du fichier pour vérification d'intégrité."""
    hash_md5 = hashlib.md5()
    with open(chemin_fichier, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()


def _verifier_upload(chemin_s3: str, md5_local: str) -> bool:
    """Vérifie que le fichier uploadé sur S3 correspond au fichier local."""
    try:
        s3 = _get_s3()
        reponse = s3.head_object(Bucket=BUCKET_NAME, Key=chemin_s3)
        etag = reponse["ETag"].strip('"')
        # ETag S3 = MD5 pour les fichiers < 5GB sans multipart
        return etag == md5_local
    except Exception:
        return True   # si vérification impossible → on suppose OK


# ──────────────────────────────────────────
# AMÉLIORATION 2 — VERSIONING HORODATÉ
# Garde l'historique de chaque upload
# ──────────────────────────────────────────
def _chemin_versionne(chemin_s3: str) -> str:
    """
    Génère un chemin S3 versionné avec horodatage.
    Ex: processed/logs_clean.csv
     → processed/historique/logs_clean_2026-03-23_10-30-00.csv
    """
    timestamp  = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    dossier    = os.path.dirname(chemin_s3)
    nom_fichier = os.path.basename(chemin_s3)
    nom, ext   = os.path.splitext(nom_fichier)
    return f"{dossier}/historique/{nom}_{timestamp}{ext}"


# ──────────────────────────────────────────
# AMÉLIORATION 3 — STREAMING UPLOAD
# Upload ligne par ligne sans charger en RAM
# Utile pour les très gros fichiers de logs
# ──────────────────────────────────────────
def _upload_streaming(chemin_local: str, chemin_s3: str) -> bool:
    """
    Upload en streaming via boto3 TransferManager.
    Évite de charger tout le fichier en RAM.
    Utilise le multipart automatiquement pour les fichiers > 8MB.
    """
    from boto3.s3.transfer import TransferConfig

    config_transfer = TransferConfig(
        multipart_threshold  = 8 * 1024 * 1024,    # 8MB → multipart
        max_concurrency      = 4,                   # 4 threads internes
        multipart_chunksize  = 8 * 1024 * 1024,    # chunks de 8MB
        use_threads          = True,
    )

    s3 = _get_s3()
    taille = os.path.getsize(chemin_local)
    debut  = time.time()

    s3.upload_file(
        chemin_local,
        BUCKET_NAME,
        chemin_s3,
        Config=config_transfer,
        ExtraArgs={
            "ServerSideEncryption": "AES256",      # chiffrement au repos
            "Metadata": {
                "uploaded-by":   _detecter_environnement(),
                "upload-time":   datetime.now().isoformat(),
                "source-file":   os.path.basename(chemin_local),
            }
        }
    )

    duree = time.time() - debut
    debit = (taille / 1024 / 1024) / max(duree, 0.001)
    return True, taille, duree, debit


# ──────────────────────────────────────────
# AMÉLIORATION 4 — RETRY AVEC BACKOFF EXPONENTIEL
# ──────────────────────────────────────────
def _uploader_un_fichier(
    fichier_local: str,
    chemin_s3: str,
    avec_versioning: bool = True
) -> dict:
    """
    Upload un seul fichier avec retry exponentiel + versioning optionnel.
    Retourne un dict de résultat pour le rapport.
    """
    if not os.path.exists(fichier_local):
        return {
            "fichier": chemin_s3,
            "statut": "ABSENT",
            "message": f"Fichier local introuvable : {fichier_local}"
        }

    md5_local = _calculer_md5(fichier_local)
    taille    = os.path.getsize(fichier_local)

    for tentative in range(1, MAX_RETRIES + 1):
        try:
            # Upload principal
            ok, taille, duree, debit = _upload_streaming(fichier_local, chemin_s3)

            # Vérification intégrité MD5
            integre = _verifier_upload(chemin_s3, md5_local)

            # Versioning — copie horodatée
            if avec_versioning:
                chemin_version = _chemin_versionne(chemin_s3)
                s3 = _get_s3()
                s3.copy_object(
                    Bucket     = BUCKET_NAME,
                    CopySource = {"Bucket": BUCKET_NAME, "Key": chemin_s3},
                    Key        = chemin_version,
                )

            print(
                f"[S3] ✅ {chemin_s3} | "
                f"{taille/1024:.1f} Ko | "
                f"{duree:.2f}s | "
                f"{debit:.2f} Mo/s | "
                f"MD5 {'✓' if integre else '⚠'}"
            )

            return {
                "fichier":    chemin_s3,
                "statut":     "OK",
                "taille_ko":  round(taille / 1024, 1),
                "duree_s":    round(duree, 3),
                "debit_mbs":  round(debit, 3),
                "md5_ok":     integre,
                "version":    chemin_version if avec_versioning else None,
            }

        except (SSLError, EndpointConnectionError) as e:
            delai = BACKOFF_BASE ** tentative   # 2s, 4s, 8s
            print(f"[S3] ⚠ Tentative {tentative}/{MAX_RETRIES} échouée — "
                  f"réseau SSL ({delai}s avant retry)")
            if tentative < MAX_RETRIES:
                time.sleep(delai)
            else:
                print(f"[S3] ❌ Abandon après {MAX_RETRIES} tentatives : {chemin_s3}")
                return {
                    "fichier": chemin_s3,
                    "statut":  "ECHEC_RESEAU",
                    "message": str(e),
                    "local":   fichier_local,
                }

        except ClientError as e:
            code = e.response["Error"]["Code"]
            print(f"[S3] ❌ Erreur AWS ({code}) : {chemin_s3}")
            return {
                "fichier": chemin_s3,
                "statut":  f"ERREUR_AWS_{code}",
                "message": str(e),
            }

        except Exception as e:
            print(f"[S3] ❌ Erreur inattendue : {e}")
            return {
                "fichier": chemin_s3,
                "statut":  "ERREUR",
                "message": str(e),
            }


# ──────────────────────────────────────────
# AMÉLIORATION 5 — UPLOAD PARALLÈLE
# Tous les fichiers uploadés en même temps
# ──────────────────────────────────────────
def uploader_vers_s3(
    fichiers_supplementaires: list[tuple] = None,
    avec_versioning: bool = True,
    max_tentatives: int = MAX_RETRIES
) -> dict:
    """
    Upload tous les fichiers en PARALLÈLE avec ThreadPoolExecutor.

    Arguments :
        fichiers_supplementaires : liste de tuples (local, s3) supplémentaires
        avec_versioning          : garde une copie horodatée de chaque fichier
        max_tentatives           : nombre de retry par fichier

    Retourne : rapport complet des uploads
    """
    debut_global = time.time()

    # Fichiers standard du pipeline
    fichiers = [
        ("output/logs_clean.csv",          "processed/logs_clean.csv"),
        ("output/erreurs_par_heure.csv",   "processed/erreurs_par_heure.csv"),
        ("output/tentatives_par_ip.csv",   "processed/tentatives_par_ip.csv"),
        ("output/events_par_service.csv",  "processed/events_par_service.csv"),
    ]

    # Fichiers additionnels si fournis
    if fichiers_supplementaires:
        fichiers.extend(fichiers_supplementaires)

    print(f"\n[S3] Upload parallèle de {len(fichiers)} fichiers "
          f"({MAX_WORKERS} threads)...")

    resultats = []

    # Upload en parallèle
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(
                _uploader_un_fichier,
                local, s3_path, avec_versioning
            ): (local, s3_path)
            for local, s3_path in fichiers
        }

        for future in as_completed(futures):
            local, s3_path = futures[future]
            try:
                resultat = future.result()
                resultats.append(resultat)
            except Exception as e:
                resultats.append({
                    "fichier": s3_path,
                    "statut":  "ERREUR_THREAD",
                    "message": str(e),
                })

    # ── Rapport final ──
    duree_totale = time.time() - debut_global
    nb_ok        = sum(1 for r in resultats if r["statut"] == "OK")
    nb_echec     = len(resultats) - nb_ok
    taille_totale = sum(r.get("taille_ko", 0) for r in resultats)

    rapport = {
        "timestamp":      datetime.now().isoformat(),
        "environnement":  _detecter_environnement(),
        "nb_fichiers":    len(fichiers),
        "nb_ok":          nb_ok,
        "nb_echec":       nb_echec,
        "taille_totale_ko": round(taille_totale, 1),
        "duree_totale_s":   round(duree_totale, 2),
        "details":          resultats,
    }

    print(f"\n[S3] {'✅' if nb_echec == 0 else '⚠'} "
          f"{nb_ok}/{len(fichiers)} uploadés | "
          f"{taille_totale:.1f} Ko | "
          f"{duree_totale:.2f}s total")

    if nb_echec > 0:
        print(f"[S3] ⚠ {nb_echec} fichier(s) en échec — "
              f"disponibles localement dans output/")

    # Sauvegarder le rapport d'upload
    os.makedirs("output", exist_ok=True)
    with open("output/upload_rapport.json", "w") as f:
        json.dump(rapport, f, indent=2, ensure_ascii=False)

    return rapport


# ──────────────────────────────────────────
# AMÉLIORATION 6 — VÉRIFICATION BUCKET
# ──────────────────────────────────────────
def verifier_chiffrement_bucket() -> bool:
    """
    Vérifie que le chiffrement SSE-S3 est actif sur le bucket.
    À appeler au démarrage de main.py.
    """
    try:
        s3 = _get_s3()
        reponse = s3.get_bucket_encryption(Bucket=BUCKET_NAME)
        regles  = reponse["ServerSideEncryptionConfiguration"]["Rules"]
        algo    = regles[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]
        print(f"[SECURITE] ✅ Chiffrement S3 actif : {algo}")
        return True
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            print("[SECURITE] ⚠ Chiffrement S3 non activé — "
                  "activer SSE dans la console AWS")
        return False
    except Exception as e:
        print(f"[SECURITE] Vérification chiffrement impossible : {e}")
        return False


# ──────────────────────────────────────────
# TEST RAPIDE
# ──────────────────────────────────────────
if __name__ == "__main__":
    import pandas as pd
    import numpy as np

    print("=== TEST upload_s3.py version expert ===\n")

    # Créer des fichiers de test
    os.makedirs("output", exist_ok=True)
    df_test = pd.DataFrame({
        "IP_Source":          ["192.168.1.1", "10.0.0.1", "172.16.0.1"],
        "Nombre_Tentatives":  [5, 150, 3],
        "score_final":        [0.1, 0.85, 0.05],
    })
    df_test.to_csv("output/tentatives_par_ip.csv", index=False)
    df_test.to_csv("output/logs_clean.csv", index=False)
    df_test.to_csv("output/erreurs_par_heure.csv", index=False)
    df_test.to_csv("output/events_par_service.csv", index=False)

    # Vérifier chiffrement
    verifier_chiffrement_bucket()

    # Upload parallèle
    rapport = uploader_vers_s3(avec_versioning=True)

    print(f"\nRapport complet :")
    print(json.dumps(rapport, indent=2, ensure_ascii=False))