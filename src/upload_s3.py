import boto3
import os
import sys
sys.path.append(r"C:\Users\LENOVO\pfe-linux-supervision")
from config.config import BUCKET_NAME, AWS_REGION, AWS_ACCESS_KEY, AWS_SECRET_KEY

def sauvegarder_localement(df_clean, erreurs_par_heure, tentatives_par_ip, events_par_service):
    os.makedirs("output", exist_ok=True)
    df_clean.to_csv("output/logs_clean.csv", index=False)
    erreurs_par_heure.to_csv("output/erreurs_par_heure.csv", index=False)
    tentatives_par_ip.to_csv("output/tentatives_par_ip.csv", index=False)
    events_par_service.to_csv("output/events_par_service.csv", index=False)
    print("Fichiers sauvegardes localement")

def uploader_vers_s3():
    s3 = boto3.client(
        "s3",
        region_name           = AWS_REGION,
        aws_access_key_id     = AWS_ACCESS_KEY,
        aws_secret_access_key = AWS_SECRET_KEY
    )
    fichiers = [
        ("output/logs_clean.csv",         "processed/logs_clean.csv"),
        ("output/erreurs_par_heure.csv",  "processed/erreurs_par_heure.csv"),
        ("output/tentatives_par_ip.csv",  "processed/tentatives_par_ip.csv"),
        ("output/events_par_service.csv", "processed/events_par_service.csv"),
    ]
    print("Upload vers S3 en cours...")
    for fichier_local, chemin_s3 in fichiers:
        s3.upload_file(fichier_local, BUCKET_NAME, chemin_s3)
        print(f"Uploade : {chemin_s3}")
    print("Tous les fichiers sont sur S3")
