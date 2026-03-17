import pandas as pd
import re
import sys
sys.path.append(r"C:\Users\LENOVO\pfe-linux-supervision")
from config.config import SERVEUR_NOM, ANNEE

def creer_datetime(df):
    df["DateTime"] = df["Month"] + " " + df["Date"].astype(str) + " " + ANNEE + " " + df["Time"]
    df["DateTime"] = pd.to_datetime(df["DateTime"], format="mixed", errors="coerce")
    return df

def detecter_etat(message):
    message = str(message).lower()
    if any(mot in message for mot in [
        "failed", "error", "critical", "denied",
        "invalid", "refused", "killed", "failure",
        "authentication failure", "unknown"
    ]):
        return "Error"
    elif any(mot in message for mot in [
        "warning", "warn", "timeout", "retry"
    ]):
        return "Warning"
    return "Info"

def extraire_ip(message):
    ip = re.search(r"\b(\d{1,3}\.){3}\d{1,3}\b", str(message))
    return ip.group(0) if ip else None

def transformer(df):
    df = creer_datetime(df)
    df_clean = pd.DataFrame()
    df_clean["Date"]      = df["DateTime"]
    df_clean["Serveur"]   = SERVEUR_NOM
    df_clean["Service"]   = df["Component"]
    df_clean["Message"]   = df["Content"]
    df_clean["EventId"]   = df["EventId"]
    df_clean["Etat"]      = df_clean["Message"].apply(detecter_etat)
    df_clean["IP_Source"] = df_clean["Message"].apply(extraire_ip)
    print("Transformation terminee")
    return df_clean
