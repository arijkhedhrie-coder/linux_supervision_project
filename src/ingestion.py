import pandas as pd
import os
import sys
sys.path.append(r"C:\Users\LENOVO\pfe-linux-supervision")
from config.config import CHEMIN_RAW

def charger_donnees():
    df = pd.read_csv(os.path.join(CHEMIN_RAW, "Linux_2k.log_structured.csv"))

    with open(os.path.join(CHEMIN_RAW, "Linux_2k.log"), "r", encoding="utf-8", errors="ignore") as f:
        lignes_brutes = f.readlines()
    df_brut = pd.DataFrame(lignes_brutes, columns=["RawLog"])

    df_templates = pd.read_csv(os.path.join(CHEMIN_RAW, "Linux_2k.log_templates.csv"))

    print(f"Fichiers charges : {len(df)} lignes")
    return df, df_brut, df_templates
