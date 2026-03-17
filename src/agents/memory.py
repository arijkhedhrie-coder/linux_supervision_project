# src/agents/memory.py
import json
import os
from datetime import datetime

MEMORY_FILE = "long_term_memory.json"

def charger_memoire():
    if os.path.exists(MEMORY_FILE):
        with open(MEMORY_FILE, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    return {"sessions": [], "anomalies_vues": [], "ips_suspectes": []}

def sauvegarder_memoire(data: dict):
    memoire = charger_memoire()
    memoire["sessions"].append({
        "date": datetime.now().isoformat(),
        "donnees": data
    })
    # Garder seulement les 50 dernières sessions
    memoire["sessions"] = memoire["sessions"][-50:]
    # Fusionner les IPs suspectes
    if "ips_suspectes" in data:
        for ip in data["ips_suspectes"]:
            if ip not in memoire["ips_suspectes"]:
                memoire["ips_suspectes"].append(ip)
    with open(MEMORY_FILE, "w", encoding="utf-8") as f:
        json.dump(memoire, f, indent=2, ensure_ascii=False)
    print(f"[MEMOIRE] Sauvegarde : {len(memoire['sessions'])} sessions en mémoire")

def get_contexte_historique():
    memoire = charger_memoire()
    if not memoire["sessions"]:
        return "Aucun historique disponible."
    derniere = memoire["sessions"][-1]
    return f"""
MEMOIRE LONG-TERME :
- Sessions analysées : {len(memoire['sessions'])}
- IPs suspectes connues : {memoire['ips_suspectes']}
- Dernière analyse : {derniere['date']}
"""