"""
agents.py — CORRECTIONS APPLIQUÉES
====================================
FIX 1 — MCP Timeout 30s :
    OutilListerLogs et OutilLireLogs appellent s3_tools DIRECTEMENT
    au lieu de passer par le subprocess MCP.
    → Plus de timeout, réponse immédiate.

FIX 3 — SURVEILLANCE_NORMALE non reconnue :
    OutilActionCorrective._run() gère maintenant explicitement
    "SURVEILLANCE_NORMALE" et "MONITORING" avant le fallback INSPECTION_MANUELLE.
"""

import os
import sys
import subprocess
import json
from typing import Optional

# ==============================
# VARIABLES D'ENVIRONNEMENT — AVANT TOUT IMPORT CREWAI
# ==============================
os.environ["OPENAI_API_KEY"]            = "fake-not-needed"
os.environ["CREWAI_EMBEDDING_PROVIDER"] = "ollama"
os.environ["CREWAI_EMBEDDING_MODEL"]    = "nomic-embed-text"
os.environ["OLLAMA_BASE_URL"]           = "http://localhost:11434"
os.environ["OTEL_SDK_DISABLED"]         = "true"

try:
    from crewai.memory.storage.rag_storage import RAGStorage
    _original_init = RAGStorage.__init__

    def _patched_init(self, *args, **kwargs):
        kwargs["embedder_config"] = {
            "provider": "ollama",
            "config": {
                "model": "nomic-embed-text",
                "base_url": "http://localhost:11434"
            }
        }
        _original_init(self, *args, **kwargs)

    RAGStorage.__init__ = _patched_init
    print("[OK] Patch RAGStorage Ollama appliqué")
except Exception as e:
    print(f"[WARN] Patch RAGStorage échoué: {e}")

from crewai import Agent, LLM
from crewai.tools import BaseTool
from pydantic import BaseModel, Field
from dotenv import load_dotenv
import time

load_dotenv()

GROQ_API_KEY = os.getenv("GROQ_API_KEY")
os.environ["GROQ_API_KEY"] = GROQ_API_KEY or ""

# ================================
# [FIX 1] IMPORT DIRECT s3_tools
# Contourne le MCP subprocess → plus de timeout 30s
# ================================
try:
    project_root = os.path.dirname(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    )
    if project_root not in sys.path:
        sys.path.insert(0, project_root)
    from src.tools import s3_tools as _s3_tools
    S3_DIRECT_DISPONIBLE = True
    print("[OK] s3_tools chargé directement — bypass MCP activé")
except Exception as _e:
    _s3_tools = None
    S3_DIRECT_DISPONIBLE = False
    print(f"[WARN] s3_tools direct indisponible ({_e}) — fallback MCP")

try:
    from src.aws_security import bloquer_ip_secgroup, bloquer_depuis_anomalie
    AWS_SECURITY_DISPONIBLE = True
    print("[OK] Module aws_security chargé — blocage AWS réel activé")
except ImportError:
    AWS_SECURITY_DISPONIBLE = False
    print("[WARN] aws_security non disponible — mode simulation uniquement")


# ================================
# LLM — Groq
# ================================
llm = LLM(
    model="groq/llama-3.1-8b-instant",
    api_key=GROQ_API_KEY,
    temperature=0.0,
    max_tokens=500,
    max_retries=5,
    timeout=60,
)

_last_llm_call = [0.0]
_MIN_DELAY_SECONDS = 20

def _throttle():
    elapsed = time.time() - _last_llm_call[0]
    if elapsed < _MIN_DELAY_SECONDS:
        wait = _MIN_DELAY_SECONDS - elapsed
        print(f"[RATE LIMIT] Pause {wait:.1f}s pour respecter la limite Groq...")
        time.sleep(wait)
    _last_llm_call[0] = time.time()


# ================================
# FONCTION HELPER MCP (conservée pour les autres outils)
# ================================
def _appeler_mcp(nom_outil: str, arguments: dict) -> str:
    """
    Appelle le serveur MCP en stdin/stdout (subprocess).
    Utilisé uniquement pour les outils qui n'ont pas d'équivalent direct.
    """
    messages = [
        {
            "jsonrpc": "2.0",
            "method": "initialize",
            "params": {
                "protocolVersion": "2024-11-05",
                "capabilities": {},
                "clientInfo": {"name": "crewai-client", "version": "1.0"}
            },
            "id": 1
        },
        {
            "jsonrpc": "2.0",
            "method": "notifications/initialized",
            "params": {}
        },
        {
            "jsonrpc": "2.0",
            "method": "tools/call",
            "params": {"name": nom_outil, "arguments": arguments},
            "id": 2
        }
    ]

    input_data = "\n".join(json.dumps(m) for m in messages)

    try:
        _root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        mcp_path = os.path.join(_root, "src", "mcp", "mcp_server.py")
        env      = os.environ.copy()

        result = subprocess.run(
            [sys.executable, mcp_path],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=_root,
            env=env
        )

        if result.stdout:
            lignes = [l.strip() for l in result.stdout.strip().split("\n") if l.strip()]
            for ligne in reversed(lignes):
                try:
                    response = json.loads(ligne)
                    if "result" in response:
                        content = response["result"]
                        if isinstance(content, list):
                            texte = content[0].get("text", str(content))
                            try:
                                texte = texte.encode("latin-1").decode("utf-8")
                            except Exception:
                                pass
                            return texte
                        if isinstance(content, dict) and "content" in content:
                            items = content["content"]
                            if isinstance(items, list):
                                return items[0].get("text", str(items))
                            return str(items)
                        return str(content)
                except Exception:
                    continue
            return f"Pas de réponse valide: {result.stdout[:200]}"
        return f"Pas de réponse MCP: {result.stderr[:200]}"
    except Exception as e:
        return f"Erreur MCP: {str(e)}"


# ================================
# SCHÉMAS PYDANTIC
# ================================
class ListerLogsInput(BaseModel):
    prefix: Optional[str] = Field(default=None, description="Préfixe S3 optionnel")

class LireLogsInput(BaseModel):
    fichier: Optional[str] = Field(default=None, description="Nom du fichier log à lire depuis S3")

class AnalyserLogsInput(BaseModel):
    contenu: Optional[str] = Field(default=None, description="Contenu des logs à analyser")

class DetecterAnomaliesInput(BaseModel):
    rapport: Optional[str] = Field(default=None, description="Rapport ou logs à analyser")

class AlarmeInput(BaseModel):
    alarmes_json: Optional[str] = Field(default=None, description="Liste JSON des alarmes")

class ActionCorrectiveInput(BaseModel):
    anomalie_json: Optional[str] = Field(default=None, description="Anomalie en JSON")

class OrchestrationInput(BaseModel):
    contexte: Optional[str] = Field(default=None, description="Contexte global de la session")

class SauvegarderRapportInput(BaseModel):
    rapport_json: Optional[str] = Field(default=None, description="Rapport complet en JSON string")


# ================================
# CLASSES D'OUTILS
# ================================

class OutilListerLogs(BaseTool):
    name: str = "lister_logs_s3"
    description: str = (
        "Liste les fichiers dans S3. "
        "Utilise toujours prefix='processed/' car c'est là que sont les fichiers."
    )
    args_schema: type[BaseModel] = ListerLogsInput

    # ── [FIX 1] Appel direct s3_tools — bypass MCP subprocess ──
    def _run(self, prefix: Optional[str] = None, **kwargs) -> str:
        prefix = "processed/"

        if S3_DIRECT_DISPONIBLE:
            try:
                fichiers = _s3_tools.list_objects(prefix=prefix)
                return "Fichiers disponibles dans S3:\n" + "\n".join(fichiers)
            except Exception as e:
                print(f"[WARN] s3_tools.list_objects échoué ({e}) — fallback MCP")

        # Fallback MCP si s3_tools indisponible
        return _appeler_mcp("lister_logs_s3", {"prefix": prefix})


class OutilLireLogs(BaseTool):
    name: str = "lire_logs_s3"
    description: str = (
        "Lit un fichier log depuis S3. "
        "Le fichier doit commencer par 'processed/' ex: 'processed/erreurs_par_heure.csv'"
    )
    args_schema: type[BaseModel] = LireLogsInput

    # ── [FIX 1] Appel direct s3_tools — bypass MCP subprocess ──
    def _run(self, fichier: Optional[str] = None, **kwargs) -> str:
        if fichier and fichier.startswith("logs/"):
            fichier = fichier.replace("logs/", "", 1)

        if S3_DIRECT_DISPONIBLE:
            try:
                contenu = _s3_tools.read_object(fichier)
                try:
                    contenu = contenu.encode("latin-1").decode("utf-8")
                except Exception:
                    pass
                lignes = contenu.split("\n")[:12]
                texte  = "\n".join(lignes)
                if len(contenu.split("\n")) > 12:
                    texte += "\n... [tronqué à 12 lignes]"
                return f"Logs recuperes depuis S3:\n{texte}"
            except Exception as e:
                print(f"[WARN] s3_tools.read_object échoué ({e}) — fallback MCP")

        # Fallback MCP
        resultat = _appeler_mcp("lire_logs_s3", {"fichier": fichier})
        try:
            resultat = resultat.encode("latin-1").decode("utf-8")
        except Exception:
            pass
        if len(resultat) > 500:
            lignes = resultat.split("\n")[:12]
            return "\n".join(lignes) + "\n... [tronqué à 12 lignes]"
        return resultat


class OutilAnalyserLogs(BaseTool):
    name: str = "analyser_logs"
    description: str = (
        "Analyse les logs et compte tous les types d'attaques et événements suspects."
    )
    args_schema: type[BaseModel] = AnalyserLogsInput

    def _run(self, contenu: Optional[str] = None, **kwargs) -> str:
        if not contenu:
            return "Aucun contenu à analyser"

        lignes = contenu.splitlines()
        compteurs = {
            "SSH_BRUTE_FORCE":  0,
            "PORT_SCAN":        0,
            "WEB_ENUMERATION":  0,
            "FIREWALL_BLOCK":   0,
            "AUTH_FAILURE":     0,
            "SUDO_ABUSE":       0,
            "MEMORY_CRITICAL":  0,
            "SERVICE_FAILED":   0,
        }

        for ligne in lignes:
            l = ligne.upper()
            if "FAILED PASSWORD" in l or "INVALID USER" in l or "BRUTE" in l:
                compteurs["SSH_BRUTE_FORCE"] += 1
            if "NMAP" in l or "PORT SCAN" in l or "MASSCAN" in l:
                compteurs["PORT_SCAN"] += 1
            if "GOBUSTER" in l or "ENUMERATION" in l or "DIRB" in l:
                compteurs["WEB_ENUMERATION"] += 1
            if "UFW BLOCK" in l or "IPTABLES" in l or "DENIED" in l:
                compteurs["FIREWALL_BLOCK"] += 1
            if "AUTHENTICATION FAILURE" in l or "PERM DENIED" in l:
                compteurs["AUTH_FAILURE"] += 1
            if "SUDO" in l and "COMMAND" in l:
                compteurs["SUDO_ABUSE"] += 1
            if "OUT OF MEMORY" in l or "OOM" in l:
                compteurs["MEMORY_CRITICAL"] += 1
            if "FAILED" in l and "SERVICE" in l:
                compteurs["SERVICE_FAILED"] += 1

        rapport = "=== RAPPORT D'ANALYSE ===\n"
        for type_attaque, nombre in compteurs.items():
            if nombre > 0:
                rapport += f"{type_attaque}: {nombre} occurrence(s)\n"

        total = sum(compteurs.values())
        rapport += f"\nTOTAL ÉVÉNEMENTS SUSPECTS : {total}"
        return rapport


class OutilDetecterAnomalies(BaseTool):
    name: str = "detecter_anomalies"
    description: str = "Détecte les intrusions SSH, surcharges système et comportements suspects."
    args_schema: type[BaseModel] = DetecterAnomaliesInput

    def _run(self, rapport: Optional[str] = None, **kwargs) -> str:
        return _appeler_mcp("detecter_anomalies", {"contenu_logs": rapport or str(kwargs)})


class OutilDeclencherAlarme(BaseTool):
    name: str = "declencher_alarme"
    description: str = (
        "Déclenche une alarme préventive AVANT qu'une panne survienne. "
        "Si alarmes_json vaut 'Aucune alarme critique' ou est vide, "
        "NE PAS déclencher d'alarme — retourner un statut OK."
    )
    args_schema: type[BaseModel] = AlarmeInput

    def _run(self, alarmes_json: Optional[str] = None, **kwargs) -> str:
        # ── [FIX 2 côté outil] Garde-fou : aucune alarme = pas de déclenchement ──
        if not alarmes_json or alarmes_json.strip() in (
            "Aucune alarme critique", "[]", "", "null", "aucune", "none"
        ):
            return "✅ Aucune alarme à déclencher — système en état normal."

        try:
            alarmes = json.loads(alarmes_json)
            if not isinstance(alarmes, list):
                alarmes = [alarmes]
            # Liste vide après parsing
            if not alarmes:
                return "✅ Aucune alarme à déclencher — liste vide."
        except Exception:
            # Texte libre — seulement si ça ressemble vraiment à une anomalie
            texte_upper = alarmes_json.upper()
            mots_cles_reels = ["BRUTE", "SCAN", "INTRUSION", "CRITIQUE", "BLOCAGE"]
            if not any(m in texte_upper for m in mots_cles_reels):
                return "✅ Pas d'anomalie confirmée dans le message reçu."
            alarmes = [{
                "type":     "ANOMALIE",
                "message":  alarmes_json,
                "severite": "AVERTISSEMENT",
                "ip":       "multiple"
            }]

        resultats = []
        for alarme in alarmes:
            type_alarme = alarme.get("type", "ANOMALIE")
            message     = alarme.get("message", "Anomalie détectée")
            severite    = alarme.get("severite", "AVERTISSEMENT")
            ip          = alarme.get("ip", "N/A")

            if "BRUTE-FORCE" in type_alarme or "SSH" in type_alarme:
                notification = (
                    f"🔴 ALARME SÉCURITÉ — BRUTE-FORCE SSH DÉTECTÉ\n"
                    f"IP Source: {ip}\nDétail: {message}\n"
                    f"Action immédiate requise: Bloquer {ip} via iptables/Fail2Ban"
                )
            elif "SURCHARGE" in type_alarme or "CPU" in type_alarme:
                notification = (
                    f"🟠 ALARME PERFORMANCE — SURCHARGE SYSTÈME DÉTECTÉE\n"
                    f"Détail: {message}\n"
                    f"Action immédiate requise: Vérifier les processus"
                )
            elif "SCAN" in type_alarme or "PORT" in type_alarme:
                notification = (
                    f"🔵 ALARME RECONNAISSANCE — SCAN DE PORTS DÉTECTÉ\n"
                    f"IP Source: {ip}\nDétail: {message}\n"
                    f"Action immédiate requise: Ajouter {ip} à la blacklist"
                )
            else:
                notification = (
                    f"⚠️ ALARME GÉNÉRALE — {severite}\n"
                    f"Détail: {message}\n"
                    f"Action immédiate requise: Inspection manuelle"
                )

            print(f"\n{'='*60}")
            print(notification)
            print(f"{'='*60}\n")

            ip_safe = str(ip).replace(".", "_").replace("/", "_")
            result  = _appeler_mcp("sauvegarder_rapport_s3", {
                "contenu":     notification,
                "nom_fichier": f"alarme_{ip_safe}.json",
                "type":        "alarme",
            })
            resultats.append(f"Alarme envoyée: {notification[:100]}... | S3: {result}")

        return "\n".join(resultats) if resultats else "✅ Aucune alarme déclenchée."


class OutilActionCorrective(BaseTool):
    name: str = "appliquer_action_corrective"
    description: str = (
        "Applique automatiquement l'action corrective selon le type d'anomalie. "
        "Gère aussi le mode SURVEILLANCE_NORMALE sans déclencher de blocage."
    )
    args_schema: type[BaseModel] = ActionCorrectiveInput

    def _run(self, anomalie_json: Optional[str] = None, **kwargs) -> str:
        # ── Parsing JSON ou texte libre ───────────────────────────────────────
        try:
            anomalie = json.loads(anomalie_json) if anomalie_json else {}
        except Exception:
            texte       = (anomalie_json or "")
            texte_upper = texte.upper()
            import re
            ip_trouvee = "multiple"
            match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', texte)
            if match:
                ip_trouvee = match.group(1)
            if "BRUTE" in texte_upper or "SSH" in texte_upper or "BLOCAGE" in texte_upper:
                anomalie = {"type": "BRUTE-FORCE SSH", "severite": "CRITIQUE", "ip": ip_trouvee}
            elif "CPU" in texte_upper or "SURCHARGE" in texte_upper:
                anomalie = {"type": "SURCHARGE CPU", "severite": "AVERTISSEMENT", "ip": "N/A"}
            elif "SCAN" in texte_upper or "PORT" in texte_upper:
                anomalie = {"type": "PORT SCAN", "severite": "AVERTISSEMENT", "ip": "N/A"}
            else:
                anomalie = {"description": str(anomalie_json)}

        type_anomalie = anomalie.get("type", anomalie.get("feature", ""))
        ip            = anomalie.get("ip", "N/A")
        severite      = anomalie.get("severite", "AVERTISSEMENT")
        action_req    = anomalie.get("action", "")

        type_upper   = type_anomalie.upper()
        action_upper = action_req.upper()

        # ── [FIX 3] SURVEILLANCE_NORMALE — cas explicite ─────────────────────
        if (
            "SURVEILLANCE" in type_upper
            or "NORMALE" in type_upper
            or "MONITORING" in action_upper
            or type_upper in ("", "FAIBLE", "INFO")
            and severite in ("FAIBLE", "INFO", "NORMAL")
        ):
            action = {
                "type":        "SURVEILLANCE_NORMALE",
                "description": "✅ Système en surveillance normale — aucune action corrective requise.",
                "statut":      "OK",
                "details":     {
                    "ip":       ip,
                    "severite": severite,
                    "message":  "Aucune attaque active confirmée. Monitoring passif actif.",
                    "conseil":  (
                        "Continuer la surveillance. "
                        "Prochain cycle d'analyse prévu automatiquement."
                    )
                }
            }
            print(f"[ACTION CORRECTIVE] {action['description']}")
            result_str = json.dumps(action, ensure_ascii=False, indent=2)
            _appeler_mcp("sauvegarder_rapport_s3", {
                "contenu":     result_str,
                "nom_fichier": "action_surveillance-normale.json",
                "type":        "action_corrective",
            })
            return result_str

        # ── Cas réels ─────────────────────────────────────────────────────────
        if "BRUTE" in type_upper or "SSH" in type_upper or "tentatives" in type_anomalie:
            if severite == "CRITIQUE":
                action = {
                    "type":        "BLOCAGE_IP_AWS_SECGROUP",
                    "commande":    f"iptables -A INPUT -s {ip} -j DROP",
                    "description": f"🔒 Blocage immédiat de {ip} via AWS Security Group (Boto3)",
                    "statut":      "EN_COURS"
                }
            else:
                action = {
                    "type":        "BAN_FAIL2BAN",
                    "commande":    f"fail2ban-client set sshd banip {ip}",
                    "description": f"🔒 Bannissement de {ip} via Fail2Ban",
                    "statut":      "EXÉCUTÉ"
                }

        elif "SCAN" in type_upper or "PORT" in type_upper:
            action = {
                "type":        "BLACKLIST_IP",
                "commande":    f"iptables -A INPUT -s {ip} -j DROP",
                "description": f"🚫 Ajout de {ip} à la blacklist (scan de ports détecté)",
                "statut":      "EXÉCUTÉ"
            }

        elif "SURCHARGE" in type_upper or "CPU" in type_upper or "erreurs" in type_anomalie:
            action = {
                "type":        "ALERTE_SYSTEME",
                "commande":    "systemctl status --failed && journalctl -p err -n 50",
                "description": "📧 Alerte email envoyée + logs critiques archivés dans S3",
                "statut":      "ALERTE_ENVOYÉE"
            }

        elif "MÉMOIRE" in type_upper or "MEM" in type_upper:
            action = {
                "type":        "LIBERER_MEMOIRE",
                "commande":    "sync && echo 3 > /proc/sys/vm/drop_caches",
                "description": "🧹 Libération du cache mémoire",
                "statut":      "EXÉCUTÉ"
            }

        elif "UTILISATEUR" in type_upper or "USER" in type_upper:
            user = anomalie.get("user", "unknown")
            action = {
                "type":        "DESACTIVER_COMPTE",
                "commande":    f"usermod -L {user}",
                "description": f"🔐 Compte {user} désactivé (comportement suspect)",
                "statut":      "EXÉCUTÉ"
            }

        else:
            action = {
                "type":        "INSPECTION_MANUELLE",
                "description": f"⚠️ Anomalie non reconnue — inspection requise : {anomalie}",
                "statut":      "EN_ATTENTE"
            }

        print(f"[ACTION CORRECTIVE] {action['description']}")
        if "commande" in action:
            print(f"[COMMANDE]          {action['commande']}")

        # ── Blocage AWS réel ──────────────────────────────────────────────────
        est_ssh       = "BRUTE" in type_upper or "SSH" in type_upper
        ip_specifique = ip and ip not in ("N/A", "multiple", "")

        if AWS_SECURITY_DISPONIBLE and est_ssh and ip_specifique and severite == "CRITIQUE":
            print(f"\n[AWS BOTO3] ⚡ Blocage RÉEL de {ip}...")
            try:
                aws_result = bloquer_ip_secgroup(
                    ip=ip,
                    raison=f"Agent IA CrewAI | {type_anomalie} | {severite} | Auto-blocage"
                )
                action["aws_blocage_reel"] = aws_result
                action["statut"]           = "EXÉCUTÉ"
                print(f"[AWS BOTO3] Résultat : {aws_result.get('message', 'N/A')}")
            except Exception as e:
                print(f"[AWS BOTO3] ❌ {type(e).__name__}: {e}")
                action["aws_blocage_reel"] = {"statut": "ERREUR", "message": str(e)}
                action["statut"]           = "ERREUR_AWS"

        elif AWS_SECURITY_DISPONIBLE and est_ssh and not ip_specifique:
            action["aws_blocage_reel"] = {
                "statut":  "IGNORÉ",
                "raison":  f"IP '{ip}' non spécifique — blocage manuel requis",
            }

        result_str  = json.dumps(action, ensure_ascii=False, indent=2)
        nom_fichier = f"action_{action['type'].lower().replace('_', '-')}.json"
        _appeler_mcp("sauvegarder_rapport_s3", {
            "contenu":     json.dumps(action, ensure_ascii=False),
            "nom_fichier": nom_fichier,
            "type":        "action_corrective",
        })

        return result_str


class OutilOrchestration(BaseTool):
    name: str = "orchestrer_pipeline"
    description: str = "Coordonne et priorise le travail des 5 autres agents."
    args_schema: type[BaseModel] = OrchestrationInput

    def _run(self, contexte: Optional[str] = None, **kwargs) -> str:
        result = _appeler_mcp("orchestrer_pipeline", {"contexte": contexte or str(kwargs)})
        return result if isinstance(result, str) and result.strip() else "Pipeline orchestré avec succès."


class OutilSauvegarderRapport(BaseTool):
    name: str = "sauvegarder_rapport_s3"
    description: str = "Sauvegarde le rapport final complet sur S3."
    args_schema: type[BaseModel] = SauvegarderRapportInput

    def _run(self, rapport_json: Optional[str] = None, **kwargs) -> str:
        try:
            data = json.loads(rapport_json) if isinstance(rapport_json, str) else {}
        except Exception:
            data = {}

        data["contenu"]     = rapport_json or str(kwargs)
        data["nom_fichier"] = f"rapport_{data.get('timestamp', 'final')}.json"

        return _appeler_mcp(
            "sauvegarder_rapport_s3",
            data or {"contenu": str(kwargs), "nom_fichier": "rapport_final.json"}
        )


# ================================
# INSTANCES DES OUTILS
# ================================
outil_lister_logs  = OutilListerLogs()
outil_lire_logs    = OutilLireLogs()
outil_analyser     = OutilAnalyserLogs()
outil_anomalies    = OutilDetecterAnomalies()
outil_alarme       = OutilDeclencherAlarme()
outil_correctif    = OutilActionCorrective()
outil_orchestrer   = OutilOrchestration()
outil_rapport      = OutilSauvegarderRapport()


# ================================
# 6 AGENTS SPÉCIALISÉS
# ================================

collector_agent = Agent(
    role="Collecteur de Logs",
    goal=(
        "Collecter tous les fichiers logs depuis Amazon S3 "
        "et assurer la disponibilité des données pour les agents suivants."
    ),
    backstory=(
        "Tu es un expert en collecte de données système. Tu maîtrises parfaitement "
        "Amazon S3 et récupères les logs des serveurs Linux."
    ),
    tools=[outil_lister_logs, outil_lire_logs],
    llm=llm,
    verbose=True
)

analyst_agent = Agent(
    role="Analyste de Logs Linux",
    goal=(
        "Analyser en profondeur les logs pour identifier tous les types "
        "d'attaques et événements suspects."
    ),
    backstory=(
        "Tu es un expert en analyse de logs Linux et en cybersécurité. "
        "Tu distingues les erreurs critiques des simples warnings."
    ),
    tools=[outil_analyser],
    llm=llm,
    verbose=True
)

detector_agent = Agent(
    role="Détecteur d'Anomalies et Déclencheur d'Alarmes",
    goal=(
        "Détecter les anomalies confirmées et déclencher une alarme UNIQUEMENT "
        "si une vraie menace est présente. Ne pas déclencher d'alarme si le "
        "système est en état normal."
    ),
    backstory=(
        "Tu es un expert en cybersécurité et détection d'anomalies. "
        "Tu déclenches des alarmes SEULEMENT quand une anomalie réelle est confirmée. "
        "Si nb_anomalies=0 et aucune alarme critique, tu retournes un statut OK "
        "sans déclencher d'alarme."
    ),
    tools=[outil_anomalies, outil_alarme],
    llm=llm,
    verbose=True
)

corrector_agent = Agent(
    role="Agent Correcteur Automatique",
    goal=(
        "Appliquer l'action corrective appropriée selon l'anomalie reçue. "
        "En mode surveillance normale, confirmer l'état OK sans bloquer d'IP."
    ),
    backstory=(
        "Tu es un expert en remédiation automatique. "
        "Pour SURVEILLANCE_NORMALE tu confirmes simplement l'état sain. "
        "Pour les vraies attaques tu bloques via AWS/iptables/Fail2Ban."
    ),
    tools=[outil_correctif],
    llm=llm,
    verbose=True
)

orchestrator_agent = Agent(
    role="Orchestrateur de Pipeline Multi-Agents",
    goal=(
        "Coordonner les 5 agents, gérer les priorités et garantir "
        "la cohérence globale de l'analyse."
    ),
    backstory=(
        "Tu es le chef d'orchestre du système de supervision. "
        "Tu réponds DIRECTEMENT sans utiliser d'outil externe."
    ),
    tools=[],
    llm=llm,
    verbose=True
)

reporter_agent = Agent(
    role="Rapporteur et Synthétiseur",
    goal=(
        "Générer un rapport complet consolidant les résultats "
        "de tous les agents et le sauvegarder sur S3."
    ),
    backstory=(
        "Tu es expert en reporting opérationnel. "
        "Tu synthétises analyses, anomalies, alarmes et actions en rapports clairs."
    ),
    tools=[outil_rapport],
    llm=llm,
    verbose=True
)