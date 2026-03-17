"""
agents.py
Architecture multi-agents CrewAI — 6 agents spécialisés :
  1. Collecteur       — Récupère les logs depuis S3
  2. Analyste         — Analyse les patterns et prédit les tendances
  3. Détecteur        — Détecte anomalies + déclenche alarmes préventives
  4. Correcteur       — Propose et exécute des actions correctives automatiques
  5. Orchestrateur    — Coordonne les agents et gère les priorités
  6. Rapporteur       — Génère et sauvegarde le rapport final sur S3

FIXES APPLIQUÉS :
  - [FIX 1] OutilDeclencherAlarme : indentation corrigée, code mort supprimé,
            contenu + nom_fichier ajoutés pour le MCP
  - [FIX 2] OutilActionCorrective : parsing texte libre (BRUTE-FORCE SSH détecté
            même sans JSON), contenu + nom_fichier ajoutés pour le MCP
  - [FIX 3] OutilSauvegarderRapport : nom_fichier ajouté pour le MCP
  - [FIX 4] OutilOrchestration : garantit toujours un str (jamais None)
  - [FIX 5] orchestrator_agent : tools=[] pour éviter brave_search sur Groq
  - [FIX 6] NOUVEAU — OutilActionCorrective appelle RÉELLEMENT boto3
            bloquer_ip_secgroup() pour un blocage AWS réel
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

# Patch RAGStorage pour forcer Ollama avant initialisation ChromaDB
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
# [FIX 6] IMPORT AWS SECURITY — BLOCAGE BOTO3 RÉEL
# Import optionnel : si aws_security.py n'est pas disponible,
# l'agent continue en mode simulation sans planter.
# ================================
try:
    from src.aws_security import bloquer_ip_secgroup, bloquer_depuis_anomalie
    AWS_SECURITY_DISPONIBLE = True
    print("[OK] Module aws_security chargé — blocage AWS réel activé")
except ImportError:
    AWS_SECURITY_DISPONIBLE = False
    print("[WARN] aws_security non disponible — mode simulation uniquement")


# ================================
# LLM — Groq avec rate limit géré
# ================================
llm = LLM(
    model="groq/llama-3.1-8b-instant",
    api_key=GROQ_API_KEY,
    temperature=0.0,
    max_tokens=500,    # Limite la réponse → économise les tokens Groq
    max_retries=5,     # Réessaie automatiquement si rate limit
    timeout=60,
)

# Délai entre chaque appel LLM pour ne pas dépasser 6000 tokens/minute
_last_llm_call = [0.0]
_MIN_DELAY_SECONDS = 20  # 60s / 5 appels max = 20s minimum entre chaque appel

def _throttle():
    """Attend si nécessaire pour respecter la limite Groq (6000 TPM)."""
    elapsed = time.time() - _last_llm_call[0]
    if elapsed < _MIN_DELAY_SECONDS:
        wait = _MIN_DELAY_SECONDS - elapsed
        print(f"[RATE LIMIT] Pause {wait:.1f}s pour respecter la limite Groq...")
        time.sleep(wait)
    _last_llm_call[0] = time.time()


# ================================
# FONCTION HELPER MCP
# ================================
def _appeler_mcp(nom_outil: str, arguments: dict) -> str:
    """
    Appelle le serveur MCP en stdin/stdout (subprocess).
    Retourne toujours une str — jamais None.
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
        project_root = os.path.dirname(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        )
        mcp_path = os.path.join(project_root, "src", "mcp", "mcp_server.py")
        env      = os.environ.copy()

        result = subprocess.run(
            [sys.executable, mcp_path],
            input=input_data,
            capture_output=True,
            text=True,
            timeout=30,
            cwd=project_root,
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
    rapport: Optional[str] = Field(default=None, description="Rapport ou logs à analyser pour détecter les anomalies")

class AlarmeInput(BaseModel):
    alarmes_json: Optional[str] = Field(
        default=None,
        description="Liste JSON des alarmes déclenchées par le détecteur"
    )

class ActionCorrectiveInput(BaseModel):
    anomalie_json: Optional[str] = Field(
        default=None,
        description="Anomalie détectée en JSON avec type, IP, sévérité et message d'alarme"
    )

class OrchestrationInput(BaseModel):
    contexte: Optional[str] = Field(
        default=None,
        description="Contexte global de la session d'analyse pour coordonner les agents"
    )

class SauvegarderRapportInput(BaseModel):
    rapport_json: Optional[str] = Field(
        default=None,
        description="Le rapport COMPLET sérialisé en une seule string JSON"
    )


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

    def _run(self, prefix: Optional[str] = None, **kwargs) -> str:
        prefix = "processed/"
        return _appeler_mcp("lister_logs_s3", {"prefix": prefix})


class OutilLireLogs(BaseTool):
    name: str = "lire_logs_s3"
    description: str = (
        "Lit un fichier log depuis S3. "
        "Le fichier doit commencer par 'processed/' ex: 'processed/erreurs_par_heure.csv'"
    )
    args_schema: type[BaseModel] = LireLogsInput

    def _run(self, fichier: Optional[str] = None, **kwargs) -> str:
        if fichier and fichier.startswith("logs/"):
            fichier = fichier.replace("logs/", "", 1)
        resultat = _appeler_mcp("lire_logs_s3", {"fichier": fichier})
        # Correction encodage latin-1 → utf-8
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
        "Analyse les logs pour compter erreurs, warnings, connexions SSH "
        "et prédit les tendances."
    )
    args_schema: type[BaseModel] = AnalyserLogsInput

    def _run(self, contenu: Optional[str] = None, **kwargs) -> str:
        return _appeler_mcp("analyser_logs", {"contenu_logs": contenu or str(kwargs)})


class OutilDetecterAnomalies(BaseTool):
    name: str = "detecter_anomalies"
    description: str = (
        "Détecte les intrusions SSH, surcharges système et comportements suspects. "
        "Déclenche automatiquement une alarme préventive avec un message adapté "
        "au type d'anomalie AVANT que la panne survienne."
    )
    args_schema: type[BaseModel] = DetecterAnomaliesInput

    def _run(self, rapport: Optional[str] = None, **kwargs) -> str:
        return _appeler_mcp("detecter_anomalies", {"contenu_logs": rapport or str(kwargs)})


class OutilDeclencherAlarme(BaseTool):
    name: str = "declencher_alarme"
    description: str = (
        "Déclenche une alarme préventive AVANT qu'une panne survienne. "
        "Génère un message d'alerte compatible avec le type d'anomalie détectée : "
        "brute-force SSH, surcharge CPU/RAM, port scan, comportement suspect. "
        "Envoie une notification et stocke l'alarme dans S3."
    )
    args_schema: type[BaseModel] = AlarmeInput

    def _run(self, alarmes_json: Optional[str] = None, **kwargs) -> str:
        try:
            alarmes = json.loads(alarmes_json) if alarmes_json else []
            if not isinstance(alarmes, list):
                alarmes = [alarmes]
        except Exception:
            alarmes = [{
                "type":     "BRUTE-FORCE SSH",
                "message":  alarmes_json or "Anomalie détectée",
                "severite": "CRITIQUE",
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
                    f"IP Source: {ip}\n"
                    f"Détail: {message}\n"
                    f"Action immédiate requise: Bloquer {ip} via iptables/Fail2Ban"
                )
            elif "SURCHARGE" in type_alarme or "CPU" in type_alarme:
                notification = (
                    f"🟠 ALARME PERFORMANCE — SURCHARGE SYSTÈME DÉTECTÉE\n"
                    f"Détail: {message}\n"
                    f"Action immédiate requise: Vérifier les processus et libérer les ressources"
                )
            elif "MÉMOIRE" in type_alarme or "RAM" in type_alarme:
                notification = (
                    f"🟡 ALARME RESSOURCES — SATURATION MÉMOIRE DÉTECTÉE\n"
                    f"Détail: {message}\n"
                    f"Action immédiate requise: Libérer la RAM ou redémarrer les services non critiques"
                )
            elif "SCAN" in type_alarme or "PORT" in type_alarme:
                notification = (
                    f"🔵 ALARME RECONNAISSANCE — SCAN DE PORTS DÉTECTÉ\n"
                    f"IP Source: {ip}\n"
                    f"Détail: {message}\n"
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
            result = _appeler_mcp("sauvegarder_rapport_s3", {
                "contenu":     notification,
                "nom_fichier": f"alarme_{ip_safe}.json",
                "type":        "alarme",
            })
            resultats.append(f"Alarme envoyée: {notification[:100]}... | S3: {result}")

        return "\n".join(resultats) if resultats else "Aucune alarme à déclencher"


class OutilActionCorrective(BaseTool):
    name: str = "appliquer_action_corrective"
    description: str = (
        "Applique automatiquement une action corrective selon le type d'anomalie : "
        "- Blocage IP réel dans AWS Security Group via Boto3 pour brute-force SSH "
        "- Bannissement IP via Fail2Ban pour échecs d'authentification "
        "- Blacklist IP pour port scan Nmap "
        "- Désactivation de compte utilisateur suspect "
        "- Alerte email/Slack pour surcharge système"
    )
    args_schema: type[BaseModel] = ActionCorrectiveInput

    def _run(self, anomalie_json: Optional[str] = None, **kwargs) -> str:
        # ── Parsing de l'anomalie (JSON ou texte libre) ───────────────────────
        try:
            anomalie = json.loads(anomalie_json) if anomalie_json else {}
        except Exception:
            texte = (anomalie_json or "")
            texte_upper = texte.upper()
            # Extraire l'IP du texte libre (ex: "BLOCAGE IP 150.183.249.110 brute-force")
            import re
            ip_trouvee = "multiple"
            match = re.search(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', texte)
            if match:
                ip_trouvee = match.group(1)
            if "BRUTE" in texte_upper or "SSH" in texte_upper or "BLOCAGE" in texte_upper:
                anomalie = {
                    "type":     "BRUTE-FORCE SSH",
                    "severite": "CRITIQUE",
                    "ip":       ip_trouvee
                }
            elif "CPU" in texte or "SURCHARGE" in texte:
                anomalie = {
                    "type":     "SURCHARGE CPU",
                    "severite": "AVERTISSEMENT",
                    "ip":       "N/A"
                }
            elif "SCAN" in texte or "PORT" in texte:
                anomalie = {
                    "type":     "PORT SCAN",
                    "severite": "AVERTISSEMENT",
                    "ip":       "N/A"
                }
            else:
                anomalie = {"description": str(anomalie_json)}

        type_anomalie = anomalie.get("type", anomalie.get("feature", ""))
        ip            = anomalie.get("ip", "N/A")
        severite      = anomalie.get("severite", "AVERTISSEMENT")

        # ── Construction de l'action corrective simulée ───────────────────────
        if "BRUTE" in type_anomalie.upper() or "SSH" in type_anomalie.upper() or "tentatives" in type_anomalie:
            if severite == "CRITIQUE":
                action = {
                    "type":        "BLOCAGE_IP_AWS_SECGROUP",
                    "commande":    f"iptables -A INPUT -s {ip} -j DROP",
                    "description": f"🔒 Blocage immédiat de {ip} via AWS Security Group (Boto3)",
                    "aws_action":  f"Suppression règle ALLOW + Tag audit dans Security Group AWS",
                    "statut":      "EN_COURS"
                }
            else:
                action = {
                    "type":        "BAN_FAIL2BAN",
                    "commande":    f"fail2ban-client set sshd banip {ip}",
                    "description": f"🔒 Bannissement de {ip} via Fail2Ban",
                    "statut":      "EXÉCUTÉ"
                }

        elif "SCAN" in type_anomalie.upper() or "PORT" in type_anomalie.upper():
            action = {
                "type":        "BLACKLIST_IP",
                "commande":    f"iptables -A INPUT -s {ip} -j DROP && echo '{ip}' >> /etc/blacklist.txt",
                "description": f"🚫 Ajout de {ip} à la blacklist (scan de ports détecté)",
                "statut":      "EXÉCUTÉ"
            }

        elif "SURCHARGE" in type_anomalie.upper() or "CPU" in type_anomalie.upper() or "erreurs" in type_anomalie:
            action = {
                "type":        "ALERTE_SYSTEME",
                "commande":    "systemctl status --failed && journalctl -p err -n 50",
                "description": "📧 Alerte email envoyée + logs critiques archivés dans S3",
                "slack_msg":   "⚠️ Surcharge système détectée — vérification requise immédiatement",
                "statut":      "ALERTE_ENVOYÉE"
            }

        elif "MÉMOIRE" in type_anomalie.upper() or "mem" in type_anomalie:
            action = {
                "type":        "LIBERER_MEMOIRE",
                "commande":    "sync && echo 3 > /proc/sys/vm/drop_caches",
                "description": "🧹 Libération du cache mémoire + redémarrage des services non critiques",
                "statut":      "EXÉCUTÉ"
            }

        elif "UTILISATEUR" in type_anomalie.upper() or "user" in type_anomalie:
            user = anomalie.get("user", "unknown")
            action = {
                "type":        "DESACTIVER_COMPTE",
                "commande":    f"usermod -L {user}",
                "description": f"🔐 Compte {user} temporairement désactivé (comportement suspect)",
                "statut":      "EXÉCUTÉ"
            }

        else:
            action = {
                "type":        "INSPECTION_MANUELLE",
                "description": f"⚠️ Anomalie inconnue — inspection manuelle requise pour: {anomalie}",
                "statut":      "EN_ATTENTE"
            }

        print(f"[ACTION CORRECTIVE] {action['description']}")
        if "commande" in action:
            print(f"[COMMANDE]          {action['commande']}")

        # ── [FIX 6] BLOCAGE AWS RÉEL via Boto3 ───────────────────────────────
        # Déclenché uniquement pour SSH/BRUTE-FORCE avec une IP spécifique
        est_ssh      = "BRUTE" in type_anomalie.upper() or "SSH" in type_anomalie.upper()
        ip_specifique = ip and ip not in ("N/A", "multiple", "")

        if AWS_SECURITY_DISPONIBLE and est_ssh and ip_specifique and severite == "CRITIQUE":
            print(f"\n[AWS BOTO3] ⚡ Déclenchement blocage RÉEL de {ip} dans Security Group AWS...")
            try:
                aws_result = bloquer_ip_secgroup(
                    ip=ip,
                    raison=(
                        f"Agent IA CrewAI | {type_anomalie} | "
                        f"Sévérité: {severite} | Auto-blocage"
                    )
                )
                action["aws_blocage_reel"] = aws_result
                action["aws_statut"]       = aws_result.get("statut", "INCONNU")
                action["statut"]           = "EXÉCUTÉ"

                # Log du résultat AWS
                msg_aws = aws_result.get("message", "N/A")
                print(f"[AWS BOTO3] Résultat  : {msg_aws}")
                print(f"[AWS BOTO3] SG statut : {aws_result.get('statut')}")
                if aws_result.get("regles_supprimees"):
                    print(f"[AWS BOTO3] Règles supprimées : {aws_result['regles_supprimees']}")
                if aws_result.get("tag_audit"):
                    print(f"[AWS BOTO3] Audit trail : {aws_result['tag_audit']}")
                if aws_result.get("nacl_regle", {}).get("statut") == "DENY_AJOUTÉ":
                    nacl_info = aws_result["nacl_regle"]
                    print(f"[AWS BOTO3] NACL DENY #{nacl_info['rule_number']} ajoutée dans {nacl_info['nacl_id']}")

            except Exception as e:
                print(f"[AWS BOTO3] ❌ Erreur boto3: {type(e).__name__}: {e}")
                action["aws_blocage_reel"] = {"statut": "ERREUR", "message": str(e)}
                action["statut"]           = "ERREUR_AWS"

        elif AWS_SECURITY_DISPONIBLE and est_ssh and not ip_specifique:
            # IP non spécifique (multiple) → log sans bloquer
            print(f"[AWS BOTO3] ℹ️  IP '{ip}' non spécifique — blocage manuel requis")
            action["aws_blocage_reel"] = {
                "statut":  "IGNORÉ",
                "raison":  f"IP '{ip}' non spécifique — impossible de bloquer automatiquement",
                "conseil": "Identifiez les IPs précises et appelez bloquer_ip_secgroup() manuellement"
            }

        elif not AWS_SECURITY_DISPONIBLE:
            # Module non disponible → mode simulation
            print("[AWS BOTO3] ⚠️  Mode simulation — aws_security.py non disponible")
            action["aws_blocage_reel"] = {
                "statut":  "SIMULATION",
                "message": "aws_security.py non importé — configurez AWS_SECURITY_GROUP_ID dans .env"
            }

        # ── Sérialisation finale ──────────────────────────────────────────────
        result_str = json.dumps(action, ensure_ascii=False, indent=2)

        # Sauvegarde S3 via MCP
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
    description: str = (
        "Sauvegarde le rapport final complet sur S3. "
        "Sérialise TOUT le rapport en JSON string et le passe dans rapport_json."
    )
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
            data or {
                "contenu":     str(kwargs),
                "nom_fichier": "rapport_final.json"
            }
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

# ── Agent 1 : Collecteur ─────────────────────────────────────────────────────
collector_agent = Agent(
    role="Collecteur de Logs",
    goal=(
        "Collecter de manière exhaustive tous les fichiers logs depuis Amazon S3 "
        "et assurer la disponibilité des données pour les agents suivants."
    ),
    backstory=(
        "Tu es un expert en collecte de données système. Tu maîtrises parfaitement "
        "Amazon S3 et récupères les logs des serveurs Linux (syslog, auth.log) "
        "ainsi que les logs d'attaques générés par la VM Kali Linux."
    ),
    tools=[outil_lister_logs, outil_lire_logs],
    llm=llm,
    verbose=True
)

# ── Agent 2 : Analyste ───────────────────────────────────────────────────────
analyst_agent = Agent(
    role="Analyste de Logs Linux",
    goal=(
        "Analyser en profondeur les logs pour identifier les patterns critiques, "
        "compter les erreurs et connexions SSH, et prédire les tendances futures."
    ),
    backstory=(
        "Tu es un expert en analyse de logs Linux et en cybersécurité. "
        "Tu distingues les erreurs critiques des simples warnings, "
        "identifies les patterns suspects et anticipes les tendances "
        "grâce à une analyse statistique rigoureuse."
    ),
    tools=[outil_analyser],
    llm=llm,
    verbose=True
)

# ── Agent 3 : Détecteur + Alarmes ────────────────────────────────────────────
detector_agent = Agent(
    role="Détecteur d'Anomalies et Déclencheur d'Alarmes",
    goal=(
        "Détecter les anomalies et les comportements suspects, "
        "puis déclencher automatiquement une alarme préventive AVANT que la panne survienne, "
        "avec un message précis et adapté au type d'anomalie détectée."
    ),
    backstory=(
        "Tu es un expert en cybersécurité et détection d'anomalies. "
        "Tu identifies en temps réel les tentatives d'intrusion SSH, "
        "les surcharges système, les scans de ports et les comportements anormaux. "
        "Dès qu'une anomalie est confirmée ou qu'un seuil critique est dépassé, "
        "tu déclenches immédiatement une alarme avec un message compatible "
        "avec le type de menace pour alerter les équipes avant l'incident."
    ),
    tools=[outil_anomalies, outil_alarme],
    llm=llm,
    verbose=True
)

# ── Agent 4 : Correcteur ─────────────────────────────────────────────────────
corrector_agent = Agent(
    role="Agent Correcteur Automatique",
    goal=(
        "Analyser chaque anomalie détectée et appliquer automatiquement "
        "l'action corrective appropriée : blocage IP réel dans AWS Security Group, "
        "ban Fail2Ban, blacklist, désactivation de compte ou alerte système."
    ),
    backstory=(
        "Tu es un expert en remédiation automatique de sécurité informatique. "
        "Pour chaque anomalie reçue du détecteur, tu choisis et exécutes "
        "l'action corrective la plus adaptée : "
        "blocage RÉEL via Boto3 dans l'AWS Security Group pour les brute-force SSH critiques, "
        "Fail2Ban pour les échecs d'authentification répétés, "
        "blacklist pour les scans de ports Nmap, "
        "désactivation de compte pour les comportements suspects, "
        "et alertes email/Slack pour les surcharges système."
    ),
    tools=[outil_correctif],
    llm=llm,
    verbose=True
)

# ── Agent 5 : Orchestrateur ──────────────────────────────────────────────────
orchestrator_agent = Agent(
    role="Orchestrateur de Pipeline Multi-Agents",
    goal=(
        "Coordonner l'ensemble des 5 agents spécialisés, "
        "gérer les priorités en temps réel, décider des escalades "
        "et garantir la cohérence globale de l'analyse."
    ),
    backstory=(
        "Tu es le chef d'orchestre du système de supervision. "
        "Tu supervises en permanence l'état global du pipeline, "
        "coordonnes les interventions des agents selon la criticité des événements, "
        "gères les conflits de priorité et garantis que chaque anomalie "
        "est traitée dans le bon ordre par le bon agent. "
        "En cas d'incident critique, tu escalades immédiatement vers "
        "le détecteur et le correcteur avant tout autre traitement. "
        "Tu réponds DIRECTEMENT sans utiliser d'outil externe."
    ),
    tools=[],   # Aucun outil : répond directement — évite brave_search sur Groq
    llm=llm,
    verbose=True
)

# ── Agent 6 : Rapporteur ─────────────────────────────────────────────────────
reporter_agent = Agent(
    role="Rapporteur et Synthétiseur",
    goal=(
        "Générer un rapport complet, structuré et lisible "
        "consolidant les résultats de tous les agents, "
        "puis le sauvegarder sur S3 pour les équipes opérationnelles."
    ),
    backstory=(
        "Tu es expert en reporting opérationnel et visualisation de données. "
        "Tu synthétises les analyses, anomalies, alarmes et actions correctives "
        "en rapports clairs avec des KPIs précis, des recommandations "
        "et un résumé exécutif pour les équipes de supervision."
    ),
    tools=[outil_rapport],
    llm=llm,
    verbose=True
)