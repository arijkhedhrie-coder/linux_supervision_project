"""
find_sg.py
Script rapide pour trouver ton Security Group ID AWS.
Place ce fichier à la RACINE du projet : C:\\Users\\LENOVO\\pfe-linux-supervision\\find_sg.py

Usage :
    python find_sg.py
"""

import boto3
import json
import os
import re
from dotenv import load_dotenv

load_dotenv()

AWS_REGION   =os.getenv("AWS_REGION3", "us-east-1")

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")

print("\n" + "="*65)
print("  RECHERCHE DES SECURITY GROUPS AWS")
print(f"  Compte : {AWS_ACCESS_KEY_ID[:8]}...")
print(f"  Région : {AWS_REGION}")
print("="*65)

ec2 = boto3.client(
    "ec2",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)

# ── 1. Lister tous les Security Groups ───────────────────────────────────────
response = ec2.describe_security_groups()
sgs      = response["SecurityGroups"]

print(f"\n  {len(sgs)} Security Group(s) trouvé(s) dans {AWS_REGION} :\n")

sg_retenu    = None
score_max    = -1
sg_avec_ssh  = []

for sg in sgs:
    sg_id   = sg["GroupId"]
    nom     = sg["GroupName"]
    desc    = sg["Description"]
    vpc_id  = sg.get("VpcId", "")
    tags    = {t["Key"]: t["Value"] for t in sg.get("Tags", [])}
    nom_tag = tags.get("Name", "")
    regles  = sg.get("IpPermissions", [])

    # Vérifier si port 22 (SSH) est ouvert
    ssh_ouvert = False
    ssh_detail = []
    for r in regles:
        fp = r.get("FromPort", -1)
        tp = r.get("ToPort",   -1)
        pr = r.get("IpProtocol", "")
        if pr == "-1" or (isinstance(fp, int) and fp <= 22 <= tp):
            for iprange in r.get("IpRanges", []):
                cidr = iprange.get("CidrIp", "")
                ssh_ouvert = True
                ssh_detail.append(cidr)

    # Score heuristique pour choisir le SG le plus pertinent
    score = 0
    if nom != "default":                         score += 2
    if ssh_ouvert:                               score += 10
    if "pfe"          in (nom+desc+nom_tag).lower(): score += 15
    if "linux"        in (nom+desc+nom_tag).lower(): score += 8
    if "supervision"  in (nom+desc+nom_tag).lower(): score += 8
    if "launch-wizard" in nom.lower():           score += 5

    marqueur = "★ RECOMMANDÉ" if score > score_max else ""

    print(f"  {'─'*55}")
    print(f"  ID    : {sg_id}  {marqueur}")
    print(f"  Nom   : {nom}{f'  [{nom_tag}]' if nom_tag else ''}")
    print(f"  VPC   : {vpc_id}")
    print(f"  Desc  : {desc}")
    print(f"  SSH   : {'✅ OUVERT depuis ' + str(ssh_detail) if ssh_ouvert else '❌ Fermé'}")
    print(f"  Règles: {len(regles)} entrée(s)")
    print(f"  Score : {score}")

    if score > score_max:
        score_max = score
        sg_retenu = sg

    if ssh_ouvert:
        sg_avec_ssh.append(sg_id)

# ── 2. Résultat ───────────────────────────────────────────────────────────────
print(f"\n{'='*65}")
print("  RÉSULTAT")
print(f"{'='*65}")

if not sg_retenu:
    print("\n  ❌ Aucun Security Group trouvé.")
    print("     Vérifiez que vous avez des instances EC2 dans us-east-1")
    exit(1)

sg_id  = sg_retenu["GroupId"]
vpc_id = sg_retenu.get("VpcId", "")

print(f"\n  ✅ Security Group recommandé : {sg_id}")
print(f"     Nom : {sg_retenu['GroupName']}")
print(f"     VPC : {vpc_id}")
print(f"\n  SGS avec SSH ouvert : {sg_avec_ssh}")

# ── 3. Chercher la NACL associée ──────────────────────────────────────────────
nacl_id = None
if vpc_id:
    try:
        response_nacl = ec2.describe_network_acls(
            Filters=[{"Name": "vpc-id", "Values": [vpc_id]}]
        )
        nacls = response_nacl["NetworkAcls"]
        print(f"\n  Network ACLs trouvées ({len(nacls)}) :")
        for nacl in nacls:
            is_def = nacl["IsDefault"]
            nid    = nacl["NetworkAclId"]
            print(f"    {'[DÉFAUT]' if is_def else '[CUSTOM] '} {nid}")
            if is_def:
                nacl_id = nid
    except Exception as e:
        print(f"  ⚠️  NACL non accessible : {e}")

# ── 4. Générer les lignes .env à ajouter ──────────────────────────────────────
print(f"\n{'='*65}")
print("  LIGNES À AJOUTER DANS TON .env")
print(f"{'='*65}\n")
print(f"  AWS_SECURITY_GROUP_ID={sg_id}")
if nacl_id:
    print(f"  AWS_NACL_ID={nacl_id}")
print()

# ── 5. Mise à jour automatique du .env ────────────────────────────────────────
# Cherche le .env à la racine du projet
env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")

if os.path.exists(env_path):
    with open(env_path, "r", encoding="utf-8") as f:
        contenu = f.read()

    # Ajouter/remplacer AWS_SECURITY_GROUP_ID
    if "AWS_SECURITY_GROUP_ID" in contenu:
        contenu = re.sub(r"AWS_SECURITY_GROUP_ID=.*", f"AWS_SECURITY_GROUP_ID={sg_id}", contenu)
        print(f"  ✅ AWS_SECURITY_GROUP_ID mis à jour dans {env_path}")
    else:
        # Insérer après la ligne AWS_REGION
        contenu = re.sub(
            r"(AWS_REGION=.*)",
            rf"\1\nAWS_SECURITY_GROUP_ID={sg_id}",
            contenu
        )
        print(f"  ✅ AWS_SECURITY_GROUP_ID ajouté dans {env_path}")

    # Ajouter AWS_NACL_ID si trouvé
    if nacl_id:
        if "AWS_NACL_ID" in contenu:
            contenu = re.sub(r"AWS_NACL_ID=.*", f"AWS_NACL_ID={nacl_id}", contenu)
        else:
            contenu = re.sub(
                r"(AWS_SECURITY_GROUP_ID=.*)",
                rf"\1\nAWS_NACL_ID={nacl_id}",
                contenu
            )
        print(f"  ✅ AWS_NACL_ID ajouté dans {env_path}")

    with open(env_path, "w", encoding="utf-8") as f:
        f.write(contenu)

    print(f"\n  .env sauvegardé : {env_path}")
    print("\n  Lance maintenant :")
    print("  python test_aws_security.py")
else:
    print(f"  ⚠️  .env non trouvé à {env_path}")
    print("  Ajoute manuellement dans ton .env :")
    print(f"  AWS_SECURITY_GROUP_ID={sg_id}")
    if nacl_id:
        print(f"  AWS_NACL_ID={nacl_id}")

print(f"\n{'='*65}\n")