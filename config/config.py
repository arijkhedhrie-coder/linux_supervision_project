# Configuration generale du projet

import os
from dotenv import load_dotenv
load_dotenv()

AWS_ACCESS_KEY_ID = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_ACCESS_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
ANTHROPIC_API_KEY = os.getenv("ANTHROPIC_API_KEY")





BUCKET_NAME    = os.getenv("S3_BUCKET_NAME", "pfe-linux-logs-supervision")
AWS_REGION     = os.getenv("AWS_REGION", "us-east-1")
AWS_ACCESS_KEY = os.getenv("AWS_ACCESS_KEY_ID")
AWS_SECRET_KEY = os.getenv("AWS_SECRET_ACCESS_KEY")
CHEMIN_RAW  = r"C:\Users\LENOVO\pfe-linux-supervision\data\raw"
SERVEUR_NOM = "server1"
ANNEE       = "2026"
