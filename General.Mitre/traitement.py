import os
import requests
import pandas as pd
from datetime import datetime, timedelta, timezone

API_KEY = "52ded5af-e3e2-4374-8caa-99289b3046f2"

def get_recent_cves(produit):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    headers = {
        "apiKey": API_KEY
    }

    utc_now = datetime.now(timezone.utc)
    utc_24h_ago = utc_now - timedelta(days=10)

    params = {
        "keywordSearch": produit,
        "pubStartDate": utc_24h_ago.isoformat(),
        "pubEndDate": utc_now.isoformat(),
        "resultsPerPage": 20
    }

    response = requests.get(base_url, headers=headers, params=params)

    results = []

    if response.status_code == 200:
        data = response.json()
        cves = data.get("vulnerabilities", [])
        for cve_item in cves:
            cve_id = cve_item["cve"]["id"]
            desc = cve_item["cve"]["descriptions"][0]["value"]
            pub_date = cve_item["cve"]["published"]
            print(f"{cve_id} - Publié le {pub_date}\nDescription: {desc}\n")

            results.append({
                "Technologie": produit,
                "CVE ID": cve_id,
                "Date de publication": pub_date,
                "Description": desc
            })
    else:
        print(f"Erreur HTTP ({response.status_code}) pour la technologie : {produit}")

    return results

# === Récupérer le dossier du script (fonctionne en script, sinon cwd) ===
try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    script_dir = os.getcwd()

# Chemin complet vers le fichier technologie.csv dans le même dossier
techno_csv_path = os.path.join(script_dir, "technologie.csv")

# Lecture des technologies depuis technologie.csv
df_tech = pd.read_csv(techno_csv_path, header=None)
technologies = df_tech[0].dropna().unique()

all_cves = []

for tech in technologies:
    print(f"\n🔍 Recherche pour : {tech}")
    cves = get_recent_cves(tech)
    all_cves.extend(cves)

# Sauvegarde CSV dans le même dossier
output_csv_path = os.path.join(script_dir, "cves_24h.csv")

if all_cves:
    df_result = pd.DataFrame(all_cves)
    df_result.to_csv(output_csv_path, index=False, encoding="utf-8")
    print(f"\nFichier '{output_csv_path}' généré avec succès.")
else:
    print("\nAucun résultat à sauvegarder.")
