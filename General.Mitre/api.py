import os
import requests
import csv

API_KEY = "52ded5af-e3e2-4374-8caa-99289b3046f2"

SAFE_MODE = True  # Neutralise guillemets/virgules si True

def sanitize(value):
    """Nettoie les champs pour éviter les problèmes de parsing CSV."""
    if value is None:
        return ""
    s = str(value).replace("\r", " ").replace("\n", " ").strip()
    if SAFE_MODE:
        s = s.replace('"', "'").replace(",", " ").replace("\t", " ")
    return s

def fetch_cves(keyword, max_results=50):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": max_results,
        "startIndex": 0
    }
    headers = {
        "apiKey": API_KEY
    }
    response = requests.get(base_url, params=params, headers=headers, timeout=30)
    response.raise_for_status()
    data = response.json()
    cve_list = []
    for item in data.get('vulnerabilities', []):
        cve_id = sanitize(item['cve']['id'])
        descriptions = item['cve'].get('descriptions', [])
        full_desc = " ".join(sanitize(desc['value']) for desc in descriptions)
        cve_list.append((cve_id, full_desc))
    return cve_list

# Liste complète des technologies et variantes
technologies = [
    # Bureautique
    "LibreOffice", "Libre Office", "OpenOffice", "Apache OpenOffice",
    "LOCalc", "LOImpress", "LOWriter",
    # Frameworks / Dev
    "Angular", "AngularJS", "Flutter", "Dart", "PHP",
    # Serveurs / Middleware
    "NGINX", "Nginx", "Nginx Web Server", "Open Policy Agent", "OPA",
    # Auth / SSO
    "OpenID", "OpenID Connect", "OIDC",
    # Logiciels/utilitaires
    "7-Zip", "7ZIP", "7zip", "Brave Browser", "Brave Conversion Engine",
    "Mozilla", "Mozilla Firefox", "Notepad++", "NP++", "Foxit Reader"
]

# Forcer l'écriture dans le dossier du script
try:
    script_dir = os.path.dirname(os.path.abspath(__file__))
except NameError:
    script_dir = os.getcwd()

csv_path = os.path.join(script_dir, "True_cves_technologies.csv")
print(f"📂 Écriture dans : {csv_path}")

# Écriture CSV avec quotage intégral
with open(csv_path, "w", newline='', encoding="utf-8-sig") as csvfile:
    writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
    writer.writerow(["Technologie", "CVE", "Description complète"])
    for tech in technologies:
        print(f"🔍 Récupération CVE pour: {tech}")
        try:
            cves = fetch_cves(tech, max_results=1000)
            for cve_id, desc in cves:
                writer.writerow([sanitize(tech), cve_id, desc])
        except Exception as e:
            print(f"❌ Erreur pour {tech}: {e}")

print("✅ Export terminé.")
