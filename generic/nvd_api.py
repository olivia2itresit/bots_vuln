import os
import requests
import csv
import argparse
from datetime import datetime, timedelta

CIRCL_API_URL = "http://cve.circl.lu/api/last"
NVD_API_KEY = "52ded5af-e3e2-4374-8caa-99289b3046f2"
SAFE_MODE = True

#Provisional techs list
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

def sanitize(value):
    if value is None:
        return ""
    s = str(value).replace("\r", " ").replace("\n", " ").strip()
    if SAFE_MODE:
        s = s.replace('"', "'").replace(",", " ").replace("\t", " ")
    return s

#Adjust dates based on the the execution frequency of this script. i.e if script executed every hour, the start_date should be set to 1 hour ago from now()
def fetch_cves(keyword=None, max_results=50, days=3):
    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    end_date = datetime.now()
    start_date = end_date - timedelta(days=days)  # Last 'days' days
    params = {
        "resultsPerPage": max_results,
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }

    if keyword:
        params["keywordSearch"] = keyword
    
    headers = {
        "apiKey": NVD_API_KEY
    }

    response = requests.get(base_url, params=params, headers=headers, timeout=30)
    response.raise_for_status()
    data = response.json()
    cve_list = []
    for item in data.get('vulnerabilities', []):
        print(item)
        print("------")
        vuln = item.get('cve', {})
        descriptions = vuln.get('descriptions', [])
        vuln_data = {
            "cve_id": sanitize(vuln.get('id')),
            "descriptions": descriptions,
            "full_desc": " ".join(sanitize(desc['value']) for desc in descriptions),
            "pubDate": vuln.get('published', ''),
        }

        cve_list.append(vuln_data)
    return cve_list


def main(techs=False, max_results=50, days=3):
    try:
        script_dir = os.path.dirname(os.path.abspath(__file__))
    except NameError:
        script_dir = os.getcwd()

    csv_path = os.path.join(script_dir, f"cve_data/cves-{datetime.now().strftime('%Y%m%d-%H%M%S')}.csv")
    print(f"Writing CVEs in {csv_path}")

    with open(csv_path, "w", newline='', encoding="utf-8-sig") as csvfile:
        writer = csv.writer(csvfile, quoting=csv.QUOTE_ALL)
        writer.writerow(["Tech", "Date", "CVE", "Description"])
        if techs:
            for tech in technologies:
                print(f"🔍 Fetching CVEs for: {tech}")
                try:
                    #cves = fetch_cves(tech, max_results=1000)
                    cves = fetch_cves(keyword=tech, max_results=max_results, days=days)
                    for cve in cves:
                        writer.writerow([sanitize(tech), cve.get("pubDate", ""), cve.get("cve_id", ""), cve.get("full_desc", "")])
                except Exception as e:
                    print(f"Error fetching CVEs for {tech}: {e}")
        else:
            try: 
                cves = fetch_cves(max_results=max_results, days=days)
                for cve in cves:
                    writer.writerow(["General", cve.get("pubDate", ""), cve.get("cve_id", ""), cve.get("full_desc", "")])
            except Exception as e:
                print(f"Error fetching CVEs: {e}")

    print("CVEs written to CSV file")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fetch CVEs for technologies.")
    parser.add_argument("--techs", action="store_true", help="Fetch CVEs for specific pool of technologies.")
    parser.add_argument("--max-results", type=int, default=50, help="Maximum number of CVEs to fetch per technology/in total.")
    parser.add_argument("--days", type=int, default=3, help="Number of days to look back for CVEs.")
    args = parser.parse_args()

    main(techs=args.techs, max_results=args.max_results, days=args.days)
