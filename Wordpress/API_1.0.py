import requests

# Fonction pour récupérer les CVE à partir d'un mot-clé
def get_cves_by_keyword(keyword):
    url = "https://www.wordfence.com/api/intelligence/vulnerabilities/production"
    response = requests.get(url)
    data = response.json()
    
    keyword = keyword.lower()
    matched_cves = []

    for vuln_id, vuln_info in data.items():
        for software in vuln_info.get("software", []):
            if keyword in software.get("slug", "").lower() or keyword in software.get("name", "").lower():
                matched_cves.append({
                    "title": vuln_info.get("title"),
                    "cve": vuln_info.get("cve"),
                    "cve_link": vuln_info.get("cve_link"),
                    "published": vuln_info.get("published"),
                    "severity": vuln_info.get("cvss", {}).get("rating")
                })
    return matched_cves

# Exemple d'utilisation
mot_cle = "elementor"  # remplace par n'importe quel mot-clé
cves = get_cves_by_keyword(mot_cle)

# Affichage
for cve in cves:
    print(f"{cve['cve']} - {cve['title']} - {cve['severity']} - {cve['published']} - {cve['cve_link']}")
