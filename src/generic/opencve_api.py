import requests, os
from dotenv import load_dotenv


def fetch_cves(keyword=None):
    load_dotenv()
    user = os.getenv("OPENCVE_USER")
    password = os.getenv("OPENCVE_PASS")
    params = {
        "search": keyword
    } if keyword and keyword.strip() else {}
    
    response = requests.get("https://app.opencve.io/api/cve", auth=(user, password), params=params)
    print(f"Status Code: {response.status_code}")
    body = response.json()
    vulns = body.get("results", [])
    if not vulns:
        raise ValueError("No vulnerabilities found")
    
    detailed_vulns = []
    for vuln in vulns:
        cve = vuln['cve_id']
        detailed_response = requests.get(f"https://app.opencve.io/api/cve/{cve}", auth=(user, password))
        if detailed_response.status_code == 200:
            detailed_vulns.append(detailed_response.json())
        else:
            print(f"Failed to fetch details for CVE: {cve}")

    return detailed_vulns


def main():
    vulns = fetch_cves()
    for vuln in vulns:
        print(vuln)
        print("------")


if __name__ == "__main__":
    main()
