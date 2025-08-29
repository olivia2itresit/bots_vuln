import requests
import csv
from pathlib import Path

SAFE_MODE = True  # Si True, on neutralise , " ' et retours à la ligne pour éviter tout décalage de colonnes

def sanitize(value: str) -> str:
    """Neutralise les caractères qui posent problème aux parseurs CSV 'naïfs'."""
    if value is None:
        return ""
    s = str(value)
    # A minima, on supprime les retours à la ligne
    s = s.replace("\r", " ").replace("\n", " ").strip()
    if SAFE_MODE:
        # Neutralisation douce des guillemets et virgules
        s = s.replace('"', "'").replace(",", " ").replace("\t", " ")
    return s

def fetch_wordfence_data():
    url = "https://www.wordfence.com/api/intelligence/vulnerabilities/production"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.json()
    except Exception as e:
        raise RuntimeError(f"Erreur API/JSON Wordfence: {e}")

def iter_matches(data, keyword):
    kw = (keyword or "").lower().strip()
    if not kw:
        return
    for vuln_id, vuln in (data or {}).items():
        software_list = vuln.get("software") or []
        if isinstance(software_list, dict):
            software_list = [software_list]

        for sw in software_list:
            slug = (sw.get("slug") or "").lower()
            name = (sw.get("name") or "").lower()
            if kw in slug or kw in name:
                cves = vuln.get("cve")
                if isinstance(cves, list):
                    cve_str = ";".join([c for c in cves if c]) or "N/A"
                else:
                    cve_str = cves or "N/A"

                cvss = vuln.get("cvss") or {}
                yield {
                    "keyword": keyword,
                    "vuln_id": vuln_id,
                    "cve": sanitize(cve_str),
                    "title": sanitize(vuln.get("title") or "N/A"),
                    "description": sanitize(vuln.get("description") or "N/A"),
                    "severity": sanitize(cvss.get("rating") or "N/A"),
                    "cvss_score": sanitize(cvss.get("score") or ""),
                    "published": sanitize(vuln.get("published") or ""),
                    "cve_link": sanitize(vuln.get("cve_link") or ""),
                    "software_name": sanitize(sw.get("name") or ""),
                    "software_slug": sanitize(sw.get("slug") or ""),
                }

def save_csv(rows, filename="cves_export.csv"):
    # Forcer l'écriture dans le même dossier que ce script
    out_path = Path(__file__).resolve().parent / filename
    fieldnames = [
        "keyword", "vuln_id", "cve", "title", "description",
        "severity", "cvss_score", "published", "cve_link",
        "software_name", "software_slug"
    ]
    # utf-8-sig améliore la compatibilité Excel ; QUOTE_ALL empêche les colonnes de “glisser”
    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
            extrasaction="ignore"
        )
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"✅ Fichier écrit : {out_path}")

if __name__ == "__main__":
    data = fetch_wordfence_data()
    # Exemple : un seul mot-clé
    mot_cle = "elementor"
    rows = list(iter_matches(data, mot_cle))
    save_csv(rows, filename=f"cves_{mot_cle}.csv")

    # --- Exemple multi-mots-clés ---
    # keywords = ["elementor", "contact form 7", "rank math", "wordpress"]
    # all_rows = []
    # for kw in keywords:
        # all_rows.extend(iter_matches(data, kw))
    # save_csv(all_rows, filename="cves_multi_keywords.csv")
