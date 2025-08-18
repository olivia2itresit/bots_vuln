import requests
import csv
from pathlib import Path
import xml.etree.ElementTree as ET

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

def fetch_msrc_data():
    url = "https://api.msrc.microsoft.com/update-guide/rss"
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return ET.fromstring(resp.content)
    except Exception as e:
        raise RuntimeError(f"Erreur API/XML MSRC: {e}")

def iter_matches(data, keyword):
    kw = (keyword or "").lower().strip()
    if not kw:
        return
    # On cherche tous les <item> du flux RSS
    for item in data.findall(".//item"):
        title = item.findtext("title") or ""
        description = item.findtext("description") or ""
        guid = item.findtext("guid") or ""
        link = item.findtext("link") or ""
        pubDate = item.findtext("pubDate") or ""

        # On filtre sur le mot-clé
        if kw in title.lower() or kw in description.lower():
            yield {
                "keyword": keyword,
                "cve": sanitize(guid),
                "title": sanitize(title),
                "description": sanitize(description),
                "published": sanitize(pubDate),
                "link": sanitize(link),
            }

def save_csv(rows, filename="msrc_cves_export.csv"):
    out_path = Path(__file__).resolve().parent / filename
    fieldnames = ["keyword", "cve", "title", "description", "published", "link"]
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
    data = fetch_msrc_data()
    # Exemple : un seul mot-clé
    mot_cle = "sharepoint"
    rows = list(iter_matches(data, mot_cle))
    save_csv(rows, filename=f"msrc_cves_{mot_cle}.csv")

    # --- Exemple multi-mots-clés ---
    # keywords = ["sharepoint", "hyper-v", "dynamics 365"]
    # all_rows = []
    # for kw in keywords:
    #     all_rows.extend(iter_matches(data, kw))
    # save_csv(all_rows, filename="msrc_cves_multi_keywords.csv")
