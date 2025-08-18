import requests
import xml.etree.ElementTree as ET
import csv
from pathlib import Path
import html

SAFE_MODE = True  # Neutralisation douce des caractères CSV problématiques

def sanitize(value: str) -> str:
    """Neutralise les caractères qui posent problème aux parseurs CSV 'naïfs'."""
    if value is None:
        return ""
    s = str(value)
    s = s.replace("\r", " ").replace("\n", " ").strip()
    if SAFE_MODE:
        s = s.replace('"', "'").replace(",", " ").replace("\t", " ")
    return s

def fetch_fortiguard_rss(url="https://filestore.fortinet.com/fortiguard/rss/ir.xml"):
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.content
    except Exception as e:
        raise RuntimeError(f"Erreur lors de la récupération du RSS FortiGuard : {e}")

def iter_rss_matches(rss_content, keyword):
    kw = (keyword or "").lower().strip()
    root = ET.fromstring(rss_content)
    items = root.findall(".//item")

    for item in items:
        title = item.findtext("title") or ""
        description = html.unescape(item.findtext("description") or "")
        link = item.findtext("link") or ""
        pub_date = item.findtext("pubDate") or ""

        if not kw or kw in title.lower() or kw in description.lower():
            yield {
                "keyword": keyword if kw else "ALL",
                "title": sanitize(title),
                "link": sanitize(link),
                "description": sanitize(description),
                "pub_date": sanitize(pub_date)
            }

def save_csv(rows, filename="FortiGuard_filtered.csv"):
    out_path = Path(__file__).resolve().parent / filename
    fieldnames = ["keyword", "title", "link", "description", "pub_date"]

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
    mot_cle = ""  # ← Vide = récupère tout le flux
    rss_content = fetch_fortiguard_rss()
    rows = list(iter_rss_matches(rss_content, mot_cle))

    # nom de fichier sans espaces
    filename = f"FortiGuard_{mot_cle.strip() or 'ALL'}.csv"
    save_csv(rows, filename=filename)
