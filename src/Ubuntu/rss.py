import requests
import xml.etree.ElementTree as ET
import csv
from pathlib import Path
import html
import re

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

def fetch_ubuntu_rss(url="https://ubuntu.com/security/notices/rss.xml"):
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.content
    except Exception as e:
        raise RuntimeError(f"Erreur lors de la récupération du RSS Ubuntu Security Notices : {e}")

def extract_cves(text: str):
    """Extrait les identifiants CVE d'un texte."""
    return re.findall(r"CVE-\d{4}-\d{4,7}", text or "")

def iter_rss_matches(rss_content, keyword):
    kw = (keyword or "").lower().strip()
    root = ET.fromstring(rss_content)
    items = root.findall(".//item")

    for item in items:
        title = item.findtext("title") or ""
        description = html.unescape(item.findtext("description") or "")
        link = item.findtext("link") or ""
        pub_date = item.findtext("pubDate") or ""

        cves = extract_cves(description)

        # Si mot-clé vide → on prend tout
        if not kw or kw in title.lower() or kw in description.lower():
            yield {
                "keyword": keyword if kw else "ALL",
                "title": sanitize(title),
                "link": sanitize(link),
                "description": sanitize(description),
                "pub_date": sanitize(pub_date),
                "cves": ";".join(cves) if cves else "N/A"
            }

def save_csv(rows, filename="Ubuntu_filtered.csv"):
    out_path = Path(__file__).resolve().parent / filename
    fieldnames = ["keyword", "title", "link", "description", "pub_date", "cves"]

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
    mot_cle = ""  # Vide = exporte tout
    rss_content = fetch_ubuntu_rss()
    rows = list(iter_rss_matches(rss_content, mot_cle))

    filename = f"Ubuntu_{mot_cle.strip() or 'ALL'}.csv"
    save_csv(rows, filename=filename)

