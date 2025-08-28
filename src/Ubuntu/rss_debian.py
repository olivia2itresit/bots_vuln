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

def fetch_debian_rss(url="https://www.debian.org/security/dsa.rdf"):
    try:
        resp = requests.get(url, timeout=30)
        resp.raise_for_status()
        return resp.content
    except Exception as e:
        raise RuntimeError(f"Erreur lors de la récupération du RSS Debian Security Advisories : {e}")

def extract_cves(text: str):
    """Extrait les identifiants CVE d'un texte (si présents)."""
    return re.findall(r"CVE-\d{4}-\d{4,7}", text or "")

def iter_rss_matches(rss_content, keyword):
    kw = (keyword or "").lower().strip()

    # Namespaces du flux Debian (RDF + RSS 1.0 + Dublin Core)
    NS_RSS = "http://purl.org/rss/1.0/"
    NS_DC  = "http://purl.org/dc/elements/1.1/"

    root = ET.fromstring(rss_content)

    # IMPORTANT: <item> est namespacé -> il faut utiliser le nom étendu
    items = root.findall(f".//{{{NS_RSS}}}item")

    for item in items:
        title = item.findtext(f"{{{NS_RSS}}}title") or ""
        link = item.findtext(f"{{{NS_RSS}}}link") or ""
        description = html.unescape(item.findtext(f"{{{NS_RSS}}}description") or "")
        pub_date = item.findtext(f"{{{NS_DC}}}date") or ""

        cves = extract_cves(description)

        # Si mot-clé vide → on prend tout
        if not kw or kw in title.lower() or kw in description.lower():
            yield {
                "keyword": keyword if kw else "ALL",
                "title": sanitize(title),
                "link": sanitize(link),
                "description": sanitize(description),
                "pub_date": sanitize(pub_date),
                "cves": ";".join(cves) if cves else "N/A",
            }

def save_csv(rows, filename="Debian_filtered.csv"):
    out_path = Path(__file__).resolve().parent / filename
    fieldnames = ["keyword", "title", "link", "description", "pub_date", "cves"]

    with open(out_path, "w", newline="", encoding="utf-8-sig") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=fieldnames,
            quoting=csv.QUOTE_ALL,
            lineterminator="\n",
            extrasaction="ignore",
        )
        writer.writeheader()
        for r in rows:
            writer.writerow(r)
    print(f"✅ Fichier écrit : {out_path}")

if __name__ == "__main__":
    mot_cle = ""  # Vide = exporte tout
    rss_content = fetch_debian_rss()
    rows = list(iter_rss_matches(rss_content, mot_cle))

    filename = f"Debian_{mot_cle.strip() or 'ALL'}.csv"
    save_csv(rows, filename=filename)
