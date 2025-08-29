import sqlite3

DB_FILE = "db/vulns.db"


class PersistenceCVE:
    """
    Handles persistence of CVE data into the SQLite database for generic sources (NVD, OpenCVE, etc.).
    """
    def __init__(self):
        self._conn = sqlite3.connect(DB_FILE)
        self._cursor = self._conn.cursor()

    def save_cve(self, cve_id, title, desc, cvss, created_at, refs="", notified=0):
        try:
            self._cursor.execute("""
            INSERT INTO cves (cve, title, description, cvss_3_1_score, created_at, refs, notified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(cve) DO NOTHING
            """, (cve_id, title, desc, cvss, created_at, refs, notified))
            self._conn.commit()

        except Exception as e:
            print(f"Error saving CVE {cve_id} to DB: {e}")
            self._conn.rollback()


    def save_cves(self, cves: list[dict]):
        """
        Saves several CVEs records in the database.
        """
        try:
            values = [
            (
                cve['cve_id'],
                cve['title'],
                cve['desc'],
                cve['cvss'],
                cve['created_at'],
                cve.get('refs', ""),
                cve.get('notified', 0)
            )
            for cve in cves
            ]

            self._cursor.executemany("""
            INSERT INTO cves (cve, title, description, cvss_3_1_score, created_at, refs, notified)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, values)
            self._conn.commit()

        except Exception as e:
            print(f"Error saving multiple CVEs to DB: {e}")
            self._conn.rollback()


    def close(self):
        self._conn.close()


