import sqlite3
import csv

DB_FILE = "db/vulns.db"
CSV_FILE = "db/techs_clients.csv"

# Create / connect DB
conn = sqlite3.connect(DB_FILE)
cursor = conn.cursor()

#Create table techs
cursor.execute("""
CREATE TABLE IF NOT EXISTS techs (
    tech TEXT NOT NULL,
    client TEXT NOT NULL
)
""")
conn.commit()


with open(CSV_FILE, newline='', encoding='utf-8') as csvfile:
    reader = csv.DictReader(csvfile)
    filas = [(row['tech'], row['client']) for row in reader]

cursor.executemany("INSERT INTO techs (tech, client) VALUES (?, ?)", filas)
conn.commit()
conn.close()

