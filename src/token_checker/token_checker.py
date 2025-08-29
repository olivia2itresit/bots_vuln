import csv
from datetime import datetime, timedelta
import re
from typing import List, Optional

import requests

CSV_FILE = "db/techs_clients.csv"
GENERIC_TECHS = ["WINDOWS", "MICROSOFT", "APPLE", "LINUX", "PHP", "SQL", "ADOBE", "ANDROID", "JAVA",
                 "ORACLE", "HP", "GOOGLE", "INTEL", "RED HAT"]

class TokenChecker:
    """
    Singleton class to check new vulnerabilities received to determine if the affected technology is in our scope
    """

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super(TokenChecker, cls).__new__(cls)
        return cls._instance

    def __init__(self):
        # Prevent reinitialization on subsequent instantiations
        if not hasattr(self, '_initialized'):
            self._tokens: dict[str, str] = self.get_techs_from_csv()
            self._techs: List[str] = list(self._tokens.keys())
            self._techs_sorted = sorted(self._techs, key=lambda x: len(x), reverse=True)
            self._tech_regexes = [(tech, self.build_regex_for_tech(tech)) for tech in self._techs_sorted]
            self._initialized = True


    def get_techs_from_csv(self) -> dict[str, str]:
        """
        Loads the client techs from a CSV file.
        """
        client_techs = {}
        with open(CSV_FILE, 'r') as f:
            reader = csv.reader(f)
            for row in reader:
                client_techs[row[0]] = row[1]
        
        #print(client_techs)
        return client_techs
    

    def escape_tech_for_regex(self, tech: str) -> str:
        return re.escape(tech)


    # Construcción de regex que valida separadores seguros
    def build_regex_for_tech(self, tech: str) -> re.Pattern:
        escaped_tech = self.escape_tech_for_regex(tech)
        # Separadores: inicio/final de línea, espacio, coma, punto, dos puntos, paréntesis, corchetes, comillas
        pattern = rf"(?i)(?:^|[\s,.:()\"'\[\]])({escaped_tech})(?:$|[\s,.:()\"'\[\]])"
        return re.compile(pattern)
    

    def find_technologies_in_text(self, text: str) -> List[str]:
        matches = []
        for tech, regex in self._tech_regexes:
            if regex.search(text):
                matches.append(tech)
        return matches


    def select_best_tech(self, matches: List[str], text: str) -> Optional[str]:
        # Priorizar más específica sobre genérica
        final_match = None
        specific_matches = [m for m in matches if m.upper() not in GENERIC_TECHS]

        filtered_matches = []
        for m in specific_matches:
            if m.upper() == "WORDPRESS" and "plugin for wordpress" in text.lower() and "ELEMENTOR" not in text.upper():
                matches.remove(m)
                continue  # descartamos WordPress en este contexto
            filtered_matches.append(m)

        if filtered_matches:
            final_match = filtered_matches[0]
        elif matches:
            final_match = matches[0]  # Solo genéricas encontradas
        
        if final_match:
            final_match = f"{final_match}|{self._tokens.get(final_match, final_match) if final_match else None}"
        return final_match


    def extract_technology(self, title: Optional[str], desc: str) -> Optional[str]:
        # Buscar en título primero si existe
        if title:
            title_matches = self.find_technologies_in_text(title)
            tech = self.select_best_tech(title_matches, title)
            if tech:
                return tech
        
        # Buscar en descripción
        desc_matches = self.find_technologies_in_text(desc)
        tech = self.select_best_tech(desc_matches, desc)
        return tech
    

if __name__ == "__main__":
    tech_checker = TokenChecker()
    
    NVD_API_KEY = "52ded5af-e3e2-4374-8caa-99289b3046f2"
    SAFE_MODE = True

    base_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    end_date = datetime.now()
    start_date = end_date - timedelta(days=3)  # Last 'days' days
    params = {
        "resultsPerPage": 100,
        "pubStartDate": start_date.strftime("%Y-%m-%dT%H:%M:%S.000Z"),
        "pubEndDate": end_date.strftime("%Y-%m-%dT%H:%M:%S.000Z")
    }
    
    headers = {
        "apiKey": NVD_API_KEY
    }

    response = requests.get(base_url, params=params, headers=headers, timeout=30)
    response.raise_for_status()
    data = response.json()
    for item in data.get('vulnerabilities', []):
        vuln = item.get('cve', {})
        if vuln:
            id = vuln.get('id', '')
            title = ""
            description = vuln['descriptions'][0]['value'] if vuln.get('descriptions') else ""
            tech = tech_checker.extract_technology(title, description)
            
            print('-----')
            print(f"{id} DESC: {description}")
            print('.......')
            if tech:
                print(f"Found technology: {tech}")
            else:
                print("No technology found.")
            print('-----\n')
