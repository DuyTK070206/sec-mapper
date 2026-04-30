"""
National Vulnerability Database (NVD) Integration (FIXED VERSION)
"""

import requests
import sqlite3
import json
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Optional


class NVDDatabase:

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def __init__(self, api_key: Optional[str] = None, db_path: Optional[str] = None):
        self.api_key = api_key
        self.db_path = db_path or str(
            Path(__file__).resolve().parent.parent / "nvd_cache.db"
        )
        self._init_database()

    # =========================
    # DB INIT
    # =========================
    def _init_database(self):
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            CREATE TABLE IF NOT EXISTS nvd_vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_score REAL,
                severity TEXT,
                cwe_ids TEXT,
                published_date TEXT,
                last_modified_date TEXT,
                reference_urls TEXT,
                last_sync TEXT
            )
        """)

        conn.commit()
        conn.close()

    # =========================
    # FETCH SINGLE CVE
    # =========================
    def fetch_vulnerability(self, cve_id: str) -> Optional[Dict]:
        cached = self._get_from_cache(cve_id)
        if cached:
            return cached

        try:
            params = {"cveId": cve_id}
            headers = {}

            if self.api_key:
                headers["apiKey"] = self.api_key

            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=10,
            )
            response.raise_for_status()

            data = response.json()

            vulns = data.get("vulnerabilities", [])
            if not vulns:
                return None

            vuln = self._parse_vulnerability(vulns[0])
            self._cache_vulnerability(vuln)
            return vuln

        except Exception as e:
            print(f"[NVD] Failed to fetch {cve_id}: {e}")
            return None

    # =========================
    # PARSER (FIXED CVSS LOGIC)
    # =========================
    def _parse_vulnerability(self, item: Dict) -> Dict:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")

        # Description
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break

        # =========================
        # FIXED CVSS PARSING
        # =========================
        cvss_score = 0.0
        severity = "unknown"

        metrics = cve.get("metrics", {})

        cvss_data = None

        # CVSS v3.1 (priority)
        if "cvssMetricV31" in metrics:
            cvss_data = metrics["cvssMetricV31"][0]

        # fallback CVSS v3.0
        elif "cvssMetricV30" in metrics:
            cvss_data = metrics["cvssMetricV30"][0]

        # fallback CVSS v2
        elif "cvssMetricV2" in metrics:
            cvss_data = metrics["cvssMetricV2"][0]

        if cvss_data:
            base = cvss_data.get("cvssData", {})
            cvss_score = base.get("baseScore", 0.0)
            severity = cvss_data.get("baseSeverity", "UNKNOWN").lower()

        # CWEs
        cwe_ids = []
        for w in cve.get("weaknesses", []):
            for d in w.get("description", []):
                val = d.get("value", "")
                if val.startswith("CWE-"):
                    cwe_ids.append(val)

        # References
        refs = [
            r.get("url", "")
            for r in cve.get("references", [])
        ]

        return {
            "cve_id": cve_id,
            "description": description,
            "cvss_score": cvss_score,
            "severity": severity,
            "cwe_ids": cwe_ids,
            "published_date": cve.get("published", ""),
            "last_modified_date": cve.get("lastModified", ""),
            "reference_urls": refs,
        }

    # =========================
    # CACHE GET
    # =========================
    def _get_from_cache(self, cve_id: str) -> Optional[Dict]:
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute(
                "SELECT * FROM nvd_vulnerabilities WHERE cve_id = ?",
                (cve_id,),
            )
            row = cursor.fetchone()
            conn.close()

            if not row:
                return None

            return {
                "cve_id": row[0],
                "description": row[1],
                "cvss_score": row[2],
                "severity": row[3],
                "cwe_ids": json.loads(row[4] or "[]"),
                "published_date": row[5],
                "last_modified_date": row[6],
                "reference_urls": json.loads(row[7] or "[]"),
            }

        except Exception as e:
            print(f"[Cache] read error: {e}")
            return None

    # =========================
    # CACHE STORE
    # =========================
    def _cache_vulnerability(self, vuln: Dict):
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()

            cursor.execute("""
                INSERT OR REPLACE INTO nvd_vulnerabilities
                (cve_id, description, cvss_score, severity,
                 cwe_ids, published_date, last_modified_date,
                 reference_urls, last_sync)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                vuln["cve_id"],
                vuln["description"],
                vuln["cvss_score"],
                vuln["severity"],
                json.dumps(vuln.get("cwe_ids", [])),
                vuln["published_date"],
                vuln["last_modified_date"],
                json.dumps(vuln.get("reference_urls", [])),
                datetime.now().isoformat(),
            ))

            conn.commit()
            conn.close()

        except Exception as e:
            print(f"[Cache] write error: {e}")

    # =========================
    # SYNC RECENT (FIXED PAGINATION)
    # =========================
    def sync_recent(self, days: int = 3650) -> int:
        print(f"Syncing CVEs last {days} days...")

        start_date = (datetime.now() - timedelta(days=days)).isoformat() + "Z"

        count = 0
        start_index = 0
        page_size = 2000

        headers = {}
        if self.api_key:
            headers["apiKey"] = self.api_key

        while True:
            try:
                params = {
                    "resultsPerPage": page_size,
                    "startIndex": start_index,
                    "lastModStartDate": start_date,
                }

                response = requests.get(
                    self.BASE_URL,
                    params=params,
                    headers=headers,
                    timeout=15,
                )
                response.raise_for_status()

                data = response.json()
                vulns = data.get("vulnerabilities", [])

                if not vulns:
                    break

                for v in vulns:
                    parsed = self._parse_vulnerability(v)
                    self._cache_vulnerability(parsed)
                    count += 1

                total = data.get("totalResults", 0)

                start_index += page_size

                if start_index >= total:
                    break

                print(f"  synced: {count}")

            except Exception as e:
                print(f"[NVD] sync error: {e}")
                break

        print(f"Done. Total CVEs synced: {count}")
        return count