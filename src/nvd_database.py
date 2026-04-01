# nvd_database.py

import requests
import sqlite3
import json
from datetime import datetime, timedelta
from typing import List, Dict, Optional

class NVDDatabase:
    """
    Integration with National Vulnerability Database
    Free API available at: https://services.nvd.nist.gov/rest/json/cves/1.0
    
    Rate limits:
    - Without API key: 5 requests per 30 seconds
    - With API key: 50 requests per 30 seconds
    """
    
    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
    
    def __init__(self, api_key: Optional[str] = None, db_path: str = 'nvd.db'):
        self.api_key = api_key
        self.db_path = db_path
        self._init_database()
    
    def _init_database(self):
        """Initialize local SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        # Create tables
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS vulnerabilities (
                cve_id TEXT PRIMARY KEY,
                description TEXT,
                cvss_v2_score REAL,
                cvss_v3_score REAL,
                cvss_v3_severity TEXT,
                cwe_ids TEXT,  -- JSON array
                published_date TEXT,
                last_modified_date TEXT,
                references TEXT,  -- JSON array
                affected_products TEXT,  -- JSON array
                last_sync TEXT
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS cpe_to_cve (
                cpe TEXT,
                cve_id TEXT,
                start_version TEXT,
                end_version TEXT,
                FOREIGN KEY(cve_id) REFERENCES vulnerabilities(cve_id)
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def fetch_vulnerability(self, cve_id: str) -> Optional[Dict]:
        """
        Fetch vulnerability by CVE ID
        
        Example CVE: CVE-2021-23337 (lodash prototype pollution)
        """
        # Check cache first
        cached = self._get_from_cache(cve_id)
        if cached:
            return cached
        
        # Fetch from NVD API
        try:
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            params = {'cveId': cve_id}
            response = requests.get(
                f"{self.BASE_URL}",
                params=params,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('result', {}).get('CVE_Items'):
                vuln = self._parse_cve_item(data['result']['CVE_Items'][0])
                self._cache_vulnerability(vuln)
                return vuln
            
            return None
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch {cve_id}: {e}")
            return None
    
    def _parse_cve_item(self, item: Dict) -> Dict:
        """Parse NVD CVE item into our format"""
        cve = item.get('cve', {})
        impact = item.get('impact', {})
        
        # Extract CVSS scores
        cvss_v3 = impact.get('baseMetricV3', {})
        cvss_score = cvss_v3.get('cvssV3', {}).get('baseScore')
        severity = cvss_v3.get('cvssV3', {}).get('baseSeverity')
        
        # Extract CWEs
        cwe_ids = []
        for weakness in cve.get('problemtype', {}).get('problemtype_data', []):
            for description in weakness.get('description', []):
                cwe = description.get('value', '')
                if cwe.startswith('CWE-'):
                    cwe_ids.append(cwe)
        
        # Extract references
        references = [
            ref.get('url', '') 
            for ref in cve.get('references', {}).get('reference_data', [])
        ]
        
        # Extract affected products (CPE)
        affected = []
        for config in item.get('configurations', {}).get('nodes', []):
            for match in config.get('cpe_match', []):
                cpe = match.get('cpe23Uri', '')
                affected.append({
                    'cpe': cpe,
                    'start_version': match.get('versionStartIncluding', ''),
                    'end_version': match.get('versionEndIncluding', ''),
                })
        
        return {
            'cve_id': cve.get('CVE_data_meta', {}).get('ID'),
            'description': cve.get('description', {}).get('description_data', [{}])[0].get('value', ''),
            'cvss_score': cvss_score,
            'severity': severity,
            'cwe_ids': cwe_ids,
            'affected_products': affected,
            'published_date': item.get('publishedDate'),
            'last_modified_date': item.get('lastModifiedDate'),
            'references': references,
        }
    
    def _get_from_cache(self, cve_id: str) -> Optional[Dict]:
        """Get vulnerability from local cache"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('SELECT * FROM vulnerabilities WHERE cve_id = ?', (cve_id,))
        row = cursor.fetchone()
        conn.close()
        
        if row:
            return self._row_to_dict(row)
        return None
    
    def _cache_vulnerability(self, vuln: Dict):
        """Cache vulnerability in local database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT OR REPLACE INTO vulnerabilities
            (cve_id, description, cvss_v3_score, cvss_v3_severity, 
             cwe_ids, published_date, last_modified_date, references, 
             affected_products, last_sync)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            vuln['cve_id'],
            vuln['description'],
            vuln['cvss_score'],
            vuln['severity'],
            json.dumps(vuln['cwe_ids']),
            vuln['published_date'],
            vuln['last_modified_date'],
            json.dumps(vuln['references']),
            json.dumps(vuln['affected_products']),
            datetime.now().isoformat(),
        ))
        
        conn.commit()
        conn.close()
    
    def sync_all_vulnerabilities(self, days_back: int = 7):
        """
        Sync recently modified vulnerabilities from NVD
        Default: sync last 7 days of changes
        """
        print(f"Syncing vulnerabilities from last {days_back} days...")
        
        start_date = (datetime.now() - timedelta(days=days_back)).isoformat() + 'Z'
        
        try:
            params = {
                'resultsPerPage': 2000,
                'startIndex': 0,
                'modStartDate': start_date,
            }
            
            if self.api_key:
                params['apiKey'] = self.api_key
            
            # Paginate through results
            while True:
                response = requests.get(
                    f"{self.BASE_URL}",
                    params=params,
                    timeout=15
                )
                response.raise_for_status()
                
                data = response.json()
                items = data.get('result', {}).get('CVE_Items', [])
                
                if not items:
                    break
                
                # Process items
                for item in items:
                    vuln = self._parse_cve_item(item)
                    self._cache_vulnerability(vuln)
                    print(f"  Cached {vuln['cve_id']}")
                
                # Check if more pages
                total_results = data.get('totalResults', 0)
                if params['startIndex'] + 2000 >= total_results:
                    break
                
                params['startIndex'] += 2000
        
        except Exception as e:
            print(f"Error syncing NVD: {e}")
