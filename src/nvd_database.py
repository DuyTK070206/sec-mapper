"""
National Vulnerability Database (NVD) Integration
API: https://services.nvd.nist.gov/rest/json/cves/2.0

Rate limits:
- Without API key: 5 requests per 30 seconds
- With API key: 50 requests per 30 seconds
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
        self.db_path = db_path or str(Path(__file__).resolve().parent.parent / 'nvd_cache.db')
        self._init_database()
    
    def _init_database(self):
        """Initialize local SQLite database"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()
        
        cursor.execute('''
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
        ''')
        
        conn.commit()
        conn.close()
    
    def fetch_vulnerability(self, cve_id: str) -> Optional[Dict]:
        """Fetch CVE by ID"""
        cached = self._get_from_cache(cve_id)
        if cached:
            return cached
        
        try:
            params = {'cveId': cve_id}
            headers = {}
            if self.api_key:
                headers['apiKey'] = self.api_key
            
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=headers,
                timeout=10
            )
            response.raise_for_status()
            
            data = response.json()
            if data.get('vulnerabilities'):
                vuln = self._parse_vulnerability(data['vulnerabilities'][0])
                self._cache_vulnerability(vuln)
                return vuln
            
            return None
        except Exception as e:
            print(f"Warning: Failed to fetch {cve_id}: {e}")
            return None
    
    def _parse_vulnerability(self, item: Dict) -> Dict:
        """Parse NVD vulnerability item"""
        cve = item.get('cve', {})
        cve_id = cve.get('id', '')
        
        # Description
        descriptions = cve.get('descriptions', [])
        description = ''
        for desc in descriptions:
            if desc.get('lang') == 'en':
                description = desc.get('value', '')
                break
        if not description and descriptions:
            description = descriptions[0].get('value', '')
        
        # CVSS score
        cvss_score = 0.0
        severity = 'unknown'
        metrics = cve.get('metrics', {})
        if metrics.get('cvssV3'):
            for m in metrics['cvssV3']:
                cvss_score = m.get('cvssV3', {}).get('baseScore', 0.0)
                severity = m.get('cvssV3', {}).get('baseSeverity', 'UNKNOWN').lower()
                break
        
        # CWEs
        cwe_ids = []
        for weakness in cve.get('weaknesses', []):
            for cwe in weakness.get('description', []):
                cwe_val = cwe.get('value', '')
                if cwe_val.startswith('CWE-'):
                    cwe_ids.append(cwe_val)
        
        # References
        references = [ref.get('url', '') for ref in cve.get('references', [])]
        
        return {
            'cve_id': cve_id,
            'description': description,
            'cvss_score': cvss_score,
            'severity': severity,
            'cwe_ids': cwe_ids,
            'published_date': cve.get('published', ''),
            'last_modified_date': cve.get('lastModified', ''),
            'reference_urls': references,
        }
    
    def _get_from_cache(self, cve_id: str) -> Optional[Dict]:
        """Get from cache"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('SELECT * FROM nvd_vulnerabilities WHERE cve_id = ?', (cve_id,))
            row = cursor.fetchone()
            conn.close()
            
            if row:
                return {
                    'cve_id': row[0],
                    'description': row[1],
                    'cvss_score': row[2],
                    'severity': row[3],
                    'cwe_ids': json.loads(row[4] or '[]'),
                    'published_date': row[5],
                    'last_modified_date': row[6],
                    'reference_urls': json.loads(row[7] or '[]'),
                }
        except Exception as e:
            print(f"Cache read error: {e}")
        
        return None
    
    def _cache_vulnerability(self, vuln: Dict):
        """Store in cache"""
        try:
            conn = sqlite3.connect(self.db_path)
            cursor = conn.cursor()
            
            cursor.execute('''
                INSERT OR REPLACE INTO nvd_vulnerabilities
                (cve_id, description, cvss_score, severity, cwe_ids,
                 published_date, last_modified_date, reference_urls, last_sync)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                vuln['cve_id'],
                vuln['description'],
                vuln['cvss_score'],
                vuln['severity'],
                json.dumps(vuln.get('cwe_ids', [])),
                vuln['published_date'],
                vuln['last_modified_date'],
                json.dumps(vuln.get('reference_urls', [])),
                datetime.now().isoformat(),
            ))
            
            conn.commit()
            conn.close()
        except Exception as e:
            print(f"Cache write error: {e}")
    
    def sync_recent(self, days: int = 7) -> int:
        """Sync recent CVEs"""
        print(f"Syncing CVEs from last {days} days...")
        
        start_date = (datetime.now() - timedelta(days=days)).isoformat() + 'Z'
        count = 0
        
        try:
            params = {
                'resultsPerPage': 2000,
                'startIndex': 0,
                'lastModStartDate': start_date,
            }
            
            if self.api_key:
                params['apiKey'] = self.api_key
            
            while True:
                response = requests.get(
                    self.BASE_URL,
                    params=params,
                    headers={},
                    timeout=15
                )
                response.raise_for_status()
                
                data = response.json()
                items = data.get('vulnerabilities', [])
                
                if not items:
                    break
                
                for item in items:
                    vuln = self._parse_vulnerability(item)
                    self._cache_vulnerability(vuln)
                    count += 1
                    if count % 100 == 0:
                        print(f"  Cached {count} CVEs...")
                
                total = data.get('totalResults', 0)
                if params['startIndex'] + 2000 >= total:
                    break
                
                params['startIndex'] += 2000
        
        except Exception as e:
            print(f"Warning: NVD sync error: {e}")
        
        print(f"Synced {count} CVEs total")
        return count
