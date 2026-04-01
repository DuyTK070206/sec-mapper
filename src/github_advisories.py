# github_advisories.py

import requests
import json
from typing import List, Dict, Optional

class GitHubAdvisories:
    """
    Fetch security advisories from GitHub
    More recent than NVD, language-specific
    
    Endpoints:
    - npm: https://api.github.com/advisories?ecosystem=npm
    - pip: https://api.github.com/advisories?ecosystem=pip
    - etc.
    """
    
    BASE_URL = "https://api.github.com/advisories"
    
    def __init__(self, github_token: Optional[str] = None):
        self.github_token = github_token
        self.headers = {
            'Accept': 'application/vnd.github.v3+json'
        }
        if github_token:
            self.headers['Authorization'] = f'token {github_token}'
    
    def fetch_advisories(self, ecosystem: str, severity: str = None) -> List[Dict]:
        """
        Fetch advisories for specific ecosystem
        
        Examples:
        - ecosystem='npm': JavaScript packages
        - ecosystem='pip': Python packages
        - ecosystem='maven': Java packages
        """
        
        params = {
            'ecosystem': ecosystem,
            'per_page': 100,
        }
        
        if severity in ['critical', 'high', 'moderate', 'low']:
            params['severity'] = severity
        
        try:
            response = requests.get(
                self.BASE_URL,
                params=params,
                headers=self.headers,
                timeout=10
            )
            response.raise_for_status()
            
            advisories = response.json()
            return advisories
            
        except requests.exceptions.RequestException as e:
            print(f"Failed to fetch GitHub advisories: {e}")
            return []
    
    def search_package_advisories(self, 
                                  ecosystem: str,
                                  package_name: str) -> List[Dict]:
        """
        Search for advisories affecting specific package
        
        Example:
        advisories = search_package_advisories('npm', 'lodash')
        """
        
        all_advisories = self.fetch_advisories(ecosystem)
        
        # Filter for this package
        matching = [
            adv for adv in all_advisories
            if adv.get('package', {}).get('name', '').lower() == package_name.lower()
        ]
        
        return matching