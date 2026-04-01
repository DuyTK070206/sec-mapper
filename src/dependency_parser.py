# dependency_parser.py

from abc import ABC, abstractmethod
from typing import List, Dict
import json
import xml.etree.ElementTree as ET
import re

class DependencyParser(ABC):
    """Base class for all ecosystem parsers"""
    
    @abstractmethod
    def parse(self, manifest_content: str) -> List['ParsedDependency']:
        pass

class ParsedDependency:
    def __init__(self, name: str, version: str, ecosystem: str, is_transitive=False):
        self.name = name
        self.version = version
        self.ecosystem = ecosystem
        self.is_transitive = is_transitive
        self.children = []

class NpmPackageJsonParser(DependencyParser):
    """Parser for npm's package.json"""
    
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        data = json.loads(manifest_content)
        dependencies = []
        
        # Direct dependencies
        for name, version_spec in data.get('dependencies', {}).items():
            dep = ParsedDependency(name, version_spec, 'npm', is_transitive=False)
            dependencies.append(dep)
        
        # Dev dependencies (also important for vulnerabilities!)
        for name, version_spec in data.get('devDependencies', {}).items():
            dep = ParsedDependency(name, version_spec, 'npm', is_transitive=False)
            dep.dev_only = True
            dependencies.append(dep)
        
        return dependencies

class PythonRequirementsParser(DependencyParser):
    """Parser for Python requirements.txt"""
    
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        dependencies = []
        
        for line in manifest_content.split('\n'):
            line = line.strip()
            
            # Skip comments and empty lines
            if not line or line.startswith('#'):
                continue
            
            # Parse different formats:
            # requests==2.25.1
            # django>=3.0,<4.0
            # flask[security]>=1.0
            
            match = re.match(r'^([a-zA-Z0-9\-_]+)\s*([<>=!]*.*)?$', line)
            if match:
                name = match.group(1)
                version_spec = match.group(2) if match.group(2) else '*'
                dep = ParsedDependency(name, version_spec, 'pip')
                dependencies.append(dep)
        
        return dependencies

class MavenPomXmlParser(DependencyParser):
    """Parser for Maven's pom.xml"""
    
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        dependencies = []
        root = ET.fromstring(manifest_content)
        
        # Handle XML namespaces
        namespaces = {'m': 'http://maven.apache.org/POM/4.0.0'}
        
        for dep_elem in root.findall('.//m:dependency', namespaces):
            group_id = dep_elem.findtext('m:groupId', namespaces=namespaces)
            artifact_id = dep_elem.findtext('m:artifactId', namespaces=namespaces)
            version = dep_elem.findtext('m:version', namespaces=namespaces)
            scope = dep_elem.findtext('m:scope', namespaces=namespaces, default='compile')
            
            # Full Maven coordinate
            name = f"{group_id}:{artifact_id}"
            dep = ParsedDependency(name, version, 'maven')
            dep.scope = scope  # compile, test, provided, runtime
            dependencies.append(dep)
        
        return dependencies

# Factory pattern for parser selection
class ParserFactory:
    @staticmethod
    def get_parser(manifest_filename: str) -> DependencyParser:
        if manifest_filename == 'package.json':
            return NpmPackageJsonParser()
        elif manifest_filename == 'requirements.txt':
            return PythonRequirementsParser()
        elif manifest_filename == 'pom.xml':
            return MavenPomXmlParser()
        # ... etc for other formats
        else:
            raise ValueError(f"Unknown manifest format: {manifest_filename}")