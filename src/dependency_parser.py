# dependency_parser.py

from abc import ABC, abstractmethod
from typing import List, Optional
import json
import re
import xml.etree.ElementTree as ET


class ParsedDependency:
    """Representation of a parsed dependency extracted from a manifest."""

    def __init__(
        self,
        name: str,
        version: str,
        ecosystem: str,
        is_transitive: bool = False,
        source: str = 'manifest',
        parent: Optional[str] = None,
    ):
        self.name = name
        self.version = version
        self.ecosystem = ecosystem
        self.is_transitive = is_transitive
        self.source = source
        self.parent = parent
        self.children: List['ParsedDependency'] = []
        self.dev_only: bool = False


class DependencyParser(ABC):
    @abstractmethod
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        """Parse manifest text into a list of ParsedDependency items."""
        pass


class NpmPackageJsonParser(DependencyParser):
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        """Parse npm package.json content and extract direct dependencies."""
        data = json.loads(manifest_content)
        dependencies: List[ParsedDependency] = []

        for section, is_dev in [('dependencies', False), ('devDependencies', True)]:
            for name, version_spec in data.get(section, {}).items():
                dep = ParsedDependency(
                    name=name,
                    version=str(version_spec).strip(),
                    ecosystem='npm',
                    is_transitive=False,
                    source='package.json',
                )
                dep.dev_only = is_dev
                dependencies.append(dep)

        return dependencies


class PackageLockParser(DependencyParser):
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        """Parse npm package-lock.json content and extract resolved dependency versions."""
        data = json.loads(manifest_content)
        dependencies: List[ParsedDependency] = []

        if 'packages' in data:
            dependencies.extend(self._parse_packages_section(data['packages']))
        elif 'dependencies' in data:
            dependencies.extend(self._parse_dependencies_section(data['dependencies']))

        return dependencies

    def _parse_packages_section(self, packages: dict) -> List[ParsedDependency]:
        """Parse the `packages` section of a package-lock.json file."""
        deps: List[ParsedDependency] = []

        for path, meta in packages.items():
            if path == '' or not path.startswith('node_modules/'):
                continue

            name = path.split('node_modules/')[-1]
            if not name:
                continue

            version = meta.get('version', '')
            is_transitive = path.count('node_modules/') > 1
            deps.append(
                ParsedDependency(
                    name=name,
                    version=version,
                    ecosystem='npm',
                    is_transitive=is_transitive,
                    source='package-lock.json',
                )
            )

        return deps

    def _parse_dependencies_section(self, dependencies: dict, parent: Optional[str] = None) -> List[ParsedDependency]:
        """Recursively parse nested dependency entries from a package-lock.json structure."""
        deps: List[ParsedDependency] = []

        for name, meta in dependencies.items():
            version = meta.get('version', '')
            is_transitive = parent is not None
            dep = ParsedDependency(
                name=name,
                version=version,
                ecosystem='npm',
                is_transitive=is_transitive,
                source='package-lock.json',
                parent=parent,
            )
            deps.append(dep)

            nested = meta.get('dependencies', {})
            if isinstance(nested, dict):
                deps.extend(self._parse_dependencies_section(nested, parent=name))

        return deps


class PythonRequirementsParser(DependencyParser):
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        """Parse a Python requirements.txt file and extract dependency specifiers."""
        dependencies: List[ParsedDependency] = []

        for line in manifest_content.splitlines():
            line = line.split('#', 1)[0].strip()
            if not line:
                continue

            match = re.match(r'^([A-Za-z0-9_.\-]+)\s*([<>=!~].*)?$', line)
            if not match:
                continue

            name = match.group(1)
            version_spec = match.group(2) or '*'
            dependencies.append(
                ParsedDependency(
                    name=name,
                    version=version_spec.strip(),
                    ecosystem='pip',
                    is_transitive=False,
                    source='requirements.txt',
                )
            )

        return dependencies


class MavenPomXmlParser(DependencyParser):
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        """Parse a Maven pom.xml file and extract compile-time dependencies."""
        dependencies: List[ParsedDependency] = []
        root = ET.fromstring(manifest_content)
        namespaces = {'m': 'http://maven.apache.org/POM/4.0.0'}

        for dep_elem in root.findall('.//m:dependency', namespaces):
            group_id = dep_elem.findtext('m:groupId', default='', namespaces=namespaces)
            artifact_id = dep_elem.findtext('m:artifactId', default='', namespaces=namespaces)
            version = dep_elem.findtext('m:version', default='', namespaces=namespaces)
            scope = dep_elem.findtext('m:scope', default='compile', namespaces=namespaces)
            name = f'{group_id}:{artifact_id}'
            dep = ParsedDependency(
                name=name,
                version=version,
                ecosystem='maven',
                is_transitive=False,
                source='pom.xml',
            )
            dep.scope = scope
            dependencies.append(dep)

        return dependencies


class ParserFactory:
    @staticmethod
    def get_parser(manifest_filename: str) -> DependencyParser:
        """Return the appropriate parser instance for a given manifest filename."""
        lower_name = manifest_filename.lower()
        if lower_name == 'package.json':
            return NpmPackageJsonParser()
        if lower_name == 'package-lock.json':
            return PackageLockParser()
        if lower_name == 'requirements.txt':
            return PythonRequirementsParser()
        if lower_name == 'pom.xml':
            return MavenPomXmlParser()
        raise ValueError(f'Unsupported manifest type: {manifest_filename}')