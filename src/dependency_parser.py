# dependency_parser.py

from abc import ABC, abstractmethod
from typing import Dict, List, Optional, Type
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
        self.scope: str = 'runtime'
        self.dependency_path: List[str] = [name]


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
            dep_path = [p for p in path.split('node_modules/') if p]
            deps.append(
                ParsedDependency(
                    name=name,
                    version=version,
                    ecosystem='npm',
                    is_transitive=is_transitive,
                    source='package-lock.json',
                )
            )
            deps[-1].dependency_path = dep_path or [name]

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
            dep.dependency_path = [parent, name] if parent else [name]
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
            dep.dependency_path = [name]
            dependencies.append(dep)

        return dependencies


class PoetryLockParser(DependencyParser):
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        dependencies: List[ParsedDependency] = []
        current_name: Optional[str] = None
        current_version: Optional[str] = None

        for raw in manifest_content.splitlines():
            line = raw.strip()
            if line == '[[package]]':
                if current_name and current_version:
                    dep = ParsedDependency(
                        name=current_name,
                        version=current_version,
                        ecosystem='pip',
                        is_transitive=True,
                        source='poetry.lock',
                    )
                    dep.dependency_path = [current_name]
                    dependencies.append(dep)
                current_name = None
                current_version = None
                continue
            if line.startswith('name = '):
                current_name = line.split('=', 1)[1].strip().strip('"')
            elif line.startswith('version = '):
                current_version = line.split('=', 1)[1].strip().strip('"')

        if current_name and current_version:
            dep = ParsedDependency(
                name=current_name,
                version=current_version,
                ecosystem='pip',
                is_transitive=True,
                source='poetry.lock',
            )
            dep.dependency_path = [current_name]
            dependencies.append(dep)

        return dependencies


class PipfileLockParser(DependencyParser):
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        data = json.loads(manifest_content)
        dependencies: List[ParsedDependency] = []
        for section in ['default', 'develop']:
            for name, meta in data.get(section, {}).items():
                version = str(meta.get('version', '*')).strip()
                dep = ParsedDependency(
                    name=name,
                    version=version,
                    ecosystem='pip',
                    is_transitive=(section == 'develop'),
                    source='Pipfile.lock',
                )
                dep.dev_only = section == 'develop'
                dep.dependency_path = [name]
                dependencies.append(dep)
        return dependencies


class GoModParser(DependencyParser):
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        dependencies: List[ParsedDependency] = []
        in_require_block = False
        for raw in manifest_content.splitlines():
            line = raw.strip()
            if line.startswith('require ('):
                in_require_block = True
                continue
            if in_require_block and line == ')':
                in_require_block = False
                continue
            if line.startswith('//') or not line:
                continue

            entry = line
            if line.startswith('require '):
                entry = line[len('require '):]

            if in_require_block or line.startswith('require '):
                parts = entry.split()
                if len(parts) >= 2:
                    dep = ParsedDependency(
                        name=parts[0],
                        version=parts[1],
                        ecosystem='go',
                        is_transitive=(' indirect' in raw),
                        source='go.mod',
                    )
                    dep.dependency_path = [parts[0]]
                    dependencies.append(dep)

        return dependencies


class CargoTomlParser(DependencyParser):
    def parse(self, manifest_content: str) -> List[ParsedDependency]:
        dependencies: List[ParsedDependency] = []
        in_dependencies = False
        for raw in manifest_content.splitlines():
            line = raw.strip()
            if line.startswith('['):
                in_dependencies = line in {'[dependencies]', '[dev-dependencies]'}
                continue
            if not in_dependencies or not line or line.startswith('#'):
                continue
            if '=' not in line:
                continue
            name, value = line.split('=', 1)
            version = value.strip().strip('"')
            dep = ParsedDependency(
                name=name.strip(),
                version=version,
                ecosystem='cargo',
                is_transitive=False,
                source='Cargo.toml',
            )
            dep.dependency_path = [name.strip()]
            dependencies.append(dep)
        return dependencies


class ParserFactory:
    _registry: Dict[str, Type[DependencyParser]] = {
        'package.json': NpmPackageJsonParser,
        'package-lock.json': PackageLockParser,
        'requirements.txt': PythonRequirementsParser,
        'pom.xml': MavenPomXmlParser,
        'poetry.lock': PoetryLockParser,
        'pipfile.lock': PipfileLockParser,
        'go.mod': GoModParser,
        'cargo.toml': CargoTomlParser,
    }

    @classmethod
    def register_parser(cls, filename: str, parser_cls: Type[DependencyParser]) -> None:
        cls._registry[filename.lower()] = parser_cls

    @staticmethod
    def get_parser(manifest_filename: str) -> DependencyParser:
        """Return the appropriate parser instance for a given manifest filename."""
        lower_name = manifest_filename.lower()
        parser_cls = ParserFactory._registry.get(lower_name)
        if parser_cls is not None:
            return parser_cls()
        raise ValueError(f'Unsupported manifest type: {manifest_filename}')