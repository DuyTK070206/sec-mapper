# version_resolver.py

from packaging import version
from typing import Optional, Tuple

class VersionResolver:
    """
    Resolve version specifiers to actual installed versions
    
    Examples:
    - "^1.2.3" in npm → resolves to "1.x.x" where x >= 2.3
    - ">=1.0,<2.0" in Python → resolves to "1.x.x"
    """
    
    @staticmethod
    def resolve_npm_version(spec: str, available_versions: List[str]) -> Optional[str]:
        """
        Resolve npm version specifier
        
        Supported:
        - ^1.2.3 → >=1.2.3, <2.0.0
        - ~1.2.3 → >=1.2.3, <1.3.0
        - 1.2.3 → exactly 1.2.3
        - >=1.0, <2.0 → range
        - * or x → latest
        """
        
        # Remove whitespace
        spec = spec.strip()
        
        # Latest version
        if spec in ['*', 'x', 'latest']:
            return max(available_versions, key=version.parse)
        
        # Caret (^) - compatible with version
        if spec.startswith('^'):
            min_ver = version.parse(spec[1:])
            # ^1.2.3 allows changes that don't modify [1]
            max_major = min_ver.major
            matching = [
                v for v in available_versions
                if version.parse(v).major == max_major and version.parse(v) >= min_ver
            ]
            return max(matching, key=version.parse) if matching else None
        
        # Tilde (~) - reasonably close to version
        if spec.startswith('~'):
            min_ver = version.parse(spec[1:])
            # ~1.2.3 allows changes in patch version only
            max_major = min_ver.major
            max_minor = min_ver.minor
            matching = [
                v for v in available_versions
                if (version.parse(v).major == max_major and 
                    version.parse(v).minor == max_minor and
                    version.parse(v) >= min_ver)
            ]
            return max(matching, key=version.parse) if matching else None
        
        # Exact version
        if spec.isdigit() or spec.replace('.', '').isdigit():
            return spec if spec in available_versions else None
        
        # Range like ">=1.0,<2.0"
        return VersionResolver._resolve_range(spec, available_versions)
    
    @staticmethod
    def _resolve_range(spec: str, available_versions: List[str]) -> Optional[str]:
        # Parse multiple constraints separated by comma
        constraints = [c.strip() for c in spec.split(',')]
        
        matching = available_versions
        for constraint in constraints:
            matching = VersionResolver._apply_constraint(constraint, matching)
        
        return max(matching, key=version.parse) if matching else None
    
    @staticmethod
    def _apply_constraint(constraint: str, versions: List[str]) -> List[str]:
        # >=1.0, <=2.0, >1.0, <2.0
        if constraint.startswith('>='):
            min_ver = version.parse(constraint[2:])
            return [v for v in versions if version.parse(v) >= min_ver]
        elif constraint.startswith('<='):
            max_ver = version.parse(constraint[2:])
            return [v for v in versions if version.parse(v) <= max_ver]
        elif constraint.startswith('>'):
            min_ver = version.parse(constraint[1:])
            return [v for v in versions if version.parse(v) > min_ver]
        elif constraint.startswith('<'):
            max_ver = version.parse(constraint[1:])
            return [v for v in versions if version.parse(v) < max_ver]
        return versions