# tests/test_dependency_parser.py

import pytest
from dependency_parser import NpmPackageJsonParser

def test_parse_package_json():
    content = '''
    {
        "name": "my-app",
        "dependencies": {
            "express": "^4.18.0",
            "lodash": "4.17.21"
        },
        "devDependencies": {
            "jest": "^28.0.0"
        }
    }
    '''
    
    parser = NpmPackageJsonParser()
    deps = parser.parse(content)
    
    assert len(deps) == 3
    assert any(d.name == 'express' for d in deps)
    assert any(d.name == 'jest' and d.dev_only for d in deps)

def test_version_resolution():
    # Test ^1.2.3 → 1.x.x
    # Test ~1.2.3 → 1.2.x
    pass