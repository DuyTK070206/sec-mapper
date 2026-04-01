import json
from pathlib import Path

from src.dependency_parser import NpmPackageJsonParser, PackageLockParser, PythonRequirementsParser


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
    assert any(d.name == 'express' and not d.dev_only for d in deps)
    assert any(d.name == 'jest' and d.dev_only for d in deps)


def test_parse_package_lock():
    sample_path = Path(__file__).resolve().parent.parent / 'samples' / 'package-lock.json'
    parser = PackageLockParser()
    lock_content = sample_path.read_text(encoding='utf-8')
    deps = parser.parse(lock_content)

    assert any(d.name == 'lodash' and d.version == '4.17.20' for d in deps)
    assert any(d.name == 'follow-redirects' for d in deps)
    assert any(d.name == 'axios' and not d.is_transitive for d in deps)


def test_parse_requirements_txt():
    content = 'requests==2.25.0\nurllib3>=1.26.0\n'
    parser = PythonRequirementsParser()
    deps = parser.parse(content)

    assert len(deps) == 2
    assert deps[0].name == 'requests'
    assert deps[1].version == '>=1.26.0'
