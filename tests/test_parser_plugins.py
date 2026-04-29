from src.dependency_parser import ParserFactory


def test_poetry_lock_parser():
    parser = ParserFactory.get_parser("poetry.lock")
    content = """
[[package]]
name = \"requests\"
version = \"2.25.0\"

[[package]]
name = \"urllib3\"
version = \"1.26.3\"
"""
    deps = parser.parse(content)
    assert len(deps) == 2
    assert deps[0].ecosystem == "pip"


def test_pipfile_lock_parser():
    parser = ParserFactory.get_parser("Pipfile.lock")
    content = '{"default": {"requests": {"version": "==2.25.0"}}, "develop": {"pytest": {"version": "==8.0.0"}}}'
    deps = parser.parse(content)
    assert any(d.name == "requests" for d in deps)
    assert any(d.name == "pytest" for d in deps)


def test_go_mod_parser():
    parser = ParserFactory.get_parser("go.mod")
    content = """
module demo

go 1.22

require (
  github.com/gin-gonic/gin v1.10.0
  golang.org/x/text v0.16.0 // indirect
)
"""
    deps = parser.parse(content)
    assert any(d.name == "github.com/gin-gonic/gin" for d in deps)


def test_cargo_toml_parser():
    parser = ParserFactory.get_parser("Cargo.toml")
    content = """
[package]
name = "demo"
version = "0.1.0"

[dependencies]
serde = "1.0"
"""
    deps = parser.parse(content)
    assert len(deps) == 1
    assert deps[0].ecosystem == "cargo"
