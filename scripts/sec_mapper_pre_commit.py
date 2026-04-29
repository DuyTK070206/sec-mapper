from pathlib import Path
import subprocess
import sys


def main() -> int:
    manifest = Path("package.json") if Path("package.json").exists() else Path("requirements.txt")
    if not manifest.exists():
        print("No package.json or requirements.txt found; skipping Sec Mapper pre-commit check.")
        return 0

    command = [sys.executable, "main.py", str(manifest), "--format", "json", "--fail-on-severity", "high"]
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode == 2:
        print("Sec Mapper blocked commit due to high/critical finding.")
        print(result.stdout)
        return 1
    if result.returncode != 0:
        print(result.stderr)
        return result.returncode
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
