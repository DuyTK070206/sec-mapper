import argparse
from pathlib import Path

from src.scanner import DependencyScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Dependency Vulnerability Mapper',
    )
    parser.add_argument(
        'manifest',
        type=Path,
        help='Path to package.json or requirements.txt',
    )
    parser.add_argument(
        '--lock',
        type=Path,
        default=None,
        help='Optional path to package-lock.json for transitive dependency analysis',
    )
    parser.add_argument(
        '--vuln-db',
        type=Path,
        default=None,
        help='Optional path to a vulnerability database JSON file',
    )
    parser.add_argument(
        '--format',
        choices=['text', 'json', 'html'],
        default='text',
        help='Output format for the scan report',
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()
    manifest_path = args.manifest

    if not manifest_path.exists():
        raise SystemExit(f'File not found: {manifest_path}')

    if args.lock and not args.lock.exists():
        raise SystemExit(f'Lockfile not found: {args.lock}')

    scanner = DependencyScanner(db_path=str(args.vuln_db) if args.vuln_db else None)
    result = scanner.scan_file(manifest_path, lock_path=args.lock)

    if args.format == 'json':
        print(scanner.generate_json_report(result))
        return

    if args.format == 'html':
        html = scanner.generate_html_report(result)
        output = manifest_path.with_suffix('.report.html')
        output.write_text(html, encoding='utf-8')
        print(f'HTML report written to: {output}')
        return

    print(scanner.format_report(result, manifest_path))


if __name__ == '__main__':
    main()
