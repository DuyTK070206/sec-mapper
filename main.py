import argparse
from pathlib import Path

from src.scanner import DependencyScanner


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description='Simple Dependency Vulnerability Mapper'
    )
    parser.add_argument(
        'manifest',
        type=Path,
        help='Path to package.json or requirements.txt',
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

    scanner = DependencyScanner()
    result = scanner.scan_file(manifest_path)

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
