import argparse
from pathlib import Path

from src.scanner import DependencyScanner


def build_parser() -> argparse.ArgumentParser:
    """Build the command-line argument parser for the vulnerability scanner."""
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
        choices=['text', 'json', 'html', 'sarif', 'attack-graph'],
        default='text',
        help='Output format for the scan report',
    )
    parser.add_argument(
        '--sync',
        action='store_true',
        help='Sync latest CVE data from NVD before scanning',
    )
    parser.add_argument(
        '--nvd-api-key',
        type=str,
        default=None,
        help='NVD API key for higher rate limits',
    )
    parser.add_argument(
        '--github-token',
        type=str,
        default=None,
        help='GitHub token for accessing advisories',
    )
    return parser


def main() -> None:
    """Entry point for the CLI tool.

    Parses command-line arguments, optionally syncs vulnerability data,
    runs the dependency scan, and outputs the result in the requested format.
    """
    args = build_parser().parse_args()
    manifest_path = args.manifest

    if not manifest_path.exists():
        raise SystemExit(f'File not found: {manifest_path}')

    if args.lock and not args.lock.exists():
        raise SystemExit(f'Lockfile not found: {args.lock}')

    # Initialize scanner with optional custom DB
    scanner = DependencyScanner(
        db_path=str(args.vuln_db) if args.vuln_db else None,
        nvd_api_key=args.nvd_api_key,
        github_token=args.github_token,
    )
    
    # Optionally sync NVD data
    if args.sync:
        from src.nvd_database import NVDDatabase
        nvd = NVDDatabase()
        nvd.sync_recent(days=7)
    
    # Perform scan
    result = scanner.scan_file(manifest_path, lock_path=args.lock)

    # Output in requested format
    if args.format == 'json':
        print(scanner.generate_json_report(result))
        return

    if args.format == 'html':
        html = scanner.generate_html_report(result)
        output = manifest_path.with_suffix('.report.html')
        output.write_text(html, encoding='utf-8')
        print(f'HTML report written to: {output}')
        return
    
    if args.format == 'sarif':
        sarif = scanner.generate_sarif_report(result)
        output = manifest_path.parent / f"{manifest_path.stem}.sarif.json"
        output.write_text(sarif, encoding='utf-8')
        print(f'SARIF report written to: {output}')
        return
    
    if args.format == 'attack-graph':
        # Generate AI-powered attack path analysis
        attack_analysis = scanner.generate_attack_path_analysis(result)
        
        # Generate interactive HTML report with D3.js visualization
        html = scanner.generate_attack_graph_html(result, attack_analysis)
        output = manifest_path.with_suffix('.attack-graph.html')
        output.write_text(html, encoding='utf-8')
        print(f'Attack graph report written to: {output}')
        print(f'  - Attack paths identified: {len(attack_analysis.get("attack_paths", []))}')
        print(f'  - AI risk assessments: {len(attack_analysis.get("ai_assessments", []))}')
        print(f'  - Blast radius score: {attack_analysis.get("blast_radius", {}).get("summary", {}).get("average_score", 0):.1f}')
        return

    print(scanner.format_report(result, manifest_path))


if __name__ == '__main__':
    main()
