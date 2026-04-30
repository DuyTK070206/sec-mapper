import argparse
import os
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
        nargs='?',
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
        choices=['text', 'json', 'html', 'sarif', 'api'],
        default='text',
        help='Output format for the scan report',
    )
    parser.add_argument(
        '--serve',
        action='store_true',
        help='Run web API/UI server instead of one-shot CLI scan',
    )
    parser.add_argument(
        '--host',
        type=str,
        default='127.0.0.1',
        help='Host for web server mode',
    )
    parser.add_argument(
        '--port',
        type=int,
        default=8000,
        help='Port for web server mode',
    )
    parser.add_argument(
        '--fail-on-severity',
        choices=['critical', 'high', 'medium', 'low'],
        default=None,
        help='Exit with code 2 when findings at or above this severity exist',
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
    parser.add_argument(
        '--openai-api-key',
        type=str,
        default=None,
        help='OpenAI API key for AI analysis (can also use OPENAI_API_KEY environment variable)',
    )
    parser.add_argument(
        '--ai-mode',
        type=bool,
        nargs='?',
        const=True,
        default=None,
        help='Enable AI analysis mode (only with --serve)',
    )
    return parser


def main() -> None:
    """Entry point for the CLI tool.

    Parses command-line arguments, optionally syncs vulnerability data,
    runs the dependency scan, and outputs the result in the requested format.
    """
    args = build_parser().parse_args()

    if args.serve:
        print("\n" + "="*60)
        print("Sec Mapper Web Server - Configuration")
        print("="*60)
        
        # Get OpenAI API Key from argument or environment or interactive prompt
        api_key = args.openai_api_key or os.environ.get("OPENAI_API_KEY")
        
        if not api_key:
            # Interactive mode
            print("\n[1/2] OpenAI API Key Configuration")
            print("-" * 60)
            api_key = input("Enter your OpenAI API key (or press Enter to skip): ").strip()
        
        if api_key:
            os.environ["OPENAI_API_KEY"] = api_key
            print("✓ OpenAI API key configured")
        else:
            print("⊗ OpenAI API key not configured (AI analysis will be disabled)")
        
        # Get AI Mode setting
        print("\n[2/2] AI Mode Configuration")
        print("-" * 60)
        
        if args.ai_mode is not None:
            # Argument provided
            ai_mode = args.ai_mode
        elif api_key:
            # Interactive mode only if API key is available
            ai_mode_input = input("Enable AI analysis by default? (y/n, default: n): ").strip().lower()
            ai_mode = ai_mode_input in ('y', 'yes', '1', 'true')
        else:
            ai_mode = False
        
        if api_key:
            if ai_mode:
                os.environ["AI_MODE"] = "true"
                print("✓ AI mode enabled")
            else:
                os.environ["AI_MODE"] = "false"
                print("⊗ AI mode disabled (can be toggled in web interface)")
        else:
            os.environ["AI_MODE"] = "false"
            print("⊗ AI mode disabled (API key not configured)")
        
        print("\n" + "="*60)
        print(f"Starting server at http://{args.host}:{args.port}")
        print("="*60 + "\n")
        
        from src.web_api import run_server
        run_server(host=args.host, port=args.port, db_path=str(args.vuln_db) if args.vuln_db else None)
        return

    manifest_path = args.manifest
    if manifest_path is None:
        raise SystemExit('Manifest path is required unless --serve is used.')

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
        _apply_fail_threshold(result, args.fail_on_severity)
        return

    if args.format == 'api':
        print(scanner.generate_api_report(result))
        _apply_fail_threshold(result, args.fail_on_severity)
        return

    print(scanner.format_report(result, manifest_path))
    _apply_fail_threshold(result, args.fail_on_severity)


def _apply_fail_threshold(result: dict, threshold: str) -> None:
    if not threshold:
        return
    severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
    threshold_rank = severity_order[threshold]
    for finding in result.get('findings', []):
        rank = severity_order.get((finding.get('severity') or 'low').lower(), 4)
        if rank <= threshold_rank:
            raise SystemExit(2)


if __name__ == '__main__':
    main()
