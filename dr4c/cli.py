"""Terminal interface for DR4C Core Recon."""
from __future__ import annotations

import argparse
import json
import shutil
import sys
from pathlib import Path

from dr4c import __version__
from dr4c.config import load_config
from dr4c.core.models import ScanResult
from dr4c.core.pipeline import run_recon
from dr4c.core.scope import Scope, ScopeError, normalize_domain


ROOT = Path(__file__).resolve().parent.parent

BANNER = r"""
╔══════════════════════════════╗
║          D R 4 C             ║
║         cyber.dr4c           ║
╚══════════════════════════════╝
"""


def parser() -> argparse.ArgumentParser:
    cli = argparse.ArgumentParser(prog="dr4c", description="DR4C — Attack Surface & Exposure Intelligence")
    cli.add_argument("--version", action="version", version=f"dr4c {__version__}")
    sub = cli.add_subparsers(dest="command")
    sub.add_parser("doctor", help="check Python, Go, and local project requirements")
    sub.add_parser("config", help="show default Core Recon settings")
    recon = sub.add_parser("recon", help="run authorized Core Recon")
    recon.add_argument("-d", "--domain", required=True)
    recon.add_argument(
        "--scope-file", help="optional JSON scope file for additional restrictions",
    )
    mode = recon.add_mutually_exclusive_group()
    mode.add_argument("--passive", action="store_true", help="passive CT discovery only")
    mode.add_argument("--active", action="store_true", help="active DNS and HTTP checks only")
    recon.add_argument("--config", default=str(ROOT / "configs" / "default.yaml"))
    recon.add_argument("--timeout", type=int)
    recon.add_argument("-t", "--threads", type=int)
    recon.add_argument(
        "--ports", help="optional TCP connect scan (comma-separated); requires an authorized scope file",
    )
    recon.add_argument("--salve", action="store_true", help="save one JSON report under results/")
    recon.add_argument("-o", "--output", help="JSON report path; requires --salve")
    recon.add_argument("--no-color", action="store_true", help="accepted for automation; output is plain text")
    return cli


def parse_ports(value: str) -> list[int]:
    try:
        ports = [int(part.strip()) for part in value.split(",")]
    except ValueError as exc:
        raise ValueError("ports must be comma-separated integers") from exc
    if not ports or len(ports) > 32 or len(set(ports)) != len(ports):
        raise ValueError("provide 1..32 unique TCP ports")
    if any(port < 1 or port > 65535 for port in ports):
        raise ValueError("TCP ports must be between 1 and 65535")
    return ports


def doctor() -> int:
    import platform
    import subprocess
    print(f"Python: {platform.python_version()} (requires >=3.12)")
    if sys.version_info < (3, 12):
        print("ERROR: Python version is too old")
        return 1
    go = shutil.which("go")
    if not go:
        print("ERROR: Go is not installed (requires >=1.23)")
        return 1
    launcher = subprocess.run([go, "version"], capture_output=True, text=True, check=False)
    version = subprocess.run(
        ["sh", str(ROOT / "scripts" / "go.sh"), "version"], cwd=ROOT / "go-engine",
        capture_output=True, text=True, check=False,
    )
    if version.returncode:
        print(f"ERROR: Go toolchain unavailable: {version.stderr.strip()}")
        return 1
    print(f"System Go launcher: {launcher.stdout.strip()}")
    print(f"Project Go toolchain: {version.stdout.strip()} (requires >=1.23)")
    import re
    match = re.search(r"go version go(\d+)\.(\d+)", version.stdout)
    if not match or tuple(map(int, match.groups())) < (1, 23):
        print("ERROR: selected Go toolchain is below 1.23")
        return 1
    print("Core Recon dependencies: available")
    return 0


def print_scan_result(result: ScanResult, json_path: Path | None) -> None:
    """Print scan observations in a terminal-friendly format."""
    print(f"\n=== Resultado da varredura: {result.target} ===")
    print(f"Scan: {result.scan_id}")

    if result.summary:
        print("\nResumo")
        for key, value in sorted(result.summary.items()):
            print(f"  {key}: {value}")

    print(f"\nAtivos encontrados ({len(result.assets)})")
    if result.assets:
        for asset in result.assets:
            print(f"  [{asset.asset_type}] {asset.value}  (fonte: {asset.source})")
    else:
        print("  Nenhum ativo encontrado.")

    print(f"\nRegistros DNS ({len(result.dns_records)})")
    if result.dns_records:
        for record in result.dns_records:
            print(f"  {record.hostname} {record.record_type} {record.value}  (fonte: {record.source})")
    else:
        print("  Nenhum registro DNS coletado.")

    print(f"\nPortas abertas ({len(result.open_ports)})")
    if result.open_ports:
        for port in result.open_ports:
            print(f"  {port.hostname} ({port.address}):{port.port} [{port.state}]")
    else:
        print("  Nenhuma porta aberta encontrada ou a verificação não foi solicitada.")

    print(f"\nResultados HTTP/HTTPS ({len(result.http_services)})")
    if result.http_services:
        for service in result.http_services:
            status = str(service.status_code) if service.status_code is not None else "ERRO"
            detail = f" | {service.classification}"
            if service.title:
                detail += f" | título: {service.title}"
            if service.redirect_location:
                detail += f" | destino: {service.redirect_location}"
            if service.error:
                detail += f" | erro: {service.error}"
            print(f"  {status} | {service.target}{detail}")
    else:
        print("  Nenhum alvo HTTP/HTTPS verificado.")

    if result.errors:
        print(f"\nNotas operacionais ({len(result.errors)})")
        for note in result.errors:
            print(f"  - {note}")

    if json_path:
        print(f"\nJSON salvo: {json_path}")
    else:
        print("\nResultado exibido na tela; nenhum arquivo foi salvo. Use --salve para salvar o JSON.")


def main() -> int:
    cli = parser()
    args = cli.parse_args()
    print(BANNER)
    if args.command == "doctor":
        return doctor()
    if args.command == "config":
        print((ROOT / "configs" / "default.yaml").read_text(encoding="utf-8"), end="")
        return 0
    if args.command == "recon":
        if args.output and not args.salve:
            cli.error("--output só pode ser usado junto com --salve")
        try:
            config = load_config(args.config)
        except (OSError, ValueError) as exc:
            print(f"ERROR: invalid configuration: {exc}", file=sys.stderr)
            return 2
        timeout = args.timeout if args.timeout is not None else config.http_timeout_seconds
        threads = args.threads if args.threads is not None else config.http_max_concurrency
        if timeout < 1 or timeout > 120 or threads < 1 or threads > 100:
            print("ERROR: timeout must be 1..120 and threads must be 1..100", file=sys.stderr)
            return 2
        try:
            domain = normalize_domain(args.domain)
            scope = Scope.load(args.scope_file) if args.scope_file else Scope.for_domain(domain)
            scope.validate_domain(domain)
            ports = parse_ports(args.ports) if args.ports else None
            if ports and not args.scope_file:
                raise ScopeError("TCP port scanning requires --scope-file with explicit allow_port_scan authorization")
            if ports and args.passive:
                raise ScopeError("TCP port scanning cannot be combined with --passive")
            if ports and not scope.allow_port_scan:
                raise ScopeError("scope file must set allow_port_scan to true")
            if ports and any(port not in scope.allowed_ports for port in ports):
                raise ScopeError("every requested TCP port must also appear in scope allowed_ports")
            if args.salve and args.output and Path(args.output).exists():
                raise FileExistsError(f"refusing to overwrite existing report: {args.output}")
            passive, active = not args.active, not args.passive
            result = run_recon(domain, scope, ROOT, passive, active, timeout, threads,
                               config.http_max_response_bytes, config.http_max_requests, ports)
            outpath = None
            if args.salve:
                outpath = Path(args.output) if args.output else ROOT / "results" / f"{result.scan_id}.json"
                outpath.parent.mkdir(parents=True, exist_ok=True)
                with outpath.open("x", encoding="utf-8") as stream:
                    json.dump(result.to_dict(), stream, ensure_ascii=False, indent=2)
                    stream.write("\n")
            print(f"DR4C {__version__} | varredura concluída")
            print_scan_result(result, outpath)
            return 0
        except (ScopeError, OSError, ValueError, RuntimeError) as exc:
            print(f"ERROR: {exc}", file=sys.stderr)
            return 1
    parser().print_help()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
