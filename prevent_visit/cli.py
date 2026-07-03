from __future__ import annotations

import argparse
import re
import socket
import subprocess
from pathlib import Path

from .config import AppConfig, DEFAULT_CONFIG_PATH
from .certs import CertificateManager
from .proxy import ProxyServer
from .rules import RuleSet
from .windows import (
    build_pac_payload,
    build_hosts_payload,
    render_firewall_script,
    render_registry_script,
    render_startup_task_script,
    render_uninstall_script,
)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prevent-visit",
        description="Windows-focused adult-content blocker helper.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    init_parser = subparsers.add_parser("init-config", help="Create the default config file.")
    init_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    run_parser = subparsers.add_parser("run-service", help="Run the local proxy blocker.")
    run_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    cert_parser = subparsers.add_parser("generate-ca", help="Generate the local interception root certificate.")
    cert_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    hosts_parser = subparsers.add_parser("build-hosts", help="Generate managed hosts entries.")
    hosts_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    hosts_parser.add_argument("--output", type=Path, default=None)

    pac_parser = subparsers.add_parser("build-pac", help="Generate the search-only proxy PAC file.")
    pac_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    pac_parser.add_argument("--output", type=Path, default=None)

    registry_parser = subparsers.add_parser("build-registry-script", help="Generate the policy apply script.")
    registry_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    registry_parser.add_argument("--output", type=Path, default=Path("build") / "apply-policies.ps1")

    firewall_parser = subparsers.add_parser("build-firewall-script", help="Generate the firewall apply script.")
    firewall_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    firewall_parser.add_argument("--output", type=Path, default=Path("build") / "apply-firewall-rules.ps1")

    uninstall_parser = subparsers.add_parser("build-uninstall-script", help="Generate the policy removal script.")
    uninstall_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    uninstall_parser.add_argument("--output", type=Path, default=Path("build") / "remove-policies.ps1")

    task_parser = subparsers.add_parser("build-startup-task", help="Generate the scheduled-task script.")
    task_parser.add_argument("--output", type=Path, default=Path("build") / "register-task.ps1")
    task_parser.add_argument("--repo-root", type=Path, default=Path.cwd())

    status_parser = subparsers.add_parser("check-status", help="Check whether the blocker is installed and running.")
    status_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "init-config":
        config = AppConfig.load(args.config)
        config.save(args.config)
        print(f"Config written to {args.config}")
        return

    if args.command == "run-service":
        config = AppConfig.load(args.config)
        ProxyServer(config).run()
        return

    if args.command == "generate-ca":
        config = AppConfig.load(args.config)
        manager = CertificateManager(config)
        _, cert_path = manager.ensure_root_ca()
        print(f"Root certificate written to {cert_path} (importable copy: {manager.root_cert_der_path})")
        return

    if args.command == "build-hosts":
        config = AppConfig.load(args.config)
        rules = RuleSet(config)
        payload = build_hosts_payload(config, rules)
        output = args.output or Path(config.hosts_output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
        print(f"Hosts payload written to {output}")
        return

    if args.command == "build-pac":
        config = AppConfig.load(args.config)
        payload = build_pac_payload(config)
        output = args.output or Path(config.pac_output_path)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(payload, encoding="utf-8")
        print(f"PAC file written to {output}")
        return

    if args.command == "build-registry-script":
        config = AppConfig.load(args.config)
        payload = render_registry_script(config)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"Registry script written to {args.output}")
        return

    if args.command == "build-firewall-script":
        config = AppConfig.load(args.config)
        payload = render_firewall_script(config)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"Firewall script written to {args.output}")
        return

    if args.command == "build-uninstall-script":
        config = AppConfig.load(args.config)
        payload = render_uninstall_script(config)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"Uninstall script written to {args.output}")
        return

    if args.command == "build-startup-task":
        payload = render_startup_task_script(args.repo_root)
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(payload, encoding="utf-8")
        print(f"Startup task script written to {args.output}")
        return

    if args.command == "check-status":
        raise SystemExit(check_status(args.config))

    parser.error("Unknown command")


def check_status(config_path: Path) -> int:
    config_exists = config_path.exists()
    config = AppConfig.load(config_path)
    repo_root = config_path.resolve().parent.parent
    runner_path = repo_root / "run_guard.py"
    root_cert_path = Path(config.certs_dir) / "root_ca_cert.cer"

    port_open = _is_port_open(config.proxy_host, config.proxy_port)
    listener_pids = _get_listener_process_ids(config.proxy_host, config.proxy_port)
    guard_processes = _get_guard_process_count(runner_path)
    task_state = _get_scheduled_task_state("PreventVisitGuard")
    cert_installed = _is_root_cert_installed(root_cert_path)
    firewall_rules = _get_firewall_rule_count()
    guard_label = _describe_guard_state(guard_processes, listener_pids)

    print(f"Config file: {'OK' if config_exists else 'MISSING'} ({config_path})")
    print(f"Guard process: {guard_label}")
    print(f"Proxy port: {'LISTENING' if port_open else 'NOT LISTENING'} ({config.proxy_host}:{config.proxy_port})")
    print(f"Scheduled task: {task_state}")
    print(f"Root certificate: {'INSTALLED' if cert_installed else 'MISSING'} ({root_cert_path})")
    print(f"Firewall rules: {'FOUND' if firewall_rules > 0 else 'MISSING'} ({firewall_rules} rule(s))")

    healthy = all(
        [
            config_exists,
            port_open,
            len(listener_pids) == 1,
            task_state not in {"MISSING", "ERROR"},
            cert_installed,
            firewall_rules > 0,
        ]
    )
    print(f"Overall status: {'ACTIVE' if healthy else 'NEEDS ATTENTION'}")
    return 0 if healthy else 1


def _is_port_open(host: str, port: int) -> bool:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(1.0)
        return sock.connect_ex((host, port)) == 0


def _get_guard_process_count(runner_path: Path) -> int:
    script = (
        "$runner = @'\n"
        f"{runner_path}\n"
        "'@.Trim(); "
        "$count = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Name -match '^pythonw?\\.exe$' -and $_.CommandLine -like \"*$runner*\" }).Count; "
        "Write-Output $count"
    )
    result = _run_powershell(script)
    if result.returncode != 0:
        return 0
    try:
        return int(result.stdout.strip() or "0")
    except ValueError:
        return 0


def _get_listener_process_ids(host: str, port: int) -> list[int]:
    result = subprocess.run(
        ["netstat", "-ano", "-p", "TCP"],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        return []

    pids: set[int] = set()
    for line in result.stdout.splitlines():
        parsed = _parse_netstat_listener(line)
        if parsed is None:
            continue
        local_address, pid = parsed
        if _matches_listener_address(local_address, host, port):
            pids.add(pid)
    return sorted(pids)


def _parse_netstat_listener(line: str) -> tuple[str, int] | None:
    parts = line.split()
    if len(parts) < 5 or parts[0].upper() != "TCP":
        return None
    if parts[3].upper() != "LISTENING":
        return None
    try:
        return parts[1], int(parts[4])
    except ValueError:
        return None


def _matches_listener_address(local_address: str, host: str, port: int) -> bool:
    normalized = local_address.strip().lower()
    if normalized.startswith("[::]"):
        return normalized.endswith(f":{port}")
    if normalized.startswith("["):
        return normalized == f"[{host.lower()}]:{port}"
    return normalized in {
        f"{host.lower()}:{port}",
        f"0.0.0.0:{port}",
        f"127.0.0.1:{port}" if host in {"localhost", "127.0.0.1"} else "",
    }


def _describe_guard_state(guard_processes: int, listener_pids: list[int]) -> str:
    if len(listener_pids) > 1:
        return f"DUPLICATE LISTENERS ({len(listener_pids)} listener PID(s): {', '.join(str(pid) for pid in listener_pids)})"
    if guard_processes > 1:
        return f"DUPLICATE PROCESSES ({guard_processes} instance(s))"
    if guard_processes == 1:
        return "RUNNING (1 detected process)"
    if len(listener_pids) == 1:
        return f"PORT ACTIVE (listener PID {listener_pids[0]}; command-line lookup unavailable)"
    return "STOPPED (no detected process or listener)"


def _get_scheduled_task_state(task_name: str) -> str:
    script = (
        f"$task = Get-ScheduledTask -TaskName '{task_name}' -ErrorAction SilentlyContinue; "
        "if ($null -eq $task) { Write-Output 'MISSING' } else { Write-Output $task.State }"
    )
    result = _run_powershell(script)
    if result.returncode != 0:
        return "ERROR"
    return result.stdout.strip() or "ERROR"


def _is_root_cert_installed(cert_path: Path) -> bool:
    if not cert_path.exists():
        return False
    script = (
        "$certPath = @'\n"
        f"{cert_path}\n"
        "'@.Trim(); "
        "$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($certPath); "
        "$installed = @(Get-ChildItem Cert:\\LocalMachine\\Root | "
        "Where-Object { $_.Thumbprint -eq $cert.Thumbprint }).Count; "
        "if ($installed -gt 0) { Write-Output 'yes' } else { Write-Output 'no' }"
    )
    result = _run_powershell(script)
    return result.returncode == 0 and result.stdout.strip().lower() == "yes"


def _get_firewall_rule_count() -> int:
    script = (
        "$count = @(Get-NetFirewallRule -DisplayName 'PreventVisit Browser * Block 80-443' "
        "-ErrorAction SilentlyContinue).Count; "
        "Write-Output $count"
    )
    result = _run_powershell(script)
    if result.returncode != 0:
        return 0
    try:
        return int(result.stdout.strip() or "0")
    except ValueError:
        return 0


def _run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["powershell", "-NoProfile", "-Command", script],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
    )


if __name__ == "__main__":
    main()
