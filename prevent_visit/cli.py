from __future__ import annotations

import argparse
import os
import subprocess
import sys
from pathlib import Path

from .config import AppConfig, DEFAULT_CONFIG_PATH
from .certs import CertificateManager
from .proxy import ProxyServer
from .rules import RuleSet
from .windows import (
    build_pac_payload,
    build_hosts_payload,
)


def _run_powershell(script: str) -> subprocess.CompletedProcess[str]:
    cmd = ["powershell", "-NoProfile", "-Command", script]
    return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace")


def _run_powershell_elevated(script: str) -> None:
    import ctypes
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", f"-NoProfile -ExecutionPolicy Bypass -Command {script}", None, 1)


def _is_port_open(host: str, port: int) -> bool:
    import socket
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(1.0)
            return sock.connect_ex((host, port)) == 0
    except OSError:
        return False


def _get_scheduled_task_state(task_name: str) -> str:
    script = f"Get-ScheduledTask -TaskName '{task_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty State"
    result = _run_powershell(script)
    if result.returncode != 0:
        return "MISSING"
    output = result.stdout.strip()
    if not output:
        return "MISSING"
    return output


def _is_root_cert_installed(cert_path: Path) -> bool:
    if not cert_path.exists():
        return False
    script = (
        f"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{cert_path}'); "
        "Get-ChildItem Cert:\\LocalMachine\\Root -ErrorAction SilentlyContinue | "
        "Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | Measure-Object | "
        "Select-Object -ExpandProperty Count"
    )
    result = _run_powershell(script)
    return result.returncode == 0 and result.stdout.strip() not in ("0", "")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="prevent-visit",
        description="Prevent Visit - Block explicit content across all browsers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    install_parser = subparsers.add_parser("install", help="Install Prevent Visit system-wide with auto-start")
    install_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    install_parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)

    uninstall_parser = subparsers.add_parser("uninstall", help="Uninstall Prevent Visit completely")
    uninstall_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)
    uninstall_parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parent.parent)

    start_parser = subparsers.add_parser("start", help="Start the Prevent Visit blocking service")
    start_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    stop_parser = subparsers.add_parser("stop", help="Stop the Prevent Visit blocking service")
    stop_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    status_parser = subparsers.add_parser("status", help="Check if Prevent Visit is installed and running")
    status_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    run_parser = subparsers.add_parser("run-service", help="Run the proxy service (internal)")
    run_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    init_parser = subparsers.add_parser("init-config", help="Create default config file")
    init_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    cert_parser = subparsers.add_parser("generate-ca", help="Generate root certificate")
    cert_parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG_PATH)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "install":
        do_install(args.config, args.repo_root)
        return

    if args.command == "uninstall":
        do_uninstall(args.config, args.repo_root)
        return

    if args.command == "start":
        do_start(args.config)
        return

    if args.command == "stop":
        do_stop(args.config)
        return

    if args.command == "status":
        do_status(args.config)
        return

    if args.command == "run-service":
        config = AppConfig.load(args.config)
        ProxyServer(config).run()
        return

    if args.command == "init-config":
        config = AppConfig.load(args.config)
        config.save(args.config)
        print(f"Config written to {args.config}")
        return

    if args.command == "generate-ca":
        config = AppConfig.load(args.config)
        manager = CertificateManager(config)
        manager.ensure_root_ca()
        print(f"Root certificate written to config/certs/")
        return

    parser.print_help()


def _is_admin() -> bool:
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def do_install(config_path: Path, repo_root: Path) -> None:
    print("=" * 50)
    print("  Prevent Visit - Installation")
    print("=" * 50)
    print()

    if not _is_admin():
        print("[!] Administrator privileges required.")
        print("[*] Re-running with elevation...")
        _run_powershell_elevated(f"Set-Location '{repo_root}'; python run_guard.py install")
        return

    print("[*] Generating configuration...")
    config = AppConfig.load(config_path)
    config.save(config_path)

    print("[*] Generating root certificate...")
    manager = CertificateManager(config)
    manager.ensure_root_ca()
    root_cert = Path(config.certs_dir) / "root_ca_cert.cer"

    print("[*] Installing root certificate...")
    _install_cert(root_cert)

    print("[*] Setting up auto-start scheduled task...")
    _setup_scheduled_task(repo_root)

    print("[*] Configuring browser proxy settings...")
    _configure_browser_proxy(config, repo_root)

    print("[*] Starting blocking service...")
    do_start(config_path)

    print()
    print("=" * 50)
    print("  Installation Complete!")
    print("=" * 50)
    print()
    print("[*] Prevent Visit is now installed and running.")
    print("[*] It will automatically start when you log in.")
    print("[*] Commands:")
    print("       prevent-visit status    - Check status")
    print("       prevent-visit stop      - Stop protection")
    print("       prevent-visit start    - Start protection")
    print("       prevent-visit uninstall - Remove completely")
    print()


def do_uninstall(config_path: Path, repo_root: Path) -> None:
    print("=" * 50)
    print("  Prevent Visit - Uninstalling")
    print("=" * 50)
    print()

    if not _is_admin():
        print("[!] Administrator privileges required.")
        print("[*] Re-running with elevation...")
        _run_powershell_elevated(f"Set-Location '{repo_root}'; python run_guard.py uninstall")
        return

    print("[*] Stopping blocking service...")
    do_stop(config_path)

    print("[*] Removing scheduled task...")
    _remove_scheduled_task()

    print("[*] Removing browser proxy settings...")
    _remove_browser_proxy()

    print("[*] Removing root certificate...")
    _remove_cert(Path(config.certs_dir) / "root_ca_cert.cer")

    print()
    print("=" * 50)
    print("  Uninstall Complete!")
    print("=" * 50)
    print()
    print("[*] Prevent Visit has been completely removed.")
    print()


def do_start(config_path: Path) -> None:
    config = AppConfig.load(config_path)
    proxy_host = config.proxy_host
    proxy_port = config.proxy_port

    if _is_port_open(proxy_host, proxy_port):
        print(f"[+] Prevent Visit is already running on {proxy_host}:{proxy_port}")
        return

    print("[*] Starting Prevent Visit blocking service...")
    repo_root = config_path.resolve().parent.parent
    runner_script = repo_root / "run_guard.py"

    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = subprocess.SW_HIDE

    subprocess.Popen(
        [sys.executable, str(runner_script), "run-service", "--config", str(config_path)],
        startupinfo=startupinfo,
        cwd=str(repo_root),
    )

    import time
    for _ in range(10):
        time.sleep(0.5)
        if _is_port_open(proxy_host, proxy_port):
            print(f"[+] Prevent Visit started on {proxy_host}:{proxy_port}")
            return

    print("[!] Failed to start Prevent Visit.")


def do_stop(config_path: Path) -> None:
    config = AppConfig.load(config_path)
    proxy_host = config.proxy_host
    proxy_port = config.proxy_port

    if not _is_port_open(proxy_host, proxy_port):
        print("[*] Prevent Visit is not running.")
        return

    print("[*] Stopping Prevent Visit blocking service...")

    script = (
        f"netstat -ano -p TCP | Where-Object {{ $_ -match 'LISTENING' -and $_ -match ':{proxy_port}' }} | "
        f"ForEach-Object {{ ($_ -split '\\s+')[-1] }} | "
        f"ForEach-Object {{ Stop-Process -Id $_ -Force -ErrorAction SilentlyContinue }}"
    )
    _run_powershell(script)

    if not _is_port_open(proxy_host, proxy_port):
        print("[+] Prevent Visit stopped.")
    else:
        print("[!] Failed to stop Prevent Visit.")


def do_status(config_path: Path) -> None:
    config = AppConfig.load(config_path)
    proxy_host = config.proxy_host
    proxy_port = config.proxy_port

    print("=" * 50)
    print("  Prevent Visit - Status")
    print("=" * 50)
    print()

    running = _is_port_open(proxy_host, proxy_port)
    print(f"  Service:        {'[RUNNING]' if running else '[STOPPED]'}")
    print(f"  Proxy:          {proxy_host}:{proxy_port}")

    task_state = _get_scheduled_task_state("PreventVisitGuard")
    auto_start = task_state not in ("", "MISSING", None)
    print(f"  Auto-start:     {'[ENABLED]' if auto_start else '[DISABLED]'}")
    if auto_start:
        print(f"  Task state:     {task_state}")

    cert_path = Path(config.certs_dir) / "root_ca_cert.cer"
    cert_installed = _is_root_cert_installed(cert_path)
    print(f"  Certificate:    {'[INSTALLED]' if cert_installed else '[NOT INSTALLED]'}")

    print()
    if running and auto_start and cert_installed:
        print("  Status: [HEALTHY] - Fully installed and running")
    elif running:
        print("  Status: [PARTIAL] - Service running but not fully installed")
    else:
        print("  Status: [STOPPED] - Install to enable protection")


def _install_cert(cert_path: Path) -> None:
    if not cert_path.exists():
        print(f"[!] Certificate not found: {cert_path}")
        return
    script = f"Import-Certificate -FilePath '{cert_path}' -CertStoreLocation Cert:\\LocalMachine\\Root -ErrorAction Stop"
    result = _run_powershell(script)
    if result.returncode == 0:
        print("[+] Root certificate installed to Trusted Root store")
    else:
        print(f"[!] Certificate install: {result.stderr.strip()}")


def _remove_cert(cert_path: Path) -> None:
    if not cert_path.exists():
        return
    script = (
        f"$cert = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2('{cert_path}'); "
        "Get-ChildItem Cert:\\LocalMachine\\Root | Where-Object { $_.Thumbprint -eq $cert.Thumbprint } | "
        "Remove-Item -Force -ErrorAction SilentlyContinue"
    )
    _run_powershell(script)
    print("[+] Root certificate removed")


def _setup_scheduled_task(repo_root: Path) -> None:
    _remove_scheduled_task()

    start_script = repo_root / "run_guard.py"
    task_xml = f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>Prevent Visit Content Blocker</Description>
  </RegistrationInfo>
  <Triggers>
    <LogonTrigger />
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>false</RunOnlyIfNetworkAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <RunOnlyIfIdle>false</RunOnlyIfIdle>
    <WakeToRun>false</WakeToRun>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>python</Command>
      <Arguments>"{start_script}" run-service</Arguments>
      <WorkingDirectory>{repo_root}</WorkingDirectory>
    </Exec>
  </Actions>
</Task>"""

    temp_file = Path(os.environ.get("TEMP", "/tmp")) / "prevent_visit_task.xml"
    temp_file.write_text(task_xml, encoding="utf-16")
    script = f"Register-ScheduledTask -TaskName 'PreventVisitGuard' -Xml (Get-Content '{temp_file}' -Raw) -Force"
    result = _run_powershell(script)
    if result.returncode == 0:
        print("[+] Auto-start scheduled task created")
    else:
        print(f"[!] Task creation: {result.stderr.strip()}")


def _remove_scheduled_task() -> None:
    script = "Unregister-ScheduledTask -TaskName 'PreventVisitGuard' -Confirm:$false -ErrorAction SilentlyContinue"
    _run_powershell(script)


def _configure_browser_proxy(config: AppConfig, repo_root: Path) -> None:
    pac_path = repo_root / "build" / "prevent-visit.pac"
    pac_path.parent.mkdir(parents=True, exist_ok=True)
    pac_path.write_text(build_pac_payload(config), encoding="utf-8")

    # Convert to proper file:// URL for Windows
    pac_path_str = str(pac_path.resolve())
    if pac_path_str.startswith("/"):
        # Unix-style path
        pac_url = f"file://{pac_path_str}"
    else:
        # Windows-style path - convert backslashes and add file://
        pac_url = f"file:///{pac_path_str.replace(chr(92), '/')}"

    chrome_policy = r"HKLM:\SOFTWARE\Policies\Google\Chrome"
    edge_policy = r"HKLM:\SOFTWARE\Policies\Microsoft\Edge"

    scripts = [
        f"New-Item -Path '{chrome_policy}' -Force | Out-Null; "
        f"Set-ItemProperty -Path '{chrome_policy}' -Name 'ProxyMode' -Value 'pac_script' -Force; "
        f"Set-ItemProperty -Path '{chrome_policy}' -Name 'ProxyPacUrl' -Value '{pac_url}' -Force; "
        f"Set-ItemProperty -Path '{chrome_policy}' -Name 'DnsOverHttpsMode' -Value 'off' -Force; "
        f"Set-ItemProperty -Path '{chrome_policy}' -Name 'IncognitoModeAvailability' -Value 1 -Force",

        f"New-Item -Path '{edge_policy}' -Force | Out-Null; "
        f"Set-ItemProperty -Path '{edge_policy}' -Name 'ProxyMode' -Value 'pac_script' -Force; "
        f"Set-ItemProperty -Path '{edge_policy}' -Name 'ProxyPacUrl' -Value '{pac_url}' -Force; "
        f"Set-ItemProperty -Path '{edge_policy}' -Name 'DnsOverHttpsMode' -Value 'off' -Force; "
        f"Set-ItemProperty -Path '{edge_policy}' -Name 'InPrivateModeAvailability' -Value 1 -Force",

        f"New-Item -Path 'HKLM:\\SOFTWARE\\Policies\\BraveSoftware\\Brave' -Force | Out-Null; "
        f"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\BraveSoftware\\Brave' -Name 'ProxyMode' -Value 'pac_script' -Force; "
        f"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\BraveSoftware\\Brave' -Name 'ProxyPacUrl' -Value '{pac_url}' -Force; "
        f"Set-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\BraveSoftware\\Brave' -Name 'IncognitoModeAvailability' -Value 1 -Force",
    ]

    for script in scripts:
        _run_powershell(script)

    print("[+] Browser proxy settings configured")


def _remove_browser_proxy() -> None:
    policies = [
        r"HKLM:\SOFTWARE\Policies\Google\Chrome",
        r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
        r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
    ]

    for policy in policies:
        props = ["ProxyMode", "ProxyPacUrl", "ProxyServer", "DnsOverHttpsMode", "IncognitoModeAvailability", "InPrivateModeAvailability"]
        for prop in props:
            script = f"Remove-ItemProperty -Path '{policy}' -Name '{prop}' -ErrorAction SilentlyContinue"
            _run_powershell(script)

    print("[+] Browser proxy settings removed")


if __name__ == "__main__":
    main()
