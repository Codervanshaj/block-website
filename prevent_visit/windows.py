from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from textwrap import dedent

from .config import AppConfig
from .rules import RuleSet


HOSTS_MARKER_START = "# >>> prevent-visit managed block start >>>"
HOSTS_MARKER_END = "# <<< prevent-visit managed block end <<<"


@dataclass(slots=True)
class RegistryValue:
    hive_path: str
    name: str
    value_type: str
    value: str | int


def build_hosts_payload(config: AppConfig, rules: RuleSet) -> str:
    lines = [HOSTS_MARKER_START]
    if config.search_only_mode:
        lines.append("# Search-only mode: no direct website blocks are installed here.")
    else:
        lines.append("# Adult-domain null routing")
        for domain in sorted(rules.blocked_domains):
            lines.append(f"0.0.0.0 {domain}")
            lines.append(f"0.0.0.0 www.{domain}")
    lines.append(HOSTS_MARKER_END)
    return "\n".join(lines) + "\n"


def build_pac_payload(config: AppConfig) -> str:
    proxy = f"PROXY {config.proxy_host}:{config.proxy_port}"
    search_hosts = sorted({host.lower() for host in config.intercept_search_hosts})
    lines = [
        "function FindProxyForURL(url, host) {",
        "  host = host.toLowerCase();",
    ]
    if search_hosts:
        lines.append("  if (")
        host_checks = []
        for host in search_hosts:
            host_checks.append(f'    dnsDomainIs(host, "{host}")')
        lines.append(" ||\n".join(host_checks))
        lines.append("  ) {")
        lines.append(f'    return "{proxy}";')
        lines.append("  }")
    lines.append('  return "DIRECT";')
    lines.append("}")
    return "\n".join(lines) + "\n"


def default_registry_values(config: AppConfig) -> list[RegistryValue]:
    proxy_server = f"{config.proxy_host}:{config.proxy_port}"
    pac_url = Path(config.pac_output_path).resolve().as_uri()
    if config.search_only_mode:
        return [
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Google\Chrome",
                name="IncognitoModeAvailability",
                value_type="DWord",
                value=1,
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Google\Chrome",
                name="ProxyMode",
                value_type="String",
                value="pac_script",
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Google\Chrome",
                name="ProxyPacUrl",
                value_type="String",
                value=pac_url,
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Google\Chrome",
                name="DnsOverHttpsMode",
                value_type="String",
                value="off",
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                name="InPrivateModeAvailability",
                value_type="DWord",
                value=1,
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                name="ProxyMode",
                value_type="String",
                value="pac_script",
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                name="ProxyPacUrl",
                value_type="String",
                value=pac_url,
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
                name="DnsOverHttpsMode",
                value_type="String",
                value="off",
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
                name="IncognitoModeAvailability",
                value_type="DWord",
                value=1,
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
                name="ProxyMode",
                value_type="String",
                value="pac_script",
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
                name="ProxyPacUrl",
                value_type="String",
                value=pac_url,
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
                name="DnsOverHttpsMode",
                value_type="String",
                value="off",
            ),
            RegistryValue(
                hive_path=r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox",
                name="DisablePrivateBrowsing",
                value_type="DWord",
                value=1,
            ),
        ]

    return [
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Google\Chrome",
            name="IncognitoModeAvailability",
            value_type="DWord",
            value=1,
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Google\Chrome",
            name="ProxyMode",
            value_type="String",
            value="fixed_servers",
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Google\Chrome",
            name="ProxyServer",
            value_type="String",
            value=proxy_server,
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Google\Chrome",
            name="DnsOverHttpsMode",
            value_type="String",
            value="off",
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
            name="InPrivateModeAvailability",
            value_type="DWord",
            value=1,
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
            name="ProxyMode",
            value_type="String",
            value="fixed_servers",
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
            name="ProxyServer",
            value_type="String",
            value=proxy_server,
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Microsoft\Edge",
            name="DnsOverHttpsMode",
            value_type="String",
            value="off",
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
            name="IncognitoModeAvailability",
            value_type="DWord",
            value=1,
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
            name="ProxyMode",
            value_type="String",
            value="fixed_servers",
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
            name="ProxyServer",
            value_type="String",
            value=proxy_server,
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave",
            name="DnsOverHttpsMode",
            value_type="String",
            value="off",
        ),
        RegistryValue(
            hive_path=r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox",
            name="DisablePrivateBrowsing",
            value_type="DWord",
            value=1,
        ),
        RegistryValue(
            hive_path=r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            name="ProxyEnable",
            value_type="DWord",
            value=1,
        ),
        RegistryValue(
            hive_path=r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings",
            name="ProxyServer",
            value_type="String",
            value=proxy_server,
        ),
    ]


def render_registry_script(config: AppConfig) -> str:
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "",
    ]
    if config.search_only_mode:
        cleanup_names = {
            r"HKLM:\SOFTWARE\Policies\Google\Chrome": ["ProxyServer"],
            r"HKLM:\SOFTWARE\Policies\Microsoft\Edge": ["ProxyServer"],
            r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave": ["ProxyServer"],
            r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings": [
                "ProxyEnable",
                "ProxyServer",
                "AutoConfigURL",
            ],
        }
    else:
        cleanup_names = {
            r"HKLM:\SOFTWARE\Policies\Google\Chrome": ["ProxyPacUrl"],
            r"HKLM:\SOFTWARE\Policies\Microsoft\Edge": ["ProxyPacUrl"],
            r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave": ["ProxyPacUrl"],
        }

    for hive_path, names in cleanup_names.items():
        lines.append(f"New-Item -Path '{hive_path}' -Force | Out-Null")
        for name in names:
            lines.append(
                f"Remove-ItemProperty -Path '{hive_path}' -Name '{name}' "
                "-ErrorAction SilentlyContinue"
            )
        lines.append("")

    for item in default_registry_values(config):
        lines.append(f"New-Item -Path '{item.hive_path}' -Force | Out-Null")
        if item.value_type == "String":
            lines.append(
                f"New-ItemProperty -Path '{item.hive_path}' -Name '{item.name}' "
                f"-PropertyType String -Value '{item.value}' -Force | Out-Null"
            )
        else:
            lines.append(
                f"New-ItemProperty -Path '{item.hive_path}' -Name '{item.name}' "
                f"-PropertyType DWord -Value {item.value} -Force | Out-Null"
            )
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def render_uninstall_script(config: AppConfig) -> str:
    policy_names = {
        r"HKLM:\SOFTWARE\Policies\Google\Chrome": [
            "IncognitoModeAvailability",
            "ProxyMode",
            "ProxyServer",
            "ProxyPacUrl",
            "DnsOverHttpsMode",
        ],
        r"HKLM:\SOFTWARE\Policies\Microsoft\Edge": [
            "InPrivateModeAvailability",
            "ProxyMode",
            "ProxyServer",
            "ProxyPacUrl",
            "DnsOverHttpsMode",
        ],
        r"HKLM:\SOFTWARE\Policies\BraveSoftware\Brave": [
            "IncognitoModeAvailability",
            "ProxyMode",
            "ProxyServer",
            "ProxyPacUrl",
            "DnsOverHttpsMode",
        ],
        r"HKLM:\SOFTWARE\Policies\Mozilla\Firefox": ["DisablePrivateBrowsing"],
        r"HKCU:\Software\Microsoft\Windows\CurrentVersion\Internet Settings": [
            "ProxyEnable",
            "ProxyServer",
            "AutoConfigURL",
        ],
    }
    removals = []
    for hive_path, names in policy_names.items():
        for name in names:
            removals.append(
                f"Remove-ItemProperty -Path '{hive_path}' -Name '{name}' "
                "-ErrorAction SilentlyContinue"
            )
    return "\n".join(removals) + "\n"


def render_firewall_script(config: AppConfig) -> str:
    if config.search_only_mode:
        return "\n".join(
            [
                "$ErrorActionPreference = 'Stop'",
                "Get-NetFirewallRule -DisplayName 'PreventVisit Browser * Block 80-443' -ErrorAction SilentlyContinue | Remove-NetFirewallRule",
                "",
            ]
        )

    browser_paths = [
        r"C:\Program Files\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
        r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
        r"C:\Program Files\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files (x86)\BraveSoftware\Brave-Browser\Application\brave.exe",
        r"C:\Program Files\Mozilla Firefox\firefox.exe",
        r"C:\Program Files (x86)\Mozilla Firefox\firefox.exe",
        r"C:\Users\%USERNAME%\AppData\Local\Programs\Opera\opera.exe",
    ]
    lines = ["$ErrorActionPreference = 'Stop'", ""]
    for index, path in enumerate(browser_paths, start=1):
        lines.append(f"$browserPath{index} = [Environment]::ExpandEnvironmentVariables('{path}')")
        lines.append(f"if (Test-Path $browserPath{index}) {{")
        lines.append(
            f"  New-NetFirewallRule -DisplayName 'PreventVisit Browser {index} Block 80-443' "
            f"-Direction Outbound -Program $browserPath{index} -Action Block "
            f"-Protocol TCP -RemotePort 80,443 -Profile Any -ErrorAction SilentlyContinue | Out-Null"
        )
        lines.append("}")
        lines.append("")
    return "\n".join(lines).strip() + "\n"


def render_startup_task_script(repo_root: Path) -> str:
    start_script = repo_root / "scripts" / "start-guard.ps1"
    return dedent(
        f"""
        $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument '-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "{start_script}"'
        $trigger = New-ScheduledTaskTrigger -AtLogOn
        Register-ScheduledTask -TaskName "PreventVisitGuard" -Action $action -Trigger $trigger -Force | Out-Null
        """
    ).strip() + "\n"
