from prevent_visit.config import AppConfig
from prevent_visit.rules import RuleSet
from prevent_visit.windows import (
    build_hosts_payload,
    build_pac_payload,
    render_firewall_script,
    render_registry_script,
    render_uninstall_script,
)


def test_search_only_mode_generates_no_direct_block_hosts() -> None:
    config = AppConfig()
    payload = build_hosts_payload(config, RuleSet(config))
    assert "Search-only mode" in payload
    assert "0.0.0.0 pornhub.com" not in payload


def test_non_search_only_mode_generates_direct_block_hosts() -> None:
    config = AppConfig(search_only_mode=False)
    payload = build_hosts_payload(config, RuleSet(config))
    assert "0.0.0.0 pornhub.com" in payload


def test_search_only_mode_removes_old_firewall_blocks() -> None:
    payload = render_firewall_script(AppConfig())
    assert "Remove-NetFirewallRule" in payload
    assert "New-NetFirewallRule" not in payload


def test_non_search_only_mode_can_generate_firewall_blocks() -> None:
    payload = render_firewall_script(AppConfig(search_only_mode=False))
    assert "New-NetFirewallRule" in payload


def test_search_only_pac_sends_only_search_hosts_to_proxy() -> None:
    payload = build_pac_payload(AppConfig())
    assert 'dnsDomainIs(host, "google.com")' in payload
    assert 'shExpMatch(host, "*.google.com")' not in payload
    assert 'return "PROXY 127.0.0.1:8877";' in payload
    assert 'return "DIRECT";' in payload


def test_search_only_registry_uses_pac_not_fixed_proxy() -> None:
    payload = render_registry_script(AppConfig())
    assert "ProxyPacUrl" in payload
    assert "pac_script" in payload
    assert "Remove-ItemProperty -Path 'HKLM:\\SOFTWARE\\Policies\\Google\\Chrome' -Name 'ProxyServer'" in payload
    assert "New-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' -Name 'ProxyEnable'" not in payload


def test_uninstall_removes_old_fixed_proxy_and_new_pac_policy() -> None:
    payload = render_uninstall_script(AppConfig())
    assert "ProxyServer" in payload
    assert "ProxyPacUrl" in payload
    assert "AutoConfigURL" in payload
