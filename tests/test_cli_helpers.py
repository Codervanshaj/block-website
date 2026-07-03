from prevent_visit.cli import _describe_guard_state, _matches_listener_address, _parse_netstat_listener


def test_parse_netstat_listener_extracts_listener_pid() -> None:
    parsed = _parse_netstat_listener("  TCP    127.0.0.1:8877         0.0.0.0:0              LISTENING       31172")
    assert parsed == ("127.0.0.1:8877", 31172)


def test_matches_listener_address_accepts_loopback_and_wildcard() -> None:
    assert _matches_listener_address("127.0.0.1:8877", "127.0.0.1", 8877) is True
    assert _matches_listener_address("0.0.0.0:8877", "127.0.0.1", 8877) is True
    assert _matches_listener_address("127.0.0.1:443", "127.0.0.1", 8877) is False


def test_describe_guard_state_surfaces_duplicate_listeners() -> None:
    label = _describe_guard_state(0, [24232, 31172])
    assert label.startswith("DUPLICATE LISTENERS")
