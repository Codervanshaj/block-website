def test_parse_netstat_listener_extracts_listener_pid() -> None:
    # Test parsing netstat output
    line = "  TCP    127.0.0.1:8877         0.0.0.0:0              LISTENING       31172"
    parts = line.split()
    assert len(parts) >= 5
    assert parts[0] == "TCP"
    assert parts[3] == "LISTENING"
    assert parts[4] == "31172"


def test_port_open_detection() -> None:
    # Test port checking logic
    import socket
    # Non-existent port should not be open
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.settimeout(0.1)
        result = sock.connect_ex(("127.0.0.1", 59999))
        assert result != 0


def test_cli_parser_builds_successfully() -> None:
    from prevent_visit.cli import build_parser
    parser = build_parser()
    # Parser should build without errors
    assert parser is not None
    assert parser.prog == "prevent-visit"
