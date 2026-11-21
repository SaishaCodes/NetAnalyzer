from netsentinel.parser import parse_line, parse_lines


def test_parse_tcp_line():
    packet = parse_line(
        "12:00:00.123 IP 10.0.0.1.51514 > 10.0.0.2.443: Flags [S], seq 1"
    )
    assert packet is not None
    assert packet.source_ip == "10.0.0.1"
    assert packet.source_port == 51514
    assert packet.destination_ip == "10.0.0.2"
    assert packet.destination_port == 443
    assert packet.protocol == "TCP"


def test_rejects_unrecognized_line():
    assert parse_line("not a packet line") is None


def test_parse_lines_tracks_rejected():
    packets, rejected = parse_lines(["12:00:00 IP 1.1.1.1.10 > 2.2.2.2.20: UDP, length 4", "bad"])
    assert len(packets) == 1
    assert rejected == ["bad"]
