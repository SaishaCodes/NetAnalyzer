from netsentinel.analyzer import analyze_packets
from netsentinel.parser import Packet


def packet(port: int) -> Packet:
    return Packet("12:00:00", "192.0.2.10", 50000, "198.51.100.5",
                  port, "TCP", "sample")


def test_detects_many_destination_ports():
    report = analyze_packets(
        [packet(port) for port in range(20, 25)],
        port_scan_threshold=5,
    )
    assert report["total_packets"] == 5
    assert report["alerts"][0]["rule"] == "possible_port_scan"


def test_no_alert_below_threshold():
    report = analyze_packets([packet(443)], port_scan_threshold=12)
    assert report["alerts"] == []
