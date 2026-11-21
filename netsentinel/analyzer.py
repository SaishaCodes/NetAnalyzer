"""Aggregate packet features and flag explainable network patterns."""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import asdict, dataclass
from typing import Iterable

from .parser import Packet


@dataclass(frozen=True)
class Alert:
    severity: str
    rule: str
    source_ip: str
    message: str
    evidence: dict


def analyze_packets(
    packets: Iterable[Packet],
    *,
    port_scan_threshold: int = 12,
    connection_burst_threshold: int = 80,
) -> dict:
    packets = list(packets)
    by_source: dict[str, list[Packet]] = defaultdict(list)
    for packet in packets:
        by_source[packet.source_ip].append(packet)

    alerts: list[Alert] = []
    summaries = []

    for source_ip, source_packets in sorted(by_source.items()):
        destinations = {p.destination_ip for p in source_packets}
        destination_ports = {p.destination_port for p in source_packets if p.destination_port is not None}
        protocols = Counter(p.protocol for p in source_packets)

        summaries.append({
            "source_ip": source_ip,
            "packet_count": len(source_packets),
            "unique_destinations": len(destinations),
            "unique_destination_ports": len(destination_ports),
            "protocols": dict(protocols),
        })

        if len(destination_ports) >= port_scan_threshold:
            alerts.append(Alert(
                severity="HIGH",
                rule="possible_port_scan",
                source_ip=source_ip,
                message=f"{source_ip} contacted {len(destination_ports)} distinct destination ports",
                evidence={"unique_destination_ports": len(destination_ports),
                          "threshold": port_scan_threshold},
            ))

        if len(source_packets) >= connection_burst_threshold:
            alerts.append(Alert(
                severity="MEDIUM",
                rule="high_packet_volume",
                source_ip=source_ip,
                message=f"{source_ip} generated {len(source_packets)} packets in the input window",
                evidence={"packet_count": len(source_packets),
                          "threshold": connection_burst_threshold},
            ))

    return {
        "total_packets": len(packets),
        "unique_sources": len(by_source),
        "sources": summaries,
        "alerts": [asdict(alert) for alert in alerts],
    }
