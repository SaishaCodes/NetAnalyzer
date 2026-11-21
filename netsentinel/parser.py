"""Parse common tcpdump-style text lines into normalized packet records."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Iterable

LINE_RE = re.compile(
    r"^(?P<timestamp>\d{2}:\d{2}:\d{2}(?:\.\d+)?)\s+IP\s+"
    r"(?P<src>[^\s>]+)\s+>\s+(?P<dst>[^:]+):\s*(?P<details>.*)$"
)
ENDPOINT_RE = re.compile(r"^(?P<host>.+)\.(?P<port>\d+)$")


@dataclass(frozen=True)
class Packet:
    timestamp: str
    source_ip: str
    source_port: int | None
    destination_ip: str
    destination_port: int | None
    protocol: str
    raw: str


def _endpoint(value: str) -> tuple[str, int | None]:
    match = ENDPOINT_RE.match(value.strip())
    if not match:
        return value.strip(), None
    host = match.group("host").strip("[]")
    try:
        return host, int(match.group("port"))
    except ValueError:
        return host, None


def parse_line(line: str) -> Packet | None:
    """Return a Packet for supported tcpdump-style IPv4/IPv6 lines, else None."""
    match = LINE_RE.match(line.strip())
    if not match:
        return None

    src_ip, src_port = _endpoint(match.group("src"))
    dst_ip, dst_port = _endpoint(match.group("dst"))
    details = match.group("details").lower()

    protocol = "OTHER"
    if "flags [" in details or "seq " in details or "tcp" in details:
        protocol = "TCP"
    elif "udp" in details or "length " in details:
        protocol = "UDP"
    elif "icmp" in details:
        protocol = "ICMP"

    return Packet(
        timestamp=match.group("timestamp"),
        source_ip=src_ip,
        source_port=src_port,
        destination_ip=dst_ip,
        destination_port=dst_port,
        protocol=protocol,
        raw=line.rstrip("\n"),
    )


def parse_lines(lines: Iterable[str]) -> tuple[list[Packet], list[str]]:
    packets: list[Packet] = []
    rejected: list[str] = []
    for line in lines:
        if not line.strip():
            continue
        packet = parse_line(line)
        if packet is None:
            rejected.append(line.rstrip("\n"))
        else:
            packets.append(packet)
    return packets, rejected
