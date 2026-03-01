"""SSDP/UPnP discovery for Arcus hubs."""

import socket
import re

SSDP_ADDR = "239.255.255.250"
SSDP_PORT = 1900

MSEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    f"HOST: {SSDP_ADDR}:{SSDP_PORT}\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 3\r\n"
    "ST: ssdp:all\r\n"
    "\r\n"
)


def discover(timeout: float = 5.0) -> list[dict]:
    """Send an SSDP M-SEARCH and return a list of parsed responses.

    Each response is a dict with the IP and all headers (lowercased keys).
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.settimeout(timeout)

    sock.sendto(MSEARCH.encode(), (SSDP_ADDR, SSDP_PORT))

    responses = []
    while True:
        try:
            data, (ip, _port) = sock.recvfrom(4096)
            headers = _parse_response(data.decode(errors="replace"))
            headers["_ip"] = ip
            responses.append(headers)
        except socket.timeout:
            break

    sock.close()
    return responses


def _parse_response(raw: str) -> dict:
    """Parse SSDP response headers into a dict with lowercased keys."""
    headers = {}
    for line in raw.splitlines()[1:]:  # skip status line
        if ":" in line:
            key, _, value = line.partition(":")
            headers[key.strip().lower()] = value.strip()
    return headers
