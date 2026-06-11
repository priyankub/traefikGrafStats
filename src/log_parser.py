"""Parses Traefik access.log records formatted as JSON.

Traefik standard JSON structure mappings:
  - Outside client IP: 'ClientHost' (or falls back to parsing 'ClientAddr')
  - Domain / Request Host: 'RequestHost'
  - Status Code: 'DownstreamStatus'
  - Content Size (bytes): 'DownstreamContentSize'
  - Internal backend target: 'ServiceAddr'
  - Timestamp: 'StartUTC' (or 'time' / 'StartLocal' in standard ISO 8601)
  - User-Agent: 'request_User-Agent' (or other matching UA fields)
"""

import json
import logging

logger = logging.getLogger(__name__)


class TraefikLogEntry:
    __slots__ = ('timestamp', 'status_code', 'outside_ip', 'domain', 'length', 'target_ip', 'user_agent')

    def __init__(self, timestamp: str, status_code: int, outside_ip: str, domain: str, length: int, target_ip: str, user_agent: str):
        self.timestamp = timestamp
        self.status_code = status_code
        self.outside_ip = outside_ip
        self.domain = domain
        self.length = length
        self.target_ip = target_ip
        self.user_agent = user_agent


def parse_traefik_json_line(line: str) -> TraefikLogEntry | None:
    """Parses a Traefik JSON access log record, returning a TraefikLogEntry object."""
    try:
        data = json.loads(line)
    except Exception:
        # Ignore non-JSON lines or malformed strings gracefully
        return None

    # 1. Extract Client IP
    # 'ClientHost' contains only the client IP, whereas 'ClientAddr' has IP:Port.
    outside_ip = data.get("ClientHost")
    if not outside_ip:
        client_addr = data.get("ClientAddr", "")
        if client_addr:
            outside_ip = client_addr.rsplit(":", 1)[0].replace("[", "").replace("]", "")
        else:
            outside_ip = "0.0.0.0"

    # 2. Extract Targeted Host/Domain
    domain = data.get("RequestHost", "unknown")

    # 3. Extract Downstream HTTP Status Code
    status_code = data.get("DownstreamStatus", 0)
    try:
        status_code = int(status_code)
    except (ValueError, TypeError):
        status_code = 0

    # 4. Extract Transferred Content Size (Length)
    length = data.get("DownstreamContentSize", 0)
    try:
        length = int(length)
    except (ValueError, TypeError):
        length = 0

    # 5. Extract Backend/Target IP
    # 'ServiceAddr' represents backend server endpoint (e.g., "10.0.1.12:80").
    target_ip_raw = data.get("ServiceAddr")
    if target_ip_raw:
        if ":" in target_ip_raw:
            target_ip = target_ip_raw.rsplit(":", 1)[0].replace("[", "").replace("]", "")
        else:
            target_ip = target_ip_raw
    else:
        target_ip = "unknown"

    # 6. Extract RFC3339 Timestamp (e.g., "2026-03-08T15:10:15Z")
    timestamp = data.get("StartUTC") or data.get("time") or data.get("StartLocal", "")

    # 7. Extract User-Agent Header
    # Traefik configuration can place this in request_User-Agent or request_Headers_User-Agent.
    user_agent = data.get("request_User-Agent")
    if not user_agent:
        # Fallback to search through keys for any variation of User-Agent
        for key, value in data.items():
            if "User-Agent" in key or "user-agent" in key:
                user_agent = value
                break
    user_agent = user_agent or ""

    return TraefikLogEntry(
        timestamp=timestamp,
        status_code=status_code,
        outside_ip=outside_ip,
        domain=domain,
        length=length,
        target_ip=target_ip,
        user_agent=user_agent,
    )
