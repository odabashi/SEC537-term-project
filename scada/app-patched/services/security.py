import ipaddress
import re


PATH_TRAVERSAL_PATTERNS = [
    "../",
    "..\\",
    ".bash",
    "passwd",
    ".env",
    "%2e%2e"
]


def detect_path_traversal(file_name):
    for pattern in PATH_TRAVERSAL_PATTERNS:
        if pattern in file_name:
            return True
    return False


COMMAND_INJECTION_PATTERNS = [
    r";",
    r"&&",
    r"\|\|",
    r"\|",
    r"\$\(",
    r"`",
]


def detect_command_injection(command):
    for pattern in COMMAND_INJECTION_PATTERNS:
        if re.search(pattern, command):
            return True
    return False


INTERNAL_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
]

INTERNAL_HOSTNAMES = [
    "localhost",
    "localhost.localdomain"
]


def detect_internal_target(target):
    """
    Detects SSRF attempts targeting internal networks or sensitive hostnames.
    """
    # Hostname-based detection
    if target.lower() in INTERNAL_HOSTNAMES:
        return True
    # IP-based detection
    try:
        ip = ipaddress.ip_address(target)
        return any(ip in net for net in INTERNAL_NETWORKS)
    except ValueError:
        # Non-IP hostname: not detected (DNS-based SSRF still possible)
        return False


# Allowed SCADA device networks (My Machine IP is 164.92.225.125)
ALLOWED_SCADA_NETWORKS = [
    ipaddress.ip_network("164.92.225.125/32"),   # Simplest & safest (single IP only since we have 1 device only)
    # ipaddress.ip_network("164.92.225.0/24"),   # PLC subnet (if we want a range)
]


def is_allowed_scada_target(target: str):
    try:
        ip = ipaddress.ip_address(target)
        return any(ip in net for net in ALLOWED_SCADA_NETWORKS)
    except ValueError:
        return False


def validate_target_ip(value: str):
    ip = ipaddress.ip_address(value)    # It may raise ValueError exception if value is not IP Address (e.g. hostname)
    return str(ip)
