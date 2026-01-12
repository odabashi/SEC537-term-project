import ipaddress


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
