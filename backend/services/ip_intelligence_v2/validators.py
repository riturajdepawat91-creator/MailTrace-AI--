import ipaddress


DOCUMENTATION_NETWORKS = (
    ipaddress.ip_network("192.0.2.0/24"),
    ipaddress.ip_network("198.51.100.0/24"),
    ipaddress.ip_network("203.0.113.0/24"),
    ipaddress.ip_network("2001:db8::/32"),
)


def validate_ip(value: str):
    value = (value or "").strip()

    if not value:
        return None, "IP address is empty."

    try:
        return ipaddress.ip_address(value), None
    except ValueError:
        return None, "Invalid IP address."


def is_documentation_ip(address) -> bool:
    return any(
        address in network
        for network in DOCUMENTATION_NETWORKS
    )


def classify_address(address) -> dict:
    return {
        "version": address.version,
        "is_private": address.is_private,
        "is_loopback": address.is_loopback,
        "is_reserved": address.is_reserved,
        "is_documentation": is_documentation_ip(address),
    }
