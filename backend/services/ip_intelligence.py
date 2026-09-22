import ipaddress
import socket
import urllib.request
import json


# ==========================================
# IP GEOLOCATION API
# ==========================================

def get_ip_geolocation(ip: str):

    url = f"https://ipapi.co/{ip}/json/"

    try:

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "MailTrace-AI/1.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        if data.get("error"):

            return {
                "success": False,
                "error": data.get(
                    "reason",
                    "IP intelligence lookup failed."
                )
            }

        return {
            "success": True,

            "country": data.get("country_name"),
            "country_code": data.get("country"),
            "region": data.get("region"),
            "city": data.get("city"),
            "postal": data.get("postal"),

            "latitude": data.get("latitude"),
            "longitude": data.get("longitude"),

            "timezone": data.get("timezone"),

            "asn": data.get("asn"),

            "organization": data.get("org"),

            "continent": data.get("continent_code")
        }

    except Exception as error:

        return {
            "success": False,
            "error": str(error)
        }


# ==========================================
# REAL-TIME PROXY / HOSTING INTELLIGENCE
# ==========================================

def get_network_intelligence(ip: str):

    url = (
        f"http://ip-api.com/json/{ip}"
        "?fields=status,message,proxy,hosting"
    )

    try:

        request = urllib.request.Request(
            url,
            headers={
                "User-Agent": "MailTrace-AI/1.0"
            }
        )

        with urllib.request.urlopen(
            request,
            timeout=8
        ) as response:

            data = json.loads(
                response.read().decode("utf-8")
            )

        if data.get("status") != "success":

            return {
                "success": False,
                "is_proxy": None,
                "is_hosting": None,
                "error": data.get(
                    "message",
                    "Network intelligence lookup failed."
                )
            }

        return {
            "success": True,

            "is_proxy": data.get(
                "proxy",
                False
            ),

            "is_hosting": data.get(
                "hosting",
                False
            )
        }

    except Exception as error:

        return {
            "success": False,
            "is_proxy": None,
            "is_hosting": None,
            "error": str(error)
        }


# ==========================================
# DOCUMENTATION / TEST IP DETECTION
# ==========================================

def is_documentation_ip(address):

    documentation_networks = [

        ipaddress.ip_network(
            "192.0.2.0/24"
        ),

        ipaddress.ip_network(
            "198.51.100.0/24"
        ),

        ipaddress.ip_network(
            "203.0.113.0/24"
        ),

        ipaddress.ip_network(
            "2001:db8::/32"
        )

    ]

    return any(
        address in network
        for network in documentation_networks
    )


# ==========================================
# SINGLE IP ANALYSIS
# ==========================================

def analyze_ip(ip: str):

    ip = ip.strip()

    result = {

        "ip": ip,

        "valid": False,

        "type": "unknown",

        "hostname": None,

        "country": None,

        "country_code": None,

        "region": None,

        "city": None,

        "postal": None,

        "latitude": None,

        "longitude": None,

        "timezone": None,

        "continent": None,

        "asn": None,

        "isp": None,

        "organization": None,

        "is_private": False,

        "is_loopback": False,

        "is_reserved": False,

        "is_documentation": False,

        "is_proxy": None,

        "is_hosting": None,

        "risk": "UNKNOWN",

        "risk_score": 0,

        "notes": []

    }


    # ======================================
    # VALIDATE IP
    # ======================================

    try:

        address = ipaddress.ip_address(ip)

        result["valid"] = True

    except ValueError:

        result["notes"].append(
            "Invalid IP address."
        )

        return result


    # ======================================
    # IP VERSION
    # ======================================

    if address.version == 4:

        result["type"] = "IPv4"

    else:

        result["type"] = "IPv6"


    # ======================================
    # ADDRESS FLAGS
    # ======================================

    result["is_private"] = address.is_private

    result["is_loopback"] = address.is_loopback

    result["is_reserved"] = address.is_reserved

    result["is_documentation"] = (
        is_documentation_ip(address)
    )


    # ======================================
    # DOCUMENTATION / TEST ADDRESS
    # ======================================

    if result["is_documentation"]:

        result["type"] = "DOCUMENTATION"

        result["risk"] = "LOW"

        result["risk_score"] = 0

        result["notes"].append(
            "Documentation/test IP address."
        )

        result["notes"].append(
            "This address is not attributable "
            "to a real Internet host."
        )

        return result


    # ======================================
    # LOOPBACK
    # ======================================

    if address.is_loopback:

        result["type"] = "LOOPBACK"

        result["risk"] = "LOW"

        result["risk_score"] = 0

        result["notes"].append(
            "Loopback IP address."
        )

        return result


    # ======================================
    # PRIVATE ADDRESS
    # ======================================

    if address.is_private:

        result["type"] = "PRIVATE"

        result["risk"] = "INTERNAL"

        result["risk_score"] = 0

        result["notes"].append(
            "Private/internal IP address."
        )

        result["notes"].append(
            "This address is not publicly routable."
        )

        return result


    # ======================================
    # RESERVED ADDRESS
    # ======================================

    if address.is_reserved:

        result["type"] = "RESERVED"

        result["risk"] = "UNKNOWN"

        result["risk_score"] = 0

        result["notes"].append(
            "Reserved IP address."
        )

        result["notes"].append(
            "The address should not be treated "
            "as a normal public endpoint."
        )

        return result


    # ======================================
    # REVERSE DNS
    # ======================================

    try:

        hostname = socket.gethostbyaddr(
            ip
        )[0]

        result["hostname"] = hostname

    except (
        socket.herror,
        socket.gaierror,
        OSError
    ):

        result["notes"].append(
            "No reverse DNS hostname found."
        )


    # ======================================
    # GEOLOCATION
    # ======================================

    geo = get_ip_geolocation(ip)


    if geo.get("success"):

        result["country"] = geo.get(
            "country"
        )

        result["country_code"] = geo.get(
            "country_code"
        )

        result["region"] = geo.get(
            "region"
        )

        result["city"] = geo.get(
            "city"
        )

        result["postal"] = geo.get(
            "postal"
        )

        result["latitude"] = geo.get(
            "latitude"
        )

        result["longitude"] = geo.get(
            "longitude"
        )

        result["timezone"] = geo.get(
            "timezone"
        )

        result["continent"] = geo.get(
            "continent"
        )

        result["asn"] = geo.get(
            "asn"
        )

        result["organization"] = geo.get(
            "organization"
        )

        result["isp"] = geo.get(
            "organization"
        )

    else:

        result["notes"].append(
            "Geolocation lookup failed: "
            + str(
                geo.get(
                    "error",
                    "Unknown error"
                )
            )
        )


    # ======================================
    # REAL-TIME NETWORK INTELLIGENCE
    # ======================================

    network = get_network_intelligence(ip)


    if network.get("success"):

        result["is_proxy"] = (
            network.get("is_proxy")
        )

        result["is_hosting"] = (
            network.get("is_hosting")
        )

    else:

        result["notes"].append(
            "Real-time network intelligence "
            "lookup failed: "
            + str(
                network.get(
                    "error",
                    "Unknown error"
                )
            )
        )


    # ======================================
    # PUBLIC IP
    # ======================================

    result["type"] = (
        "PUBLIC IPv4"
        if address.version == 4
        else "PUBLIC IPv6"
    )

    result["risk"] = "PUBLIC"

    result["risk_score"] = 0

    result["notes"].append(
        "Publicly routable IP address."
    )


    # ======================================
    # NETWORK INTELLIGENCE NOTES
    # ======================================

    if result["is_proxy"] is True:

        result["notes"].append(
            "IP is associated with proxy, VPN, "
            "or Tor infrastructure."
        )


    if result["is_hosting"] is True:

        result["notes"].append(
            "IP is associated with hosting "
            "or data-center infrastructure."
        )


    return result


# ==========================================
# MULTIPLE IP ANALYSIS
# ==========================================

def analyze_ips(ip_addresses: list):

    results = []

    seen = set()

    for ip in ip_addresses:

        if not ip:
            continue

        ip = ip.strip()

        if not ip:
            continue

        if ip in seen:
            continue

        seen.add(ip)

        results.append(
            analyze_ip(ip)
        )

    return results


# ==========================================
# EXTRACT IPS FROM RELAY CHAIN
# ==========================================

def extract_ips_from_chain(
    received_chain: list
):

    ips = []

    for hop in received_chain:

        hop_ips = hop.get(
            "ip_addresses",
            []
        )

        for ip in hop_ips:

            if ip not in ips:

                ips.append(ip)

    return ips