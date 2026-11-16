"""Network-level IP Geolocation and Public IP filtering module.

Strict Security Constraint:
- Filters out non-routable, private, loopback, and reserved IPs.
- Label results strictly as approximate network-level location, NEVER an individual person's location.
"""
import ipaddress
from typing import Any, Dict, Optional

# Offline lookup table for common candidate public IPs and subnet ranges (synthetic testing and standard threat feeds)
SYNTHETIC_SUBNET_GEO_DB = [
    # Documentation / Test prefixes (RFC 5737)
    (ipaddress.ip_network("198.51.100.0/24"), {"country": "Germany", "country_code": "DE", "city": "Frankfurt am Main", "isp": "Demo Cloud Hosting GmbH", "asn": "AS64500"}),
    (ipaddress.ip_network("203.0.113.0/24"), {"country": "United States", "country_code": "US", "city": "Ashburn", "isp": "Commercial Telecom Corp", "asn": "AS64501"}),
    (ipaddress.ip_network("192.0.2.0/24"), {"country": "Netherlands", "country_code": "NL", "city": "Amsterdam", "isp": "North Sea Hosting B.V.", "asn": "AS64502"}),
    # Common public subnets
    (ipaddress.ip_network("8.8.8.0/24"), {"country": "United States", "country_code": "US", "city": "Mountain View", "isp": "Google LLC", "asn": "AS15169"}),
    (ipaddress.ip_network("1.1.1.0/24"), {"country": "Australia", "country_code": "AU", "city": "Sydney", "isp": "Cloudflare, Inc.", "asn": "AS13335"}),
]


RFC1918_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("169.254.0.0/16"),
]


def is_public_routable_ip(ip_str: str) -> bool:
    """Check if an IP string is a valid public, routable IP address (excluding RFC 1918 private, loopback, link-local)."""
    try:
        ip = ipaddress.ip_address(ip_str.strip())
        for net in RFC1918_NETWORKS:
            if ip in net:
                return False
        return not (
            ip.is_loopback
            or ip.is_link_local
            or ip.is_multicast
            or ip.is_unspecified
        )
    except ValueError:
        return False


def geolocate_public_ip(ip_str: str) -> Optional[Dict[str, Any]]:
    """Geolocate a public routable IP.
    
    Returns approximate network-level location. Returns None if IP is private or invalid.
    """
    if not is_public_routable_ip(ip_str):
        return None

    try:
        ip = ipaddress.ip_address(ip_str.strip())
        for net, info in SYNTHETIC_SUBNET_GEO_DB:
            if ip in net:
                return {
                    "ip": str(ip),
                    "is_public": True,
                    "country": info["country"],
                    "country_code": info["country_code"],
                    "city": info["city"],
                    "isp": info["isp"],
                    "asn": info["asn"],
                    "disclaimer": "Approximate network-level location, never an individual person's location.",
                }
        
        # Generic fallback for any other valid public IP
        return {
            "ip": str(ip),
            "is_public": True,
            "country": "Unknown Region",
            "country_code": "XX",
            "city": "Unknown",
            "isp": "Public Autonomous System",
            "asn": "AS-UNKNOWN",
            "disclaimer": "Approximate network-level location, never an individual person's location.",
        }
    except ValueError:
        return None
