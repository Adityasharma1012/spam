"""URL and domain defanging utilities for security display.

Ensures that no URL or domain extracted from untrusted email data can be
accidentally resolved or clicked.
"""
import re

URL_PATTERN = re.compile(
    r'(https?://[^\s<>"\']+)',
    re.IGNORECASE
)

DOMAIN_PATTERN = re.compile(
    r'([a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}'
)


def defang_url(url: str) -> str:
    """Defang a single URL string for safe display.
    
    Example:
        http://example.com/login -> hxxp://example[.]com/login
        https://evil.site/malware -> hxxps://evil[.]site/malware
    """
    if not url:
        return ""
    
    # Replace protocol
    defanged = re.sub(r'^https://', 'hxxps://', url, flags=re.IGNORECASE)
    defanged = re.sub(r'^http://', 'hxxp://', defanged, flags=re.IGNORECASE)
    defanged = re.sub(r'^ftp://', 'fxp://', defanged, flags=re.IGNORECASE)
    
    # Replace dots in the domain portion
    parts = defanged.split('/', 3)
    if len(parts) >= 3 and ('hxxp://' in defanged or 'hxxps://' in defanged or 'fxp://' in defanged):
        domain_part = parts[2]
        domain_defanged = domain_part.replace('.', '[.]').replace(':', '[:]')
        parts[2] = domain_defanged
        return '/'.join(parts)
    
    return defanged.replace('.', '[.]')


def defang_domain(domain: str) -> str:
    """Defang a domain name for safe display."""
    if not domain:
        return ""
    return domain.replace('.', '[.]').replace('@', '[@]')


def extract_and_defang_urls(text: str) -> list[dict]:
    """Find all URLs in raw text, returning both raw (for internal analysis) and defanged (for display)."""
    if not text:
        return []
    matches = URL_PATTERN.findall(text)
    unique_urls = []
    seen = set()
    for m in matches:
        cleaned = m.rstrip('.,;:)>\'"')
        if cleaned and cleaned not in seen:
            seen.add(cleaned)
            unique_urls.append({
                "raw_url": cleaned,
                "defanged_url": defang_url(cleaned)
            })
    return unique_urls
