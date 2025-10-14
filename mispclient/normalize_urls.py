#!/usr/bin/env python3
"""
Script to normalize a list of URLs by removing protocols and ports,
optimizing them for a firewall block list.
If there are identical third-level domains, it writes only one with * from the fourth level onwards.
"""
__version__ = "1.0.0"

from urllib.parse import urlparse
from collections import defaultdict


def normalize_urls(urls):
    """
    Normalize a list of URLs by removing protocols and ports.
    If there are identical third-level domains, it writes only one with * from the fourth level onwards.

    Args:
        urls (list[str]): List of URLs to normalize.

    Returns:
        list[str]: List of normalized hosts without duplicates.
    """
    hosts = set()
    for url in urls:
        url = url.strip()
        if not url:
            continue
        if '://' in url:
            # Full URL with protocol
            parsed = urlparse(url)
            host = parsed.hostname
            if host:
                hosts.add(host)
        else:
            # Possible host:port or just host
            host = url.split(':')[0]
            if host:
                hosts.add(host)

    # Group by third-level domain
    domain_groups = defaultdict(list)
    for host in hosts:
        parts = host.split('.')
        if len(parts) >= 3:
            # Third-level domain: e.g. sub.example.com -> example.com
            third_level = '.'.join(parts[-3:])
            domain_groups[third_level].append(host)
        else:
            # Second-level domain or less
            domain_groups[host].append(host)

    normalized = set()
    for group, subhosts in domain_groups.items():
        if len(subhosts) > 1:
            # Multiple subdomains, use wildcard
            parts = group.split('.')
            if len(parts) == 3:
                wildcard = f"*.{group}"
                normalized.add(wildcard)
            else:
                # For shorter domains, add as is
                normalized.update(subhosts)
        else:
            # Single host
            normalized.update(subhosts)

    return sorted(list(normalized))
