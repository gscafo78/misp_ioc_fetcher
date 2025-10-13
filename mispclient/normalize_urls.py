#!/usr/bin/env python3
"""
Script per normalizzare una lista di URL rimuovendo protocolli e porte,
ottimizzandoli per una lista di blocco firewall.
Se ci sono domini di terzo livello uguali, ne scrive uno solo con * da quarto livello in poi.
"""

import sys
from urllib.parse import urlparse
from collections import defaultdict


def normalize_urls(urls):
    """
    Normalizza una lista di URL rimuovendo protocolli e porte.
    Se ci sono domini di terzo livello uguali, ne scrive uno solo con * da quarto livello in poi.

    Args:
        urls (list[str]): Lista di URL da normalizzare.

    Returns:
        list[str]: Lista di host normalizzati senza duplicati.
    """
    hosts = set()
    for url in urls:
        url = url.strip()
        if not url:
            continue
        if '://' in url:
            # URL completo con protocollo
            parsed = urlparse(url)
            host = parsed.hostname
            if host:
                hosts.add(host)
        else:
            # Possibile host:port o solo host
            host = url.split(':')[0]
            if host:
                hosts.add(host)

    # Raggruppa per dominio di terzo livello
    domain_groups = defaultdict(list)
    for host in hosts:
        parts = host.split('.')
        if len(parts) >= 3:
            # Dominio di terzo livello: es. sub.example.com -> example.com
            third_level = '.'.join(parts[-3:])
            domain_groups[third_level].append(host)
        else:
            # Dominio di secondo livello o meno
            domain_groups[host].append(host)

    normalized = set()
    for group, subhosts in domain_groups.items():
        if len(subhosts) > 1:
            # Più sottodomini, usa wildcard
            parts = group.split('.')
            if len(parts) == 3:
                wildcard = f"*.{group}"
                normalized.add(wildcard)
            else:
                # Per domini più corti, aggiungi come sono
                normalized.update(subhosts)
        else:
            # Unico host
            normalized.update(subhosts)

    return sorted(list(normalized))


def main():
    urls = ["http://asfwfrwgeg.google.it:8999",
        "http://asfwfrwgegsadasfd.google.it:4563",
        "htts://asfwffdwfewfeg.microsoft.com:8999/ciccio/bello.exe",
        "https://asfwfrwgeg.chebanca.it:8999",
        "http://as.google.baubau.it:4563",
        "htts://asfwffdwfewfeg.microsoft.com/ciccio/bello.zip",
        "http://asfwfrwgeg.google.it:8999",
        "http://asfwfrwgegsadasfd.google.it:4563",
        "htts://asfwffdwfewfeg.microsoft.com:8999/ciccio/bello.exe",
        "http://asfwfrwgeg.google.it:8999",
        "http://asfwfrwgegsadasfd.google.it:4563",
        "htts://asfwffdwfewfeg.microsoft.com:8999/ciccio/bello.exe",
        "http://asfwfrwgeg.google.it:8999",
        "asfwfrwgegsadasfd.googlexxx.it:4563",
        "htts://asdasda.xxx.www.asfwffdwfewfeg.microsoft.com:8999/ciccio/bello.exe",
        "htts://www.asfwffdwfewfeg.microsoft.com:8999/ciccio/bello.exe",
        "htts://xxx.asfwffdwfewfeg.microsoft.com/ciccio/bello.exe",
        "htts://www.asfwffdwfewfeg.microsoft.com/ciccio/bello.exe",
        "1.1.1.1:888"
        ]

    
    
    
    normalized = normalize_urls(urls)
    for host in normalized:
        print(host)


if __name__ == "__main__":
    main()