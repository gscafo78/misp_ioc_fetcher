"""
MISP Client module for fetching malicious indicators of compromise (IOCs).

This module provides a client class to interact with a MISP (Malware Information Sharing Platform)
instance and retrieve malicious IP addresses, URLs, and hashes.

Author: Giovanni Scafetta
"""

import requests
from datetime import datetime
import ipaddress
from mispclient.normalize_urls import normalize_urls

class MISPClient:
    """
    A client for interacting with a MISP (Malware Information Sharing Platform) instance.
    This class provides methods to fetch malicious indicators of compromise (IOCs) such as
    IP addresses, URLs, and hashes from a MISP server.

    Attributes:
        misp_url (str): The base URL of the MISP instance.
        api_key (str): The API key for authentication.
        start_date (str): The start date for queries in YYYY-MM-DD format.
        verify_cert (bool): Whether to verify SSL certificates.
    """

    __version__ = "1.0.2"

    private_networks = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16')
    ]

    def _load_whitelist(self, file_path):
        """
        Loads a whitelist from a file, returning a set of whitelisted items.

        Args:
            file_path (str): Path to the whitelist file.

        Returns:
            set: A set of whitelisted items from the file.
        """
        whitelist = set()
        try:
            with open(file_path, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line:  # Skip empty lines
                        whitelist.add(line)
        except FileNotFoundError:
            print(f"Warning: Whitelist file {file_path} not found. Using empty whitelist.")
        return whitelist

    def __init__(self, misp_url, api_key, start_date, verify_cert, whitelist_ip_file=None, whitelist_urls_file=None, whitelist_hashes_file=None):
        self.misp_url = misp_url
        self.api_key = api_key
        self.start_date = start_date
        self.verify_cert = verify_cert
        self.whitelist_ip_file = whitelist_ip_file
        self.whitelist_urls_file = whitelist_urls_file
        self.whitelist_hashes_file = whitelist_hashes_file
        self.whitelist_ips = self._load_whitelist(whitelist_ip_file) if whitelist_ip_file else set()
        self.whitelist_urls = self._load_whitelist(whitelist_urls_file) if whitelist_urls_file else set()
        self.whitelist_hashes = self._load_whitelist(whitelist_hashes_file) if whitelist_hashes_file else set()

    @classmethod
    def is_in_private(cls, ip):
        try:
            addr = ipaddress.ip_address(ip)
            return any(addr in net for net in cls.private_networks)
        except ValueError:
            return False

    def get_malicious_ips(self, output_file):
        """
        Fetches malicious IP addresses from MISP.

        Args:
            output_file (str): Path to the output file for IOC IPs.

        Returns:
            list: A sorted list of unique malicious IP addresses.
        """
        # Define the API endpoint for attribute search
        misp_endpoint = '/attributes/restSearch'

        # Set up headers for the request
        headers = {
            'Authorization': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        # Define the request body for searching attributes
        body = {
            "returnFormat": "json",
            "type": ["ip-src", "ip-dst"],
            "timestamp": f"{self.start_date}..now",  # Query from start_date to now
            "to_ids": True  # Only include attributes marked as to_ids
        }

        # Make the POST request to MISP
        response = requests.post(f"{self.misp_url}{misp_endpoint}", headers=headers, json=body, verify=self.verify_cert)

        if response.status_code != 200:
            print(f"Error from MISP: {response.status_code} - {response.text}")
            return []

        # Parse the JSON response
        data = response.json()['response']['Attribute']

        # Extract unique IPs
        ips = set()
        for attr in data:
            if attr['type'] in ['ip-src', 'ip-dst'] and attr['value']:
                ips.add(attr['value'])

        print(f"Extracted {len(ips)} unique IP addresses from MISP.")

        filtered_ips = sorted([ip for ip in ips if not self.is_in_private(ip) and ip not in self.whitelist_ips])
        whitelisted_count = len(ips) - len(filtered_ips)
        if whitelisted_count > 0:
            print(f"Excluded {whitelisted_count} IPs from whitelist.")

        # Write IPs to a text file
        with open(output_file, 'w') as f:
            f.write('# Last updated ' + datetime.now().strftime('%Y-%m-%d %H:%M') + '\n')
            for ip in filtered_ips:
                f.write(ip + '\n')

        return filtered_ips

    def get_malicious_urls(self, output_file):
        """
        Fetches malicious URLs from MISP.

        Args:
            output_file (str): Path to the output file for IOC URLs.

        Returns:
            list: A sorted list of unique malicious URLs.
        """
        # Define the API endpoint for attribute search
        misp_endpoint = '/attributes/restSearch'

        # Set up headers for the request
        headers = {
            'Authorization': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        # Define the request body for searching attributes
        body = {
            "returnFormat": "json",
            "type": ["url"],
            "analysis": [2],
            "timestamp": f"{self.start_date}..now",  # Query from start_date to now
            "to_ids": True
        }

        # Make the POST request to MISP
        response = requests.post(f"{self.misp_url}{misp_endpoint}", headers=headers, json=body, verify=self.verify_cert)

        if response.status_code != 200:
            print(f"Error from MISP: {response.status_code} - {response.text}")
            return []

        # Parse the JSON response
        data = response.json()['response']['Attribute']

        # Extract unique URLs
        urls = set()
        for attr in data:
            if attr['type'] == 'url' and attr['value']:
                cleaned_url = attr['value'].replace('[', '').replace(']', '')
                urls.add(cleaned_url)

        print(f"Extracted {len(urls)} unique URLs from MISP.")
        urls = normalize_urls(list(urls))
        filtered_urls = [url for url in urls if url not in self.whitelist_urls]
        whitelisted_count = len(urls) - len(filtered_urls)
        if whitelisted_count > 0:
            print(f"Excluded {whitelisted_count} URLs from whitelist.")

        # Write URLs to a text file
        with open(output_file, 'w') as f:
            f.write('# Last updated ' + datetime.now().strftime('%Y-%m-%d %H:%M') + '\n')
            for url in sorted(filtered_urls):
                f.write(url + '\n')

        return sorted(filtered_urls)

    def get_malicious_hashes(self, output_file):
        """
        Fetches malicious hashes from MISP.

        Args:
            output_file (str): Path to the output file for IOC hashes.

        Returns:
            list: A sorted list of unique malicious hashes.
        """
        # Define the API endpoint for attribute search
        misp_endpoint = '/attributes/restSearch'

        # Set up headers for the request
        headers = {
            'Authorization': self.api_key,
            'Accept': 'application/json',
            'Content-Type': 'application/json'
        }

        # Define the request body for searching attributes
        body = {
            "returnFormat": "json",
            "type": ["md5", "sha1", "sha256"],
            "analysis": [2],
            "timestamp": f"{self.start_date}..now",  # Query from start_date to now
            "to_ids": True
        }

        # Make the POST request to MISP
        response = requests.post(f"{self.misp_url}{misp_endpoint}", headers=headers, json=body, verify=self.verify_cert)

        if response.status_code != 200:
            print(f"Error from MISP: {response.status_code} - {response.text}")
            return []

        # Parse the JSON response
        data = response.json()['response']['Attribute']

        # Extract unique hashes
        hashes = set()
        for attr in data:
            if attr['type'] in ['md5', 'sha1', 'sha256'] and attr['value']:
                # event_info = attr['Event']['info'] if 'Event' in attr and 'info' in attr['Event'] else 'No Event Info'
                # hashes.add(f"{attr['value']} {event_info}")
                hashes.add(attr['value'])

        print(f"Extracted {len(hashes)} unique hashes from MISP.")
        filtered_hashes = [h for h in sorted(hashes) if h not in self.whitelist_hashes]
        whitelisted_count = len(hashes) - len(filtered_hashes)
        if whitelisted_count > 0:
            print(f"Excluded {whitelisted_count} hashes from whitelist.")

        # Write hashes to a text file
        with open(output_file, 'w') as f:
            f.write('# Last updated ' + datetime.now().strftime('%Y-%m-%d %H:%M') + '\n')
            for h in filtered_hashes:
                f.write(h + '\n')

        return filtered_hashes

