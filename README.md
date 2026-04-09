# MISP IOC Fetcher

A Python script to fetch malicious Indicators of Compromise (IOCs) such as IP addresses, URLs, and hashes from a MISP (Malware Information Sharing Platform) instance.

## Features

- Fetches malicious IP addresses (excluding private networks)
- Fetches malicious URLs
- Fetches malicious hashes (MD5, SHA1, SHA256)
- Saves IOCs to text files
- Supports selective output for IPs, URLs, and hashes
- Supports periodic updates
- Configurable via environment variables or command-line arguments
- Includes a whitelist for public DNS IP addresses to avoid false positives

## Requirements

- Python 3.6+
- `requests` library
- `ipaddress` library (built-in)
- Access to a MISP instance with API key

## Installation

1. Clone or download the repository.
2. Install dependencies:
   ```
   pip install requests
   ```
3. Ensure you have access to a MISP instance.

## Configuration

Configure the script using environment variables or command-line arguments:

### Environment Variables

- `MISP_URL`: The base URL of the MISP instance (e.g., `https://misp.example.com`)
- `MISP_API_KEY`: The API key for MISP authentication
- `MISP_START_DATE`: Start date for queries in YYYY-MM-DD format (default: 2 years ago)
- `MISP_VERIFY_CERT`: Verify SSL certificates (default: false)
- `OUTPUT_IP`: Enable output for IPs (default: true)
- `OUTPUT_URLS`: Enable output for URLs (default: false)
- `OUTPUT_HASHES`: Enable output for hashes (default: false)
- `OUTPUT_IP_FILE`: Output file for IPs (default: `ioc_ips.txt`)
- `OUTPUT_URLS_FILE`: Output file for URLs (default: `ioc_urls.txt`)
- `OUTPUT_HASHES_FILE`: Output file for hashes (default: `ioc_hashes.txt`)
- `WHITELIST_IP_FILE`: Path to whitelist file for IPs (default: `ioc/whitelist_ip_file.txt`)
- `WHITELIST_URLS_FILE`: Path to whitelist file for URLs (default: `ioc/whitelist_urls_file.txt`)
- `WHITELIST_HASHES_FILE`: Path to whitelist file for hashes (default: `ioc/whitelist_hashes_file.txt`)
- `UPDATE_TIME`: Time in seconds to wait between updates (default: 0, no updates)

### Command-Line Arguments

Run `python app.py --help` for a list of all arguments.

## Usage

### Basic Usage

Set environment variables or use arguments:

```bash
export MISP_URL="https://misp.example.com"
export MISP_API_KEY="your_api_key"
python app.py
```

### With Arguments

```bash
python app.py --misp-url https://misp.example.com --apykey your_api_key --start-date 2023-01-01
```

### Periodic Updates

To enable periodic fetching:

```bash
python app.py --update-time 3600  # Update every hour
```

The script will run once, then update periodically. Press Ctrl+C to stop.

## Output

The script can generate up to three text files based on the selected options:

- `ioc_ips.txt`: List of malicious IP addresses (if `--output-ip` or `OUTPUT_IP=true`)
- `ioc_urls.txt`: List of malicious URLs (if `--output-urls` or `OUTPUT_URLS=true`)
- `ioc_hashes.txt`: List of malicious hashes (if `--output-hashes` or `OUTPUT_HASHES=true`)

Each file includes a timestamp of the last update.

## Architecture

- `app.py`: Main script with argument parsing and execution logic
- `mispclient/mispclient.py`: MISPClient class for interacting with MISP API

## Author

Giovanni Scafetta

## Version

1.0.2

## License

Copyright (C) 2024 Giovanni Scafetta

This program is free software: you can redistribute it and/or modify it under the terms of the GNU General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for more details.

You should have received a copy of the GNU General Public License along with this program.  If not, see <https://www.gnu.org/licenses/>.