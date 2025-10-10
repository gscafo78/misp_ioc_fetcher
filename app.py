"""
mispclinet - A Script to fetch malicious IP addresses, URLs, and hashes (IOCs) from a MISP instance.
It queries for IP-src and IP-dst attributes from a specified start date to now,
URLs with analysis 2 and hashes (MD5, SHA1, SHA256) with analysis 2 and outputs unique IPs, URLs, and hashes to text files.

Author: Giovanni Scafetta
"""

import argparse
import os
import logging
import warnings
import time
from datetime import datetime, timedelta
from mispclient.mispclient import MISPClient

__version__ = "1.0.0"

# ------------------------------------------------------------------------------
# Module‑level logging configuration
# ------------------------------------------------------------------------------
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"


def run(logger, args, client):
    """
    Run the fetching of IOCs from MISP.
    """
    # Fetch and save IPs
    ips = client.get_malicious_ips(args.output_ip_file)

    if not ips:
        logger.warning("No IPs found.")
    else:
        logger.info(f"Successfully saved {len(ips)} IPs to {args.output_ip_file}")

    # # Fetch and save URLs
    # urls = client.get_malicious_urls(args.output_urls_file)

    # if not urls:
    #     logger.warning("No URLs found.")
    # else:
    #     logger.info(f"Successfully saved {len(urls)} URLs to {args.output_urls_file}")

    # Fetch and save hashes
    hashes = client.get_malicious_hashes(args.output_hashes_file)

    if not hashes:
        logger.warning("No hashes found.")
    else:
        logger.info(f"Successfully saved {len(hashes)} hashes to {args.output_hashes_file}")

def main():
    """
    Main function to parse arguments and execute the IP, URL and HASHES fetching.
    """
    parser = argparse.ArgumentParser(description='Fetch malicious IPs, URLs, and hashes from MISP and save to text files.')

    # Arguments with defaults from environment variables
    parser.add_argument(
        '--version',
        action='version',
        version=f"%(prog)s {__version__}",
        help="Show program version and exit.",
        )
    parser.add_argument(
        '--misp-url', 
        default=os.getenv('MISP_URL'),
        help='The base URL of the MISP instance (e.g., https://misp.example.com). Can be set via MISP_URL env var.'
        )
    parser.add_argument(
        '--apykey', 
        default=os.getenv('MISP_APY_KEY'),
        help='The API key for MISP authentication. Can be set via MISP_APY_KEY env var.'
        )
    parser.add_argument(
        '--start-date', 
        default=os.getenv('MISP_START_DATE', (datetime.now() - timedelta(days=365*2)).strftime('%Y-%m-%d')),
        help='Start date for the query in YYYY-MM-DD format (default: 2 years ago or MISP_START_DATE env var).'
        )
    parser.add_argument(
        '--verycert', 
        action='store_true', 
        default=os.getenv('MISP_VERIFY_CERT', 'false').lower() == 'true',
        help='Verify SSL certificates (default: False or based on MISP_VERIFY_CERT env var).'
        )
    # Get the directory of the script to make paths relative to it
    script_dir = os.path.dirname(os.path.abspath(__file__))
    default_ip_file = os.path.join(script_dir, 'ioc', 'ioc_ips.txt')
    default_urls_file = os.path.join(script_dir, 'ioc', 'ioc_urls.txt')
    default_hashes_file = os.path.join(script_dir, 'ioc', 'ioc_hashes.txt')

    parser.add_argument(
        '--output-ip-file',
        default=os.getenv('OUTPUT_IP_FILE', default_ip_file),
        help=f'Output file path for the IOC IPs (default: {default_ip_file} or OUTPUT_IP_FILE env var).'
        )
    parser.add_argument(
        '--output-urls-file',
        default=os.getenv('OUTPUT_URLS_FILE', default_urls_file),
        help=f'Output file path for the IOC URLs (default: {default_urls_file} or OUTPUT_URLS_FILE env var).'
        )
    parser.add_argument(
        '--output-hashes-file',
        default=os.getenv('OUTPUT_HASHES_FILE', default_hashes_file),
        help=f'Output file path for the IOC hashes (default: {default_hashes_file} or OUTPUT_HASHES_FILE env var).'
        )
    parser.add_argument(
        '--verbose', 
        action='store_true', 
        help='Enable verbose logging.'
        )
    parser.add_argument(
        '--update-time', 
        default=os.getenv('UPDATE_TIME', 0),
        help='Time to recheck update from misp (default: 0 (no update) or UPDATE_TIME env var).'
        )
    args = parser.parse_args()
    
    warnings.filterwarnings("ignore", message="Unverified HTTPS request")

    logging.basicConfig(format=LOG_FORMAT)
    logger = logging.getLogger(__name__)
    # Start with verbose if requested, otherwise INFO
    logger.setLevel(logging.DEBUG if args.verbose else logging.INFO)

    # Check required arguments
    if not args.misp_url:
        parser.error("--misp-url is required (or set MISP_URL environment variable)")
    if not args.apykey:
        parser.error("--apykey is required (or set MISP_APY_KEY environment variable)")

    # Create MISP client instance
    client = MISPClient(args.misp_url, args.apykey, args.start_date, args.verycert)

    # Run the fetching once
    try:
        run(logger, args, client)
    except Exception as e:
        logger.error(f"An error occurred: {e}")

    # If update_time > 0, loop with sleep
    if int(args.update_time) > 0:
        try:
            while True:
                logger.info(f"Waiting {args.update_time} seconds before next update...")
                time.sleep(int(args.update_time))
                try:
                    run(logger, args, client)
                except Exception as e:
                    logger.error(f"An error occurred: {e}")
        except KeyboardInterrupt:
            logger.info("Interrupted by user")
    
    


if __name__ == "__main__":
    main()