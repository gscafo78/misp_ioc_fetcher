# MISP IOC Fetcher - Docker Setup

This directory contains the Docker configuration for running the MISP IOC Fetcher application.

## Prerequisites

- Docker and Docker Compose installed on your system
- Access to a MISP instance with API key

## Quick Start

1. **Copy the environment file:**
   ```bash
   cp .env_sample .env
   ```

2. **Edit the `.env` file** with your MISP instance details:
   - `MISP_APY_KEY`: Your MISP API key
   - `MISP_URL`: The base URL of your MISP instance
   - `MISP_VERIFY_CERT`: Set to `true` if you want to verify SSL certificates
   - `UPDATE_TIME`: Interval in seconds for periodic updates (0 = run once)

3. **Build and run the container:**
   ```bash
   docker-compose up --build
   ```

The application will start fetching IOCs from your MISP instance and save them to the `./ioc` directory.

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `MISP_APY_KEY` | MISP API key (required) | - |
| `MISP_URL` | MISP base URL (required) | - |
| `MISP_VERIFY_CERT` | Verify SSL certificates | `false` |
| `MISP_START_DATE` | Start date for IOC queries (YYYY-MM-DD) | 2 years ago |
| `OUTPUT_IP_FILE` | Path for IP output file | `ioc/ioc_ips.txt` |
| `OUTPUT_URLS_FILE` | Path for URLs output file | `ioc/ioc_urls.txt` |
| `OUTPUT_HASHES_FILE` | Path for hashes output file | `ioc/ioc_hashes.txt` |
| `UPDATE_TIME` | Update interval in seconds (0 = run once) | `0` |

### Volumes

- `./ioc:/app/ioc`: Persistent storage for IOC output files

## Usage

### Running in Background

```bash
docker-compose up -d
```

### Viewing Logs

```bash
docker-compose logs -f misp-ioc-fetcher
```

### Stopping the Service

```bash
docker-compose down
```

### Manual Execution

If you want to run the fetcher manually without the update loop:

```bash
docker-compose run --rm misp-ioc-fetcher python app.py --verbose
```

## Output Files

The application generates three output files in the `./ioc` directory:

- `ioc_ips.txt`: Malicious IP addresses
- `ioc_urls.txt`: Malicious URLs
- `ioc_hashes.txt`: Malicious file hashes (MD5, SHA1, SHA256)

Each file includes a timestamp header indicating when it was last updated.

## Troubleshooting

- **API Key Error**: Ensure `MISP_APY_KEY` is correctly set in `.env`
- **Connection Error**: Verify `MISP_URL` is accessible and `MISP_VERIFY_CERT` is set appropriately
- **Permission Issues**: Ensure the Docker daemon has access to the `./ioc` directory

## Development

To modify the application:

1. Edit the source code in the parent directory
2. Rebuild the container:
   ```bash
   docker-compose build
   ```
3. Restart the service:
   ```bash
   docker-compose up -d