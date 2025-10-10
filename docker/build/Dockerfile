# Use an official Python runtime as a parent image
FROM python:3.11.12-slim

# Install required packages using apt (not apk, which is for Alpine)
RUN apt-get update && \
    apt-get install -y --no-install-recommends tzdata \
                                               curl \
                                               python3-dev \
                                               build-essential && \
    rm -rf /var/lib/apt/lists/*

# Improve container logging
ENV PYTHONUNBUFFERED=1 \
    PYTHONIOENCODING=UTF-8

# Set the working directory in the container
WORKDIR /app


# Clone the repository directly into /app
RUN git clone --single-branch https://github.com/gscafo78/misp_ioc_fetcher.git /app

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Create the ioc directory for output files
RUN mkdir -p ioc

# Define environment variable (optional, can be overridden at runtime)
# ENV MISP_URL=""
# ENV MISP_APY_KEY=""
# ENV MISP_START_DATE=""
# ENV MISP_VERIFY_CERT="false"
# ENV OUTPUT_IP_FILE="ioc/ioc_ips.txt"
# ENV OUTPUT_URLS_FILE="ioc/ioc_urls.txt"
# ENV OUTPUT_HASHES_FILE="ioc/ioc_hashes.txt"
# ENV UPDATE_TIME="0"

# Create a volume for the ioc directory to persist output files
VOLUME ["/app/ioc"]

# Run app.py when the container launches
CMD ["python", "app.py"]