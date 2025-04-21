#!/bin/bash
# Quick start script for GCS server with optional configuration

# Default settings
SKIP_VERIFICATION=${SKIP_VERIFICATION:-false}
CERT_VALIDITY_MINUTES=${CERT_VALIDITY_MINUTES:-59}

# Parse command line arguments
while [[ "$#" -gt 0 ]]; do
    case $1 in
        --skip-verification) SKIP_VERIFICATION="true" ;;
        --cert-validity=*) CERT_VALIDITY_MINUTES="${1#*=}" ;;
        --help)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --skip-verification      Skip device identity verification (for testing)"
            echo "  --cert-validity=MINUTES  Set certificate validity period in minutes (default: 59)"
            echo "  --help                   Show this help message"
            exit 0
            ;;
        *) echo "Unknown parameter: $1"; exit 1 ;;
    esac
    shift
done

# Check if allowed_devices.json exists
if [ "$SKIP_VERIFICATION" = "false" ] && [ ! -f "./gcs/allowed_devices.json" ]; then
    echo "Warning: allowed_devices.json not found, but verification is enabled."
    echo "Certificate requests may fail. Use --skip-verification for testing."
    echo ""
fi

# Print configuration
echo "Starting GCS with configuration:"
echo "  SKIP_VERIFICATION: $SKIP_VERIFICATION"
echo "  CERT_VALIDITY_MINUTES: $CERT_VALIDITY_MINUTES"
echo ""

# Export environment variables
export SKIP_VERIFICATION
export CERT_VALIDITY_MINUTES

# Run the GCS container
echo "Starting GCS service..."
docker-compose -f docker-compose.gcs.yml up
