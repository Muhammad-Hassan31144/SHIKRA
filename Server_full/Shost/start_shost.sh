#!/bin/bash
cd "$(dirname "$0")"

echo "🚀 Starting Shikra Host (Shost)..."

# Load configuration
source test_config.sh

# Activate virtual environment
source venv/bin/activate

# Start the server
python run.py
