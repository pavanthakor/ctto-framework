#!/bin/bash

echo "Starting CTTO Framework..."

# activate virtual environment
source .venv/bin/activate

# start web login honeypot
echo "Starting Web Login Honeypot..."
python ctto.py serve web-login &

# start api honeypot
echo "Starting API Honeypot..."
python ctto.py serve api-auth &

# set dashboard key
export CTTO_DASHBOARD_KEY=admin123

# start dashboard
echo "Starting Dashboard..."
python ctto.py serve dashboard &

echo "All CTTO services started."

# keep script running
wait
