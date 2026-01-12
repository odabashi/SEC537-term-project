#!/bin/bash
# -----------------------------
# SCADA Vulnerable Startup Script
# -----------------------------

IMAGE_NAME="scada-vulnerable-img"
CONTAINER_NAME="scada-vuln"
PORT=8000

echo "Building SCADA (vulnerable) Docker image ..."
docker build -t $IMAGE_NAME .

echo "Stopping old container (if exists) ..."
docker stop $CONTAINER_NAME 2>/dev/null
docker rm $CONTAINER_NAME 2>/dev/null

echo "Starting SCADA container ..."
docker run -d \
  --name $CONTAINER_NAME \
  -p $PORT:$PORT \
  --restart unless-stopped \
  $IMAGE_NAME

echo "Vulnerable SCADA Web Interface is running on port $PORT"
