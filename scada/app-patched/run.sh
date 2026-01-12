#!/bin/bash
# -----------------------------
# SCADA Patched Startup Script
# -----------------------------

IMAGE_NAME="scada-patched-img"
CONTAINER_NAME="scada-patched"
PORT=8001

echo "Building SCADA (patched) Docker image ..."
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

echo "Patched SCADA Web Interface is running on port $PORT"
