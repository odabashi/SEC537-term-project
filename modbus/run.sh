#!/bin/bash
# -----------------------------
# Startup Shell Script
# -----------------------------

IMAGE_NAME="modbus-server-img"
CONTAINER_NAME="modbus-server"
PORT=5020

echo "Building Modbus PLC Docker image ..."
docker build -t $IMAGE_NAME .

echo "Stopping old container (if exists) ..."
docker stop $CONTAINER_NAME 2>/dev/null
docker rm $CONTAINER_NAME 2>/dev/null

echo "Starting Modbus PLC container ..."
docker run -d \
  --name $CONTAINER_NAME \
  -p $PORT:$PORT \
  --restart unless-stopped \
  $IMAGE_NAME

echo "Modbus PLC is running on port $PORT"
