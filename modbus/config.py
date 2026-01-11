"""
Configuration file for the Modbus PLC simulator.

This file defines network-level and protocol-level settings. In real OT systems, these are often hardcoded
in PLC firmware.
"""
import logging


MODBUS_HOST = "0.0.0.0"

# # Port 502 requires root/admin privileges. Do not forget to use sudo: "sudo python3 modbus_server.py"
# MODBUS_PORT = 502

# Using 5020 instead of 502 to avoid root privileges. Protocol behavior is identical to Modbus TCP on 502.
MODBUS_PORT = 5020


# Logging Configuration
logger = logging.getLogger("modbus")
formatter = logging.Formatter('%(asctime)s - %(levelname)s: %(message)s',
                              "%Y-%m-%d %H:%M:%S")

stream_handler = logging.StreamHandler()
stream_handler.setFormatter(formatter)
stream_handler.setLevel(logging.INFO)
logger.addHandler(stream_handler)

file_handler = logging.FileHandler("modbus.log")
file_handler.setFormatter(formatter)
file_handler.setLevel(logging.INFO)
logger.addHandler(file_handler)

logger.setLevel(logging.INFO)
logger.propagate = False
