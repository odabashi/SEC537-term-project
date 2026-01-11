"""
Main entry point for the Modbus PLC simulator. Starts a Modbus TCP server exposing the PLC memory.
"""
from pymodbus.server import StartAsyncTcpServer
from pymodbus import ModbusDeviceIdentification
from datastore import create_server_context, start_background_updater
from config import MODBUS_HOST, MODBUS_PORT
import logging
import asyncio


logger = logging.getLogger("modbus")


async def main():
    """
    Initializes and starts the Modbus TCP server.
    """

    # -----------------------------
    # Create Server Context and Start the PLC Simulation thread (Updating Input Registers)
    # -----------------------------
    context = create_server_context()
    await start_background_updater(context)

    # -----------------------------
    # PLC Identification: Defines the Modbus device identification. This metadata is often retrievable by SCADA systems
    # -----------------------------

    identity = ModbusDeviceIdentification()
    identity.VendorName = "Sabanci University OT Lab"
    identity.ProductCode = "PLC-SUOTLAB"
    identity.VendorUrl = "https://ot-lab.sabanciuniv.edu"
    identity.ProductName = "Industrial SEC537 PLC Simulator"
    identity.ModelName = "PLC-SUOTLAB-SEC537-01"
    identity.MajorMinorRevision = "1.0"

    # -----------------------------
    # Start Modbus Server
    # -----------------------------

    logger.info(f"Starting Modbus PLC on {MODBUS_HOST}: {MODBUS_PORT}")
    logger.warning("Warning: No authentication, no encryption, trust-based access!!!")

    await StartAsyncTcpServer(
        context=context,
        identity=identity,
        address=(MODBUS_HOST, MODBUS_PORT)
    )


if __name__ == "__main__":
    try:
        asyncio.run(main(), debug=True)
    except KeyboardInterrupt:
        logger.error("Modbus Server stopped by user!")
    except Exception as e:
        logger.error(f"Error occurred: {e}")
