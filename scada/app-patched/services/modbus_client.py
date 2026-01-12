from pymodbus.client import ModbusTcpClient
import logging
from datetime import datetime


logger = logging.getLogger("SEC537_SCADA_Patched")


def read_plc_data(plc_ip: str, function_codes: list, port: int = 502, device_id=1):
    """
    Reads sensitive data from PLC via Modbus.
    Uses only read functions (0x01, 0x02, 0x03, 0x04).
    No write operations.
    """

    client = ModbusTcpClient(plc_ip, port=port)
    try:
        client.connect()
    except Exception as e:
        logger.error(f"Unable to Connect to PLC Modbus TCP! The error message is {e}")
        raise ConnectionError(f"Unable to Connect to PLC Modbus TCP! The error message is {e}")

    logger.info("Connection to PLC Modbus TCP established, Start reading registers data ...")
    data = {}

    time_of_read = datetime.now().strftime("%Y-%m-%d %H:%M:%SZ")
    try:
        if "0x01" in function_codes:
            # 0x01 – Read Coils (Control flags)
            rr_coils = client.read_coils(address=0, count=3, device_id=device_id)
            if not rr_coils.isError():
                data["0x01"] = rr_coils.registers

        if "0x02" in function_codes:
            # 0x02 – Read Discrete Inputs (Status Indicators)
            rr_discrete = client.read_discrete_inputs(address=0, count=3, device_id=device_id)
            if not rr_discrete.isError():
                data["0x02"] = rr_discrete.registers

        if "0x03" in function_codes:
            # 0x03 – Read Holding Registers (Thresholds / Configurations)
            rr_holding = client.read_holding_registers(address=0, count=5, device_id=device_id)
            if not rr_holding.isError():
                data["0x03"] = rr_holding.registers

        if "0x04" in function_codes:
            # 0x04 – Read Input Registers (Sensors)
            rr_inputs = client.read_input_registers(address=0, count=5, device_id=device_id)
            if not rr_inputs.isError():
                data["0x04"] = rr_inputs.registers

    finally:
        client.close()
        logger.info("Connection to PLC Modbus TCP closed, Data read completed.")

    return data, time_of_read
