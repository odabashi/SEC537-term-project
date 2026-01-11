"""
Defines the internal memory of the PLC. This includes registers and coils exposed via Modbus.
"""
from pymodbus.datastore import (
    ModbusSequentialDataBlock,
    ModbusDeviceContext,
    ModbusServerContext
)
import threading
import random
import time
import logging


logger = logging.getLogger("modbus")


def create_slave_context():
    """
    Creates a Modbus slave context with initial values.

    Returns:
        - slave_context
    """
    # -----------------------------
    # STATIC VALUE INITIALIZATION
    # -----------------------------

    # As stated in the assignment document in page 5, here are some simulated data which will be read by SCADA server.

    # Important note when using pymodbus is that Modbus logical addresses (e.g., 40001) are mapped to zero-based indices
    # internally by pymodbus. Therefore, we use 0 in address argument parts.

    # -----------------------------
    # COILS (0x01)
    # Range: 00001 - 10000
    # Purpose: Binary control flags/outputs (1-bit)
    # -----------------------------

    coils = ModbusSequentialDataBlock(
        0,
        [
            False,  # 00001 - Emergency stop (False = released)
            True,   # 00002 - Conveyor enabled
            True,   # 00003 - Cooling system active
        ]
    )

    # -----------------------------
    # DISCRETE INPUTS (0x02)
    # Range: 10001 - 20000
    # Purpose: Binary status indicators (1-bit)
    # -----------------------------

    discrete_inputs = ModbusSequentialDataBlock(
        0,
        [
            True,   # 10001 - Machine running
            False,  # 10002 - Maintenance mode
            True,   # 10003 - Safety interlock OK
        ]
    )

    # -----------------------------
    # HOLDING REGISTERS (0x03)
    # Range: 40001 - 50000
    # Purpose: Configuration, thresholds, limits (16-bit)
    # -----------------------------

    holding_registers = ModbusSequentialDataBlock(
        0,
        [
            75,    # 40001 - Temperature alarm threshold (°C)
            120,   # 40002 - Pressure alarm threshold (PSI)
            90,    # 40003 - Vibration alarm threshold (%)
            5000,  # 40004 - Daily production target (units)
            1,     # 40005 - Safety mode enabled (1 = ON)
        ]
    )

    # -----------------------------
    # INPUT REGISTERS (0x04)
    # Range: 30001 - 40000
    # Purpose: Live sensor readings (Dummy) (read-only in PLC) (16-bit)
    # -----------------------------

    input_registers = ModbusSequentialDataBlock(
        0,
        [
            68,     # 30001 - Current temperature (°C)
            110,    # 30002 - Current pressure (PSI)
            55,     # 30003 - Vibration level (%)
            4200,   # 30004 - Units produced today
            92      # 30005 - Power consumption (kW)
        ]
    )

    # Based on the statement in the Assignment document "Students must extract at least 2 types of sensitive data", we
    # actually need 2, but we have many more :)

    # -----------------------------
    # SLAVE CONTEXT
    # -----------------------------

    # Modbus uses old master/slave model where Master is the Client (SCADA, HMI, etc.) and the Slave is the server (PLC)
    # So creating slave context means the memory of 1 PLC device (in our case it is a container of aforementioned 4
    # memory tables (coils, discrete inputs, holding registers, input registers)

    slave_context = ModbusDeviceContext(
        di=discrete_inputs,
        co=coils,
        hr=holding_registers,
        ir=input_registers
    )

    return slave_context


def create_server_context():
    """
    Creates a Modbus server context with a single slave (unit id = 1)
    """
    # -----------------------------
    # Slave / Server Context: 1 PLC device (actually it is single slave, with unit ID 1)
    # -----------------------------
    slave_context = create_slave_context()
    server_context = ModbusServerContext(
        devices={1: slave_context},
        single=False
    )
    return server_context


def update_registers_periodically(context, unit_id=1, interval=1):
    """
    Periodically updates Modbus registers to simulate live PLC data.

    Args:
        - context: ModbusServerContext
        - unit_id: Slave ID
        - interval: Update interval in seconds
    """
    while True:
        # Update Input Registers (3xxxx): Live sensor readings
        temperature = random.randint(20, 80)            # °C
        pressure = random.randint(50, 150)              # PSI
        vibration_level = random.randint(10, 100)       # percentage
        units_produced = random.randint(4000, 4500)     # units
        power = random.randint(80, 120)                 # kW

        context[unit_id].setValues(4, 0, [temperature])
        context[unit_id].setValues(4, 1, [pressure])
        context[unit_id].setValues(4, 2, [vibration_level])
        context[unit_id].setValues(4, 3, [units_produced])
        context[unit_id].setValues(4, 4, [power])

        logger.info(f"Updated registers:\n\t\tTemperature={temperature}°C,\n\t\tPressure={pressure},\n\t\t"
                    f"Vibration Level={vibration_level},\n\t\tUnits Produced Today={units_produced},\n\t\t"
                    f"Consumed Power={power}")
        time.sleep(interval)


def start_background_updater(context):
    """
    Starts the background thread that updates Modbus registers.
    """
    thread = threading.Thread(
        target=update_registers_periodically,
        args=(context,),
        daemon=True
    )
    thread.start()
