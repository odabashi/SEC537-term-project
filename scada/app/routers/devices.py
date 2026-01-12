from fastapi import APIRouter, Depends
import logging
import requests
from datetime import datetime
from scada.app.models.schemas import DeviceCheckRequest, DeviceAddRequest
from scada.app.services.session import require_session
from scada.app.services.security import detect_internal_target
from scada.app.services.monitoring import log_attack
from scada.app.services.devices import add_device, list_devices
from scada.app.services.modbus_client import read_plc_data


logger = logging.getLogger("SEC537_SCADA")


router = APIRouter(tags=["Device Management Handlers"])


@router.post("/check")
def check_device(data: DeviceCheckRequest,session: str = Depends(require_session)):
    """
    Device health check.
    VULNERABILITY: Vulnerable to SSRF (no IP validation).
    """
    ssrf_attempt = detect_internal_target(data.ip)

    if ssrf_attempt:
        # MONITORING: Log SSRF attack
        log_attack(
            attack_type='SSRF',
            target_url='/api/device/check',
            payload=f'Blind SSRF attempt to: {data.ip}',
            source_ip=session['ip'],
            user_agent=session['user_agent'],
            success=True,
            details={
                'user': session['user'],
                'target_ip': data.ip,
                'attack_vector': 'Device health check',
                'ssrf_type': 'Blind SSRF',
                'vulnerability': 'No IP validation or whitelist',
                'internal_target_detected': True
            }
        )
        logger.critical("Blind SSRF attempt!!!")

    logger.info(f"Checking device health for {data.ip} based on the request of {session['user']}")
    try:
        r = requests.get(f"http://{data.ip}:{data.port}", timeout=2)
        logger.info(f"The target device on {data.ip}:{data.port} is reachable. The response is {r.text[:100]}")
        return {"status": "device health check completed"}  # Blind SSRF: response is irrelevant
    except Exception as e:
        logger.error(f"The target device on {data.ip}:{data.port} is unreachable. The error message is {e}")
        return {"status": "device health check completed"}  # Still blind: attacker learns nothing


@router.post("/add")
def add_new_device(data: DeviceAddRequest, session: str = Depends(require_session)):
    """
    Adds a new device to the SCADA system.
    VULNERABILITY: Stored SSRF due to unsafe device discovery. (No IP validation)
    """
    device = {
        "name": data.name,
        "ip": str(data.ip),
        "port": int(data.port),
        "type": data.type,
        "added_by": session["user"],
        "added_at": datetime.now().strftime("%Y-%m-%dT%H:%M:%SZ")
    }

    # Monitoring: detect stored SSRF attempt
    if detect_internal_target(device["ip"]):
        # MONITORING: Log Stored SSRF
        log_attack(
            attack_type='STORED_SSRF',
            target_url='/api/device/add',
            payload=f'Stored SSRF via unsafe device addition: {device["ip"]}',
            source_ip=session['ip'],
            user_agent=session['user_agent'],
            success=True,
            details={
                'user': session['user'],
                'device_name': device['name'],
                'device_ip': device['ip'],
                'device_type': device['type'],
                'attack_vector': 'Unsafe device discovery',
                'ssrf_type': 'Stored SSRF',
                'vulnerability': 'No IP validation, allows arbitrary internal IPs to be stored and queried',
                'persistence': 'Device will be periodically queried, creating persistent SSRF vector',
                'internal_target_detected': True
            }
        )
        logger.critical("Stored SSRF attempt via Unsafe Device Discovery!!!")
    else:
        # Even non-malicious device additions should be logged
        log_attack(
            attack_type='UNSAFE_DEVICE_ADD',
            target_url='/api/device/add',
            payload=f'Unsafe device addition: {device["ip"]}',
            source_ip=session['ip'],
            user_agent=session['user_agent'],
            success=True,
            details={
                'user': session['user'],
                'device_name': device['name'],
                'device_ip': device['ip'],
                'device_type': device['type'],
                'vulnerability': 'No validation or approval workflow for new devices'
            }
        )

    # Store device (persistent SSRF vector)
    add_device(device)

    logger.info(f"New device added by {session['user']}: {device['name']} of type {device['type']} "
                f"(IP: {device['ip']}:{device['port']})")

    # Unsafe discovery check (SSRF trigger)
    try:
        r = requests.get(f"http://{data.ip}:{data.port}", timeout=2)
        logger.info(f"The new device on {data.ip}:{data.port} is reachable. The response is {r.text[:100]}")
    except Exception as e:
        logger.error(f"The new device on {data.ip}:{data.port} is unreachable. The error message is {e}")
        pass
    return {"status": "Device is added and will be monitored periodically"}


@router.get("/list_all_devices")
def list_all_devices(session: str = Depends(require_session)):
    """
    Extra VULNERABILITY: No Access Control (No Authorization check)
    """
    return {"devices": list_devices()}


@router.get("/read_specific_device")
def read_device_data(plc_ip: str, plc_port: int = 502,
                     read_coils: bool = False, read_discrete_inputs: bool = False,
                     read_holding_registers: bool = False, read_input_registers: bool = True,
                     session: str = Depends(require_session)):
    """
    Reads PLC data.
    VULNERABILITY: Risk of Unauthorized Modbus read (No Authorization check for device ownership)
    """
    function_codes = []
    if read_coils:
        function_codes.append("0x01")
    if read_discrete_inputs:
        function_codes.append("0x02")
    if read_holding_registers:
        function_codes.append("0x03")
    if read_input_registers:
        function_codes.append("0x04")

    data = read_plc_data(plc_ip, function_codes, plc_port)

    # MONITORING: Modbus read (Log Sensitive OT Access together with PLC IP/Port and Session Owner Info)
    log_attack(
        attack_type='MODBUS_UNAUTHORIZED',
        target_url='/api/device/read_specific_device',
        payload=f'Possible Unauthorized Modbus read from PLC {plc_ip}:{plc_port}',
        source_ip=session['ip'],
        user_agent=session['user_agent'],
        success=True,
        details={
            'user': session['user'],
            'plc_ip': plc_ip,
            'plc_port': plc_port,
            'function_codes': function_codes,
            'read_operations': {
                'read_coils': read_coils,
                'read_discrete_inputs': read_discrete_inputs,
                'read_holding_registers': read_holding_registers,
                'read_input_registers': read_input_registers
            },
            'vulnerability': 'No proper authorization check for device ownership or access control',
            'sensitive_data': data
        }
    )
    return {
        "data": data,
    }
