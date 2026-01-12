from fastapi import APIRouter, Depends
import logging
import requests
from datetime import datetime
from models.schemas import DeviceCheckRequest, DeviceAddRequest
from services.session import require_session
from services.security import detect_internal_target
from services.devices import add_device
from services.monitoring import log_attack  


logger = logging.getLogger("SEC537_SCADA")
router = APIRouter()


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
        r = requests.get(f"http://{data.ip}", timeout=2)
        logger.info(f"The target device on {data.ip} is reachable. The response is {r.text[:100]}")
        return {"status": "device health check completed"}  # Blind SSRF: response is irrelevant
    except Exception as e:
        logger.error(f"The target device on {data.ip} is unreachable. The error message is {e}")
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
        "type": data.type,
        "added_by": session["user"],
        "added_at": datetime.now()
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
                f"(IP: {device['ip']})")

    # Unsafe discovery check (SSRF trigger)
    try:
        r = requests.get(f"http://{data.ip}", timeout=2)
        logger.info(f"The new device on {data.ip} is reachable. The response is {r.text[:100]}")
    except Exception as e:
        logger.error(f"The new device on {data.ip} is unreachable. The error message is {e}")
        pass

    return {"status": "Device is added and will be monitored periodically"}