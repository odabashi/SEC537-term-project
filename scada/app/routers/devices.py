from fastapi import APIRouter, Depends
import logging
import requests
from datetime import datetime
from scada.app.models.schemas import DeviceCheckRequest, DeviceAddRequest
from scada.app.services.session import require_session
from scada.app.services.security import detect_internal_target
from scada.app.services.devices import add_device


logger = logging.getLogger("SEC537_SCADA")


router = APIRouter()


@router.post("/check")
def check_device(data: DeviceCheckRequest, session: str = Depends(require_session)):
    """
    Device health check.
    VULNERABILITY: Vulnerable to SSRF (no IP validation).
    """
    ssrf_attempt = detect_internal_target(data.ip)

    if ssrf_attempt:
        # TODO: MONITORING - Blind SSRF
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
        "added_at": datetime.now()
    }

    # Monitoring: detect stored SSRF attempt
    if detect_internal_target(device["ip"]):
        # TODO: MONITORING - Stored SSRF
        logger.critical("Stored SSRF attempt via Unsafe Device Discovery!!!")

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
