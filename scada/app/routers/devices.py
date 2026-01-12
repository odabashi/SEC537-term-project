from fastapi import APIRouter, Depends
import logging
import requests
from scada.app.models.schemas import DeviceCheckRequest
from scada.app.services.session import require_session
from scada.app.services.security import detect_internal_target


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
        r = requests.get(f"http://{data.ip}", timeout=2)
        logger.info(f"The target device on {data.ip} is reachable. The response is {r.text[:100]}")
        return {"status": "device health check completed"}  # Blind SSRF: response is irrelevant
    except Exception as e:
        logger.error(f"The target device on {data.ip} is unreachable. The error message is {e}")
        return {"status": "device health check completed"}  # Still blind: attacker learns nothing
