from fastapi import APIRouter, Depends
import logging
import requests
from scada.app.models.schemas import DeviceCheckRequest
from scada.app.services.session import require_session


logger = logging.getLogger("SEC537_SCADA")

router = APIRouter()


@router.post("/check")
def check_device(data: DeviceCheckRequest, session: str = Depends(require_session)):
    """
    Device health check.
    VULNERABILITY: Vulnerable to SSRF (no IP validation).
    """
    logger.info(f"Checking device {data.ip}")

    try:
        r = requests.get(f"http://{data.ip}", timeout=2)
        return {"status": "reachable", "response": r.text[:100]}
    except Exception as e:
        return {"status": "unreachable", "error": str(e)}
