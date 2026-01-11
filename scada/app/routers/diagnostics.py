from fastapi import Request, APIRouter
from ..models.schemas import DiagnosticRequest
from ..services.session import require_session
import os
import logging


logger = logging.getLogger("SEC537_SCADA")

router = APIRouter()


@router.post("/ping")
def ping(data: DiagnosticRequest, request: Request):
    """
    VULNERABILITY: Command injection.
    """
    user = require_session(request)
    if not user:
        logger.warning("Unauthorized session usage attempt")
        return {"error": "Unauthorized"}

    cmd = f"ping -c 1 {data.host}"
    os.system(cmd)
    return {"executed": cmd}
