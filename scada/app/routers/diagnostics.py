from fastapi import Depends, APIRouter
import os
import logging
from scada.app.models.schemas import DiagnosticRequest
from scada.app.services.session import require_user


logger = logging.getLogger("SEC537_SCADA")

router = APIRouter()


@router.post("/ping")
def ping(data: DiagnosticRequest, user: str = Depends(require_user)):
    """
    VULNERABILITY: Command injection.
    """
    cmd = f"ping -c 1 {data.host}"
    os.system(cmd)
    return {"executed": cmd}
