from fastapi import Depends, APIRouter
import os
import logging
from ..models.schemas import DiagnosticRequest
from ..services.session import require_session


logger = logging.getLogger("SEC537_SCADA")

router = APIRouter()


@router.post("/ping")
def ping(data: DiagnosticRequest, user: str = Depends(require_session)):
    """
    VULNERABILITY: Command injection.
    """
    cmd = f"ping -c 1 {data.host}"
    os.system(cmd)
    return {"executed": cmd}
