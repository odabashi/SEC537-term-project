from fastapi import Depends, APIRouter
from fastapi.responses import FileResponse
import logging
from ..services.session import require_session


logger = logging.getLogger("SEC537_SCADA")


router = APIRouter()


@router.get("/export")
def export_logs(file: str, user: str = Depends(require_session)):
    """
    VULNERABILITY: Path traversal.
    """
    path = f"/var/log/scada/{file}"
    return FileResponse(path)
