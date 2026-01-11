from fastapi import Depends, APIRouter
from fastapi.responses import FileResponse
import logging
from scada.app.services.session import require_user


logger = logging.getLogger("SEC537_SCADA")


router = APIRouter()


@router.get("/export")
def export_logs(file: str, user: str = Depends(require_user)):
    """
    VULNERABILITY: Path traversal. No sanitization, whitelist, path validation, extension restriction (e.g., "../../")
    """
    if any(p in file for p in ["..", "/", ".bash", "passwd", ".env"]):
        # TODO: MONITORING - VULNERABILITY: PATH TRAVERSAL
        logger.warning(
            f"PATH TRAVERSAL attempt by user={user}, file={file}"
        )
    path = f"/var/log/scada/{file}"
    return FileResponse(path)
