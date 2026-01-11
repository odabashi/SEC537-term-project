from fastapi import APIRouter
from fastapi.responses import FileResponse


router = APIRouter()


@router.get("/export")
def export_logs(file: str):
    """
    VULNERABILITY: Path traversal.
    """
    path = f"/var/log/scada/{file}"
    return FileResponse(path)
