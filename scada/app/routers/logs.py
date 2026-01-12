from fastapi import Depends, APIRouter, HTTPException
from fastapi.responses import FileResponse
import logging
from services.session import require_session
from services.security import detect_path_traversal
from services.monitoring import log_attack

logger = logging.getLogger("SEC537_SCADA")


router = APIRouter()


@router.get("/export")
def export_logs(file_name: str, session: str = Depends(require_session)):
    """
    VULNERABILITY: Path traversal. No sanitization, whitelist, path validation, extension restriction (e.g., "../../")
    """
    if detect_path_traversal(file_name):
        log_attack(
            attack_type='PATH_TRAVERSAL',
            target_url='/api/logs/export',
            payload=f'Attempted file access: {file_name}',
            source_ip=session["ip"],
            user_agent=session["user_agent"],
            success=True,  # Attacker gets response (vulnerability exists)
            details={
                'user': session["user"],
                'requested_file': file_name,
                'detected_patterns': [p for p in traversal_patterns if p in file_name],
                'vulnerability': 'No input sanitization or path validation',
                'attempted_path': f'/var/log/scada/{file_name}'
            }
        )
        
        logger.warning(
            f"PATH TRAVERSAL attempt by user={session["user"]}, file={file_name}"
        )
    else:
        # Even legitimate file access should be logged for monitoring
        log_attack(
            attack_type='PATH_INJECTION',  # Less severe, but still logged
            target_url='/api/logs/export',
            payload=f'File access: {file_name}',
            source_ip=session["ip"],
            user_agent=session["user_agent"],
            success=True,
            details={
                'user': session["user"],
                'requested_file': file_name,
                'vulnerability': 'File access without proper access control'
            }
        )
    
    path = f"/var/log/scada/{file_name}"
    # Check if such file exists
    try:
        with open(path, "rb"):
            pass
    except FileNotFoundError:
        logger.warning(f"Requested log not found: {path}")
        raise HTTPException(status_code=404, detail="Log file not found")
    except Exception as e:
        logger.exception(f"Error accessing log file {path}: {e}")
        raise HTTPException(status_code=500, detail="Unable to access log file")

    return FileResponse(path, filename=file_name)
