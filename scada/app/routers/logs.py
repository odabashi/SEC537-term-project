from fastapi import Depends, APIRouter, Request
from fastapi.responses import FileResponse
import logging
from scada.app.services.session import require_user
from scada.app.services.monitoring import log_attack

logger = logging.getLogger("SEC537_SCADA")


router = APIRouter()


@router.get("/export")
def export_logs(file: str, request: Request, user: str = Depends(require_user)):  # ← request eklendi
    """
    VULNERABILITY: Path traversal. No sanitization, whitelist, path validation, extension restriction (e.g., "../../")
    """
    # Extract client IP
    xff = request.headers.get("x-forwarded-for")
    if xff:
        ip = xff.split(",")[0].strip()
    else:
        ip = request.client.host
    
    user_agent = request.headers.get("user-agent", "unknown")
    
    # Check for path traversal patterns
    traversal_patterns = ["..", "/", ".bash", "passwd", ".env"]
    is_suspicious = any(p in file for p in traversal_patterns)
    
    if is_suspicious:
        # MONITORING: Log path traversal attempt
        log_attack(
            attack_type='PATH_TRAVERSAL',
            target_url='/api/logs/export',
            payload=f'Attempted file access: {file}',
            source_ip=ip,
            user_agent=user_agent,
            success=True,  # Attacker gets response (vulnerability exists)
            details={
                'user': user,
                'requested_file': file,
                'detected_patterns': [p for p in traversal_patterns if p in file],
                'vulnerability': 'No input sanitization or path validation',
                'attempted_path': f'/var/log/scada/{file}'
            }
        )
        
        logger.warning(
            f"PATH TRAVERSAL attempt by user={user}, file={file}"
        )
    else:
        # Even legitimate file access should be logged for monitoring
        log_attack(
            attack_type='PATH_INJECTION',  # Less severe, but still logged
            target_url='/api/logs/export',
            payload=f'File access: {file}',
            source_ip=ip,
            user_agent=user_agent,
            success=True,
            details={
                'user': user,
                'requested_file': file,
                'vulnerability': 'File access without proper access control'
            }
        )
    
    path = f"/var/log/scada/{file}"
    return FileResponse(path)
