from fastapi import Depends, APIRouter, HTTPException
from fastapi.responses import FileResponse
import logging
from pathlib import Path
from services.session import require_session
from services.security import detect_path_traversal, PATH_TRAVERSAL_PATTERNS
from services.monitoring import log_attack


logger = logging.getLogger("SEC537_SCADA_Patched")


router = APIRouter(tags=["Log Exporting Handlers"])


@router.get("/export")
def export_logs(file_name: str, session: str = Depends(require_session)):
    """
    VULNERABILITY: Path traversal. No sanitization, whitelist, path validation, extension restriction (e.g., "../../")
    """
    # Base directory that contains ALL exportable logs
    # This directory MUST NOT be writable by users
    # PATCHED: Use pathlib.Path to prevent path traversal with Canonical Path resolution
    BASE_LOG_DIR = Path("/var/log/scada").resolve()

    # Only allow log files (strict allowlist)
    ALLOWED_EXTENSIONS = {".log"}

    # PATCHED: Use pathlib.Path to prevent path traversal with Canonical Path resolution
    # There will be no need to detect_path_traversal but still used for monitoring purposes
    requested_path = (BASE_LOG_DIR / file_name).resolve()

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
                'detected_patterns': [p for p in PATH_TRAVERSAL_PATTERNS if p in file_name],
                'vulnerability': 'No input sanitization or path validation',
                'attempted_path': f'/var/log/scada/{file_name}'
            }
        )
        logger.warning(
            f"PATH TRAVERSAL attempt by user={session['user']}, file={file_name}"
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

    if not str(requested_path).startswith(str(BASE_LOG_DIR)):
        log_attack(
            attack_type='PATH_INJECTION',
            target_url='/api/logs/export',
            payload=file_name,
            source_ip=session["ip"],
            user_agent=session["user_agent"],
            success=False,
            details={
                'user': session["user"],
                'reason': 'Resolved path escapes base log directory',
                'base_dir': str(BASE_LOG_DIR),
                'resolved_path': str(requested_path),
                'attack_mitigated': True
            }
        )

        logger.warning(
            f"Blocked path traversal attempt by user={session['user']}, "
            f"requested={file_name}"
        )

        raise HTTPException(
            status_code=403,
            detail="Access denied"
        )

    # PATCHED: Additional Patch for allowed extensions
    if requested_path.suffix not in ALLOWED_EXTENSIONS:
        log_attack(
            attack_type='PATH_INJECTION',
            target_url='/api/logs/export',
            payload=file_name,
            source_ip=session["ip"],
            user_agent=session["user_agent"],
            success=False,
            details={
                'user': session["user"],
                'requested_extension': requested_path.suffix,
                'allowed_extensions': list(ALLOWED_EXTENSIONS)
            }
        )

        raise HTTPException(
            status_code=400,
            detail="Invalid file type"
        )

    # Check if such file exists
    if not requested_path.exists():
        raise HTTPException(
            status_code=404,
            detail="Log file not found"
        )

    return FileResponse(str(requested_path), filename=requested_path.name)
