from fastapi import Depends, APIRouter
import os
import logging
from models.schemas import DiagnosticRequest
from services.security import detect_command_injection
from services.session import require_session
from services.monitoring import log_attack


logger = logging.getLogger("SEC537_SCADA_Patched")


router = APIRouter(tags=["Device Diagnostics Handlers"])


@router.post("/ping")
def ping(data: DiagnosticRequest, session: str = Depends(require_session)):
    """
    System will execute ping command by sending 4 packets to the host to check if the host is up.

    VULNERABILITY: Command injection.
    """
    if detect_command_injection(data.host):
        # MONITORING: Log Command Injection
        log_attack(
            attack_type='CMD_INJECTION',
            target_url='/api/diagnostics/ping',
            payload=f'Command injection attempt: {data.host}',
            source_ip=session['ip'],
            user_agent=session['user_agent'],
            success=True,
            details={
                'user': session['user'],
                'injected_command': data.host,
                'executed_command': f'ping -c 1 {data.host}',
                'attack_vector': 'Ping diagnostic',
                'vulnerability': 'User input passed directly to os.system() without sanitization',
                'detected_patterns': 'Command injection characters detected (e.g., ;, |, &, $, `, etc.)'
            }
        )
        logger.critical("Command Injection attempt!!!")

    cmd = f"ping -c 1 {data.host}"
    os.system(cmd)
    return {"executed": cmd}


@router.post("/traceroute")
def traceroute(data: DiagnosticRequest, session: str = Depends(require_session)):
    """
    System will execute traceroute command to the host and show every single "hop" (router) the data passes through
    along the way.

    VULNERABILITY: Command injection.
    """
    if detect_command_injection(data.host):
        # MONITORING: Log Command Injection
        log_attack(
            attack_type='CMD_INJECTION',
            target_url='/api/diagnostics/traceroute',
            payload=f'Command injection attempt: {data.host}',
            source_ip=session['ip'],
            user_agent=session['user_agent'],
            success=True,
            details={
                'user': session['user'],
                'injected_command': data.host,
                'executed_command': f'traceroute {data.host}',
                'attack_vector': 'Traceroute diagnostic',
                'vulnerability': 'User input passed directly to os.system() without sanitization',
                'detected_patterns': 'Command injection characters detected (e.g., ;, |, &, $, `, etc.)'
            }
        )
        logger.critical("Command Injection attempt!!!")

    cmd = f"traceroute {data.host}"
    os.system(cmd)
    return {"executed": cmd}
