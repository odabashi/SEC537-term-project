from fastapi import Depends, APIRouter, HTTPException
import os
import logging
import subprocess
from models.schemas import DiagnosticRequest
from services.security import detect_command_injection, validate_target_ip
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
    # For MONITORING: Log Command Injection
    if detect_command_injection(data.host):
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

    # PREVIOUS VULNERABILITY: Command injection
    # PATCHED: Enforce IP-only input, Validate IP input, Reject Command Injection, Reject Argument Injection,
    #          Reject Flag Abuse
    #          Rejected Inputs: ('-t', '--help', 'google.com', '127.0.0.1; rm -rf /')
    #          Only allowed inputs: ('127.0.0.1', '123.32.123.21')
    try:
        # PATCHED: Validate IP input
        target_ip = validate_target_ip(data.host)

        # PATCHED: Use subprocess.run() instead of os.system() to execute ping command
        result = subprocess.run(
            ["ping", "-c", "1", target_ip],
            capture_output=True,    # Capture output to return it in the response
            text=True,              # Return output as string instead of bytes
            timeout=3,              # Set timeout to 3 seconds
            check=False             # Do not raise exception on non-zero exit code
        )

        return {
            "executed": f"ping -c 1 {target_ip}",
            "target": target_ip,
            "output": result.stdout
        }
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail="Only literal IP addresses are allowed"
        )


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
